import ast
import asyncio
import os
import tempfile
import time
import unittest

from aerodrift import remediation as rem
from aerodrift.daemon import Watcher
from aerodrift.dashboard import render_plain, topology_tree
from aerodrift.drift import diff_states, evaluate
from aerodrift.models import CloudState, Rule
from aerodrift.providers import MockCloud, sample_cloud
from aerodrift.report import write_incident_report
from aerodrift.store import Store
from aerodrift.topology import INTERNET, build_graph, exposure_paths

OPEN_DB = {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
OPEN_SSH = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}


def tmpdb():
    return os.path.join(tempfile.mkdtemp(), "t.db")


class GraphTests(unittest.TestCase):
    def test_baseline_has_only_the_approved_indirect_path(self):
        g = build_graph(sample_cloud())
        (p,) = exposure_paths(g)
        self.assertFalse(p.direct)
        self.assertEqual(p.path, [INTERNET, "sg:sg-web", "i-web", "sg:sg-app", "i-app", "sg:sg-db", "db-prod"])
        self.assertEqual(evaluate(sample_cloud()), [])

    def test_open_db_rule_creates_direct_path(self):
        c = MockCloud()
        c.ec2.authorize_security_group_ingress(GroupId="sg-db", IpPermissions=[OPEN_DB])
        (p,) = exposure_paths(build_graph(c.state))
        self.assertTrue(p.direct)
        (f,) = evaluate(c.state)
        self.assertEqual((f.kind, f.severity, f.sg_id), ("db_exposed", "CRITICAL", "sg-db"))

    def test_open_ssh_and_all_ports_rule(self):
        c = MockCloud()
        c.ec2.authorize_security_group_ingress(GroupId="sg-bastion", IpPermissions=[OPEN_SSH])
        self.assertEqual([f.kind for f in evaluate(c.state)], ["open_admin_port"])
        c.state.sgs["sg-app"].ingress.append(Rule("-1", cidr="::/0"))      # IPv6 any-any on the app tier
        kinds = {(f.kind, f.sg_id) for f in evaluate(c.state)}
        self.assertIn(("open_admin_port", "sg-app"), kinds)

    def test_corp_cidr_is_not_internet(self):
        self.assertFalse(Rule("tcp", 22, 22, cidr="203.0.113.0/24").is_internet)
        self.assertTrue(Rule("tcp", 22, 22, cidr="0.0.0.0/0").is_internet)

    def test_diff(self):
        a, b = sample_cloud(), sample_cloud()
        b.sgs["sg-db"].ingress.append(Rule("tcp", 5432, 5432, cidr="0.0.0.0/0"))
        (c,) = diff_states(a, b)
        self.assertEqual((c.kind, c.target), ("rule_added", "sg-db"))

    def test_state_roundtrip(self):
        s = sample_cloud()
        self.assertEqual(CloudState.from_dict(s.to_dict()).fingerprint(), s.fingerprint())


class RemediationTests(unittest.TestCase):
    def _actions(self, c):
        return rem.plan_remediation(evaluate(c.state))[0]

    def test_generated_code_validates_and_fixes_the_cloud(self):
        c = MockCloud()
        c.ec2.authorize_security_group_ingress(GroupId="sg-db", IpPermissions=[OPEN_DB])
        src = rem.generate_source(self._actions(c))
        rem.validate(ast.parse(src))
        log = rem.execute(src, c.ec2, dry_run=False)
        self.assertEqual(log[0]["GroupId"], "sg-db")
        self.assertEqual(evaluate(c.state), [])

    def test_dry_run_changes_nothing(self):
        c = MockCloud()
        c.ec2.authorize_security_group_ingress(GroupId="sg-db", IpPermissions=[OPEN_DB])
        rem.execute(rem.generate_source(self._actions(c)), c.ec2, dry_run=True)
        self.assertEqual(len(evaluate(c.state)), 1)

    def test_validator_rejects_unsafe_code(self):
        bad = [
            "def remediate(ec2):\n    __import__('os').system('id')",
            "def remediate(ec2):\n    ec2.delete_security_group(GroupId='sg-1')",
            "def remediate(ec2):\n    ec2.revoke_security_group_ingress(GroupId=open('/etc/passwd').read(), IpPermissions=[])",
            "import os\ndef remediate(ec2):\n    pass",
            "def remediate(ec2, x):\n    pass",
            "def remediate(ec2):\n    ec2.revoke_security_group_ingress(GroupId='a', IpPermissions=[], DryRun=False)",
            "def remediate(ec2):\n    ec2.__class__.__mro__",
            "def remediate(ec2):\n    ec2.revoke_security_group_ingress(*['a'])",
        ]
        for src in bad:
            with self.subTest(src=src), self.assertRaises(rem.UnsafeCode):
                rem.validate(ast.parse(src))
            with self.assertRaises((rem.UnsafeCode, SyntaxError)):
                rem.execute(src, MockCloud().ec2)

    def test_action_cap_forces_review(self):
        c = MockCloud()
        for i in range(8):
            c.state.sgs["sg-bastion"].ingress.append(Rule("tcp", 22 - i, 22 + i, cidr="0.0.0.0/0"))
        todo, skipped = rem.plan_remediation(evaluate(c.state), max_actions=3)
        self.assertEqual((len(todo), len(skipped)), (3, 5))


class WatcherTests(unittest.TestCase):
    def test_detects_within_5s_heals_and_verifies(self):
        async def go():
            c = MockCloud()
            w = Watcher(c, Store(tmpdb()), auto_remediate=True)
            self.assertEqual((await w.cycle()).findings, [])
            c.ec2.authorize_security_group_ingress(GroupId="sg-db", IpPermissions=[OPEN_DB])
            t0 = time.time()
            res = await w.cycle()
            self.assertLess(res.detected_at - t0, 5.0)
            self.assertTrue(res.applied and res.verified)
            self.assertEqual((await w.cycle()).findings, [])
            return res
        res = asyncio.run(go())
        self.assertIn("sg-db", res.drifted)

    def test_default_is_dry_run(self):
        async def go():
            c = MockCloud()
            w = Watcher(c, Store(tmpdb()))
            await w.cycle()
            c.ec2.authorize_security_group_ingress(GroupId="sg-db", IpPermissions=[OPEN_DB])
            res = await w.cycle()
            self.assertFalse(res.applied)
            self.assertEqual(len((await w.cycle()).findings), 1)     # still exposed
        asyncio.run(go())

    def test_refuses_to_baseline_a_violating_state(self):
        async def go():
            c = MockCloud()
            c.ec2.authorize_security_group_ingress(GroupId="sg-db", IpPermissions=[OPEN_DB])
            st = Store(tmpdb())
            await Watcher(c, st).cycle()
            self.assertIsNone(st.get_baseline())
        asyncio.run(go())


class StoreReportDashboardTests(unittest.TestCase):
    def test_snapshot_diff_between_two_timestamps(self):
        st = Store(tmpdb())
        a = sample_cloud(); b = sample_cloud()
        b.sgs["sg-db"].ingress.append(Rule("tcp", 5432, 5432, cidr="0.0.0.0/0"))
        ia, ib = st.save_snapshot(a, "t1"), st.save_snapshot(b, "t2")
        self.assertEqual([c.kind for c in st.diff(ia, ib)], ["rule_added"])
        self.assertEqual(st.diff(ib, ia)[0].kind, "rule_removed")

    def test_pdf_report_is_written(self):
        async def go():
            c = MockCloud(); w = Watcher(c, Store(tmpdb()), auto_remediate=True)
            await w.cycle()
            c.ec2.authorize_security_group_ingress(GroupId="sg-db", IpPermissions=[OPEN_DB])
            return await w.cycle()
        res = asyncio.run(go())
        out = write_incident_report(os.path.join(tempfile.mkdtemp(), "r.pdf"), res, 0.4)
        self.assertTrue(os.path.getsize(out) > 1000)
        if out.endswith(".pdf"):
            self.assertEqual(open(out, "rb").read(4), b"%PDF")

    def test_drifted_resources_are_highlighted(self):
        c = MockCloud()
        c.ec2.authorize_security_group_ingress(GroupId="sg-db", IpPermissions=[OPEN_DB])
        f = evaluate(c.state)
        text = render_plain(topology_tree(c.state, {"sg-db", "db-prod"}, {(x.sg_id, x.rule.key) for x in f}))
        self.assertIn("!! SG sg-db", text)
        self.assertIn("EXPOSED", text)
        self.assertNotIn("!! SG sg-app", text)


if __name__ == "__main__":
    unittest.main()
