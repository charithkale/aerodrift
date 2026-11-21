"""AeroDrift CLI.

  python -m aerodrift demo [--dry-run]        full scenario against a mock cloud
  python -m aerodrift watch --provider aws    poll a real account (dry-run unless --auto-remediate)
  python -m aerodrift history | diff A B      snapshot history and topology diffs
"""
from __future__ import annotations

import argparse
import asyncio
import os
import time

from .dashboard import Dashboard
from .daemon import Watcher
from .providers import MockCloud
from .report import write_incident_report
from .store import Store

OPEN_DB = {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
OPEN_SSH = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}


async def run_demo(db: str, out_dir: str, auto: bool, poll: float = 1.0) -> dict:
    ui = Dashboard()
    store = Store(db)
    cloud = MockCloud()
    watcher = Watcher(cloud, store, auto_remediate=auto)

    ui.title("1. Baseline (approved topology)")
    base = await watcher.cycle()
    ui.topology(base.state)
    ui.paths(base.state)

    ui.title("2. An engineer makes a 'temporary' manual change")
    print("  authorize 5432 from 0.0.0.0/0 on sg-db   (database now exposed)")
    print("  authorize   22 from 0.0.0.0/0 on sg-bastion")
    cloud.ec2.authorize_security_group_ingress(GroupId="sg-db", IpPermissions=[OPEN_DB])
    cloud.ec2.authorize_security_group_ingress(GroupId="sg-bastion", IpPermissions=[OPEN_SSH])
    t_change = time.time()

    while True:                                     # the daemon's polling loop
        res = await watcher.cycle()
        if res.findings:
            break
        await asyncio.sleep(poll)
    latency = res.detected_at - t_change

    ui.title("3. Detection (%.2f s after the change)" % latency)
    ui.topology(res.state, res.drifted, res.findings)
    ui.paths(res.state)
    ui.findings(res.findings)
    ui.diff(res.changes)
    ui.remediation(res)

    if res.after is not None:
        ui.title("4. Topology after self-healing")
        ui.topology(res.after)
        ui.paths(res.after)

    os.makedirs(out_dir, exist_ok=True)
    report = write_incident_report(os.path.join(out_dir, "incident_report.pdf"), res, latency)
    ui.title("Done")
    print("incident report:", report)
    print("snapshots stored in %s: %d" % (db, len(store.list_snapshots())))
    return {"latency": latency, "result": res, "report": report}


async def run_watch(provider, db, interval, auto):
    ui, store = Dashboard(), Store(db)
    watcher = Watcher(provider, store, auto_remediate=auto)
    stop = asyncio.Event()

    def show(res):
        stamp = time.strftime("%H:%M:%S")
        if not res.findings:
            print("[%s] clean (%d changes vs baseline) %s" % (stamp, len(res.changes), "; ".join(res.notes)))
            return
        ui.findings(res.findings)
        ui.remediation(res)

    print("watching (%s, every %.0fs, %s) - Ctrl-C to stop" % (
        provider.name, interval, "AUTO-REMEDIATE" if auto else "dry-run"))
    try:
        await watcher.run(interval, stop, on_cycle=show)
    except asyncio.CancelledError:
        pass


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aerodrift")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo"); d.add_argument("--db", default="aerodrift_demo.db")
    d.add_argument("--out", default="reports"); d.add_argument("--dry-run", action="store_true")
    w = sub.add_parser("watch"); w.add_argument("--provider", choices=["mock", "aws"], default="mock")
    w.add_argument("--region", default="us-east-1"); w.add_argument("--profile")
    w.add_argument("--interval", type=float, default=5.0); w.add_argument("--db", default="aerodrift.db")
    w.add_argument("--auto-remediate", action="store_true")
    h = sub.add_parser("history"); h.add_argument("--db", default="aerodrift.db")
    f = sub.add_parser("diff"); f.add_argument("a", type=int); f.add_argument("b", type=int)
    f.add_argument("--db", default="aerodrift.db")
    a = ap.parse_args(argv)

    if a.cmd == "demo":
        asyncio.run(run_demo(a.db, a.out, auto=not a.dry_run))
    elif a.cmd == "watch":
        if a.provider == "aws":
            from .providers import AwsProvider
            provider = AwsProvider(a.region, a.profile)
        else:
            provider = MockCloud()
        try:
            asyncio.run(run_watch(provider, a.db, a.interval, a.auto_remediate))
        except KeyboardInterrupt:
            pass
    elif a.cmd == "history":
        for sid, ts, label, fp in Store(a.db).list_snapshots():
            print("%4d  %s  %-18s %s" % (sid, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)), label, fp))
    elif a.cmd == "diff":
        Dashboard().diff(Store(a.db).diff(a.a, a.b), "Topology diff #%d -> #%d" % (a.a, a.b))


if __name__ == "__main__":
    main()
