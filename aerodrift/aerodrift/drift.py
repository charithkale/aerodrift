"""Drift detection: policy findings from graph queries + diffs against a baseline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import CloudState, Rule
from .topology import INTERNET, build_graph, pretty_path, sg_node

SEVERITY = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


@dataclass
class Finding:
    kind: str                       # db_exposed | open_admin_port
    severity: str
    sg_id: str
    rule: Rule
    resources: list = field(default_factory=list)
    message: str = ""

    @property
    def id(self) -> str:
        return "%s:%s:%s" % (self.kind, self.sg_id, self.rule.key)


def evaluate(state: CloudState) -> list:
    """Return policy violations, worst first. Pure function of the state."""
    g = build_graph(state)
    found: dict = {}                # (sg_id, rule.key) -> Finding, keep the worst

    def put(f: Finding):
        k = (f.sg_id, f.rule.key)
        if k not in found or SEVERITY[f.severity] > SEVERITY[found[k].severity]:
            if k in found:
                f.resources = sorted(set(f.resources) | set(found[k].resources))
            found[k] = f
        else:
            found[k].resources = sorted(set(found[k].resources) | set(f.resources))

    internet_sgs = set(g.successors(INTERNET))
    # 1) a database that has a *direct* internet -> SG -> DB path
    for db, data in g.nodes(data=True):
        if not data.get("is_db"):
            continue
        for sgn in set(g.predecessors(db)) & internet_sgs:
            sg_id = g.nodes[sgn]["sg_id"]
            for rule in g[INTERNET][sgn]["rules"]:
                put(Finding("db_exposed", "CRITICAL", sg_id, rule, [db],
                            "Database %s is reachable from the internet via %s (%s)" % (
                                data["label"], pretty_path(g, [INTERNET, sgn, db]), rule.describe())))
    # 2) SSH / RDP open to the world on any host
    for sgn in internet_sgs:
        sg_id = g.nodes[sgn]["sg_id"]
        hosts = [h for h in g.successors(sgn)]
        for rule in g[INTERNET][sgn]["rules"]:
            for port, name in ADMIN_PORTS.items():
                if rule.covers_port(port):
                    put(Finding("open_admin_port", "HIGH", sg_id, rule, hosts,
                                "%s (port %d) is open to the internet on %s" % (name, port, sg_id)))
                    break
    return sorted(found.values(), key=lambda f: (-SEVERITY[f.severity], f.id))


@dataclass
class Change:
    kind: str           # rule_added | rule_removed | sg_added | sg_removed | instance_added | instance_removed
    target: str
    detail: str = ""
    rule: Optional[Rule] = None

    def describe(self) -> str:
        return "%s %s %s" % (self.kind, self.target, self.detail)


def diff_states(old: CloudState, new: CloudState) -> list:
    out = []
    for sg_id in sorted(set(old.sgs) | set(new.sgs)):
        a, b = old.sgs.get(sg_id), new.sgs.get(sg_id)
        if a is None:
            out.append(Change("sg_added", sg_id, b.name))
        elif b is None:
            out.append(Change("sg_removed", sg_id, a.name))
        else:
            ra, rb = set(a.ingress), set(b.ingress)
            out += [Change("rule_added", sg_id, r.describe(), r) for r in sorted(rb - ra, key=lambda r: r.key)]
            out += [Change("rule_removed", sg_id, r.describe(), r) for r in sorted(ra - rb, key=lambda r: r.key)]
    for i in sorted(set(old.instances) | set(new.instances)):
        if i not in old.instances:
            out.append(Change("instance_added", i, new.instances[i].name))
        elif i not in new.instances:
            out.append(Change("instance_removed", i, old.instances[i].name))
    return out


def drifted_resources(state: CloudState, findings: list, changes: list) -> set:
    """Ids (SGs and hosts) to highlight in red on the dashboard."""
    ids = set()
    for f in findings:
        ids.add(f.sg_id); ids.update(f.resources)
    for c in changes:
        if c.kind in ("rule_added", "rule_removed", "sg_added"):
            ids.add(c.target)
            for inst in state.instances.values():
                if c.target in inst.sg_ids:
                    ids.add(inst.id)
    return ids
