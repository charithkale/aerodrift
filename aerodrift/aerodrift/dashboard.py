"""Audit dashboard. Uses Rich when installed (red = drifted), plain text otherwise.

Tree/table content is built as plain data first, so both renderers (and the tests)
share one source of truth.
"""
from __future__ import annotations

import os
import time

from .models import CloudState
from .topology import build_graph, exposure_paths, pretty_path

try:                                    # pragma: no cover - exercised only when rich is installed
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.tree import Tree
    HAVE_RICH = os.environ.get("AERODRIFT_PLAIN") != "1"
except ImportError:
    HAVE_RICH = False


def topology_tree(state: CloudState, drifted: set, bad_rules: set) -> tuple:
    """(label, style, children) tuples:  VPC > subnet > host > security group > rules."""
    vpcs = sorted({s.vpc_id for s in state.subnets.values()} | {g.vpc_id for g in state.sgs.values()})
    root = []
    for vpc in vpcs:
        subnets = []
        for sub in sorted((s for s in state.subnets.values() if s.vpc_id == vpc), key=lambda s: s.id):
            hosts = []
            for inst in sorted((i for i in state.instances.values() if i.subnet_id == sub.id), key=lambda i: i.id):
                sgs = []
                for sg_id in inst.sg_ids:
                    sg = state.sgs.get(sg_id)
                    if not sg:
                        continue
                    rules = [("ingress: " + r.describe() + ("   <-- EXPOSED" if (sg_id, r.key) in bad_rules else ""),
                              "red" if (sg_id, r.key) in bad_rules else "", [])
                             for r in sg.ingress]
                    sgs.append(("SG %s (%s)" % (sg.id, sg.name), "red" if sg_id in drifted else "cyan", rules))
                hosts.append(("%s [%s] %s/%s" % (inst.name, inst.id, inst.kind, inst.role),
                              "bold red" if inst.id in drifted else "green", sgs))
            subnets.append(("%s (%s)" % (sub.id, "public" if sub.public else "private"), "yellow", hosts))
        root.append(("VPC %s" % vpc, "bold", subnets))
    return ("Cloud topology", "bold", root)


def render_plain(node: tuple, indent: int = 0) -> str:
    label, style, kids = node
    mark = "!! " if "red" in style else ""
    lines = ["%s%s%s" % ("  " * indent, mark, label)]
    for k in kids:
        lines.append(render_plain(k, indent + 1))
    return "\n".join(lines)


def _rich_tree(node: tuple, parent=None):
    label, style, kids = node
    t = Tree(label, style=style or None) if parent is None else parent.add(label, style=style or None)
    for k in kids:
        _rich_tree(k, t)
    return t


class Dashboard:
    def __init__(self):
        self.console = Console() if HAVE_RICH else None

    def _print(self, text=""):
        print(text)

    def title(self, text: str):
        if self.console:
            self.console.rule("[bold]%s" % text)
        else:
            print("\n=== %s ===" % text)

    def topology(self, state, drifted=frozenset(), findings=()):
        bad = {(f.sg_id, f.rule.key) for f in findings}
        tree = topology_tree(state, set(drifted), bad)
        if self.console:
            self.console.print(_rich_tree(tree))
        else:
            print(render_plain(tree))

    def paths(self, state):
        g = build_graph(state)
        paths = exposure_paths(g)
        rows = [(p.database, "DIRECT (violation)" if p.direct else "via application tier (approved)",
                 pretty_path(g, p.path)) for p in paths] or [("-", "no internet path to any database", "-")]
        self._table("Internet -> database reachability", ["Database", "Verdict", "Path"], rows,
                    row_styles=["bold red" if "DIRECT" in r[1] else "green" for r in rows])

    def findings(self, findings):
        rows = [(f.severity, f.kind, f.sg_id, f.rule.describe(), ", ".join(f.resources)) for f in findings]
        self._table("Policy findings", ["Severity", "Kind", "SG", "Rule", "Affected"], rows or [("none",) * 5],
                    row_styles=["bold red" if r[0] == "CRITICAL" else "red" for r in rows] or None)

    def diff(self, changes, title="Topology diff vs baseline"):
        rows = [(c.kind, c.target, c.detail) for c in changes] or [("no changes", "", "")]
        self._table(title, ["Change", "Resource", "Detail"], rows,
                    row_styles=["red" if "added" in r[0] else "yellow" for r in rows])

    def remediation(self, result):
        self.title("Remediation")
        if not result.actions:
            print("No action needed.")
            return
        if self.console:
            self.console.print(Panel(Syntax(result.source, "python", theme="ansi_dark"),
                                     title="Generated remediation (python ast)"))
        else:
            print("Generated remediation (python ast):\n" + result.source)
        rows = [(("DRY-RUN" if c["dry_run"] else "APPLIED"), c["method"], c["GroupId"]) for c in result.call_log]
        self._table("Executed calls", ["Mode", "API", "Security group"], rows)
        if result.verified is not None:
            msg = "VERIFIED: targeted findings are gone after re-scan" if result.verified else \
                  "NOT VERIFIED: findings remain - escalate to a human"
            if self.console:
                self.console.print("[bold %s]%s" % ("green" if result.verified else "red", msg))
            else:
                print(msg)
        for n in result.notes:
            print("note:", n)

    def _table(self, title, cols, rows, row_styles=None):
        if self.console:
            t = Table(title=title)
            for c in cols:
                t.add_column(c)
            for i, r in enumerate(rows):
                t.add_row(*[str(x) for x in r], style=(row_styles[i] if row_styles else None))
            self.console.print(t)
        else:
            print("\n%s" % title)
            widths = [max(len(str(x)) for x in [c] + [r[i] for r in rows]) for i, c in enumerate(cols)]
            print("  ".join(c.ljust(w) for c, w in zip(cols, widths)))
            for r in rows:
                print("  ".join(str(x).ljust(w) for x, w in zip(r, widths)))
