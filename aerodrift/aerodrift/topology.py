"""Cloud topology as a NetworkX directed graph.

Nodes : "internet", "sg:<id>" for security groups, "<instance-id>" for hosts.
Edges : internet -> sg      the SG has an ingress rule open to 0.0.0.0/0 or ::/0
        instance -> sg      the SG has a rule whose source is the instance's own SG
        sg -> instance      membership (traffic admitted by the SG reaches the host)

So `nx.has_path(G, "internet", "db-prod")` answers "can the internet reach this
database?", and a path that goes internet -> sg -> db (no host in between) is a
*direct* exposure, while internet -> sg-web -> web -> sg-app -> app -> sg-db -> db
is the approved three-tier path.

Model assumption: reachability is evaluated at security-group level only
(conservative). Route tables / NACLs are not modelled.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from .models import CloudState

INTERNET = "internet"


def sg_node(sg_id: str) -> str:
    return "sg:" + sg_id


def build_graph(state: CloudState) -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node(INTERNET, type="internet", label="Internet")
    members: dict = {sg_id: [] for sg_id in state.sgs}
    for inst in state.instances.values():
        g.add_node(inst.id, type="instance", label=inst.name, is_db=inst.is_database)
        for sg_id in inst.sg_ids:
            members.setdefault(sg_id, []).append(inst.id)
    for sg in state.sgs.values():
        g.add_node(sg_node(sg.id), type="sg", label=sg.name, sg_id=sg.id)

    def add(u, v, rule):
        if g.has_edge(u, v):
            g[u][v]["rules"].append(rule)
        else:
            g.add_edge(u, v, rules=[rule])

    for sg in state.sgs.values():
        for rule in sg.ingress:
            if rule.is_internet:
                add(INTERNET, sg_node(sg.id), rule)
            elif rule.source_sg:
                for src_host in members.get(rule.source_sg, []):
                    add(src_host, sg_node(sg.id), rule)
        for host in members.get(sg.id, []):
            g.add_edge(sg_node(sg.id), host, rules=[])
    return g


@dataclass
class ExposurePath:
    database: str
    path: list              # node ids from "internet" to the database
    direct: bool            # True => no application host in between


def exposure_paths(g: nx.DiGraph) -> list:
    out = []
    for node, data in g.nodes(data=True):
        if data.get("is_db") and nx.has_path(g, INTERNET, node):
            path = nx.shortest_path(g, INTERNET, node)
            out.append(ExposurePath(node, path, direct=len(path) == 3))
    return out


def pretty_path(g: nx.DiGraph, path: list) -> str:
    return " -> ".join(g.nodes[n].get("label", n) for n in path)
