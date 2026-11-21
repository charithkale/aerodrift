"""Agentic remediation: generate a fix with Python's `ast`, validate it, run it sandboxed.

Pipeline:  Finding -> Action -> ast.Module (generated)  -> validate() -> exec
Safety layers (the brief asks for ast + exec; these make that defensible):
  1. The code is built from AST nodes, never by string concatenation of cloud data.
  2. validate() whitelists node types, the single function shape, the only callable
     (ec2.revoke_security_group_ingress) and its keyword names. Anything else
     raises UnsafeCode *before* compile/exec.
  3. exec runs with empty __builtins__, and the function only receives a
     recorder proxy that re-checks the method name and logs every call.
  4. Dry-run is the default; the live client is only passed when auto-remediation
     is explicitly enabled. A per-cycle action cap forces human review of big changes.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .models import Rule

ALLOWED_METHODS = {"revoke_security_group_ingress"}
REQUIRED_KW = {"GroupId", "IpPermissions"}
_ALLOWED_NODES = (ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Expr, ast.Pass, ast.Call,
                  ast.Attribute, ast.Name, ast.Load, ast.Constant, ast.Dict, ast.List, ast.keyword)


class UnsafeCode(Exception):
    pass


@dataclass
class Action:
    sg_id: str
    rule: Rule
    reason: str
    finding_ids: list = field(default_factory=list)


def plan_remediation(findings: list, max_actions: int = 5):
    """One revoke action per distinct (sg, rule). Returns (actions, skipped_for_review)."""
    actions: dict = {}
    for f in findings:
        k = (f.sg_id, f.rule.key)
        if k in actions:
            actions[k].finding_ids.append(f.id)
        else:
            actions[k] = Action(f.sg_id, f.rule, f.message, [f.id])
    ordered = list(actions.values())
    return ordered[:max_actions], ordered[max_actions:]


def _lit(v):
    if isinstance(v, dict):
        return ast.Dict(keys=[ast.Constant(k) for k in v], values=[_lit(x) for x in v.values()])
    if isinstance(v, (list, tuple)):
        return ast.List(elts=[_lit(x) for x in v], ctx=ast.Load())
    return ast.Constant(v)


def build_ast(actions: list) -> ast.Module:
    calls = []
    for a in actions:
        calls.append(ast.Expr(ast.Call(
            func=ast.Attribute(value=ast.Name("ec2", ast.Load()),
                               attr="revoke_security_group_ingress", ctx=ast.Load()),
            args=[],
            keywords=[ast.keyword("GroupId", ast.Constant(a.sg_id)),
                      ast.keyword("IpPermissions", _lit([a.rule.to_ip_permission()]))])))
    tree = ast.parse("def remediate(ec2):\n    pass")
    tree.body[0].body = calls or [ast.Pass()]
    return ast.fix_missing_locations(tree)


def generate_source(actions: list) -> str:
    return ast.unparse(build_ast(actions))


def validate(tree: ast.AST) -> None:
    if not isinstance(tree, ast.Module) or len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise UnsafeCode("module must contain exactly one function definition")
    fn = tree.body[0]
    if (fn.name != "remediate" or [a.arg for a in fn.args.args] != ["ec2"] or fn.decorator_list
            or fn.args.defaults or fn.args.vararg or fn.args.kwarg or fn.args.kwonlyargs):
        raise UnsafeCode("function must be exactly: def remediate(ec2)")
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise UnsafeCode("disallowed syntax: %s" % type(node).__name__)
        if isinstance(node, ast.Name) and node.id != "ec2":
            raise UnsafeCode("disallowed name: %s" % node.id)
        if isinstance(node, ast.Constant) and not isinstance(node.value, (str, int, bool)):
            raise UnsafeCode("disallowed constant: %r" % (node.value,))
        if isinstance(node, ast.Dict) and any(not (isinstance(k, ast.Constant) and isinstance(k.value, str))
                                              for k in node.keys):
            raise UnsafeCode("dict keys must be string literals")
    for stmt in fn.body:
        if isinstance(stmt, ast.Pass):
            continue
        call = stmt.value if isinstance(stmt, ast.Expr) else None
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name) and call.func.value.id == "ec2"
                and call.func.attr in ALLOWED_METHODS and not call.args):
            raise UnsafeCode("only ec2.%s(...) calls are allowed" % "/".join(sorted(ALLOWED_METHODS)))
        if {k.arg for k in call.keywords} != REQUIRED_KW:
            raise UnsafeCode("call must pass exactly %s" % sorted(REQUIRED_KW))


class _Recorder:
    """Proxy handed to generated code: re-checks the method, logs, honours dry-run."""

    def __init__(self, client, dry_run: bool):
        self._client, self._dry, self.log = client, dry_run, []

    def __getattr__(self, name):
        if name not in ALLOWED_METHODS:
            raise AttributeError(name)

        def call(**kwargs):
            self.log.append({"method": name, "dry_run": self._dry, **kwargs})
            return {"DryRun": True} if self._dry else getattr(self._client, name)(**kwargs)
        return call


def execute(source: str, client, dry_run: bool = True) -> list:
    """Validate and run generated remediation source. Returns the call log."""
    tree = ast.parse(source)
    validate(tree)
    code = compile(tree, "<aerodrift-remediation>", "exec")
    namespace = {"__builtins__": {}}
    exec(code, namespace)                       # defines `remediate` only (validated above)
    rec = _Recorder(client, dry_run)
    namespace["remediate"](rec)
    return rec.log
