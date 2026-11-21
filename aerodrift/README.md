# AeroDrift - agentic cloud topology and self-healing remediation

Polls cloud state, models it as a NetworkX graph, asks graph questions
("can the internet reach this database?"), diffs against an approved baseline, then
**generates a fix with Python's `ast`, validates it, and executes it sandboxed**.

```
provider (mock | AWS boto3, async) -> CloudState -> NetworkX graph -> drift findings
        -> plan -> ast-generated remediate(ec2) -> validate -> exec (dry-run by default)
        -> re-scan to verify -> SQLite snapshots/audit log -> Rich dashboard + PDF report
```

## Run

```bash
pip install -r requirements.txt            # networkx, rich, boto3 (optional), reportlab
python -m aerodrift demo                   # full scenario on a mock cloud (auto-heals)
python -m aerodrift demo --dry-run         # same, but only shows what it WOULD do
python -m aerodrift watch --provider aws --region ap-south-1            # real account, dry-run
python -m aerodrift watch --provider aws --auto-remediate               # real account, applies fixes
python -m aerodrift history | diff 1 2     # snapshot history / topology diff between two snapshots
python -m unittest discover -s tests -t . -v                            # 16 tests
```
`AERODRIFT_PLAIN=1` forces plain-text output even when Rich is installed.

## Modules (maps to the brief)

| Brief module | File |
|---|---|
| Cloud Ingestion (boto3 + asyncio) | `providers.py` (`AwsProvider` uses `asyncio.to_thread` + `gather`; `MockCloud` for sandboxes) |
| Topology Engine (NetworkX) | `topology.py` (internet -> SG -> host -> SG -> host paths) |
| Drift detection | `drift.py` (graph-query policies + baseline diff) |
| Code Generator (`ast`) + Execution Sandbox (`exec`) | `remediation.py` |
| State persistence + diff between timestamps | `store.py` |
| Audit Dashboard (Rich) + PDF incident report | `dashboard.py`, `report.py` |
| Orchestration | `daemon.py`, `cli.py` |

## Policies detected
* `db_exposed` (CRITICAL): a database has a *direct* internet -> SG -> DB path. The approved path through the
  web and app tiers is reported as fine.
* `open_admin_port` (HIGH): SSH/RDP open to 0.0.0.0/0 or ::/0.

## Why exec() is acceptable here
The brief asks for `ast` + `exec()`. Executing generated code is only safe with layers around it:
1. Code is built from AST nodes, never by pasting cloud data into a string.
2. `validate()` whitelists node types, one function shape, one callable (`ec2.revoke_security_group_ingress`)
   and its exact keywords; 8 hostile inputs are covered in `tests/test_aerodrift.py`.
3. `exec` runs with empty `__builtins__`, and the function only sees a recording proxy.
4. **Dry-run is the default.** Live changes require `--auto-remediate`. A per-cycle action cap (5) leaves
   larger changes for a human. After applying, AeroDrift re-scans and reports whether the fix verified.

## AWS use (not exercised against a live account)
`AwsProvider` is written against the boto3 API but I had no AWS access or network, so it is untested
beyond sharing an interface with the mock. Try it in dry-run mode first. Minimal IAM:
`ec2:DescribeSecurityGroups, ec2:DescribeSubnets, ec2:DescribeInstances, rds:DescribeDBInstances`, plus
`ec2:RevokeSecurityGroupIngress` only if you enable auto-remediation.

## Limits
* Reachability is evaluated at security-group level only (no route tables / NACLs), a conservative model.
* Only ingress revocation is automated. Public-subnet detection on AWS is approximated by `MapPublicIpOnLaunch`.
* Rich rendering is written against Rich's documented API but untested here (Rich was not installable offline);
  the plain-text renderer is what the tests and demo output cover.
* Detection time is bounded by the poll interval plus one fetch; the demo and tests assert < 5 s.
