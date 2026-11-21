"""Cloud state model (provider-neutral, JSON-serialisable)."""
from __future__ import annotations

import ipaddress
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

ALL_PORTS = (0, 65535)


@dataclass(frozen=True)
class Rule:
    """One security-group ingress rule. Exactly one of cidr / source_sg is set."""
    protocol: str = "tcp"            # tcp | udp | icmp | -1 (all)
    from_port: int = 0
    to_port: int = 65535
    cidr: Optional[str] = None       # e.g. 0.0.0.0/0, ::/0, 10.0.0.0/16
    source_sg: Optional[str] = None  # another security group id

    @property
    def key(self) -> str:
        return "%s:%s-%s:%s" % (self.protocol, self.from_port, self.to_port, self.cidr or self.source_sg)

    @property
    def is_internet(self) -> bool:
        """True when the rule admits the whole internet (any /0 CIDR)."""
        if not self.cidr:
            return False
        return ipaddress.ip_network(self.cidr, strict=False).prefixlen == 0

    def covers_port(self, port: int) -> bool:
        return self.protocol == "-1" or self.from_port <= port <= self.to_port

    def describe(self) -> str:
        src = self.cidr or self.source_sg
        ports = "all ports" if self.protocol == "-1" else (
            str(self.from_port) if self.from_port == self.to_port else "%d-%d" % (self.from_port, self.to_port))
        return "%s %s from %s" % (self.protocol if self.protocol != "-1" else "all", ports, src)

    def to_ip_permission(self) -> dict:
        """Render as a boto3 IpPermissions entry (exactly what revoke_* expects)."""
        perm: dict = {"IpProtocol": self.protocol}
        if self.protocol != "-1":
            perm["FromPort"], perm["ToPort"] = self.from_port, self.to_port
        if self.source_sg:
            perm["UserIdGroupPairs"] = [{"GroupId": self.source_sg}]
        elif self.cidr and ":" in self.cidr:
            perm["Ipv6Ranges"] = [{"CidrIpv6": self.cidr}]
        else:
            perm["IpRanges"] = [{"CidrIp": self.cidr}]
        return perm


@dataclass
class SecurityGroup:
    id: str
    name: str
    vpc_id: str
    ingress: list = field(default_factory=list)       # list[Rule]


@dataclass
class Subnet:
    id: str
    vpc_id: str
    public: bool = False


@dataclass
class Instance:
    id: str
    name: str
    subnet_id: str
    sg_ids: list = field(default_factory=list)
    kind: str = "ec2"                                  # ec2 | rds
    role: str = "app"                                  # web | app | database | bastion ...

    @property
    def is_database(self) -> bool:
        return self.kind == "rds" or self.role == "database"


@dataclass
class CloudState:
    sgs: dict = field(default_factory=dict)            # id -> SecurityGroup
    subnets: dict = field(default_factory=dict)
    instances: dict = field(default_factory=dict)
    captured_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "captured_at": self.captured_at,
            "sgs": [{**asdict(s), "ingress": [asdict(r) for r in s.ingress]} for s in self.sgs.values()],
            "subnets": [asdict(s) for s in self.subnets.values()],
            "instances": [asdict(i) for i in self.instances.values()],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CloudState":
        st = cls(captured_at=d.get("captured_at", 0.0))
        for s in d["sgs"]:
            st.sgs[s["id"]] = SecurityGroup(s["id"], s["name"], s["vpc_id"], [Rule(**r) for r in s["ingress"]])
        for s in d["subnets"]:
            st.subnets[s["id"]] = Subnet(**s)
        for i in d["instances"]:
            st.instances[i["id"]] = Instance(**i)
        return st

    def fingerprint(self) -> str:
        """Stable content hash (ignores capture time)."""
        import hashlib, json
        d = self.to_dict(); d.pop("captured_at")
        for k in ("sgs", "subnets", "instances"):
            d[k] = sorted(d[k], key=lambda x: x["id"])
        for s in d["sgs"]:
            s["ingress"] = sorted(s["ingress"], key=lambda r: json.dumps(r, sort_keys=True))
        return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()[:16]
