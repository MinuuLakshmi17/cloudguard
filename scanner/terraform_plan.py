from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Any

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    resource_address: str
    resource_type: str
    evidence: str
    remediation: str
    fingerprint: str
    status: str = "open"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def _stable_id(rule_id: str, address: str, evidence: str) -> str:
    return hashlib.sha256(f"{rule_id}|{address}|{evidence}".encode()).hexdigest()[:20]

def _attrs(resource: dict[str, Any]) -> dict[str, Any]:
    values = resource.get("values") or {}
    return values if isinstance(values, dict) else {}

def _resources(plan: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    # Terraform show -json output includes planned_values.resources and may also
    # include resource_changes[].change.after. Prefer planned values, then fill
    # addresses absent there from resource_changes.
    planned = (plan.get("planned_values") or {}).get("root_module") or {}
    def walk(module: dict[str, Any]) -> None:
        resources.extend(module.get("resources") or [])
        for child in module.get("child_modules") or []:
            walk(child)
    walk(planned)
    seen = {r.get("address") for r in resources}
    for change in plan.get("resource_changes") or []:
        change_obj = change.get("change") or {}
        after = change_obj.get("after")
        if after is None or change.get("address") in seen:
            continue
        resources.append({
            "address": change.get("address", "unknown"),
            "type": change.get("type", "unknown"),
            "values": after,
        })
        seen.add(change.get("address"))
    return resources

def scan_plan(plan: dict[str, Any]) -> list[Finding]:
    if not isinstance(plan, dict):
        raise ValueError("Terraform plan must be a JSON object")
    findings: list[Finding] = []
    for resource in _resources(plan):
        rtype = resource.get("type", "unknown")
        address = resource.get("address", "unknown")
        a = _attrs(resource)

        def add(rule_id: str, title: str, severity: str, evidence: str, remediation: str) -> None:
            findings.append(Finding(rule_id, title, severity, address, rtype, evidence, remediation,
                                    _stable_id(rule_id, address, evidence)))

        if rtype == "aws_s3_bucket":
            if not a.get("server_side_encryption_configuration"):
                add("CG-S3-001", "S3 bucket has no explicit server-side encryption",
                    "high", "server_side_encryption_configuration is absent or empty",
                    "Add server_side_encryption_configuration with aws:kms or AES256 encryption.")
        if rtype == "aws_s3_bucket_public_access_block":
            flags = ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
            bad = [key for key in flags if a.get(key) is False]
            if bad:
                add("CG-S3-002", "S3 public access block is permissive", "critical",
                    "False settings: " + ", ".join(bad),
                    "Set all four public-access-block settings to true and review bucket policies/ACLs.")
        if rtype == "aws_s3_bucket_acl" and str(a.get("acl", "")).lower() in {"public-read", "public-read-write", "authenticated-read"}:
            add("CG-S3-003", "S3 bucket ACL grants public or broad access", "critical",
                f"acl={a.get('acl')}", "Remove public ACLs; use least-privilege bucket policies.")
        if rtype == "aws_security_group":
            for ingress in a.get("ingress") or []:
                cidrs = list(ingress.get("cidr_blocks") or []) + list(ingress.get("ipv6_cidr_blocks") or [])
                ports = {ingress.get("from_port"), ingress.get("to_port")}
                public = any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs)
                protocol = str(ingress.get("protocol", ""))
                sensitive = bool(ports & {22, 3389}) or protocol == "-1" or (ingress.get("from_port") == 0 and ingress.get("to_port") == 65535)
                if public and sensitive:
                    add("CG-NET-001", "Sensitive security-group ingress is open to the internet", "critical",
                        f"cidrs={cidrs}; ports={ingress.get('from_port')}-{ingress.get('to_port')}; protocol={protocol}",
                        "Restrict ingress to approved CIDRs and expose only required ports.")
                elif public:
                    add("CG-NET-002", "Security-group ingress is open to the internet", "high",
                        f"cidrs={cidrs}; ports={ingress.get('from_port')}-{ingress.get('to_port')}",
                        "Restrict ingress to trusted source ranges; avoid 0.0.0.0/0 and ::/0.")
        if rtype == "aws_ebs_volume" and a.get("encrypted") is not True:
            add("CG-STO-001", "EBS volume encryption is not enabled", "high",
                f"encrypted={a.get('encrypted')!r}", "Set encrypted = true and configure an approved KMS key if required.")
        if rtype in {"aws_db_instance", "aws_rds_cluster"} and a.get("storage_encrypted") is not True:
            add("CG-STO-002", "RDS storage encryption is not enabled", "high",
                f"storage_encrypted={a.get('storage_encrypted')!r}", "Set storage_encrypted = true; evaluate snapshot and key migration needs.")
        if rtype in {"aws_iam_policy", "aws_iam_role_policy"}:
            policy = a.get("policy")
            try:
                doc = json.loads(policy) if isinstance(policy, str) else policy
            except (json.JSONDecodeError, TypeError):
                doc = None
            if isinstance(doc, dict):
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for statement in statements:
                    if not isinstance(statement, dict):
                        continue
                    actions = statement.get("Action", [])
                    resources = statement.get("Resource", [])
                    actions = [actions] if isinstance(actions, str) else actions
                    resources = [resources] if isinstance(resources, str) else resources
                    if "*" in actions:
                        add("CG-IAM-001", "IAM policy grants wildcard actions", "critical",
                            f"Sid={statement.get('Sid', '<none>')}; Action contains '*'; Resource={resources}",
                            "Replace wildcard actions with the minimum required API actions.")
                    if "*" in resources:
                        add("CG-IAM-002", "IAM policy applies to all resources", "high",
                            f"Sid={statement.get('Sid', '<none>')}; Resource contains '*'",
                            "Scope Resource to specific ARNs wherever supported.")
    return sorted(findings, key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.resource_address, f.rule_id))

def scan_file(path: str) -> list[Finding]:
    with open(path, encoding="utf-8") as f:
        plan = json.load(f)
    return scan_plan(plan)
