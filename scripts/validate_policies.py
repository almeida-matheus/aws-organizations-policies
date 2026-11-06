"""Validate the JSON policies embedded in the docs.

Checks every ```json block in the SCP and RCP example pages:
- valid JSON with no duplicate keys
- required elements and allowed values
- minified size within the AWS Organizations quota
- actions, condition keys and condition operators exist, using the
  AWS Service Authorization Reference (no AWS credentials needed)
- service condition keys apply to at least one action in the statement

With --access-analyzer, also runs IAM Access Analyzer ValidatePolicy on each
policy. That needs the AWS CLI and credentials (for example AWS_PROFILE).
"""

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
CACHE = ROOT / ".cache" / "service-reference"
CACHE_TTL = 24 * 3600
SERVICE_REFERENCE = "https://servicereference.us-east-1.amazonaws.com/v1/{0}/{0}.json"

POLICY_FILES = {
    "aws-scp-examples.md": {"type": "SCP", "max_size": 10240, "aa_type": "SERVICE_CONTROL_POLICY"},
    "aws-rcp-examples.md": {"type": "RCP", "max_size": 5120, "aa_type": "RESOURCE_CONTROL_POLICY"},
}

BLOCK = re.compile(r"^#{2,3} (?P<title>.+?)$|^```json\n(?P<body>.*?)^```", re.M | re.S)

# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
GLOBAL_KEYS = {
    "aws:assumedroot", "aws:calledvia", "aws:calledviaawsmcp", "aws:calledviafirst",
    "aws:calledvialast", "aws:chatbotsourcearn", "aws:currenttime",
    "aws:ec2instancesourceprivateipv4", "aws:ec2instancesourcevpc", "aws:epochtime",
    "aws:federatedprovider", "aws:ismcpserviceaction", "aws:multifactorauthage",
    "aws:multifactorauthpresent", "aws:principalaccount", "aws:principalarn",
    "aws:principalisawsservice", "aws:principalorgid", "aws:principalorgpaths",
    "aws:principalservicename", "aws:principalservicenameslist", "aws:principaltype",
    "aws:referer", "aws:requestedregion", "aws:resourceaccount", "aws:resourceorgid",
    "aws:resourceorgpaths", "aws:securetransport", "aws:signinsessionarn",
    "aws:sourceaccount", "aws:sourcearn", "aws:sourceidentity", "aws:sourceip",
    "aws:sourceorgid", "aws:sourceorgpaths", "aws:sourcevpc", "aws:sourcevpcarn",
    "aws:sourcevpce", "aws:tagkeys", "aws:tokenissuetime", "aws:useragent",
    "aws:userid", "aws:username", "aws:viaawsmcpservice", "aws:viaawsservice",
    "aws:viacustomerdomain", "aws:vpcsourceip", "aws:vpceaccount", "aws:vpceorgid",
    "aws:vpceorgpaths",
}
GLOBAL_TAG_KEYS = ("aws:principaltag/", "aws:requesttag/", "aws:resourcetag/")

OPERATORS = {
    "StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
    "StringLike", "StringNotLike", "NumericEquals", "NumericNotEquals", "NumericLessThan",
    "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals", "DateEquals",
    "DateNotEquals", "DateLessThan", "DateLessThanEquals", "DateGreaterThan",
    "DateGreaterThanEquals", "Bool", "BinaryEquals", "IpAddress", "NotIpAddress",
    "ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike",
}

# Findings that are known false positives of Access Analyzer.
# cognito-identity-unauth:* keys are documented in the Service Authorization
# Reference for cognito-identity, but Access Analyzer doesn't know the prefix.
AA_IGNORED = [("INVALID_SERVICE", "cognito-identity-unauth")]


class ServiceReference:
    def __init__(self):
        self.services = {}

    def get(self, prefix):
        prefix = prefix.lower()
        if prefix not in self.services:
            self.services[prefix] = self._load(prefix)
        return self.services[prefix]

    def _load(self, prefix):
        path = CACHE / f"{prefix}.json"
        if path.exists() and time.time() - path.stat().st_mtime < CACHE_TTL:
            data = json.loads(path.read_text())
        else:
            try:
                with urllib.request.urlopen(SERVICE_REFERENCE.format(prefix), timeout=30) as resp:
                    data = json.load(resp)
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 404):
                    return None
                raise
            CACHE.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data))
        return {
            "actions": {a["Name"].lower(): a for a in data["Actions"]},
            "resources": {r["Name"]: r for r in data.get("Resources", [])},
            "keys": [key_pattern(k["Name"]) for k in data.get("ConditionKeys", [])],
        }


def key_pattern(name):
    """Turn 'aws:RequestTag/${TagKey}' into a regex that matches real keys."""
    parts = re.split(r"\$\{[^}]+\}", name.lower())
    return re.compile(".+".join(re.escape(p) for p in parts) + "$")


def as_list(value):
    return value if isinstance(value, list) else [value]


def no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    dupes = {k for k in keys if keys.count(k) > 1}
    if dupes:
        raise ValueError(f"duplicate keys: {', '.join(sorted(dupes))}")
    return dict(pairs)


def check_structure(stmt, policy_type):
    errors = []
    if stmt.get("Effect") not in ("Allow", "Deny"):
        errors.append(f"invalid Effect: {stmt.get('Effect')!r}")
    if ("Action" in stmt) == ("NotAction" in stmt):
        errors.append("needs exactly one of Action/NotAction")
    if ("Resource" in stmt) == ("NotResource" in stmt):
        errors.append("needs exactly one of Resource/NotResource")
    if policy_type == "SCP" and ("Principal" in stmt or "NotPrincipal" in stmt):
        errors.append("SCPs don't support Principal/NotPrincipal")
    if policy_type == "RCP":
        if stmt.get("Principal") != "*":
            errors.append('RCPs require "Principal": "*"')
        if stmt.get("Effect") != "Deny":
            errors.append("RCP statements must be Deny")
    return errors


def resolve_actions(stmt, ref):
    """Return (errors, matched action dicts or None when the statement uses '*' or NotAction)."""
    errors, matched = [], []
    for action in as_list(stmt.get("Action", stmt.get("NotAction", []))):
        if action == "*":
            matched = None
            continue
        prefix, _, name = action.partition(":")
        service = ref.get(prefix)
        if service is None:
            errors.append(f"unknown service prefix: {prefix}")
            continue
        hits = [a for n, a in service["actions"].items() if fnmatch.fnmatchcase(n, name.lower())]
        if not hits:
            errors.append(f"unknown action: {action}")
        elif matched is not None:
            wildcard = "*" in name or "?" in name
            matched += [(service, a, None if wildcard else action) for a in hits]
    if "NotAction" in stmt:
        matched = None
    return errors, matched


def supported_keys(service, action):
    patterns = [key_pattern(k) for k in action.get("ActionConditionKeys", [])]
    for res in action.get("Resources", []):
        resource = service["resources"].get(res["Name"], {})
        patterns += [key_pattern(k) for k in resource.get("ConditionKeys", [])]
    return patterns


def check_conditions(stmt, ref, matched):
    errors = []
    per_action = [(name, supported_keys(s, a)) for s, a, name in matched or []]
    applicable = [p for _, patterns in per_action for p in patterns] if matched else None
    for operator, block in stmt.get("Condition", {}).items():
        base = re.sub(r"^For(AnyValue|AllValues):", "", operator)
        if base != "Null":
            base = re.sub(r"IfExists$", "", base)
        if base != "Null" and base not in OPERATORS:
            errors.append(f"unknown condition operator: {operator}")
        for key in block:
            lower = key.lower()
            prefix = lower.split(":", 1)[0]
            if prefix == "aws":
                if lower not in GLOBAL_KEYS and not lower.startswith(GLOBAL_TAG_KEYS):
                    errors.append(f"unknown global condition key: {key}")
                continue
            if "." in prefix:
                continue  # OIDC/SAML provider keys, e.g. token.actions.githubusercontent.com:sub
            candidates = list(applicable or [])
            service = ref.get(prefix)
            if service:
                candidates += service["keys"]
            if not any(p.match(lower) for p in candidates):
                errors.append(f"unknown condition key: {key}")
            elif applicable is not None and not any(p.match(lower) for p in applicable):
                errors.append(f"condition key {key} is not supported by any action in the statement")
            else:
                # Explicit actions (no wildcard) must each support the key,
                # otherwise the condition silently never matches for them.
                for name, patterns in per_action:
                    if name and not any(p.match(lower) for p in patterns):
                        errors.append(f"condition key {key} is not supported by {name}")
    return errors


def access_analyzer(policy, policy_type):
    result = subprocess.run(
        ["aws", "accessanalyzer", "validate-policy", "--policy-type", policy_type,
         "--policy-document", json.dumps(policy), "--output", "json"],
        capture_output=True, text=True, env=os.environ,
    )
    if result.returncode:
        # Credential and CLI errors would repeat for every policy, so stop here.
        sys.exit(f"access analyzer failed: {result.stderr.strip()}")
    errors, notes = [], []
    for finding in json.loads(result.stdout)["findings"]:
        detail = f"{finding['issueCode']}: {finding['findingDetails']}"
        if any(code == finding["issueCode"] and text in detail for code, text in AA_IGNORED):
            continue
        if finding["findingType"] in ("ERROR", "SECURITY_WARNING"):
            errors.append(detail)
        else:
            notes.append(detail)
    return errors, notes


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--access-analyzer", action="store_true",
                        help="also run IAM Access Analyzer ValidatePolicy (needs AWS credentials)")
    args = parser.parse_args()

    ref = ServiceReference()
    failures = total = 0
    for filename, spec in POLICY_FILES.items():
        text = (DOCS / filename).read_text()
        title = None
        for match in BLOCK.finditer(text):
            if match.group("title"):
                title = match.group("title").strip()
                continue

            total += 1
            label = f"{filename} :: {title}"
            try:
                policy = json.loads(match.group("body"), object_pairs_hook=no_duplicates)
            except ValueError as exc:
                print(f"FAIL {label}: {exc}")
                failures += 1
                continue

            errors, notes = [], []
            if policy.get("Version") != "2012-10-17":
                errors.append('Version must be "2012-10-17"')
            statements = as_list(policy.get("Statement", []))
            sids = [s["Sid"] for s in statements if "Sid" in s]
            if len(sids) != len(set(sids)):
                errors.append("duplicate Sid")
            for stmt in statements:
                errors += check_structure(stmt, spec["type"])
                action_errors, matched = resolve_actions(stmt, ref)
                errors += action_errors
                errors += check_conditions(stmt, ref, matched)

            size = len(json.dumps(policy, separators=(",", ":")))
            if size > spec["max_size"]:
                errors.append(f"minified size {size} > {spec['max_size']}")

            if args.access_analyzer and not errors:
                aa_errors, notes = access_analyzer(policy, spec["aa_type"])
                errors += aa_errors

            if errors:
                failures += 1
                print(f"FAIL {label}")
                for error in errors:
                    print(f"     - {error}")
            else:
                print(f"ok   {label} ({size}/{spec['max_size']} chars)")
            for note in notes:
                print(f"     note: {note}")

    print(f"\n{total - failures}/{total} policies ok")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
