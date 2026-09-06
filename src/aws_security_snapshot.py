#!/usr/bin/env python3
"""Read-only AWS security posture snapshot using the AWS CLI.

This tool intentionally avoids SDK dependencies and only invokes read-only AWS APIs.
It never uploads results and does not persist credentials.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


STATUS_ORDER = {"PASS": 0, "INFO": 1, "WARN": 2, "FAIL": 3, "ERROR": 4}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


class AWSCLIError(RuntimeError):
    """Raised when an AWS CLI command fails."""

    def __init__(self, command: list[str], stderr: str, returncode: int) -> None:
        super().__init__(stderr.strip() or f"AWS CLI exited with {returncode}")
        self.command = command
        self.stderr = stderr.strip()
        self.returncode = returncode


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    status: str
    severity: str
    summary: str
    remediation: str | None = None
    region: str | None = None


class AWSRunner:
    def __init__(self, profile: str | None = None, region: str | None = None) -> None:
        self.profile = profile
        self.region = region

    def run(self, *args: str, region: str | None = None) -> dict[str, Any]:
        command = ["aws", *args, "--output", "json", "--no-cli-pager"]
        if self.profile:
            command.extend(["--profile", self.profile])
        effective_region = region or self.region
        if effective_region:
            command.extend(["--region", effective_region])

        proc = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        if proc.returncode != 0:
            raise AWSCLIError(command, proc.stderr, proc.returncode)
        stdout = proc.stdout.strip()
        return json.loads(stdout) if stdout else {}


def mask_account_id(account_id: str) -> str:
    if len(account_id) <= 4:
        return "*" * len(account_id)
    return "*" * (len(account_id) - 4) + account_id[-4:]


def finding(
    check_id: str,
    title: str,
    status: str,
    severity: str,
    summary: str,
    remediation: str | None = None,
    region: str | None = None,
) -> Finding:
    return Finding(check_id, title, status, severity, summary, remediation, region)


def check_identity(runner: AWSRunner) -> tuple[dict[str, str], list[Finding]]:
    data = runner.run("sts", "get-caller-identity")
    account_id = str(data.get("Account", "unknown"))
    arn = str(data.get("Arn", "unknown"))
    principal_type = arn.split(":")[-1].split("/")[0] if ":" in arn else "unknown"
    metadata = {
        "account": mask_account_id(account_id),
        "principal_type": principal_type,
    }
    return metadata, [
        finding(
            "identity.authenticated",
            "AWS authentication",
            "INFO",
            "low",
            f"Authenticated to account {metadata['account']} as principal type '{principal_type}'.",
        )
    ]


def check_iam_root(runner: AWSRunner) -> list[Finding]:
    try:
        summary = runner.run("iam", "get-account-summary").get("SummaryMap", {})
    except AWSCLIError as exc:
        return [
            finding(
                "iam.root",
                "Root account safeguards",
                "ERROR",
                "high",
                f"Could not read IAM account summary: {exc}",
            )
        ]

    findings: list[Finding] = []
    root_mfa = int(summary.get("AccountMFAEnabled", 0)) == 1
    findings.append(
        finding(
            "iam.root_mfa",
            "Root user MFA",
            "PASS" if root_mfa else "FAIL",
            "high",
            "Root user MFA is enabled." if root_mfa else "Root user MFA is not enabled.",
            None if root_mfa else "Enable MFA for the AWS account root user and keep root usage exceptional.",
        )
    )

    root_keys = int(summary.get("AccountAccessKeysPresent", 0))
    findings.append(
        finding(
            "iam.root_access_keys",
            "Root user access keys",
            "PASS" if root_keys == 0 else "FAIL",
            "high",
            "No root user access key is present."
            if root_keys == 0
            else f"Root user has {root_keys} access key(s) present.",
            None if root_keys == 0 else "Delete root user access keys and use short-lived role credentials instead.",
        )
    )
    return findings


def _all_block_public_access(block: dict[str, Any]) -> bool:
    keys = (
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    )
    return all(block.get(key) is True for key in keys)


def check_s3(runner: AWSRunner) -> list[Finding]:
    try:
        buckets = runner.run("s3api", "list-buckets").get("Buckets", [])
    except AWSCLIError as exc:
        return [
            finding(
                "s3.public_access",
                "S3 Block Public Access",
                "ERROR",
                "high",
                f"Could not list S3 buckets: {exc}",
            )
        ]

    if not buckets:
        return [
            finding(
                "s3.public_access",
                "S3 Block Public Access",
                "PASS",
                "high",
                "No S3 buckets were returned for this account.",
            )
        ]

    public_block_ok = 0
    versioning_enabled = 0
    errors = 0

    for bucket in buckets:
        name = str(bucket.get("Name", ""))
        if not name:
            continue
        try:
            block = runner.run("s3api", "get-public-access-block", "--bucket", name).get(
                "PublicAccessBlockConfiguration", {}
            )
            if _all_block_public_access(block):
                public_block_ok += 1
        except AWSCLIError:
            # Missing configuration and insufficient permissions are both treated conservatively.
            errors += 1

        try:
            versioning = runner.run("s3api", "get-bucket-versioning", "--bucket", name)
            if versioning.get("Status") == "Enabled":
                versioning_enabled += 1
        except AWSCLIError:
            errors += 1

    total = len(buckets)
    block_status = "PASS" if public_block_ok == total else "FAIL"
    findings = [
        finding(
            "s3.public_access",
            "S3 Block Public Access",
            block_status,
            "high",
            f"{public_block_ok}/{total} buckets have all four bucket-level Block Public Access controls enabled."
            + (f" {errors} bucket checks returned errors." if errors else ""),
            None
            if block_status == "PASS"
            else "Enable all four S3 Block Public Access controls unless a reviewed public bucket is intentionally required.",
        ),
        finding(
            "s3.versioning",
            "S3 bucket versioning",
            "PASS" if versioning_enabled == total else "WARN",
            "medium",
            f"{versioning_enabled}/{total} buckets have versioning enabled.",
            None
            if versioning_enabled == total
            else "Consider enabling versioning for buckets that store important or mutable data.",
        ),
    ]
    return findings


def check_cloudtrail(runner: AWSRunner) -> list[Finding]:
    try:
        trails = runner.run("cloudtrail", "describe-trails", "--include-shadow-trails", "false").get(
            "trailList", []
        )
    except AWSCLIError as exc:
        return [
            finding(
                "cloudtrail.logging",
                "CloudTrail logging",
                "ERROR",
                "high",
                f"Could not describe CloudTrail trails: {exc}",
            )
        ]

    if not trails:
        return [
            finding(
                "cloudtrail.logging",
                "CloudTrail logging",
                "FAIL",
                "high",
                "No non-shadow CloudTrail trail was found.",
                "Create an organization or account trail and enable continuous logging.",
            )
        ]

    logging = 0
    multi_region = 0
    validation = 0
    kms = 0
    errors = 0
    for trail in trails:
        name = str(trail.get("TrailARN") or trail.get("Name") or "")
        if name:
            try:
                status = runner.run("cloudtrail", "get-trail-status", "--name", name)
                if status.get("IsLogging") is True:
                    logging += 1
            except AWSCLIError:
                errors += 1
        if trail.get("IsMultiRegionTrail") is True:
            multi_region += 1
        if trail.get("LogFileValidationEnabled") is True:
            validation += 1
        if trail.get("KmsKeyId"):
            kms += 1

    total = len(trails)
    findings = [
        finding(
            "cloudtrail.logging",
            "CloudTrail logging",
            "PASS" if logging > 0 else "FAIL",
            "high",
            f"{logging}/{total} trails are actively logging."
            + (f" {errors} status checks returned errors." if errors else ""),
            None if logging > 0 else "Enable logging on at least one trail that covers the account.",
        ),
        finding(
            "cloudtrail.multi_region",
            "CloudTrail multi-Region coverage",
            "PASS" if multi_region > 0 else "WARN",
            "medium",
            f"{multi_region}/{total} trails are multi-Region trails.",
            None if multi_region > 0 else "Prefer a multi-Region trail so activity in newly used Regions is not missed.",
        ),
        finding(
            "cloudtrail.log_validation",
            "CloudTrail log file validation",
            "PASS" if validation > 0 else "WARN",
            "medium",
            f"{validation}/{total} trails have log file validation enabled.",
            None if validation > 0 else "Enable log file validation to support integrity verification of delivered logs.",
        ),
        finding(
            "cloudtrail.kms",
            "CloudTrail KMS encryption",
            "PASS" if kms > 0 else "WARN",
            "medium",
            f"{kms}/{total} trails use an AWS KMS key for log encryption.",
            None if kms > 0 else "Consider encrypting CloudTrail logs with a customer-managed KMS key where appropriate.",
        ),
    ]
    return findings


def check_guardduty(runner: AWSRunner, region: str | None) -> list[Finding]:
    label = region or "configured-region"
    try:
        detector_ids = runner.run("guardduty", "list-detectors", region=region).get("DetectorIds", [])
    except AWSCLIError as exc:
        return [finding("guardduty.enabled", "GuardDuty", "ERROR", "high", f"Could not list detectors: {exc}", region=label)]

    if not detector_ids:
        return [
            finding(
                "guardduty.enabled",
                "GuardDuty",
                "FAIL",
                "high",
                "No GuardDuty detector is enabled in this Region.",
                "Enable GuardDuty in Regions that are in scope for this account.",
                label,
            )
        ]

    enabled = 0
    for detector_id in detector_ids:
        try:
            detector = runner.run("guardduty", "get-detector", "--detector-id", detector_id, region=region)
            if detector.get("Status") == "ENABLED":
                enabled += 1
        except AWSCLIError:
            continue
    return [
        finding(
            "guardduty.enabled",
            "GuardDuty",
            "PASS" if enabled > 0 else "FAIL",
            "high",
            f"{enabled}/{len(detector_ids)} GuardDuty detectors are enabled.",
            None if enabled > 0 else "Enable the GuardDuty detector in this Region.",
            label,
        )
    ]


def check_config(runner: AWSRunner, region: str | None) -> list[Finding]:
    label = region or "configured-region"
    try:
        recorders = runner.run("configservice", "describe-configuration-recorders", region=region).get(
            "ConfigurationRecorders", []
        )
        statuses = runner.run("configservice", "describe-configuration-recorder-status", region=region).get(
            "ConfigurationRecordersStatus", []
        )
    except AWSCLIError as exc:
        return [finding("config.recording", "AWS Config recording", "ERROR", "medium", f"Could not inspect AWS Config: {exc}", region=label)]

    recording_names = {str(item.get("name")) for item in statuses if item.get("recording") is True}
    active = [item for item in recorders if str(item.get("name")) in recording_names]
    return [
        finding(
            "config.recording",
            "AWS Config recording",
            "PASS" if active else "WARN",
            "medium",
            f"{len(active)}/{len(recorders)} configuration recorders are actively recording.",
            None if active else "Consider enabling AWS Config recording for resource inventory and configuration history.",
            label,
        )
    ]


def check_security_hub(runner: AWSRunner, region: str | None) -> list[Finding]:
    label = region or "configured-region"
    try:
        hub = runner.run("securityhub", "describe-hub", region=region)
    except AWSCLIError as exc:
        message = exc.stderr.lower()
        not_enabled = "not subscribed" in message or "invalidaccess" in message or "not enabled" in message
        return [
            finding(
                "securityhub.enabled",
                "Security Hub",
                "WARN" if not_enabled else "ERROR",
                "medium",
                "Security Hub is not enabled in this Region." if not_enabled else f"Could not inspect Security Hub: {exc}",
                "Consider enabling Security Hub for centralized findings and security standards."
                if not_enabled
                else None,
                label,
            )
        ]
    enabled = bool(hub.get("HubArn"))
    return [
        finding(
            "securityhub.enabled",
            "Security Hub",
            "PASS" if enabled else "WARN",
            "medium",
            "Security Hub is enabled in this Region." if enabled else "Security Hub did not return an active hub.",
            None if enabled else "Consider enabling Security Hub in this Region.",
            label,
        )
    ]


def check_ebs_encryption(runner: AWSRunner, region: str | None) -> list[Finding]:
    label = region or "configured-region"
    try:
        data = runner.run("ec2", "get-ebs-encryption-by-default", region=region)
    except AWSCLIError as exc:
        return [finding("ec2.ebs_default_encryption", "EBS encryption by default", "ERROR", "high", f"Could not inspect EBS default encryption: {exc}", region=label)]
    enabled = data.get("EbsEncryptionByDefault") is True
    return [
        finding(
            "ec2.ebs_default_encryption",
            "EBS encryption by default",
            "PASS" if enabled else "FAIL",
            "high",
            "EBS encryption by default is enabled." if enabled else "EBS encryption by default is disabled.",
            None if enabled else "Enable EBS encryption by default in this Region.",
            label,
        )
    ]


def discover_regions(runner: AWSRunner) -> list[str]:
    data = runner.run("ec2", "describe-regions", "--all-regions")
    return sorted(
        str(item["RegionName"])
        for item in data.get("Regions", [])
        if item.get("RegionName") and item.get("OptInStatus") in {"opt-in-not-required", "opted-in"}
    )


def sort_findings(items: Iterable[Finding]) -> list[Finding]:
    return sorted(
        items,
        key=lambda item: (
            -STATUS_ORDER.get(item.status, 99),
            -SEVERITY_ORDER.get(item.severity, 0),
            item.region or "",
            item.check_id,
        ),
    )


def render_markdown(metadata: dict[str, Any], findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for item in findings:
        counts[item.status] = counts.get(item.status, 0) + 1

    lines = [
        "# AWS Security Snapshot",
        "",
        f"- Account: `{metadata.get('account', 'unknown')}`",
        f"- Principal type: `{metadata.get('principal_type', 'unknown')}`",
        f"- Regions checked: `{', '.join(metadata.get('regions', [])) or 'configured region'}`",
        "- This report intentionally masks the AWS account ID and does not include resource names.",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status in ("FAIL", "ERROR", "WARN", "PASS", "INFO"):
        lines.append(f"| {status} | {counts.get(status, 0)} |")

    lines.extend(["", "## Findings", ""])
    for item in sort_findings(findings):
        scope = f" ({item.region})" if item.region else ""
        lines.append(f"### {item.status} · {item.title}{scope}")
        lines.append("")
        lines.append(f"- Severity: `{item.severity}`")
        lines.append(f"- Check: `{item.check_id}`")
        lines.append(f"- Result: {item.summary}")
        if item.remediation:
            lines.append(f"- Suggested action: {item.remediation}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(metadata: dict[str, Any], findings: list[Finding]) -> str:
    payload = {
        "metadata": metadata,
        "findings": [asdict(item) for item in sort_findings(findings)],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def should_fail(findings: list[Finding], threshold: str) -> bool:
    if threshold == "none":
        return False
    minimum = SEVERITY_ORDER[threshold]
    return any(item.status in {"FAIL", "ERROR"} and SEVERITY_ORDER.get(item.severity, 0) >= minimum for item in findings)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a read-only snapshot of common AWS security guardrails using the AWS CLI."
    )
    parser.add_argument("--profile", help="AWS CLI profile to use. Credentials are never written by this tool.")
    parser.add_argument("--region", action="append", dest="regions", help="Region to inspect. Repeat to check multiple Regions.")
    parser.add_argument("--all-regions", action="store_true", help="Inspect all enabled/opted-in Regions.")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", type=Path, help="Write the report to a local file instead of stdout.")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high"),
        default="none",
        help="Exit with code 2 when a FAIL/ERROR finding meets this severity threshold.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if shutil.which("aws") is None:
        print("error: AWS CLI v2 is required and was not found in PATH", file=sys.stderr)
        return 3

    runner = AWSRunner(profile=args.profile)
    findings: list[Finding] = []
    try:
        metadata, identity_findings = check_identity(runner)
    except (AWSCLIError, json.JSONDecodeError) as exc:
        print(f"error: could not authenticate with AWS CLI: {exc}", file=sys.stderr)
        return 3
    findings.extend(identity_findings)

    findings.extend(check_iam_root(runner))
    findings.extend(check_s3(runner))
    findings.extend(check_cloudtrail(runner))

    regions = list(dict.fromkeys(args.regions or []))
    if args.all_regions:
        try:
            regions = discover_regions(runner)
        except AWSCLIError as exc:
            print(f"error: could not discover Regions: {exc}", file=sys.stderr)
            return 3
    if not regions:
        regions = [None]

    for region in regions:
        findings.extend(check_guardduty(runner, region))
        findings.extend(check_config(runner, region))
        findings.extend(check_security_hub(runner, region))
        findings.extend(check_ebs_encryption(runner, region))

    metadata["regions"] = [region for region in regions if region] or ["configured-region"]
    output = render_json(metadata, findings) if args.format == "json" else render_markdown(metadata, findings)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
        print(f"Wrote report to {args.output}")
    else:
        print(output, end="")

    return 2 if should_fail(findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
