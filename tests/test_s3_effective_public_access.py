import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "src" / "aws_security_snapshot.py"
spec = importlib.util.spec_from_file_location("aws_security_snapshot_s3_effective_test", MODULE_PATH)
assert spec is not None
assert spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


ACCOUNT_ID = "000000000000"
ALL_BLOCKED = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


class FakeS3Runner:
    def __init__(
        self,
        *,
        account_block=None,
        bucket_blocks=None,
        versioning=None,
        account_error: str | None = None,
    ) -> None:
        self.account_block = account_block
        self.bucket_blocks = bucket_blocks or {}
        self.versioning = versioning or {}
        self.account_error = account_error
        self.calls: list[tuple[str, ...]] = []

    def run(self, *args: str, region: str | None = None):
        self.calls.append(args)
        if args == ("s3api", "list-buckets"):
            return {"Buckets": [{"Name": "bucket-a"}, {"Name": "bucket-b"}]}
        if args == ("sts", "get-caller-identity"):
            return {"Account": ACCOUNT_ID}
        if args == ("s3control", "get-public-access-block", "--account-id", ACCOUNT_ID):
            if self.account_error:
                raise module.AWSCLIError(["aws", *args], self.account_error, 254)
            if self.account_block is None:
                raise module.AWSCLIError(
                    ["aws", *args],
                    "NoSuchPublicAccessBlockConfiguration",
                    254,
                )
            return {"PublicAccessBlockConfiguration": self.account_block}
        if len(args) == 4 and args[:3] == ("s3api", "get-public-access-block", "--bucket"):
            name = args[3]
            value = self.bucket_blocks.get(name)
            if isinstance(value, Exception):
                raise value
            if value is None:
                raise module.AWSCLIError(
                    ["aws", *args],
                    "NoSuchPublicAccessBlockConfiguration",
                    254,
                )
            return {"PublicAccessBlockConfiguration": value}
        if len(args) == 4 and args[:3] == ("s3api", "get-bucket-versioning", "--bucket"):
            name = args[3]
            value = self.versioning.get(name, "Enabled")
            if isinstance(value, Exception):
                raise value
            return {"Status": value}
        raise AssertionError(f"Unexpected AWS CLI call: {args!r}")


class S3EffectivePublicAccessTests(unittest.TestCase):
    def test_account_level_all_blocked_protects_every_bucket(self):
        runner = FakeS3Runner(account_block=dict(ALL_BLOCKED))

        findings = module.check_s3(runner)
        by_id = {item.check_id: item for item in findings}

        self.assertEqual(by_id["s3.public_access"].status, "PASS")
        self.assertIn("2/2", by_id["s3.public_access"].summary)
        self.assertFalse(
            any(call[:2] == ("s3api", "get-public-access-block") for call in runner.calls),
            "Bucket-level BPA calls are unnecessary when effective account-level BPA blocks all four controls.",
        )

    def test_account_and_bucket_settings_are_combined(self):
        account = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
        bucket = {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        runner = FakeS3Runner(
            account_block=account,
            bucket_blocks={"bucket-a": bucket, "bucket-b": bucket},
        )

        finding = module.check_s3(runner)[0]

        self.assertEqual(finding.status, "PASS")
        self.assertIn("account/organization and bucket settings", finding.summary)

    def test_known_missing_account_config_and_incomplete_bucket_is_fail(self):
        incomplete = dict(ALL_BLOCKED)
        incomplete["RestrictPublicBuckets"] = False
        runner = FakeS3Runner(
            account_block=None,
            bucket_blocks={"bucket-a": incomplete, "bucket-b": incomplete},
        )

        finding = module.check_s3(runner)[0]

        self.assertEqual(finding.status, "FAIL")
        self.assertIn("2 bucket(s) are missing", finding.summary)

    def test_unreadable_account_config_does_not_create_false_fail(self):
        incomplete = dict(ALL_BLOCKED)
        incomplete["RestrictPublicBuckets"] = False
        runner = FakeS3Runner(
            account_error=(
                "AccessDenied: account " + ACCOUNT_ID + " cannot call GetPublicAccessBlock"
            ),
            bucket_blocks={"bucket-a": incomplete, "bucket-b": incomplete},
        )

        finding = module.check_s3(runner)[0]

        self.assertEqual(finding.status, "ERROR")
        self.assertIn("could not be fully evaluated", finding.summary)
        self.assertNotIn(ACCOUNT_ID, finding.summary)

    def test_versioning_errors_do_not_change_public_access_result(self):
        error = module.AWSCLIError(
            ["aws", "s3api", "get-bucket-versioning"],
            "AccessDenied",
            254,
        )
        runner = FakeS3Runner(
            account_block=dict(ALL_BLOCKED),
            versioning={"bucket-a": error, "bucket-b": error},
        )

        findings = module.check_s3(runner)
        by_id = {item.check_id: item for item in findings}

        self.assertEqual(by_id["s3.public_access"].status, "PASS")
        self.assertNotIn("versioning", by_id["s3.public_access"].summary.lower())
        self.assertEqual(by_id["s3.versioning"].status, "ERROR")
        self.assertIn("2 versioning check(s) returned errors", by_id["s3.versioning"].summary)


if __name__ == "__main__":
    unittest.main()
