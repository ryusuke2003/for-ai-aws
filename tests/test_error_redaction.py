import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "src" / "aws_security_snapshot.py"
spec = importlib.util.spec_from_file_location("aws_security_snapshot_error_redaction_test", MODULE_PATH)
assert spec is not None
assert spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


ACCOUNT_ID = "123456789012"
PRINCIPAL_ARN = f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/ProductionAdmin/example-session"
RESOURCE_NAME = "private-production-bucket-example"
RESOURCE_ARN = f"arn:aws:s3:::{RESOURCE_NAME}"
RAW_ACCESS_DENIED = (
    "An error occurred (AccessDenied) when calling the operation: "
    f"User: {PRINCIPAL_ARN} is not authorized to access resource: {RESOURCE_ARN}"
)
SENSITIVE_MARKERS = (ACCOUNT_ID, PRINCIPAL_ARN, RESOURCE_NAME, RESOURCE_ARN)


class AlwaysErrorRunner:
    def __init__(self, stderr: str = RAW_ACCESS_DENIED) -> None:
        self.stderr = stderr

    def run(self, *args: str, region: str | None = None):
        command = ["aws", *args]
        if region:
            command.extend(["--region", region])
        raise module.AWSCLIError(command, self.stderr, 254)


def assert_no_sensitive_data(testcase: unittest.TestCase, text: str) -> None:
    for marker in SENSITIVE_MARKERS:
        testcase.assertNotIn(marker, text)


class ErrorRedactionTests(unittest.TestCase):
    def test_aws_cli_error_string_and_repr_do_not_expose_raw_stderr(self):
        exc = module.AWSCLIError(
            ["aws", "s3api", "get-bucket-policy", "--bucket", RESOURCE_NAME],
            RAW_ACCESS_DENIED,
            254,
        )

        self.assertIn("details were omitted", str(exc))
        self.assertIn(RAW_ACCESS_DENIED, exc.stderr)
        assert_no_sensitive_data(self, str(exc))
        assert_no_sensitive_data(self, repr(exc))

    def test_error_findings_do_not_expose_aws_identifiers(self):
        checks = (
            ("iam", lambda runner: module.check_iam_root(runner)),
            ("s3", lambda runner: module.check_s3(runner)),
            ("cloudtrail", lambda runner: module.check_cloudtrail(runner)),
            ("guardduty", lambda runner: module.check_guardduty(runner, "ap-northeast-1")),
            ("config", lambda runner: module.check_config(runner, "ap-northeast-1")),
            ("securityhub", lambda runner: module.check_security_hub(runner, "ap-northeast-1")),
            ("ebs", lambda runner: module.check_ebs_encryption(runner, "ap-northeast-1")),
        )

        metadata = {
            "account": "********9012",
            "principal_type": "assumed-role",
            "regions": ["ap-northeast-1"],
        }

        for name, check in checks:
            with self.subTest(check=name):
                findings = check(AlwaysErrorRunner())
                self.assertTrue(findings)

                markdown = module.render_markdown(metadata, findings)
                json_output = module.render_json(metadata, findings)
                assert_no_sensitive_data(self, markdown)
                assert_no_sensitive_data(self, json_output)

    def test_security_hub_can_classify_not_enabled_without_exposing_stderr(self):
        stderr = (
            "An error occurred (InvalidAccessException) when calling DescribeHub: "
            f"Account {ACCOUNT_ID} is not subscribed to AWS Security Hub"
        )

        finding = module.check_security_hub(AlwaysErrorRunner(stderr), "ap-northeast-1")[0]

        self.assertEqual(finding.status, "WARN")
        self.assertEqual(finding.summary, "Security Hub is not enabled in this Region.")
        self.assertNotIn(ACCOUNT_ID, finding.summary)


if __name__ == "__main__":
    unittest.main()
