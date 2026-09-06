import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "src" / "aws_security_snapshot.py"
spec = importlib.util.spec_from_file_location("aws_security_snapshot_cloudtrail_test", MODULE_PATH)
assert spec is not None
assert spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class OrganizationTrailRunner:
    """Minimal runner that behaves like a member account seeing an organization trail."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, *args: str, region: str | None = None):
        self.calls.append(args)
        if args == ("cloudtrail", "describe-trails"):
            return {
                "trailList": [
                    {
                        "Name": "organization-trail",
                        "TrailARN": "arn:aws:cloudtrail:ap-northeast-1:111122223333:trail/organization-trail",
                        "IsOrganizationTrail": True,
                        "IsMultiRegionTrail": True,
                        "LogFileValidationEnabled": True,
                        "KmsKeyId": "arn:aws:kms:ap-northeast-1:111122223333:key/example",
                    }
                ]
            }
        if args == (
            "cloudtrail",
            "get-trail-status",
            "--name",
            "arn:aws:cloudtrail:ap-northeast-1:111122223333:trail/organization-trail",
        ):
            return {"IsLogging": True}
        raise AssertionError(f"Unexpected AWS CLI call: {args!r}")


class CloudTrailTests(unittest.TestCase):
    def test_organization_trail_is_included_and_counted_as_logging(self):
        runner = OrganizationTrailRunner()

        findings = module.check_cloudtrail(runner)
        by_id = {item.check_id: item for item in findings}

        self.assertEqual(runner.calls[0], ("cloudtrail", "describe-trails"))
        self.assertEqual(by_id["cloudtrail.logging"].status, "PASS")
        self.assertEqual(by_id["cloudtrail.multi_region"].status, "PASS")
        self.assertEqual(by_id["cloudtrail.log_validation"].status, "PASS")
        self.assertEqual(by_id["cloudtrail.kms"].status, "PASS")
        self.assertIn("1/1", by_id["cloudtrail.logging"].summary)

    def test_empty_result_does_not_claim_shadow_trails_were_excluded(self):
        class EmptyRunner:
            def run(self, *args: str, region: str | None = None):
                self_args = args
                if self_args != ("cloudtrail", "describe-trails"):
                    raise AssertionError(f"Unexpected AWS CLI call: {self_args!r}")
                return {"trailList": []}

        finding = module.check_cloudtrail(EmptyRunner())[0]

        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.summary, "No CloudTrail trail was found.")
        self.assertNotIn("non-shadow", finding.summary.lower())


if __name__ == "__main__":
    unittest.main()
