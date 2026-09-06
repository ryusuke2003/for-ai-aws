import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "src" / "aws_security_snapshot.py"
spec = importlib.util.spec_from_file_location("aws_security_snapshot", MODULE_PATH)
assert spec is not None
assert spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

Finding = module.Finding


class SnapshotTests(unittest.TestCase):
    def test_mask_account_id(self):
        self.assertEqual(module.mask_account_id("123456789012"), "********9012")
        self.assertEqual(module.mask_account_id("1234"), "****")

    def test_public_access_block_requires_all_four_flags(self):
        good = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        self.assertTrue(module._all_block_public_access(good))

        bad = dict(good)
        bad["RestrictPublicBuckets"] = False
        self.assertFalse(module._all_block_public_access(bad))

    def test_should_fail_respects_threshold(self):
        findings = [
            Finding("x", "x", "FAIL", "medium", "bad"),
            Finding("y", "y", "WARN", "high", "warning"),
        ]
        self.assertFalse(module.should_fail(findings, "none"))
        self.assertTrue(module.should_fail(findings, "low"))
        self.assertTrue(module.should_fail(findings, "medium"))
        self.assertFalse(module.should_fail(findings, "high"))

    def test_render_markdown_does_not_expose_raw_account_id(self):
        metadata = {
            "account": module.mask_account_id("123456789012"),
            "principal_type": "assumed-role",
            "regions": ["ap-northeast-1"],
        }
        output = module.render_markdown(
            metadata,
            [Finding("x", "Example", "PASS", "low", "Looks good")],
        )
        self.assertNotIn("123456789012", output)
        self.assertIn("********9012", output)
        self.assertIn("ap-northeast-1", output)


if __name__ == "__main__":
    unittest.main()
