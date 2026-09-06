import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "check_no_secrets.py"
spec = importlib.util.spec_from_file_location("check_no_secrets_test", MODULE_PATH)
assert spec is not None
assert spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class SecretScanTests(unittest.TestCase):
    def labels(self, text: str) -> set[str]:
        return {label for label, _line in module.scan_text(Path("example.txt"), text)}

    def test_detects_aws_access_key_id(self):
        value = "AKIA" + ("A" * 16)
        self.assertIn("AWS access key ID", self.labels(f"key={value}"))

    def test_detects_aws_secret_access_key_assignment(self):
        value = ("a" * 20) + ("B" * 20)
        self.assertIn(
            "AWS secret access key assignment",
            self.labels(f"AWS_SECRET_ACCESS_KEY={value}"),
        )

    def test_detects_private_key_header(self):
        header = "-----BEGIN " + "PRIVATE KEY-----"
        self.assertIn("private key", self.labels(header))

    def test_detects_github_token(self):
        value = "ghp_" + ("A" * 36)
        self.assertIn("GitHub token", self.labels(value))

    def test_placeholders_do_not_trigger(self):
        text = "AWS_ACCESS_KEY_ID=<set-via-profile>\nAWS_SECRET_ACCESS_KEY=<do-not-commit>\n"
        self.assertEqual(self.labels(text), set())


if __name__ == "__main__":
    unittest.main()
