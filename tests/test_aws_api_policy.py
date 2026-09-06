import ast
import unittest
from pathlib import Path


SOURCE_PATH = Path(__file__).parents[1] / "src" / "aws_security_snapshot.py"

# Explicit allowlist of AWS CLI operations that this project may invoke.
# Adding a new AWS API call requires a conscious review of this list.
ALLOWED_AWS_OPERATIONS = {
    ("cloudtrail", "describe-trails"),
    ("cloudtrail", "get-trail-status"),
    ("configservice", "describe-configuration-recorder-status"),
    ("configservice", "describe-configuration-recorders"),
    ("ec2", "describe-regions"),
    ("ec2", "get-ebs-encryption-by-default"),
    ("guardduty", "get-detector"),
    ("guardduty", "list-detectors"),
    ("iam", "get-account-summary"),
    ("s3api", "get-bucket-versioning"),
    ("s3api", "get-public-access-block"),
    ("s3api", "list-buckets"),
    ("securityhub", "describe-hub"),
    ("sts", "get-caller-identity"),
}


class RunnerCallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.operations: list[tuple[str, str, int]] = []
        self.invalid_calls: list[tuple[int, str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        is_runner_run = (
            isinstance(func, ast.Attribute)
            and func.attr == "run"
            and isinstance(func.value, ast.Name)
            and func.value.id == "runner"
        )

        if is_runner_run:
            if len(node.args) < 2:
                self.invalid_calls.append((node.lineno, "service and operation must be explicit"))
            else:
                service = self._literal_string(node.args[0])
                operation = self._literal_string(node.args[1])
                if service is None or operation is None:
                    self.invalid_calls.append(
                        (node.lineno, "service and operation must be string literals")
                    )
                else:
                    self.operations.append((service, operation, node.lineno))

        self.generic_visit(node)

    @staticmethod
    def _literal_string(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None


class AwsApiPolicyTests(unittest.TestCase):
    def test_all_runner_calls_are_explicitly_allowlisted(self):
        tree = ast.parse(SOURCE_PATH.read_text(encoding="utf-8"), filename=str(SOURCE_PATH))
        visitor = RunnerCallVisitor()
        visitor.visit(tree)

        self.assertFalse(
            visitor.invalid_calls,
            "AWSRunner calls must use literal service/operation names so CI can audit them: "
            f"{visitor.invalid_calls}",
        )
        self.assertTrue(visitor.operations, "Expected at least one AWSRunner call to audit")

        unexpected = [
            (service, operation, line)
            for service, operation, line in visitor.operations
            if (service, operation) not in ALLOWED_AWS_OPERATIONS
        ]
        self.assertFalse(
            unexpected,
            "Unreviewed AWS CLI operation detected. Verify it is strictly read-only, then "
            f"add it to ALLOWED_AWS_OPERATIONS: {unexpected}",
        )

    def test_allowlist_contains_only_read_style_operation_names(self):
        # This is defense in depth, not the primary proof of safety. The explicit allowlist
        # above remains the source of truth and should be reviewed whenever it changes.
        allowed_prefixes = ("describe-", "get-", "list-")
        suspicious = sorted(
            f"{service} {operation}"
            for service, operation in ALLOWED_AWS_OPERATIONS
            if not operation.startswith(allowed_prefixes)
        )
        self.assertFalse(
            suspicious,
            f"Allowlist contains an operation without a read-style prefix: {suspicious}",
        )


if __name__ == "__main__":
    unittest.main()
