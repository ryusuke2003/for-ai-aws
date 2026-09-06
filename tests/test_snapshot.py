import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "src" / "aws_security_snapshot.py"
spec = importlib.util.spec_from_file_location("aws_security_snapshot", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

Finding = module.Finding


def test_mask_account_id():
    assert module.mask_account_id("123456789012") == "********9012"
    assert module.mask_account_id("1234") == "****"


def test_public_access_block_requires_all_four_flags():
    good = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    assert module._all_block_public_access(good) is True

    bad = dict(good)
    bad["RestrictPublicBuckets"] = False
    assert module._all_block_public_access(bad) is False


def test_should_fail_respects_threshold():
    findings = [
        Finding("x", "x", "FAIL", "medium", "bad"),
        Finding("y", "y", "WARN", "high", "warning"),
    ]
    assert module.should_fail(findings, "none") is False
    assert module.should_fail(findings, "low") is True
    assert module.should_fail(findings, "medium") is True
    assert module.should_fail(findings, "high") is False


def test_render_markdown_does_not_expose_raw_account_id():
    metadata = {
        "account": module.mask_account_id("123456789012"),
        "principal_type": "assumed-role",
        "regions": ["ap-northeast-1"],
    }
    output = module.render_markdown(
        metadata,
        [Finding("x", "Example", "PASS", "low", "Looks good")],
    )
    assert "123456789012" not in output
    assert "********9012" in output
    assert "ap-northeast-1" in output
