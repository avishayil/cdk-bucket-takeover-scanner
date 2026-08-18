import pytest
from moto import mock_aws

from cdk_bucket_takeover_scanner import __version__, build_parser, main
from cdk_bucket_takeover_scanner.cdk_bucket_scanner import CDKBucketScanner


def test_help_smoke(capsys):
    # --help should print usage and exit cleanly.
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "cdk-bucket-takeover-scanner" in captured.out


def test_build_parser_parses_arguments():
    parser = build_parser()
    args = parser.parse_args(
        ["--account-ids", "111", "222", "--assume-role-name", "MyRole", "--fix"]
    )
    assert args.account_ids == ["111", "222"]
    assert args.assume_role_name == "MyRole"
    assert args.fix is True


def test_missing_required_args_exits():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


@mock_aws
def test_main_runs_scan_and_returns_scanner():
    scanner = main(["--account-ids", "123456789012", "--assume-role-name", "TestRole"])
    assert isinstance(scanner, CDKBucketScanner)


def test_version_exposed():
    assert __version__ == "0.0.1"
