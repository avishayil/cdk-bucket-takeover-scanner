from unittest.mock import patch

import boto3
from moto import mock_aws

from cdk_bucket_takeover_scanner.account_manager import AWSAccountManager
from cdk_bucket_takeover_scanner.cdk_bucket_scanner import CDKBucketScanner

ROLE_NAME = "cdk-hnb659fds-file-publishing-role-123456789012-us-east-1"


@mock_aws
def test_run_scan():
    # Mock AWS environment setup
    session = boto3.Session()
    iam_client = session.client("iam", region_name="us-east-1")
    ssm_client = session.client("ssm", region_name="us-east-1")

    # Create mock IAM role and S3 bucket
    iam_client.create_role(
        RoleName=ROLE_NAME,
        AssumeRolePolicyDocument="{}",
    )

    # Create a mock SSM parameter for bootstrap version
    ssm_client.put_parameter(
        Name="/cdk-bootstrap/hnb659fds/version", Value="10", Type="String"
    )

    # Initialize the scanner and run
    scanner = CDKBucketScanner(["123456789012"], "TestRole", fix=False)
    scanner.run_scan()

    # Assertions to validate scan results
    assert len(scanner.unmatched_roles) == 1
    assert len(scanner.risky_bootstraps) == 1


@mock_aws
def test_run_scan_with_fix():
    # Mock AWS environment setup
    session = boto3.Session()
    iam_client = session.client("iam", region_name="us-east-1")
    ssm_client = session.client("ssm", region_name="us-east-1")

    # Create mock IAM role and S3 bucket
    iam_client.create_role(
        RoleName=ROLE_NAME,
        AssumeRolePolicyDocument="{}",
    )

    # Create a mock SSM parameter for bootstrap version
    ssm_client.put_parameter(
        Name="/cdk-bootstrap/hnb659fds/version", Value="10", Type="String"
    )

    # Initialize the scanner and run
    scanner = CDKBucketScanner(["123456789012"], "TestRole", fix=True)
    scanner.run_scan()

    # Assertions to validate scan results
    assert scanner.risky_bootstraps
    for risky_bootstrap in scanner.risky_bootstraps:
        assert risky_bootstrap[3] == "Mitigated"


@mock_aws
def test_scan_account_flags_missing_bucket():
    manager = AWSAccountManager("123456789012", "TestRole")
    scanner = CDKBucketScanner(["123456789012"], "TestRole")

    # Role exists but no matching staging bucket -> takeover risk (Gap).
    scanner.scan_account(manager, s3_buckets=[], iam_roles=[ROLE_NAME])

    assert len(scanner.unmatched_roles) == 1
    account_id, role, suffix, expected_bucket, status = scanner.unmatched_roles[0]
    assert status == "Gap"
    assert expected_bucket == "cdk-hnb659fds-assets-123456789012-us-east-1"


@mock_aws
def test_scan_account_safe_when_bucket_present():
    manager = AWSAccountManager("123456789012", "TestRole")
    scanner = CDKBucketScanner(["123456789012"], "TestRole")

    # Matching staging bucket exists -> safe, nothing flagged.
    scanner.scan_account(
        manager,
        s3_buckets=["cdk-hnb659fds-assets-123456789012-us-east-1"],
        iam_roles=[ROLE_NAME],
    )

    assert scanner.unmatched_roles == []


@mock_aws
def test_scan_account_no_cdk_roles_is_noop():
    manager = AWSAccountManager("123456789012", "TestRole")
    scanner = CDKBucketScanner(["123456789012"], "TestRole")

    scanner.scan_account(manager, s3_buckets=[], iam_roles=["some-other-role"])

    assert scanner.unmatched_roles == []


@mock_aws
def test_check_bootstrap_versions_flags_low_version():
    manager = AWSAccountManager("123456789012", "TestRole")
    ssm = manager.session.client("ssm", region_name="us-east-1")
    ssm.put_parameter(
        Name="/cdk-bootstrap/hnb659fds/version", Value="10", Type="String"
    )

    scanner = CDKBucketScanner(["123456789012"], "TestRole")
    scanner.check_bootstrap_versions(manager, ["us-east-1"])

    assert len(scanner.risky_bootstraps) == 1
    assert scanner.risky_bootstraps[0][2] == 10


@mock_aws
def test_check_bootstrap_versions_passes_safe_version():
    manager = AWSAccountManager("123456789012", "TestRole")
    ssm = manager.session.client("ssm", region_name="us-east-1")
    ssm.put_parameter(
        Name="/cdk-bootstrap/hnb659fds/version", Value="21", Type="String"
    )

    scanner = CDKBucketScanner(["123456789012"], "TestRole")
    scanner.check_bootstrap_versions(manager, ["us-east-1"])

    assert scanner.risky_bootstraps == []


def test_run_scan_skips_accounts_when_assume_role_fails():
    scanner = CDKBucketScanner(["123456789012", "999999999999"], "TestRole")

    with patch.object(AWSAccountManager, "assume_role", return_value=None):
        with patch(
            "cdk_bucket_takeover_scanner.cdk_bucket_scanner.CSVReportWriter.write_csv_report"
        ) as mock_writer:
            scanner.run_scan()

    # Both accounts skipped due to assume-role failure -> no findings.
    assert scanner.unmatched_roles == []
    assert scanner.risky_bootstraps == []
    mock_writer.assert_called_once()


def test_extract_suffix_returns_last_four_parts():
    assert CDKBucketScanner.extract_suffix("a-b-c-d-e-f") == "c-d-e-f"
