import boto3
from moto import mock_aws

from src.cdk_bucket_scanner import CDKBucketScanner


@mock_aws
def test_run_scan():
    # Mock AWS environment setup
    session = boto3.Session()
    iam_client = session.client("iam", region_name="us-east-1")
    ssm_client = session.client("ssm", region_name="us-east-1")

    # Create mock IAM role and S3 bucket
    iam_client.create_role(
        RoleName="cdk-hnb659fds-file-publishing-role-123456789012-us-east-1",
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
        RoleName="cdk-hnb659fds-file-publishing-role-123456789012-us-east-1",
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
    for risky_bootstrap in scanner.risky_bootstraps:
        assert risky_bootstrap[3] == "Mitigated"
