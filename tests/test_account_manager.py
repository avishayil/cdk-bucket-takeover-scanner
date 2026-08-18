from unittest.mock import patch

from botocore.exceptions import ClientError
from moto import mock_aws

from cdk_bucket_takeover_scanner.account_manager import AWSAccountManager


@mock_aws
def test_assume_role():
    manager = AWSAccountManager("123456789012", "TestRole")
    assert manager.session is not None


def test_assume_role_failure_returns_none():
    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "AssumeRole"
    )
    with patch("boto3.client") as mock_client:
        mock_client.return_value.assume_role.side_effect = error
        manager = AWSAccountManager("123456789012", "TestRole")
    assert manager.session is None
    # Methods degrade gracefully with no session.
    assert manager.list_s3_buckets() == []
    assert manager.list_iam_roles() == []
    assert manager.check_cdk_bootstrap_version("us-east-1") is None


@mock_aws
def test_list_s3_buckets():
    manager = AWSAccountManager("123456789012", "TestRole")
    s3 = manager.session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    assert "test-bucket" in manager.list_s3_buckets()


@mock_aws
def test_list_iam_roles():
    manager = AWSAccountManager("123456789012", "TestRole")
    iam = manager.session.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="TestRole", AssumeRolePolicyDocument="{}")
    assert "TestRole" in manager.list_iam_roles()


@mock_aws
def test_check_cdk_bootstrap_version_flags_low():
    manager = AWSAccountManager("123456789012", "TestRole")
    ssm = manager.session.client("ssm", region_name="us-east-1")
    ssm.put_parameter(
        Name="/cdk-bootstrap/hnb659fds/version", Value="10", Type="String"
    )
    assert manager.check_cdk_bootstrap_version("us-east-1") == 10


@mock_aws
def test_check_cdk_bootstrap_version_passes_safe():
    manager = AWSAccountManager("123456789012", "TestRole")
    ssm = manager.session.client("ssm", region_name="us-east-1")
    ssm.put_parameter(
        Name="/cdk-bootstrap/hnb659fds/version", Value="21", Type="String"
    )
    # A bootstrap version >= 21 is not vulnerable, so nothing is reported.
    assert manager.check_cdk_bootstrap_version("us-east-1") is None


@mock_aws
def test_check_cdk_bootstrap_version_missing_parameter():
    manager = AWSAccountManager("123456789012", "TestRole")
    assert manager.check_cdk_bootstrap_version("us-east-1") is None
