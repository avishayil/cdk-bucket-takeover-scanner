from moto import mock_aws

from src.account_manager import AWSAccountManager


@mock_aws
def test_assume_role():
    manager = AWSAccountManager("123456789012", "TestRole")
    assert manager.session is not None


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
