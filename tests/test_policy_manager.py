import boto3
from moto import mock_aws

from src.policy_manager import PolicyManager


@mock_aws
def test_create_bucket_takeover_fix_policy():
    session = boto3.Session(region_name="us-east-1")
    manager = PolicyManager(session, "123456789012")
    policy_arn = manager.create_bucket_takeover_fix_policy()
    assert policy_arn is not None


@mock_aws
def test_attach_policy_to_risky_roles():
    session = boto3.Session(region_name="us-east-1")
    manager = PolicyManager(session, "123456789012")
    iam_client = session.client("iam")
    iam_client.create_role(RoleName="RiskyRole", AssumeRolePolicyDocument="{}")
    policy_arn = manager.create_bucket_takeover_fix_policy()
    status = manager.attach_policy_to_risky_roles(policy_arn, ["RiskyRole"])
    assert status == "Mitigated"
