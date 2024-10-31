import json
import logging
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError


class PolicyManager:
    def __init__(self, session: boto3.Session, account_id: str):
        self.session = session
        self.account_id = account_id

    def create_bucket_takeover_fix_policy(self) -> Optional[str]:
        iam_client = self.session.client("iam")
        policy_name = "cdk-bootstrap-bucket-takeover-fix"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Condition": {
                        "StringNotEquals": {"aws:ResourceAccount": self.account_id}
                    },
                    "Action": [
                        "s3:GetObject*",
                        "s3:GetBucket*",
                        "s3:GetEncryptionConfiguration",
                        "s3:List*",
                        "s3:DeleteObject*",
                        "s3:PutObject*",
                        "s3:Abort*",
                    ],
                    "Resource": [
                        f"arn:aws:s3:::cdk-hnb659fds-assets-{self.account_id}-*",
                        f"arn:aws:s3:::cdk-hnb659fds-assets-{self.account_id}-*/*",
                    ],
                    "Effect": "Deny",
                }
            ],
        }

        try:
            policy_arn = None
            policies = iam_client.list_policies(Scope="Local")["Policies"]
            for policy in policies:
                if policy["PolicyName"] == policy_name:
                    policy_arn = policy["Arn"]
                    break
            if not policy_arn:
                response = iam_client.create_policy(
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(policy_document),
                )
                policy_arn = response["Policy"]["Arn"]
                logging.info(
                    f"Created policy {policy_name} in account {self.account_id}"
                )
            return policy_arn
        except ClientError as e:
            logging.error(f"Failed to create policy in account {self.account_id}: {e}")
            return None

    def attach_policy_to_risky_roles(
        self, policy_arn: str, risky_roles: List[str]
    ) -> str:
        iam_client = self.session.client("iam")
        status = "Gap"
        for role_name in risky_roles:
            try:
                iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                logging.info(f"Attached policy {policy_arn} to role {role_name}")
                status = "Mitigated"
            except ClientError as e:
                logging.error(f"Failed to attach policy to role {role_name}: {e}")
        return status
