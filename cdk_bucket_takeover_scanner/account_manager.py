import logging
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError


class AWSAccountManager:
    def __init__(self, account_id: str, role_name: str):
        self.account_id = account_id
        self.role_name = role_name
        self.session = self.assume_role()

    def assume_role(self) -> Optional[boto3.Session]:
        sts_client = boto3.client("sts")
        try:
            assumed_role = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{self.account_id}:role/{self.role_name}",
                RoleSessionName="CrossAccountSession",
            )
            credentials = assumed_role["Credentials"]
            return boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
            )
        except ClientError as e:
            logging.error(f"Failed to assume role in account {self.account_id}: {e}")
            return None

    def list_s3_buckets(self) -> List[str]:
        if not self.session:
            return []
        s3_client = self.session.client("s3")
        try:
            buckets = s3_client.list_buckets().get("Buckets", [])
            return [bucket["Name"] for bucket in buckets]
        except ClientError as e:
            logging.error(
                f"Failed to list S3 buckets in account {self.account_id}: {e}"
            )
            return []

    def list_iam_roles(self) -> List[str]:
        if not self.session:
            return []
        iam_client = self.session.client("iam")
        try:
            roles = []
            paginator = iam_client.get_paginator("list_roles")
            for page in paginator.paginate():
                roles.extend(page["Roles"])
            return [role["RoleName"] for role in roles]
        except ClientError as e:
            logging.error(f"Failed to list IAM roles in account {self.account_id}: {e}")
            return []

    def check_cdk_bootstrap_version(self, region: str) -> Optional[int]:
        if not self.session:
            return None
        ssm_client = self.session.client("ssm", region_name=region)
        try:
            parameters = ssm_client.describe_parameters(
                Filters=[
                    {"Key": "Name", "Values": ["/cdk-bootstrap/hnb659fds/version"]}
                ]
            )
            if not parameters["Parameters"]:
                logging.info(
                    f"No CDK bootstrap version parameter found for account {self.account_id} in region {region}"
                )
                return None
            param = ssm_client.get_parameter(Name="/cdk-bootstrap/hnb659fds/version")
            version = int(param["Parameter"]["Value"])
            if version < 21:
                logging.warning(
                    f"Account {self.account_id}, Region {region} has a risky CDK bootstrap version: {version}"
                )
                return version
        except ClientError as e:
            logging.error(
                f"Failed to check CDK bootstrap version in account {self.account_id}, region {region}: {e}"
            )
        return None
