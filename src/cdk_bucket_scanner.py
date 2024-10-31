import logging
from typing import List, Optional

import boto3

from src.account_manager import AWSAccountManager
from src.policy_manager import PolicyManager
from src.report_writer import CSVReportWriter


class CDKBucketScanner:
    def __init__(
        self, account_ids: List[str], assume_role_name: str, fix: bool = False
    ):
        self.account_ids = account_ids
        self.assume_role_name = assume_role_name
        self.fix = fix
        self.unmatched_roles = []
        self.risky_bootstraps = []

    def run_scan(self) -> None:
        for account_id in self.account_ids:
            logging.info(f"Processing account {account_id}")
            account_manager = AWSAccountManager(account_id, self.assume_role_name)

            if not account_manager.session:
                logging.error(
                    f"Skipping account {account_id} due to assume role failure."
                )
                continue

            s3_buckets = account_manager.list_s3_buckets()
            iam_roles = account_manager.list_iam_roles()
            self.scan_account(account_manager, s3_buckets, iam_roles)

            regions = boto3.Session().get_available_regions("ssm")
            self.check_bootstrap_versions(account_manager, regions)

        CSVReportWriter.write_csv_report(self.unmatched_roles, self.risky_bootstraps)

    def scan_account(
        self,
        account_manager: AWSAccountManager,
        s3_buckets: List[str],
        iam_roles: List[str],
    ) -> None:
        role_prefix = "cdk-hnb659fds-file-publishing-role"
        filtered_iam_roles = [
            role for role in iam_roles if role.startswith(role_prefix)
        ]
        if not filtered_iam_roles:
            logging.info(
                f"No IAM roles with prefix {role_prefix} found in account {account_manager.account_id}."
            )
            return

        bucket_suffixes = {self.extract_suffix(bucket) for bucket in s3_buckets}
        for iam_role in filtered_iam_roles:
            role_suffix = self.extract_suffix(iam_role)
            expected_bucket_name = f"cdk-hnb659fds-assets-{role_suffix}"
            status = "Gap"
            if role_suffix not in bucket_suffixes:
                self.unmatched_roles.append(
                    (
                        account_manager.account_id,
                        iam_role,
                        role_suffix,
                        expected_bucket_name,
                        status,
                    )
                )
            else:
                logging.info(
                    f"Successfully matched IAM role {iam_role} in account {account_manager.account_id} with bucket {expected_bucket_name}."
                )

    def check_bootstrap_versions(
        self, account_manager: AWSAccountManager, regions: List[str]
    ) -> None:
        for region in regions:
            version = account_manager.check_cdk_bootstrap_version(region)
            status = "Gap"
            if version is not None and version < 21:
                self.risky_bootstraps.append(
                    (account_manager.account_id, region, version, status)
                )

                if self.fix:
                    policy_manager = PolicyManager(
                        account_manager.session, account_manager.account_id
                    )
                    policy_arn = policy_manager.create_bucket_takeover_fix_policy()
                    risky_roles = [
                        role
                        for role in account_manager.list_iam_roles()
                        if self.extract_suffix(role)
                        == f"{account_manager.account_id}-{region}"
                    ]
                    status = policy_manager.attach_policy_to_risky_roles(
                        policy_arn, risky_roles
                    )
                    self.risky_bootstraps[-1] = (
                        account_manager.account_id,
                        region,
                        version,
                        status,
                    )

    @staticmethod
    def extract_suffix(name: str) -> Optional[str]:
        try:
            parts = name.split("-")
            suffix = "-".join(parts[-4:])
            return suffix
        except IndexError as e:
            logging.error(f"Error extracting suffix from {name}: {e}")
            return None
