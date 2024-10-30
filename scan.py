import argparse
import csv
import logging
import sys

import boto3
from botocore.exceptions import ClientError

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("bucket_takeover_report.log", mode="w"),
    ],
)


# Function to print a cool banner
def print_banner():
    banner = """
    ________  __ __  ___           __       __
    / ___/ _ \/ //_/ / _ )__ ______/ /_____ / /_
    / /__/ // / ,<   / _  / // / __/  '_/ -_) __/
    \___/____/_/|_| /____/\_,_/\__/_/\_\\__/\__/

    ___                         __    ______     __
    / _ |___________  __ _____  / /_  /_  __/__ _/ /_____ ___ _  _____ ____
    / __ / __/ __/ _ \/ // / _ \/ __/   / / / _ `/  '_/ -_) _ \ |/ / -_) __/
    /_/ |_\__/\__/\___/\_,_/_//_/\__/   /_/  \_,_/_/\_\\__/\___/___/\__/_/

    ____
    / __/______ ____  ___  ___ ____
    _\ \/ __/ _ `/ _ \/ _ \/ -_) __/
    /___/\__/\_,_/_//_/_//_/\__/_/

    """
    print(banner)
    print("\r\nCDK Bucket Accounts Takeover Scanner\r\n")
    print(
        "\r\nBased on the research made by Aqua Security:\r\n"
        "\r\nhttps://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover\r\n"
    )


# Function to extract the suffix (account id and region) from the IAMRoleName and BucketName
def extract_suffix(name):
    try:
        parts = name.split("-")
        suffix = "-".join(parts[-4:])  # Get the last four parts: account id and region
        return suffix
    except IndexError as e:
        logging.error(f"Error extracting suffix from {name}: {e}")
        return None


# Function to assume a role in another account
def assume_role(account_id, role_name):
    sts_client = boto3.client("sts")
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
            RoleSessionName="CrossAccountSession",
        )
        credentials = assumed_role["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
    except ClientError as e:
        logging.error(f"Failed to assume role in account {account_id}: {e}")
        return None


# Function to list all S3 buckets in an account
def list_s3_buckets(session):
    s3_client = session.client("s3")
    try:
        buckets = s3_client.list_buckets().get("Buckets", [])
        return [bucket["Name"] for bucket in buckets]
    except ClientError as e:
        logging.error(f"Failed to list S3 buckets: {e}")
        return []


# Function to list all IAM roles in an account
def list_iam_roles(session):
    iam_client = session.client("iam")
    try:
        roles = []
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            roles.extend(page["Roles"])
        return [role["RoleName"] for role in roles]
    except ClientError as e:
        logging.error(f"Failed to list IAM roles: {e}")
        return []


# Function to check if the CDK bootstrap version parameter exists and retrieve its value
def check_cdk_bootstrap_version(session, account_id, region):
    ssm_client = session.client("ssm", region_name=region)
    try:
        # Check if the parameter exists
        parameters = ssm_client.describe_parameters(
            Filters=[{"Key": "Name", "Values": ["/cdk-bootstrap/hnb659fds/version"]}]
        )

        if not parameters["Parameters"]:
            logging.info(
                f"No CDK bootstrap version parameter found for account {account_id} in region {region}"
            )
            return None

        # If the parameter exists, retrieve the value
        param = ssm_client.get_parameter(Name="/cdk-bootstrap/hnb659fds/version")
        version = int(param["Parameter"]["Value"])
        if version < 21:
            logging.warning(
                f"Account {account_id}, Region {region} has a risky CDK bootstrap version: {version}"
            )
            return version
    except ClientError as e:
        logging.error(
            f"Failed to check CDK bootstrap version in account {account_id}, region {region}: {e}"
        )
    return None


# Function to write mismatches to CSV
def write_csv_report(unmatched_roles, risky_bootstraps):
    csv_file = "bucket_takeover_report.csv"
    with open(csv_file, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Account ID", "IAMRoleName", "Suffix", "Expected Bucket"])
        for role_data in unmatched_roles:
            writer.writerow(role_data)
        writer.writerow([])  # Blank row for separation
        writer.writerow(["Account ID", "Region", "Bootstrap Version"])
        for bootstrap_data in risky_bootstraps:
            writer.writerow(bootstrap_data)
    logging.info(f"CSV report written to {csv_file}")


# Main function to check IAM roles, buckets, and CDK bootstrap versions across specified accounts
def check_iam_roles_and_buckets(account_ids, assume_role_name):
    role_prefix = "cdk-hnb659fds-file-publishing-role"
    unmatched_roles = []
    risky_bootstraps = []

    # List of all AWS regions to check CDK bootstrap versions
    regions = boto3.Session().get_available_regions("ssm")

    for account_id in account_ids:
        logging.info(f"Processing account {account_id}")

        # Assume role in each account
        session = assume_role(account_id, assume_role_name)
        if not session:
            logging.error(f"Skipping account {account_id} due to assume role failure.")
            continue

        # List S3 buckets and IAM roles in the account
        s3_buckets = list_s3_buckets(session)
        iam_roles = list_iam_roles(session)

        # Filter IAM roles with the specific prefix
        filtered_iam_roles = [
            role for role in iam_roles if role.startswith(role_prefix)
        ]
        if not filtered_iam_roles:
            logging.info(
                f"No IAM roles with prefix {role_prefix} found in account {account_id}."
            )
            continue

        # Extract suffixes from S3 buckets
        bucket_suffixes = {extract_suffix(bucket) for bucket in s3_buckets}

        for iam_role in filtered_iam_roles:
            role_suffix = extract_suffix(iam_role)
            expected_bucket_name = (
                f"cdk-hnb659fds-assets-{role_suffix}"  # Expected bucket name format
            )
            if role_suffix in bucket_suffixes:
                logging.info(
                    f"Successfully matched IAM role {iam_role} in account {account_id} with bucket suffix {role_suffix}."
                )
            else:
                unmatched_roles.append(
                    (account_id, iam_role, role_suffix, expected_bucket_name)
                )

        # Check CDK bootstrap version for each region
        for region in regions:
            version = check_cdk_bootstrap_version(session, account_id, region)
            if version is not None and version < 21:
                risky_bootstraps.append((account_id, region, version))

    if unmatched_roles or risky_bootstraps:
        if unmatched_roles:
            logging.warning(
                f"{len(unmatched_roles)} IAM roles do not have matching bucket names."
            )
        if risky_bootstraps:
            logging.warning(
                f"{len(risky_bootstraps)} regions have risky CDK bootstrap versions."
            )
        # Write the mismatches and risky bootstraps to CSV
        write_csv_report(unmatched_roles, risky_bootstraps)
    else:
        logging.info(
            "All IAM roles with prefix have matching bucket names across accounts, and CDK bootstraps are safe."
        )


if __name__ == "__main__":
    # Print the banner
    print_banner()

    # Set up argument parsing
    parser = argparse.ArgumentParser(
        description="Check IAM roles, S3 buckets, and CDK bootstrap versions in multiple AWS accounts"
    )
    parser.add_argument(
        "--account-ids",
        nargs="+",
        required=True,
        help="List of AWS account IDs to check",
    )
    parser.add_argument(
        "--assume-role-name",
        required=True,
        help="The name of the role to assume in each account",
    )

    args = parser.parse_args()

    # Check IAM roles, buckets, and CDK bootstraps in the provided accounts
    check_iam_roles_and_buckets(args.account_ids, args.assume_role_name)
