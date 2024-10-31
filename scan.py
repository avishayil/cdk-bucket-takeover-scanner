import argparse

from src.banner import BannerPrinter
from src.cdk_bucket_scanner import CDKBucketScanner

if __name__ == "__main__":
    BannerPrinter.print_banner()
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
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Create and attach policy to mitigate bucket takeover risk",
    )

    args = parser.parse_args()
    scanner = CDKBucketScanner(args.account_ids, args.assume_role_name, args.fix)
    scanner.run_scan()
