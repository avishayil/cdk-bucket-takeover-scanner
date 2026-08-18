import argparse
from typing import List, Optional

from .banner import BannerPrinter
from .cdk_bucket_scanner import CDKBucketScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cdk-bucket-takeover-scanner",
        description="Check IAM roles, S3 buckets, and CDK bootstrap versions in multiple AWS accounts",
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
    return parser


def main(argv: Optional[List[str]] = None) -> CDKBucketScanner:
    BannerPrinter.print_banner()
    parser = build_parser()
    args = parser.parse_args(argv)
    scanner = CDKBucketScanner(args.account_ids, args.assume_role_name, args.fix)
    scanner.run_scan()
    return scanner


if __name__ == "__main__":
    main()
