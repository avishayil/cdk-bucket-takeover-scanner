
# CDK Bucket Takeover Scanner

## Overview

The **CDK Bucket Takeover Scanner** is a command-line tool designed to scan a list of AWS accounts for risks related to potential S3 bucket takeovers, particularly in environments using AWS CDK. The scanner matches IAM roles with specific prefixes to expected S3 bucket names and checks whether the required buckets exist.

Additionally, the tool checks the AWS CDK bootstrap version in each region to ensure it is not vulnerable to future bucket takeover risks.

For more details on the research behind this tool, please refer to Aqua Security's blog post:  
[Exploiting a Missing S3 Bucket for AWS Account Takeover](https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover)

## Features

- Scans multiple AWS accounts for CDK bucket takeover risk.
- Assumes a specified role in each account and lists IAM roles and S3 buckets.
- Matches IAM roles with the prefix `cdk-hnb659fds-file-publishing-role` to corresponding S3 buckets.
- Checks if the AWS CDK is bootstrapped in each region with a version lower than 21 (which may introduce future risks).
- Generates a CSV report of IAM roles that do not have matching S3 buckets and regions where the CDK bootstrap version is vulnerable.

## Requirements

- Python 3.8.1 or higher
- AWS credentials configured for cross-account role assumption.

## Installation

You can install the dependencies using [Poetry](https://python-poetry.org/), a Python dependency management tool.

1. Install Poetry if you haven't already:
   ```bash
   pip install poetry
   ```

2. Clone the repository and navigate to the project directory:
   ```bash
   git clone https://github.com/avishayil/cdk-bucket-takeover-scanner.git
   cd cdk-bucket-takeover-scanner
   ```

3. Install dependencies:
   ```bash
   poetry install
   ```

## Usage

### IAM Permissions

To run this script, you will need to assign the following minimal IAM policy to the role being assumed in each AWS account:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "iam:ListRoles"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter",
                "ssm:DescribeParameters"
            ],
            "Resource": "arn:aws:ssm:*:*:parameter/cdk-bootstrap/hnb659fds/version"
        }
    ]
}
```

To run the scanner, use the following command:

```bash
poetry run python scan.py --account-ids <ACCOUNT_ID_1> <ACCOUNT_ID_2> ... --assume-role-name <ROLE_NAME>
```

- `--account-ids`: A space-separated list of AWS account IDs to scan.
- `--assume-role-name`: The name of the IAM role to assume in each account for cross-account access.

### Example

```bash
poetry run python scan.py --account-ids 123456789012 987654321098 --assume-role-name OrganizationAccountAccessRole
```

This example assumes the role `OrganizationAccountAccessRole` in both accounts (`123456789012` and `987654321098`) and checks for mismatched IAM roles, S3 buckets, and vulnerable CDK bootstrap versions.

## Output

The scanner outputs logs to the console and writes a detailed log to `bucket_takeover.log`. If any IAM roles do not have matching S3 buckets or if any regions have a vulnerable CDK bootstrap version, it generates a CSV report (`bucket_takeover_report.csv`) listing the affected roles and regions.

## Development

This project follows Python best practices, including formatting and linting. The following tools are used in development:

- **Black** for code formatting.
- **Isort** for import sorting.
- **Flake8** for linting.

You can run these tools using [pre-commit](https://pre-commit.com/), which is configured in this project:

```bash
poetry run pre-commit install
poetry run pre-commit run --all-files
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

Author: Avishay Bar  
Email: avishay.bar@cyberark.com
