import csv
import logging
from typing import List, Optional, Tuple


class CSVReportWriter:
    @staticmethod
    def write_csv_report(
        unmatched_roles: List[Tuple[str, str, Optional[str], str, str]],
        risky_bootstraps: List[Tuple[str, str, int, str]],
    ) -> None:
        csv_file = "bucket_takeover_report.csv"
        with open(csv_file, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(
                ["Account ID", "IAMRoleName", "Suffix", "Expected Bucket", "Status"]
            )
            for role_data in unmatched_roles:
                writer.writerow(role_data)
            writer.writerow([])
            writer.writerow(["Account ID", "Region", "Bootstrap Version", "Status"])
            for bootstrap_data in risky_bootstraps:
                writer.writerow(bootstrap_data)
        logging.info(f"CSV report written to {csv_file}")
