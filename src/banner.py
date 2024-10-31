class BannerPrinter:
    @staticmethod
    def print_banner() -> None:
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
