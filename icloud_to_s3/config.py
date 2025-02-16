"""
Configuration management
"""

import os
import logging

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class Config:
    def __init__(self):
        self.icloud_username = None
        self.icloud_password = None
        self.aws_access_key = None
        self.aws_secret_key = None
        self.s3_bucket = None

    def load_from_input(self):
        """
        Load configuration from user input
        """
        print("\n=== iCloud Credentials ===")
        self.icloud_username = input("iCloud Username: ")
        self.icloud_password = input("iCloud Password: ")

        print("\n=== AWS Credentials ===")
        self.aws_access_key = input("AWS Access Key ID: ")
        self.aws_secret_key = input("AWS Secret Access Key: ")
        self.s3_bucket = input("S3 Bucket Name: ")