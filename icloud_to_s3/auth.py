"""
Authentication handlers for iCloud and AWS S3
"""

import boto3
from pyicloud import PyiCloudService
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

class AuthenticationManager:
    def __init__(self):
        self.icloud_api = None
        self.s3_client = None

    def authenticate_icloud(self, username, password):
        """
        Authenticate with iCloud using provided credentials
        """
        try:
            self.icloud_api = PyiCloudService(username, password)
            logger.info("Successfully authenticated with iCloud")
            return True
        except Exception as e:
            logger.error(f"iCloud authentication failed: {str(e)}")
            return False

    def authenticate_aws(self, aws_access_key, aws_secret_key):
        """
        Authenticate with AWS using provided credentials
        """
        try:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key
            )
            # Test connection by listing buckets
            self.s3_client.list_buckets()
            logger.info("Successfully authenticated with AWS S3")
            return True
        except ClientError as e:
            logger.error(f"AWS authentication failed: {str(e)}")
            return False

    def get_icloud_api(self):
        """
        Return authenticated iCloud API instance
        """
        if not self.icloud_api:
            raise ValueError("iCloud not authenticated")
        return self.icloud_api

    def get_s3_client(self):
        """
        Return authenticated S3 client
        """
        if not self.s3_client:
            raise ValueError("AWS not authenticated")
        return self.s3_client
