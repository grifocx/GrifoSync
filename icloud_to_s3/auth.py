"""
Authentication handlers for iCloud and AWS S3
"""

import boto3
from pyicloud import PyiCloudService
from botocore.exceptions import ClientError, NoCredentialsError
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
            # Validate credentials format
            if not aws_access_key or len(aws_access_key.strip()) < 16:
                logger.error("Invalid AWS Access Key format")
                raise ValueError("AWS Access Key ID appears to be invalid. It should be at least 16 characters long.")

            if not aws_secret_key or len(aws_secret_key.strip()) < 32:
                logger.error("Invalid AWS Secret Key format")
                raise ValueError("AWS Secret Access Key appears to be invalid. It should be at least 32 characters long.")

            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key
            )

            # Test connection with specific error handling
            try:
                self.s3_client.list_buckets()
                logger.info("Successfully authenticated with AWS S3")
                return True
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'InvalidAccessKeyId':
                    logger.error("AWS Access Key ID does not exist in AWS records")
                    raise ValueError("The AWS Access Key ID provided does not exist. Please verify your credentials.")
                elif error_code == 'SignatureDoesNotMatch':
                    logger.error("AWS Secret Key is invalid")
                    raise ValueError("The AWS Secret Access Key is incorrect. Please verify your credentials.")
                else:
                    logger.error(f"AWS API error: {error_code}")
                    raise ValueError(f"AWS API error: {str(e)}")

        except NoCredentialsError:
            logger.error("No AWS credentials provided")
            raise ValueError("AWS credentials are missing. Please provide both Access Key ID and Secret Access Key.")
        except ClientError as e:
            logger.error(f"AWS authentication failed: {str(e)}")
            return False
        except ValueError as e:
            # Re-raise ValueError for more specific error messages
            raise
        except Exception as e:
            logger.error(f"Unexpected error during AWS authentication: {str(e)}")
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