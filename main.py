#!/usr/bin/env python3
"""
Main entry point for iCloud to S3 backup utility
"""

import sys
import logging
from icloud_to_s3.auth import AuthenticationManager
from icloud_to_s3.backup import BackupManager
from icloud_to_s3.config import Config
from icloud_to_s3.utils import validate_bucket_name, handle_2fa_challenge

logger = logging.getLogger(__name__)

def main():
    print("=== iCloud to S3 Backup Utility ===")

    # Initialize configuration
    config = Config()

    # Try loading from environment variables first
    config.load_from_env()

    # If any required config is missing, prompt user for input
    if not all([config.icloud_username, config.icloud_password,
                config.aws_access_key, config.aws_secret_key,
                config.s3_bucket]):
        config.load_from_input()

    try:
        # Initialize authentication manager
        auth_manager = AuthenticationManager()

        # Authenticate with iCloud
        print("\nAuthenticating with iCloud...")
        if not auth_manager.authenticate_icloud(config.icloud_username, config.icloud_password):
            logger.error("Failed to authenticate with iCloud")
            sys.exit(1)

        # Handle 2FA if needed
        if not handle_2fa_challenge(auth_manager.get_icloud_api()):
            logger.error("Failed to complete 2FA verification")
            sys.exit(1)

        # Authenticate with AWS
        print("\nAuthenticating with AWS...")
        if not auth_manager.authenticate_aws(config.aws_access_key, config.aws_secret_key):
            logger.error("Failed to authenticate with AWS")
            sys.exit(1)

        # Validate S3 bucket
        if not validate_bucket_name(auth_manager.get_s3_client(), config.s3_bucket):
            logger.error(f"Unable to access bucket: {config.s3_bucket}")
            sys.exit(1)

        # Initialize backup manager
        backup_manager = BackupManager(
            auth_manager.get_icloud_api(),
            auth_manager.get_s3_client()
        )

        # List files from iCloud
        print("\nListing files from iCloud...")
        files = backup_manager.list_icloud_files()
        if not files:
            logger.error("No files found in iCloud")
            sys.exit(1)

        print(f"\nFound {len(files)} files to backup")

        # Confirm backup
        confirm = input("\nDo you want to proceed with the backup? (y/N): ")
        if confirm.lower() != 'y':
            print("Backup cancelled")
            sys.exit(0)

        # Perform backup
        print("\nStarting backup process...")
        backup_manager.backup_to_s3(config.s3_bucket, files)

        print("\nBackup completed successfully!")

    except KeyboardInterrupt:
        print("\nBackup process interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()