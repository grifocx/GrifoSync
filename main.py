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

    try:
        # Initialize managers
        auth_manager = AuthenticationManager()
        backup_manager = None

        # If we have credentials, try to authenticate
        if all([config.icloud_username, config.icloud_password,
                config.aws_access_key, config.aws_secret_key,
                config.s3_bucket]):

            # Authenticate with services
            if auth_manager.authenticate_icloud(config.icloud_username, config.icloud_password):
                # Handle 2FA if needed
                if not handle_2fa_challenge(auth_manager.get_icloud_api()):
                    logger.error("Failed to complete 2FA verification")
                    sys.exit(1)

                if auth_manager.authenticate_aws(config.aws_access_key, config.aws_secret_key):
                    backup_manager = BackupManager(
                        auth_manager.get_icloud_api(),
                        auth_manager.get_s3_client()
                    )

        # Start backup process if authenticated
        if backup_manager:
            files = backup_manager.list_icloud_files()
            if not files:
                logger.error("No files found in iCloud")
                sys.exit(1)

            print(f"\nFound {len(files)} files to backup")
            backup_manager.backup_to_s3(config.s3_bucket, files)
            print("\nBackup completed successfully!")
        else:
            print("\nNo credentials configured. Please configure through the web interface.")

    except KeyboardInterrupt:
        print("\nBackup process interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()