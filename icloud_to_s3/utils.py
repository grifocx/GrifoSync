"""
Utility functions
"""

import logging
import sys
from getpass import getpass
import time

logger = logging.getLogger(__name__)

def validate_bucket_name(s3_client, bucket_name):
    """
    Validate S3 bucket exists and is accessible
    """
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        return True
    except Exception as e:
        logger.error(f"Error validating bucket {bucket_name}: {str(e)}")
        return False

def handle_2fa_challenge(api):
    """
    Handle two-factor authentication if required
    """
    if api.requires_2fa:
        print("\nTwo-factor authentication required.")
        print("A verification code has been sent to your Apple devices.")

        max_attempts = 3
        current_attempt = 0

        while current_attempt < max_attempts:
            try:
                current_attempt += 1
                print(f"\nAttempt {current_attempt} of {max_attempts}")

                # Use input() for more reliable input handling
                code = input("Enter the verification code you received: ").strip()

                if not code:
                    print("Code cannot be empty. Please try again.")
                    continue

                result = api.validate_2fa_code(code)
                if result:
                    logger.info("2FA verification successful")
                    return True
                else:
                    print("Invalid verification code. Please try again.")
                    # Small delay before next attempt
                    time.sleep(1)

            except EOFError:
                logger.error("Error reading verification code input")
                print("\nError reading input. Please try again.")
            except Exception as e:
                logger.error(f"Error during 2FA verification: {str(e)}")
                print(f"\nError verifying code: {str(e)}")

        logger.error("Failed to verify 2FA code after maximum attempts")
        print("\nMaximum verification attempts reached. Please try again later.")
        sys.exit(1)

    return True

def format_size(size):
    """
    Format file size in human-readable format
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.2f}{unit}"
        size /= 1024
    return f"{size:.2f}TB"