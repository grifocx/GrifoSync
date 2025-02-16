"""
Core backup functionality
"""

import os
import logging
from datetime import datetime
from tqdm import tqdm
import tempfile

logger = logging.getLogger(__name__)

class BackupManager:
    def __init__(self, icloud_api, s3_client):
        self.icloud_api = icloud_api
        self.s3_client = s3_client
        self.temp_dir = tempfile.mkdtemp()

    def list_icloud_files(self):
        """
        List all available files in iCloud
        """
        files = []
        try:
            # Get files from iCloud Drive
            drive_files = self._get_drive_files(self.icloud_api.drive)
            files.extend(drive_files)

            # Get photos if available
            if hasattr(self.icloud_api, 'photos'):
                photo_files = self._get_photos(self.icloud_api.photos)
                files.extend(photo_files)

            logger.info(f"Found {len(files)} files in iCloud")
            return files
        except Exception as e:
            logger.error(f"Error listing iCloud files: {str(e)}")
            return []

    def _get_drive_files(self, drive, path=""):
        """
        Recursively get all files from iCloud Drive
        """
        files = []
        for item in drive.dir():
            if item.type == 'file':
                files.append({
                    'name': os.path.join(path, item.name),
                    'size': item.size,
                    'type': 'file',
                    'source': item
                })
            elif item.type == 'folder':
                subfolder = drive[item.name]
                files.extend(self._get_drive_files(subfolder, os.path.join(path, item.name)))
        return files

    def _get_photos(self, photos):
        """
        Get all photos from iCloud Photos
        """
        files = []
        for photo in photos.all:
            files.append({
                'name': f"photos/{photo.filename}",
                'size': 0,  # Size not available until download
                'type': 'photo',
                'source': photo
            })
        return files

    def backup_to_s3(self, bucket_name, files):
        """
        Backup files to S3 bucket
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        with tqdm(total=len(files), desc="Backing up files") as pbar:
            for file_info in files:
                try:
                    # Create S3 key with timestamp prefix
                    s3_key = f"backup_{timestamp}/{file_info['name']}"
                    
                    # Download file to temporary location
                    temp_path = os.path.join(self.temp_dir, os.path.basename(file_info['name']))
                    
                    if file_info['type'] == 'file':
                        file_info['source'].download(temp_path)
                    elif file_info['type'] == 'photo':
                        download = file_info['source'].download()
                        with open(temp_path, 'wb') as f:
                            f.write(download.raw.read())

                    # Upload to S3
                    self.s3_client.upload_file(temp_path, bucket_name, s3_key)
                    
                    # Clean up temporary file
                    os.remove(temp_path)
                    
                    logger.info(f"Successfully backed up {file_info['name']}")
                except Exception as e:
                    logger.error(f"Error backing up {file_info['name']}: {str(e)}")
                
                pbar.update(1)

        # Clean up temporary directory
        os.rmdir(self.temp_dir)
