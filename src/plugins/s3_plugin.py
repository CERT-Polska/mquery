from typing import Optional, List
import os
import shutil
import logging
from minio import Minio, S3Error  # type: ignore

from ..db import Database
from ..metadata import MetadataPlugin, MetadataPluginConfig


class S3Plugin(MetadataPlugin):
    """Can be used to download files from minio prior to running yara.
    Names of the files in configured bucket must be equal to basenames
    (filenames without paths) of matched files.

    The files are always saved to /mnt/s3 directory. This directory must exist, and be
    writable by the indexeing process.
    """

    is_filter = True
    config_fields = {
        "s3_url": "Url of the S3 server.",
        "s3_bucket": "Bucket where the samples are stored.",
        "s3_access_key": "S3 access key.",
        "s3_secret_key": "S3 secret key.",
        "s3_secure": "Use https? Set to 'true' or 'false'.",
        "s3_download_dir": "Local directory for s3 files (this path is stored in ursadb). Default is '/mnt/s3'.",
    }
    config_defaults = {
        "s3_secure": "true",
        "s3_download_dir": "/mnt/s3",
    }

    def __init__(self, db: Database, config: MetadataPluginConfig) -> None:
        super().__init__(db, config)
        self.tmpfiles: List[str] = []

        assert config["s3_secure"] in ["true", "false"]
        self.minio = Minio(
            config["s3_url"],
            config["s3_access_key"],
            config["s3_secret_key"],
            secure=config["s3_secure"] == "true",
        )
        self.bucket = config["s3_bucket"]
        self.download_dir = config["s3_download_dir"] or "/mnt/s3"

    def filter(self, matched_fname: str, file_path: str) -> Optional[str]:
        if matched_fname != file_path:
            # We override the file. It doesn't make sense to use other
            # content-modifying filters before the s3 plugin.
            raise RuntimeError("S3 plugin should be the first filter")

        if not os.path.isdir(self.download_dir):
            raise RuntimeError(
                f"Download dir {self.download_dir} does not exist."
            )

        name = os.path.basename(matched_fname)
        target = os.path.join(self.download_dir, name)
        if os.path.isfile(target):
            # Target file already exists - hopefully it's the one we expect.
            return target

        self.tmpfiles.append(target)
        try:
            response = self.minio.get_object(self.bucket, name)
        except S3Error:
            # File is missing from minio. This is not recoverable.
            # To avoid infinite crashes, skip this file.
            logging.warning("Skipping a missing file %s/%s", self.bucket, name)
            return None
        try:
            with open(target, "wb") as f_out:
                shutil.copyfileobj(response, f_out)
        finally:
            response.close()
            response.release_conn()
        return target

    def clean(self) -> None:
        for tmp in self.tmpfiles:
            os.remove(tmp)
        self.tmpfiles = []
