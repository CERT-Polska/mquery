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

    Files and directories are mapped depending on s3_bucket, s3_source_dir and
    s3_target_dir, in a following way:

    * If filtered path doesn't start with s3_source_dir, skip it (don't do anything)
    * Otherwise strip the s3_source_dir prefix and use the rest as object name.
    * Download that object to s3_target_dir directory.

    On a practical example, let's say:

    * s3_source_dir is /s3/mwdb/
    * s3_target_dir it /mnt/samples
    * s3_bucket is mwdb

    Then indexing file /s3/mwdb/0/1/2/3/0123e9d3 will strip the `/s3/mwdb` prefix,
    and consider `0/1/2/3/0123e9d3` as the object name. This object will be downloaded
    from `mwdb` bucket, to /mnt/samples/0/1/2/3/0123e9d for indexing.
    """

    is_filter = True
    config_fields = {
        "s3_host": "Host of the S3 server (for example, `127.0.0.1:9000`).",
        "s3_access_key": "S3 access key.",
        "s3_secret_key": "S3 secret key.",
        "s3_secure": "Use https? Set to 'true' or 'false'. Default is true.",
        "s3_bucket": "Bucket where the samples are stored.",
        "s3_source_dir": "Path prefix for S3 files. Indexing files from this directory will instead pull them from S3. This directory doesn't have to exist.",
        "s3_target_dir": "Download s3 files here before indexing. Ursadb must see this directory. This directory must exist!",
    }
    config_defaults = {
        "s3_secure": "true",
    }

    def __init__(self, db: Database, config: MetadataPluginConfig) -> None:
        super().__init__(db, config)
        self.tmpfiles: List[str] = []

        assert config["s3_secure"] in ["true", "false"]
        self.minio = Minio(
            config["s3_host"],
            config["s3_access_key"],
            config["s3_secret_key"],
            secure=config["s3_secure"] == "true",
        )
        self.bucket = config["s3_bucket"]
        self.source_dir = config["s3_source_dir"]
        self.target_dir = config["s3_target_dir"]

    def filter(self, matched_fname: str, file_path: str) -> Optional[str]:
        if not matched_fname.startswith(self.source_dir):
            # The file is outside of our configured directory with s3 files.
            return file_path

        if matched_fname != file_path:
            # We override the file. It doesn't make sense to use other
            # content-modifying filters before the s3 plugin.
            raise RuntimeError("S3 plugin should be the first filter")

        # This is how this code is supposed to work:

        # Assume source_dir is /s3/mwdb/, target_dir it /mnt/samples, bucket is mwdb

        # Then indexing file /s3/mwdb/0/1/2/3/0123e9d3 will strip the `/s3/mwdb` prefix,
        # `0/1/2/3/0123e9d3` is the object name. This will be downloaded
        # from `mwdb` bucket, to /mnt/samples/0/1/2/3/0123e9d for indexing.

        object_name = os.path.relpath(file_path, self.source_dir)
        target_file = os.path.join(self.target_dir, object_name)

        if os.path.isfile(target_file):
            # Target file already exists - hopefully it's the one we expect.
            # We are not going to overwrite this file - if anything, this could
            # raise an exception, because reindexing the same file won't work.
            # Since we don't own it, we will not remove it.
            return target_file

        try:
            response = self.minio.get_object(self.bucket, object_name)
        except S3Error as e:
            # File is probably missing from minio. This is not recoverable.
            # To avoid infinite crashes, skip this file.
            logging.warning(
                "Skipping %s/%s because %r", self.bucket, object_name, e
            )
            return None

        try:
            self.tmpfiles.append(target_file)
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            with open(target_file, "wb") as f_out:
                shutil.copyfileobj(response, f_out)
        finally:
            response.close()
            response.release_conn()

        return target_file

    def clean(self) -> None:
        for tmp in self.tmpfiles:
            os.remove(tmp)
        self.tmpfiles = []
