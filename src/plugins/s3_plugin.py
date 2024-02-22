from typing import Optional, List, IO
import os
import shutil
import tempfile
from minio import Minio  # type: ignore

from ..db import Database
from ..metadata import MetadataPlugin, MetadataPluginConfig


class S3Plugin(MetadataPlugin):
    """Can be used to download files from minio prior to running yara.
    Names of the files in configured bucket must be equal to basenames
    (filenames without paths) of matched files.
    """

    is_filter = True
    config_fields = {
        "s3_url": "Url of the S3 server.",
        "s3_bucket": "Bucket where the samples are stored.",
        "s3_access_key": "S3 access key.",
        "s3_secret_key": "S3 secret key.",
        "s3_secure": "Use https? Set to 'true' or 'false'.",
    }

    def __init__(self, db: Database, config: MetadataPluginConfig) -> None:
        super().__init__(db, config)
        self.tmpfiles: List[IO[bytes]] = []

        assert config["s3_secure"] in ["true", "false"]
        self.minio = Minio(
            config["s3_url"],
            config["s3_access_key"],
            config["s3_secret_key"],
            secure=config["s3_secure"] == "true",
        )
        self.bucket = config["s3_bucket"]

    def filter(self, orig_name: str, file_path: str) -> Optional[str]:
        if orig_name != file_path:
            # We override the file. It doesn't make sense to use other
            # content-modifying filters before the s3 plugin.
            raise RuntimeError("S3 plugin should be the first filter")

        name = os.path.basename(orig_name)
        tmp = tempfile.NamedTemporaryFile()
        self.tmpfiles.append(tmp)

        response = self.minio.get_object(self.bucket, name)
        try:
            with open(tmp.name, "wb") as f_out:
                shutil.copyfileobj(response, f_out)
        finally:
            response.close()
            response.release_conn()
        return tmp.name

    def clean(self) -> None:
        for tmp in self.tmpfiles:
            tmp.close()
        self.tmpfiles = []
