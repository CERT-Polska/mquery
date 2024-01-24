from typing import Optional, List, IO
import gzip
import shutil
import tempfile

from ..db import Database
from ..metadata import MetadataPlugin, MetadataPluginConfig


class GzipPlugin(MetadataPlugin):
    """Can be used to automatically extract gzip contents before running
    Yara on them. This plugin will look for all files that end with .gz,
    and add extract them to disk before further processing.
    """

    is_filter = True

    def __init__(self, db: Database, config: MetadataPluginConfig) -> None:
        super().__init__(db, config)
        self.tmpfiles: List[IO[bytes]] = []

    def filter(self, orig_name: str, file_path: str) -> Optional[str]:
        if orig_name.endswith(".gz"):
            tmp = tempfile.NamedTemporaryFile()
            self.tmpfiles.append(tmp)
            with gzip.open(file_path, "rb") as f_in:
                with open(tmp.name, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            return tmp.name

        return file_path

    def clean(self):
        for tmp in self.tmpfiles:
            tmp.close()
        self.tmpfiles = []
