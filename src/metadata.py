from abc import ABC
from typing import Any, Dict, Optional

from .db import Database

DEFAULT_CACHE_EXPIRE_TIME = 60 * 60 * 12

Metadata = Dict[str, Any]
MetadataPluginConfig = Dict[str, str]


class MetadataPlugin(ABC):
    # Can extract() results be cached? Currently unused.
    cacheable: bool = False
    # Overrides default cache expire time
    cache_expire_time: int = DEFAULT_CACHE_EXPIRE_TIME
    # Configuration keys required by plugin with description as a value
    config_fields: Dict[str, str] = {}
    # can this plugin be used for prefiltering mwdb results?
    is_filter = False
    # can this plugin be used for extracting metadata?
    is_extractor = False

    def __init__(self, db: Database, config: MetadataPluginConfig) -> None:
        self.db = db
        for key in self.config_fields.keys():
            if key not in config or not config[key]:
                raise KeyError(
                    f"Required configuration key '{key}' is not set"
                )

    @classmethod
    def get_name(cls) -> str:
        return cls.__name__

    def identify(self, matched_fname: str) -> Optional[str]:
        """Returns file unique identifier based on matched path.

        Intended to be overridden by plugin.
        """
        return matched_fname

    def run(self, matched_fname: str, current_meta: Metadata) -> Metadata:
        """Extracts metadata and updates cache. This method can only be run if
        the plugin sets `is_extractor` to True.

        :param matched_fname: Filename of the processed file
        :param current_meta: Metadata that will be updated
        :return: New metadata
        """
        identifier = self.identify(matched_fname)
        if identifier is None:
            return {}

        return self.extract(identifier, matched_fname, current_meta)

    def filter(self, matched_fname: str, file_path: str) -> Optional[str]:
        """Checks if the file is a good candidate for further processing,
        and fix the file path if necessary.
        :param matched_fname: Original file path coming from ursadb
        :param file_path: Current path to the file contents
        :return: New path to a file (may be the same path). None if the file
        should be discarded.
        """
        raise NotImplementedError

    def cleanup(self) -> None:
        """Optionally, clean up after the plugin, for example remove any
        temporary files. Called after processing a single batch of files.
        """
        pass

    def extract(
        self, identifier: str, matched_fname: str, current_meta: Metadata
    ) -> Metadata:
        """Extracts metadata for matched path.

        Intended to be overridden by plugin, if is_extractor is True.

        :param identifier: File identifier returned by overridable
                           :py:meth:`MetadataPlugin.identify` method
        :param matched_fname: Matched file path
        :param current_meta: Metadata extracted so far by dependencies
        :return: Metadata object. If you can't extract metadata for current file,
                 return empty dict.
        """
        raise NotImplementedError
