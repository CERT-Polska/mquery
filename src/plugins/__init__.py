from typing import List, Type
from metadata import MetadataPlugin
from .blacklist import RegexBlacklistPlugin

# Feel free to import plugins here and add them to list below
METADATA_PLUGINS: List[Type[MetadataPlugin]] = [RegexBlacklistPlugin]
