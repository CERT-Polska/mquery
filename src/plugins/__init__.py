from typing import List, Type
from metadata import MetadataPlugin

from .example_plugin import ExampleTagPlugin

# Feel free to import plugins here and add them to list below
METADATA_PLUGINS: List[Type[MetadataPlugin]] = [ExampleTagPlugin]
