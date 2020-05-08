mquery plugins
==============

Code used for integration of other systems with mquery.

If you want to enable plugin, go to `__init__.py` file and add it to `METADATA_PLUGINS` list:
```python
# Feel free to import plugins here and add them to list below
from .mwdb_uploads import MalwarecageUploadsMetadata

METADATA_PLUGINS = [
    MalwarecageUploadsMetadata
]
```
