from typing import List, Type
from metadata import MetadataPlugin
from importlib import import_module


def parse_plugin_list(plugins: str) -> List[str]:
    """Parses and validates a plugin list into a list of non-empty components
    divided by `,`.

    >>> parse_plugin_list("plugins.Test, plugins.Other")
    ["plugins.Test", "plugins.Other"]

    >>> parse_plugin_list("")
    []

    :param plugins: String with a list of comma separated plugins
    :return: List of plugins, with no unnecessary spaces.
    """
    result = []
    for desc in plugins.split(","):
        desc = desc.strip()
        if not desc:
            continue
        assert ":" in desc
        result.append(desc)
    return result


def load_plugins(specs: List[str]) -> List[Type[MetadataPlugin]]:
    result = []
    for spec in specs:
        module, classname = spec.split(":")
        moduleobj = import_module(module)
        result.append(getattr(moduleobj, classname))
    return result
