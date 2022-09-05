from typing import List, Type, Optional
from metadata import MetadataPlugin
from importlib import import_module
from db import Database
import logging


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


class PluginManager:
    def __init__(self, specs: List[str], db: Database) -> None:
        self.plugin_classes = load_plugins(specs)

        active_plugins = []
        for plugin_class in self.plugin_classes:
            plugin_name = plugin_class.get_name()
            plugin_config = db.get_plugin_config(plugin_name)
            try:
                active_plugins.append(plugin_class(db, plugin_config))
                logging.info("Loaded plugin %s", plugin_name)
            except Exception:
                logging.exception("Failed to load %s plugin", plugin_name)
        self.active_plugins = active_plugins

    def filter(self, orig_name: str) -> Optional[str]:
        """ Runs all available filter plugins on the provided file.
        Returns new file path, or None. User should call cleanup() later. """
        current_path: Optional[str] = orig_name
        for plugin in self.active_plugins:
            if not plugin.is_filter:
                continue
            if current_path:
                current_path = plugin.filter(orig_name, current_path)
        return current_path

    def cleanup(self) -> None:
        for plugin in self.active_plugins:
            plugin.cleanup()
