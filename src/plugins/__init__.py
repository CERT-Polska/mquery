from typing import List, Type
from metadata import MetadataPlugin
from importlib import import_module


def load_plugins(specs: List[str]) -> List[Type[MetadataPlugin]]:
    result = []
    for spec in specs:
        module, classname = spec.split(":")
        moduleobj = import_module(module)
        result.append(getattr(moduleobj, classname))
    return result
