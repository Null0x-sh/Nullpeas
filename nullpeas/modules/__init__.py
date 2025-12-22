# nullpeas/modules/__init__.py

from typing import Callable, Dict, Any, List
import pkgutil
import importlib
from pathlib import Path

# Simple module record type:
# {
#   "key": "sudo_enum",
#   "description": "...",
#   "required_triggers": ["sudo_privesc_surface"],
#   "run": <callable>
# }
_MODULE_REGISTRY: Dict[str, Dict[str, Any]] = {}
_DISCOVERED = False


def register_module(
    key: str,
    description: str,
    required_triggers: List[str],
) -> Callable:
    """
    Decorator for modules to self-register.

    Usage in a module:
        @register_module(
            key="sudo_enum",
            description="Analyse sudo -l and GTFOBins correlation",
            required_triggers=["sudo_privesc_surface"],
        )
        def run(state, report):
            ...
    """

    def decorator(func: Callable):
        _MODULE_REGISTRY[key] = {
            "key": key,
            "description": description,
            "required_triggers": required_triggers,
            "run": func,
        }
        return func

    return decorator


def _ensure_discovered():
    """
    Auto-import all *_module.py files in this package once,
    so their @register_module decorators run and populate the registry.
    """
    global _DISCOVERED
    if _DISCOVERED:
        return

    package_name = __name__
    package_path = Path(__file__).parent

    for module_info in pkgutil.iter_modules([str(package_path)]):
        # Only import files that look like modules, e.g. sudo_enum_module.py
        if not module_info.name.endswith("_module"):
            continue
        importlib.import_module(f"{package_name}.{module_info.name}")

    _DISCOVERED = True


def get_available_modules(triggers: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Return a list of module records that are applicable for the given triggers.
    required_triggers is treated as "all must be True" in the trigger dict.
    """
    _ensure_discovered()

    options: List[Dict[str, Any]] = []
    for mod in _MODULE_REGISTRY.values():
        reqs = mod.get("required_triggers") or []
        if all(triggers.get(t, False) for t in reqs):
            options.append(mod)

    # Consistent order
    options.sort(key=lambda m: m["key"])
    return options


def list_all_modules() -> List[Dict[str, Any]]:
    """
    Return all known modules (regardless of triggers).
    Useful for debugging or a future '--list-modules' CLI.
    """
    _ensure_discovered()
    return sorted(_MODULE_REGISTRY.values(), key=lambda m: m["key"])
