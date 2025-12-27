from typing import List, Dict, Callable, Any
from nullpeas.core.report import Report

# Registry list to hold module metadata and entrypoints
_MODULE_REGISTRY = []


def register_module(
    key: str, description: str, required_triggers: List[str] = None
):
    """
    Decorator to register a module.
    
    We use explicit registration rather than auto-discovery to ensure 
    compatibility with Nuitka/PyInstaller compilation.
    """

    def decorator(func: Callable[[Dict[str, Any], Report], None]):
        _MODULE_REGISTRY.append(
            {
                "key": key,
                "description": description,
                "required_triggers": required_triggers or [],
                "run": func,
            }
        )
        return func

    return decorator


def get_available_modules(triggers: Dict[str, bool]) -> List[Dict[str, Any]]:
    """
    Returns a list of modules that should run based on the current triggers.
    """
    available = []
    for mod in _MODULE_REGISTRY:
        reqs = mod["required_triggers"]
        # If no requirements, it always runs (or could be manual-only).
        if not reqs:
            available.append(mod)
            continue

        # Check if ALL required triggers are True
        if all(triggers.get(r) for r in reqs):
            available.append(mod)

    return available


# =============================================================================
# EXPLICIT IMPORTS (WIRED IN)
# =============================================================================
from . import sudo_enum_module
from . import cron_enum_module
from . import docker_enum
from . import systemd_module
from . import suid_module
from . import path_enum_module
