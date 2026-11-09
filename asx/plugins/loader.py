"""Plugin loader with a safety gate.

Refuses to load any plugin whose source imports process/system modules.
This is a policy check, not a security boundary — do not run plugins
you do not trust."""
from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass
from pathlib import Path

BANNED = re.compile(r"^\s*(import|from)\s+(os|subprocess|socket|ctypes|shutil|pty|signal)\b", re.M)


class PluginError(Exception):
    pass


@dataclass
class LoadedPlugin:
    name: str
    version: str
    description: str
    path: Path
    module: object

    async def run(self, ctx):
        return await self.module.run(ctx)  # type: ignore[attr-defined]


def load_plugin(path: str | Path) -> LoadedPlugin:
    path = Path(path)
    source = path.read_text(encoding="utf-8")
    if BANNED.search(source):
        raise PluginError(
            f"Plugin '{path.name}' imports banned system modules (os/subprocess/socket/...). "
            "Plugins must be passive and non-destructive."
        )
    spec = importlib.util.spec_from_file_location(f"asx_plugin_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise PluginError(f"Cannot load plugin from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    meta = getattr(module, "META", None)
    if not isinstance(meta, dict) or "name" not in meta:
        raise PluginError(f"Plugin '{path.name}' missing META dict with at least a 'name'.")
    if not callable(getattr(module, "run", None)):
        raise PluginError(f"Plugin '{path.name}' must define `async def run(ctx)`.")
    return LoadedPlugin(
        name=str(meta["name"]),
        version=str(meta.get("version", "0.0.0")),
        description=str(meta.get("description", "")),
        path=path,
        module=module,
    )


def load_plugins_dir(directory: str | Path) -> list[LoadedPlugin]:
    directory = Path(directory)
    plugins: list[LoadedPlugin] = []
    if not directory.is_dir():
        return plugins
    for file in sorted(directory.glob("*.py")):
        if file.name.startswith("_"):
            continue
        plugins.append(load_plugin(file))
    return plugins
