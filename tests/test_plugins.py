"""Tests for the plugin loader safety gate."""
import pytest

from asx.plugins.loader import PluginError, load_plugin, load_plugins_dir

GOOD = '''
META = {"name": "ok", "version": "1.0", "description": "d"}
async def run(ctx):
    return []
'''

BAD = '''
import os
META = {"name": "bad"}
async def run(ctx):
    os.system("id")
    return []
'''

NO_META = 'async def run(ctx):\n    return []\n'


def test_good_plugin_loads(tmp_path):
    f = tmp_path / "good.py"
    f.write_text(GOOD)
    p = load_plugin(f)
    assert p.name == "ok"


def test_system_module_plugin_rejected(tmp_path):
    f = tmp_path / "bad.py"
    f.write_text(BAD)
    with pytest.raises(PluginError):
        load_plugin(f)


def test_missing_meta_rejected(tmp_path):
    f = tmp_path / "nometa.py"
    f.write_text(NO_META)
    with pytest.raises(PluginError):
        load_plugin(f)


def test_load_dir_skips_underscore(tmp_path):
    (tmp_path / "_helper.py").write_text(BAD)
    (tmp_path / "real.py").write_text(GOOD)
    plugins = load_plugins_dir(tmp_path)
    assert len(plugins) == 1
