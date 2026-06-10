"""Smoke tests — verify package imports and exposes expected API."""

import reconfox


def test_version_exposed() -> None:
    assert hasattr(reconfox, "__version__")
    assert isinstance(reconfox.__version__, str)
    assert reconfox.__version__.count(".") == 2


def test_cli_main_callable() -> None:
    from reconfox.cli import main

    assert callable(main)
