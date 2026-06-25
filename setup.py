"""Compatibility shim.

All project metadata lives in ``pyproject.toml`` (PEP 621). This file exists only
so that legacy tooling and ``pip install -e .`` on older toolchains keep working;
``setuptools.setup()`` reads its configuration from ``pyproject.toml``.
"""

from setuptools import setup

setup()
