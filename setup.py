"""
Setup script for ActiveDirectoryMCP.

This file is used for backward compatibility with older build systems.
Modern builds should use pyproject.toml configuration.
"""

from setuptools import setup, find_packages

setup(
    name="active-directory-mcp",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.11",
)
