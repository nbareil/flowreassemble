"""Sphinx configuration. Build with ``make docs``."""

from importlib.metadata import version as _version

project = "flowreassemble"
author = "Nicolas Bareil"
copyright = "2026, Nicolas Bareil"
release = _version("flowreassemble")
version = ".".join(release.split(".")[:2])

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
]
exclude_patterns = ["_build"]

myst_heading_anchors = 3

autodoc_default_options = {"members": True, "undoc-members": True}
autodoc_member_order = "bysource"
# Types go on the fields and in the parameter lists, not in signatures.
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented_params"

intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

html_theme = "furo"
html_title = f"flowreassemble {release}"
