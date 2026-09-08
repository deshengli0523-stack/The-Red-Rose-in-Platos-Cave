"""Single source for installed distribution version metadata."""

from importlib import metadata


UNINSTALLED_VERSION = "0.0.0+uninstalled"


def distribution_version() -> str:
    """Return the ``graphifyy`` distribution version or a source-tree fallback."""
    try:
        return metadata.version("graphifyy")
    except metadata.PackageNotFoundError:
        return UNINSTALLED_VERSION
