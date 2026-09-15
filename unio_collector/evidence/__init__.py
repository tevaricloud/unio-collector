"""Neutral evidence storage with a deferred application compatibility facade.

Internal collection code imports collection_store directly. The EvidenceStore
application export remains until its finding-projection API is retired through
a documented compatibility release.
"""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from unio_collector.evidence.collection_store import CollectionEvidenceStore
from unio_collector.evidence.models import EvidenceRecord

if TYPE_CHECKING:
    from unio_collector.evidence.store import EvidenceStore

_EXPORTS = {"EvidenceStore": ("unio_collector.evidence.store", "EvidenceStore")}

__all__ = ["CollectionEvidenceStore", "EvidenceRecord", "EvidenceStore"]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve only explicitly requested legacy application exports."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        message = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(message) from exc
    return getattr(import_module(module_name), attribute_name)
