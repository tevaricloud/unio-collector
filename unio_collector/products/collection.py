"""Collection-safe product identity and scanner-selection contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Never, get_args

from unio_collector.products.scanner_sets import (
    CUSTEX_SCANNERS,
    ITERO_SCANNERS,
    MONETA_SCANNERS,
    VETO_SCANNERS,
)
from unio_collector.scanners.registry.definitions import SCANNERS

type ProductId = Literal["moneta", "custex", "veto", "itero"]
type ProductProviderId = Literal["aws"]

COLLECTION_PRODUCT_REGISTRY_VERSION = "1"


@dataclass(frozen=True)
class CollectionProductDefinition:
    """Immutable product fields required by evidence collection."""

    product_id: ProductId
    definition_version: str
    supported_provider_ids: tuple[ProductProviderId, ...]
    default_scanner_ids: tuple[str, ...]
    optional_scanner_ids: tuple[str, ...]

    @property
    def allowed_scanner_ids(self) -> tuple[str, ...]:
        """Return every scanner declared by this collection contract."""
        return (*self.default_scanner_ids, *self.optional_scanner_ids)


MONETA_COLLECTION_PRODUCT = CollectionProductDefinition(
    product_id="moneta",
    definition_version="1",
    supported_provider_ids=("aws",),
    default_scanner_ids=MONETA_SCANNERS,
    optional_scanner_ids=(
        "cur-data-export-attribution",
        "kms-cost-governance-review",
        "secrets-manager-cost-governance-review",
    ),
)
CUSTEX_COLLECTION_PRODUCT = CollectionProductDefinition(
    product_id="custex",
    definition_version="1",
    supported_provider_ids=("aws",),
    default_scanner_ids=CUSTEX_SCANNERS,
    optional_scanner_ids=("vpc-flow-log-attribution",),
)
VETO_COLLECTION_PRODUCT = CollectionProductDefinition(
    product_id="veto",
    definition_version="1",
    supported_provider_ids=("aws",),
    default_scanner_ids=VETO_SCANNERS,
    optional_scanner_ids=(
        "cur-data-export-attribution",
        "kms-cost-governance-review",
        "secrets-manager-cost-governance-review",
        "vpc-flow-log-attribution",
    ),
)
ITERO_COLLECTION_PRODUCT = CollectionProductDefinition(
    product_id="itero",
    definition_version="1",
    supported_provider_ids=("aws",),
    default_scanner_ids=ITERO_SCANNERS,
    optional_scanner_ids=(),
)

COLLECTION_PRODUCT_DEFINITIONS = (
    MONETA_COLLECTION_PRODUCT,
    CUSTEX_COLLECTION_PRODUCT,
    VETO_COLLECTION_PRODUCT,
    ITERO_COLLECTION_PRODUCT,
)


def validate_collection_product_definitions(
    definitions: tuple[CollectionProductDefinition, ...],
    *,
    product_id_alternatives: tuple[str, ...] | None = None,
) -> None:
    """Fail closed when collection product definitions are inconsistent."""
    ids = [item.product_id for item in definitions]
    if len(ids) != len(set(ids)):
        _raise_collection_product_error("Product IDs must be unique.")
    alternatives = _product_id_alternatives() if product_id_alternatives is None else product_id_alternatives
    if tuple(ids) != alternatives:
        _raise_collection_product_error(
            "ProductId alternatives must match collection product definitions.",
        )
    for item in definitions:
        if not item.definition_version.strip():
            _raise_collection_product_error(
                f"Product {item.product_id} has no definition version.",
            )
        if item.supported_provider_ids != ("aws",):
            _raise_collection_product_error(
                f"Product {item.product_id} must be AWS-only.",
            )
        defaults = set(item.default_scanner_ids)
        optional = set(item.optional_scanner_ids)
        if defaults & optional:
            _raise_collection_product_error(
                f"Product {item.product_id} default and optional scanners overlap.",
            )
        unknown = sorted((defaults | optional) - set(SCANNERS))
        if unknown:
            _raise_collection_product_error(
                f"Product {item.product_id} references unknown scanners: {', '.join(unknown)}.",
            )


def get_collection_product(
    product_id: ProductId | str,
) -> CollectionProductDefinition:
    """Return one registered collection product definition."""
    for definition in COLLECTION_PRODUCT_DEFINITIONS:
        if definition.product_id == product_id:
            return definition
    allowed = ", ".join(item.product_id for item in COLLECTION_PRODUCT_DEFINITIONS)
    msg = f"Unknown product ID: {product_id}. Allowed: {allowed}."
    raise ValueError(msg)


def _product_id_alternatives() -> tuple[str, ...]:
    value = getattr(ProductId, "__value__", ProductId)
    return tuple(str(item) for item in get_args(value))


def _raise_collection_product_error(message: str) -> Never:
    raise ValueError(message)


validate_collection_product_definitions(COLLECTION_PRODUCT_DEFINITIONS)

__all__ = [
    "COLLECTION_PRODUCT_DEFINITIONS",
    "COLLECTION_PRODUCT_REGISTRY_VERSION",
    "CUSTEX_COLLECTION_PRODUCT",
    "ITERO_COLLECTION_PRODUCT",
    "MONETA_COLLECTION_PRODUCT",
    "VETO_COLLECTION_PRODUCT",
    "CollectionProductDefinition",
    "ProductId",
    "ProductProviderId",
    "get_collection_product",
    "validate_collection_product_definitions",
]
