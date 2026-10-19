"""Ordered closed-note preflight without changing transformation state semantics."""

from unio_collector.privacy.backup.notes import unknown_backup_notes
from unio_collector.privacy.billing.notes import unknown_billing_notes
from unio_collector.privacy.cache.preflight import CacheNotePreflight
from unio_collector.privacy.dynamodb.notes import unknown_dynamo_notes
from unio_collector.privacy.ec2.notes import unknown_compute_notes
from unio_collector.privacy.edge.notes import unknown_edge_notes
from unio_collector.privacy.exposure.notes import unknown_exposure_notes
from unio_collector.privacy.identity.notes import unknown_identity_notes
from unio_collector.privacy.inventory_notes import unknown_inventory_notes
from unio_collector.privacy.platform.notes import unknown_managed_notes
from unio_collector.privacy.serverless.notes import unknown_polling_notes
from unio_collector.privacy.tagging.notes import unknown_tagging_notes


class NotePreflight:
    """Retain each explicit owner check, append ordering and partial failure state."""

    @staticmethod
    def append_failures(value: object, member: str, failures: list[str]) -> None:
        """Append each owner's findings before invoking the next unchanged check."""
        scoped = CacheNotePreflight.partition(value, member, failures)
        for check in (
            unknown_tagging_notes,
            unknown_edge_notes,
            unknown_dynamo_notes,
            unknown_backup_notes,
            unknown_polling_notes,
            unknown_compute_notes,
            unknown_identity_notes,
            unknown_inventory_notes,
            unknown_managed_notes,
            unknown_exposure_notes,
            unknown_billing_notes,
        ):
            failures.extend(check(scoped, member))
