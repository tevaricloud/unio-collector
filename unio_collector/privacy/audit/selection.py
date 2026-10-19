"""Selection of exact reviewed execution and configured-limit producer notes."""

from __future__ import annotations

from typing import Any

from unio_collector.privacy.audit.governance.limit import GovernanceLimitContract
from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.backup.notes import BackupNoteContract
from unio_collector.privacy.billing.notes import BillingNoteContract
from unio_collector.privacy.cache.notes import CacheNoteContract
from unio_collector.privacy.dynamodb.notes import DynamoNoteContract
from unio_collector.privacy.ec2.notes import ComputeLimitNoteContract
from unio_collector.privacy.edge.notes import EdgeNoteContract
from unio_collector.privacy.exposure.notes import EcrNoteContract
from unio_collector.privacy.identity.notes import IdentityNoteContract
from unio_collector.privacy.inventory_notes import InventoryNoteContract
from unio_collector.privacy.platform.notes import ManagedNoteContract
from unio_collector.privacy.serverless.notes import PollingNoteContract
from unio_collector.privacy.tagging.notes import TaggingNoteContract


def select_audit_note(value: dict[str, Any]) -> AuditNoteContract | None:
    """Admit only enumerated note identities, without importing producer implementations."""
    return (
        TaggingNoteContract.for_note(value)
        or EdgeNoteContract.for_note(value)
        or DynamoNoteContract.for_note(value)
        or BackupNoteContract.for_note(value)
        or PollingNoteContract.for_note(value)
        or CacheNoteContract.for_note(value)
        or ManagedNoteContract.for_note(value)
        or InventoryNoteContract.for_note(value)
        or ComputeLimitNoteContract.for_note(value)
        or BillingNoteContract.for_note(value)
        or EcrNoteContract.for_note(value)
        or AuditNoteContract.for_note(value)
        or GovernanceLimitContract.for_note(value)
        or IdentityNoteContract.for_note(value)
    )
