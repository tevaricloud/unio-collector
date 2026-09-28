"""Collector-side recipient-encrypted transport command."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.collector_cli.console import print_success
from unio_collector.transport.encryptor import TransportPackageEncryptor

if TYPE_CHECKING:
    import argparse

    from unio_collector.core.console_like import ConsoleLike


class CollectorTransportService:
    """Validate and encrypt one transferable evidence archive."""

    def __init__(self, console: ConsoleLike) -> None:
        """Store the collector output surface."""
        self.console = console

    def run(self, args: argparse.Namespace) -> int:
        """Run the additive ``encrypt-bundle`` workflow."""
        bundle_path = Path(args.bundle)
        EvidenceBundleValidator().validate_or_raise(bundle_path)
        result = TransportPackageEncryptor().encrypt(
            bundle_path=bundle_path,
            output_path=Path(args.output),
            recipient_public_key_path=Path(args.recipient_public_key),
            recipient_key_id=args.recipient_key_id,
            overwrite=bool(args.overwrite),
        )
        payload = {
            "status": "encrypted",
            "schema_version": result.schema_version,
            "encryption_algorithm": result.encryption_algorithm,
            "key_wrap_algorithm": result.key_wrap_algorithm,
            "recipient_key_id": result.recipient_key_id,
            "payload_size": result.payload_size,
        }
        if args.json:
            self.console.print(json.dumps(payload, sort_keys=True))
        else:
            print_success(self.console, f"Encrypted transport package written: {args.output}")
            self.console.print(
                f"Recipient key: {result.recipient_key_id}; algorithms: {result.encryption_algorithm} / {result.key_wrap_algorithm}",
            )
        return 0


__all__ = ["CollectorTransportService"]
