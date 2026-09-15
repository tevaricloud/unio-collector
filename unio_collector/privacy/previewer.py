from __future__ import annotations  # noqa: D100

# ruff: noqa: SLF001
from typing import TYPE_CHECKING

from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.privacy.archive_scan import scan_provisional_archive
from unio_collector.privacy.bundle import ProtectedBundleProtector
from unio_collector.privacy.constants import PRIVACY_PREVIEW_SCHEMA_VERSION
from unio_collector.privacy.known_originals import collect_known_original_values
from unio_collector.privacy.options import PrivacyProtectOptions
from unio_collector.privacy.profiles import load_privacy_profile
from unio_collector.privacy.source_identity import derive_source_bundle_identity

if TYPE_CHECKING:
    from unio_collector.privacy.preview_options import PrivacyPreviewOptions


class PrivacyPreviewer:
    """Classify and transform a bundle entirely in memory."""

    def preview(self, options: PrivacyPreviewOptions) -> dict[str, object]:
        """Return a non-secret simulation without publishing artifacts."""
        EvidenceBundleValidator().validate_or_raise(options.bundle_path)
        source = derive_source_bundle_identity(options.bundle_path)
        protector = ProtectedBundleProtector()
        protect_options = PrivacyProtectOptions(
            bundle_path=options.bundle_path,
            output_path=options.bundle_path.parent / ".privacy-preview-unused.zip",
            vault_path=options.bundle_path.parent / ".privacy-preview-unused-vault.json",
            profile_id=options.profile_id,
            token_scope=options.token_scope,
            engagement_id=options.engagement_id,
            client_id=options.client_id,
            allow_unknown_fields=options.allow_unknown_fields,
            acknowledge_vault_loss_risk=True,
            existing_vault_path=options.existing_vault_path,
            existing_recovery_key_path=options.existing_recovery_key_path,
            passphrase=options.passphrase,
        )
        profile = load_privacy_profile(
            options.profile_id,
            token_scope=options.token_scope,
            allow_unknown_fields=options.allow_unknown_fields,
        )
        state = protector._build_state(
            protect_options,
            profile,
            source_bundle_id=source.value,
            protected_bundle_id="preview-only",
        )
        files, _manifest = protector._read_and_transform_files(options.bundle_path, state)
        known_originals = collect_known_original_values(state.token_service, minimum_length=4)
        leak_scan = scan_provisional_archive(files, known_original_values=known_originals)
        token_count = len(state.token_service.vault_builder.entries_by_token)
        return {
            "schema_version": PRIVACY_PREVIEW_SCHEMA_VERSION,
            "mode": "preview_only",
            "source_bundle_id": source.value,
            "source_bundle_id_scheme": source.scheme,
            "profile": profile.convert_to_dict(),
            "token_scope": options.token_scope,
            "tokenised_categories": dict(sorted(state.classification.tokenised.items())),
            "token_count": token_count,
            "reused_token_count": state.token_service.reused_token_count,
            "new_token_count": state.token_service.new_token_count,
            "removed_count": state.classification.removed,
            "preserved_count": state.classification.preserved,
            "unclassified_field_count": len(state.classification.unclassified),
            "unclassified_fields": list(state.classification.unclassified),
            "prohibited_field_count": len(state.classification.prohibited_paths),
            "prohibited_paths": list(state.classification.prohibited_paths),
            "actual_applied_transformations": state.classification.applied_transformations(),
            "resolver_decisions": state.classification.resolver_decisions(),
            "leak_risk": leak_scan,
            "limitations": [
                "Preview uses an in-memory transformation and does not create a protected export.",
                "Pattern-based leak analysis cannot prove that all contextual sensitivity is removed.",
            ],
            "artifacts_written": [],
        }
