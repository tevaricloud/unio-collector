"""Registered historical RDS identities retain actual-producer privacy compatibility."""

from __future__ import annotations

import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_rds.fixture import COLLECTORS, rds_producer_observation
from unio_collector.privacy.rds.instance import RdsInstancePrivacyContract
from unio_collector.privacy.rds.snapshot import RdsSnapshotPrivacyContract

pytestmark = pytest.mark.offline
CONTRACTS = {RdsInstancePrivacyContract.scanner_id: RdsInstancePrivacyContract, RdsSnapshotPrivacyContract.scanner_id: RdsSnapshotPrivacyContract}


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_registered_legacy_rds_identity_uses_actual_serialized_shape(scanner: str, profile: str) -> None:
    """No manually simplified DTO replaces the current populated producer output."""
    row = json.loads(json.dumps(rds_producer_observation(scanner)["evidence"]))
    row["evidence_module"] = "unio_collector.scanners.fixture_parity.synthetic_types"
    row["evidence_type"] = CONTRACTS[scanner].fixture_type
    operation = transformer(profile)
    result = operation.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not operation.summary.unclassified
    encoded = json.dumps(result)
    assert "synthetic-customer" not in encoded
    assert "123456789012" not in encoded
    assert len(result["scanner_evidence"][0]["payload"]["records"]) == len(row["payload"]["records"])
