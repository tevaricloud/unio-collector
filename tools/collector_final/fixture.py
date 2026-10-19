"""Combine actual conditional producer observations without hand-written evidence DTOs."""

from __future__ import annotations

from typing import Any

from tools.collector_attribution.flow import flow_producer_observation
from tools.collector_attribution.tagging import tagging_producer_observation
from tools.collector_commitment.fixture import commitment_producer_observation
from tools.collector_edge.fixture import COLLECTORS, edge_producer_observation
from tools.collector_sdk_fixture import add_wrapper_observation


def final_producer_observations() -> dict[str, dict[str, Any]]:
    """Return the same populated actual shapes used by regression and packaged smoke."""
    observed = {scanner: edge_producer_observation(scanner, "metrics" if "cost-review" in scanner else "success") for scanner in COLLECTORS}
    alb = observed["cloudfront-alb-origin-protection-review"]
    vpc = edge_producer_observation("cloudfront-alb-origin-protection-review", "vpc")
    for key in (
        "cloudfront_origins",
        "load_balancers",
        "listeners",
        "listener_rules",
        "vpc_origins",
        "header_verifications",
        "coverage",
        "security_group_rules",
        "waf_associations",
    ):
        alb["evidence"]["payload"][key].extend(vpc["evidence"]["payload"][key])
    tagging = tagging_producer_observation()
    tagging["execution"]["coverage_notes"].extend(tagging_producer_observation("partial")["execution"]["coverage_notes"])
    observed["tagging-missing-cost-tags"] = tagging
    observed["vpc-flow-log-attribution"] = flow_producer_observation()
    portfolio = commitment_producer_observation("groups")
    payload = portfolio["evidence"]["payload"]["portfolio"]
    for variant in ("nullable", "partial", "malformed_numeric"):
        actual = commitment_producer_observation(variant)["evidence"]["payload"]["portfolio"]
        payload["inventory"].extend(actual["inventory"])
        payload["observed_metrics"].extend(actual["observed_metrics"])
        payload["source_outcomes"].extend(actual["source_outcomes"])
    observed["commitment-and-pricing-review"] = portfolio
    return observed


def add_final_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Enrich the real collected fixture with full edge, topology, tag and portfolio shapes."""
    observed = final_producer_observations()
    if unknown:
        observed["cloudfront-alb-origin-protection-review"]["evidence"]["payload"]["listener_rules"][0]["unknown_edge_control"] = None
        observed["cloudfront-origin-cost-review"]["evidence"]["payload"]["records"][0]["unknown_edge_cost"] = None
        observed["tagging-missing-cost-tags"]["evidence"]["payload"]["records"][0]["unknown_tagging_control"] = None
        observed["vpc-flow-log-attribution"]["evidence"]["payload"]["metadata"]["topology"]["eu-west-2"]["facts"][0]["unknown_flow_fact"] = None
        observed["commitment-and-pricing-review"]["evidence"]["payload"]["portfolio"]["inventory"][0]["payment"]["unknown_commitment_control"] = None
    for row in observed.values():
        add_wrapper_observation(files, row)
