"""Numeric reason codes for incomplete CloudWatch provider reads."""

from enum import IntEnum


class MetricReadReason(IntEnum):
    """Identify read limitations without carrying provider messages or identifiers."""

    MISSING_RESULT = 1
    INCOMPLETE_RESPONSE = 2
    MALFORMED_RESULT = 3
    DUPLICATE_RESULT = 4
    PROVIDER_RESULT_UNAVAILABLE = 5
    MALFORMED_SAMPLES = 6
    PARTIAL_PROVIDER_DATA = 7
    MISSING_DATAPOINTS = 8
    MALFORMED_DATAPOINT = 9
    INVALID_NUMERIC_VALUE = 10
    UNREPRESENTABLE_AGGREGATE = 11
    READ_FAILED = 12
