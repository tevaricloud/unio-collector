from __future__ import annotations  # noqa: D100

import time
from dataclasses import replace
from threading import Lock
from typing import TYPE_CHECKING, Any, TypeVar

from unio_collector.aws.cache.access import AwsScanCacheAccess
from unio_collector.aws.cache.consumer_stats import AwsScanCacheConsumerStats
from unio_collector.aws.cache.entry import CacheEntry
from unio_collector.aws.cache.errors import (
    AwsScanCacheCancelledError,
    AwsScanCacheDeadlineExceededError,
    AwsScanCacheGenerationSupersededError,
    AwsScanCacheLoadError,
    AwsScanCacheWaitTimeoutError,
)
from unio_collector.aws.cache.failure import CacheFailureSnapshot, DefaultCacheFailureClassifier
from unio_collector.aws.cache.key import AwsScanCacheKey
from unio_collector.aws.cache.policy import AwsScanCacheAccessPolicy
from unio_collector.aws.cache.stats import AwsScanCacheStats
from unio_collector.aws.cache.wait_behavior import CacheWaitTimeoutBehavior

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import NoReturn

    from unio_collector.aws.cache.types import CacheAccessStatus

T = TypeVar("T")

_CANCELLATION_POLL_SECONDS = 0.05


class AwsScanCache:
    """Thread-safe scan-level cache for repeatable AWS read results."""

    def __init__(self) -> None:  # noqa: D107
        self._lock = Lock()
        self._entries: dict[AwsScanCacheKey, CacheEntry[object]] = {}
        self._namespace_stats: dict[str, AwsScanCacheStats] = {}
        self._consumer_stats: dict[str, AwsScanCacheConsumerStats] = {}
        self._next_generation = 1

    def get_or_load(  # noqa: D102
        self,
        namespace: str,
        parts: tuple[object, ...],
        loader: Callable[[], T],
        *,
        consumer_id: str | None = None,
        access_policy: AwsScanCacheAccessPolicy | None = None,
    ) -> T:
        return self.get_or_load_with_status(
            namespace,
            parts,
            loader,
            consumer_id=consumer_id,
            access_policy=access_policy,
        ).value

    def get_or_load_with_status(  # noqa: D102
        self,
        namespace: str,
        parts: tuple[object, ...],
        loader: Callable[[], T],
        *,
        consumer_id: str | None = None,
        access_policy: AwsScanCacheAccessPolicy | None = None,
    ) -> AwsScanCacheAccess[T]:
        policy = self._resolve_access_policy(
            consumer_id=consumer_id,
            access_policy=access_policy,
        )
        key = self._build_key(namespace, parts)
        entry, should_load, status = self._begin_access(key, policy)
        if should_load:
            return self._load_for_consumer(key, entry, loader, policy)

        replacement_owner = False
        try:
            wait_completed = self._wait_for_entry(entry, policy)
            if not wait_completed or entry.abandoned:
                if policy.wait_timeout_behavior is CacheWaitTimeoutBehavior.RAISE:
                    self._raise_wait_timeout(key, policy)
                replacement, owns_replacement = self._claim_replacement(
                    key,
                    entry,
                    policy,
                )
                if replacement is None:
                    self._raise_wait_timeout(key, policy)
                if owns_replacement:
                    replacement_owner = True
                    return self._load_for_consumer(
                        key,
                        replacement,
                        loader,
                        policy,
                    )
                entry = replacement
            return self._consume_entry(key, entry, status, policy)
        except BaseException:
            if not replacement_owner:
                self._record_consumer_error(policy.consumer_id, namespace)
            raise

    def get_existing_with_status(  # noqa: D102
        self,
        namespace: str,
        parts: tuple[object, ...],
        *,
        consumer_id: str | None = None,
        access_policy: AwsScanCacheAccessPolicy | None = None,
    ) -> AwsScanCacheAccess[Any] | None:
        policy = self._resolve_access_policy(
            consumer_id=consumer_id,
            access_policy=access_policy,
        )
        key = self._build_key(namespace, parts)
        with self._lock:
            self._get_stats(key.namespace).request_count += 1
            entry = self._entries.get(key)
            if entry is None:
                return None
            status = self._record_wait_or_hit_locked(key, entry)
        try:
            if status == "waited":
                wait_completed = self._wait_for_entry(entry, policy)
                if not wait_completed:
                    if policy.wait_timeout_behavior is CacheWaitTimeoutBehavior.RAISE:
                        self._raise_wait_timeout(key, policy)
                    self._abandon_if_current(key, entry)
                    return None
                if entry.abandoned:
                    return None
            return self._consume_entry(key, entry, status, policy)
        except BaseException:
            self._record_consumer_error(policy.consumer_id, namespace)
            raise

    def discard(self, namespace: str, parts: tuple[object, ...]) -> None:  # noqa: D102
        key = self._build_key(namespace, parts)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return
            entry.abandoned = True
            entry.event.set()
            self._remove_entry_locked(key, entry)

    def _begin_access(
        self,
        key: AwsScanCacheKey,
        policy: AwsScanCacheAccessPolicy,
    ) -> tuple[CacheEntry[object], bool, CacheAccessStatus]:
        with self._lock:
            stats = self._get_stats(key.namespace)
            stats.request_count += 1
            existing = self._entries.get(key)
            if existing is None:
                return self._create_entry_locked(key, policy), True, "loaded"
            if existing.loaded:
                stats.hit_count += 1
                return existing, False, "hit"
            stats.wait_count += 1
            return existing, False, "waited"

    def _create_entry_locked(
        self,
        key: AwsScanCacheKey,
        policy: AwsScanCacheAccessPolicy,
    ) -> CacheEntry[object]:
        generation = self._next_generation
        self._next_generation += 1
        owner_id = policy.attempt_id or policy.consumer_id or "anonymous"
        entry: CacheEntry[object] = CacheEntry(
            generation=generation,
            owner_id=owner_id,
        )
        self._entries[key] = entry
        stats = self._get_stats(key.namespace)
        stats.miss_count += 1
        stats.key_count += 1
        return entry

    def _load_for_consumer(
        self,
        key: AwsScanCacheKey,
        entry: CacheEntry[object],
        loader: Callable[[], T],
        policy: AwsScanCacheAccessPolicy,
    ) -> AwsScanCacheAccess[T]:
        try:
            value = self._load_entry(key, entry, loader, policy)
        except BaseException:
            self._record_consumer_error(policy.consumer_id, key.namespace)
            raise
        self._record_consumer_status(
            policy.consumer_id,
            key.namespace,
            "loaded",
        )
        return AwsScanCacheAccess(value=value, status="loaded", key=key)

    def _load_entry(
        self,
        key: AwsScanCacheKey,
        entry: CacheEntry[object],
        loader: Callable[[], T],
        policy: AwsScanCacheAccessPolicy,
    ) -> T:
        stopped = self._get_access_stop_error(policy)
        if stopped is not None:
            self._abandon_if_current(key, entry)
            raise stopped
        try:
            value = loader()
        except BaseException as exc:
            self._publish_failure(key, entry, exc, policy)
            raise

        with self._lock:
            stopped = self._get_access_stop_error(policy)
            if self._entries.get(key) is not entry or entry.abandoned:
                raise self._build_superseded_error(key, entry)
            if stopped is not None:
                entry.abandoned = True
                entry.event.set()
                self._remove_entry_locked(key, entry)
                raise stopped
            entry.value = value
            entry.loaded = True
            entry.event.set()
        return value

    def _publish_failure(
        self,
        key: AwsScanCacheKey,
        entry: CacheEntry[object],
        error: BaseException,
        policy: AwsScanCacheAccessPolicy,
    ) -> None:
        try:
            decision = policy.failure_classifier.classify(error)
        except Exception:  # noqa: BLE001
            decision = DefaultCacheFailureClassifier().classify(error)
        snapshot = CacheFailureSnapshot.from_error(error, decision)
        with self._lock:
            self._get_stats(key.namespace).error_count += 1
            stopped = self._get_access_stop_error(policy)
            if self._entries.get(key) is not entry or entry.abandoned:
                return
            if stopped is not None:
                entry.abandoned = True
                entry.event.set()
                self._remove_entry_locked(key, entry)
                return
            entry.failure = snapshot
            entry.loaded = True
            entry.event.set()
            if decision.retention.value == "evict":
                self._remove_entry_locked(key, entry)

    def _wait_for_entry(
        self,
        entry: CacheEntry[object],
        policy: AwsScanCacheAccessPolicy,
    ) -> bool:
        wait_deadline = time.monotonic() + policy.max_wait_seconds
        while True:
            stopped = self._get_access_stop_error(policy)
            if stopped is not None:
                raise stopped
            remaining = wait_deadline - time.monotonic()
            if remaining <= 0:
                return False
            if entry.event.wait(min(_CANCELLATION_POLL_SECONDS, remaining)):
                return True

    def _claim_replacement(
        self,
        key: AwsScanCacheKey,
        old_entry: CacheEntry[object],
        policy: AwsScanCacheAccessPolicy,
    ) -> tuple[CacheEntry[object] | None, bool]:
        with self._lock:
            current = self._entries.get(key)
            if current is None:
                return self._create_entry_locked(key, policy), True
            if current is old_entry:
                if not current.loaded:
                    current.abandoned = True
                    current.event.set()
                    self._remove_entry_locked(key, current)
                    return self._create_entry_locked(key, policy), True
                return current, False
            if current.loaded:
                return current, False
            return None, False

    def _abandon_if_current(
        self,
        key: AwsScanCacheKey,
        entry: CacheEntry[object],
    ) -> None:
        with self._lock:
            if self._entries.get(key) is not entry:
                return
            entry.abandoned = True
            entry.event.set()
            self._remove_entry_locked(key, entry)

    def _consume_entry(
        self,
        key: AwsScanCacheKey,
        entry: CacheEntry[object],
        status: CacheAccessStatus,
        policy: AwsScanCacheAccessPolicy,
    ) -> AwsScanCacheAccess[Any]:
        if entry.abandoned or not entry.loaded:
            raise self._build_superseded_error(key, entry)
        if entry.failure is not None:
            raise AwsScanCacheLoadError(entry.failure)
        self._record_consumer_status(
            policy.consumer_id,
            key.namespace,
            status,
        )
        return AwsScanCacheAccess(value=entry.value, status=status, key=key)

    def _record_wait_or_hit_locked(
        self,
        key: AwsScanCacheKey,
        entry: CacheEntry[object],
    ) -> CacheAccessStatus:
        stats = self._get_stats(key.namespace)
        if entry.loaded:
            stats.hit_count += 1
            return "hit"
        stats.wait_count += 1
        return "waited"

    def convert_to_summary(self) -> dict[str, object]:  # noqa: D102
        with self._lock:
            return {
                "enabled": True,
                "contains_client_result_data": False,
                "entry_count": len(self._entries),
                "namespaces": {namespace: stats.convert_to_dict() for namespace, stats in sorted(self._namespace_stats.items())},
                "consumer_usage": {consumer_id: stats.convert_to_dict() for consumer_id, stats in sorted(self._consumer_stats.items())},
            }

    def _resolve_access_policy(
        self,
        *,
        consumer_id: str | None,
        access_policy: AwsScanCacheAccessPolicy | None,
    ) -> AwsScanCacheAccessPolicy:
        policy = access_policy or AwsScanCacheAccessPolicy()
        if consumer_id and policy.consumer_id and consumer_id != policy.consumer_id:
            message = "consumer_id conflicts with access_policy.consumer_id."
            raise ValueError(message)
        if consumer_id and not policy.consumer_id:
            return replace(policy, consumer_id=consumer_id)
        return policy

    def _get_access_stop_error(
        self,
        policy: AwsScanCacheAccessPolicy,
    ) -> AwsScanCacheCancelledError | AwsScanCacheDeadlineExceededError | None:
        now = time.monotonic()
        if policy.deadline_monotonic is not None and now >= policy.deadline_monotonic:
            attempt = f" for attempt {policy.attempt_id}" if policy.attempt_id else ""
            return AwsScanCacheDeadlineExceededError(
                f"Cache access deadline expired{attempt}.",
            )
        token = policy.cancellation_token
        if token is not None and token.is_cancelled():
            reason = getattr(token, "reason", "Cache access was cancelled.")
            return AwsScanCacheCancelledError(str(reason))
        return None

    def _build_key(
        self,
        namespace: str,
        parts: tuple[object, ...],
    ) -> AwsScanCacheKey:
        return AwsScanCacheKey(
            namespace=namespace,
            parts=tuple(self._normalize_part(part) for part in parts),
        )

    def _build_wait_timeout_error(
        self,
        key: AwsScanCacheKey,
        policy: AwsScanCacheAccessPolicy,
    ) -> AwsScanCacheWaitTimeoutError:
        return AwsScanCacheWaitTimeoutError(
            f"Cache wait for {key.namespace} exceeded {policy.max_wait_seconds:g} seconds.",
        )

    def _raise_wait_timeout(
        self,
        key: AwsScanCacheKey,
        policy: AwsScanCacheAccessPolicy,
    ) -> NoReturn:
        raise self._build_wait_timeout_error(key, policy)

    def _build_superseded_error(
        self,
        key: AwsScanCacheKey,
        entry: CacheEntry[object],
    ) -> AwsScanCacheGenerationSupersededError:
        return AwsScanCacheGenerationSupersededError(
            f"Cache generation {entry.generation} for {key.namespace} no longer owns publication authority.",
        )

    def _remove_entry_locked(
        self,
        key: AwsScanCacheKey,
        expected: CacheEntry[object],
    ) -> None:
        if self._entries.get(key) is not expected:
            return
        del self._entries[key]
        stats = self._get_stats(key.namespace)
        stats.key_count = max(0, stats.key_count - 1)

    def _get_stats(self, namespace: str) -> AwsScanCacheStats:
        stats = self._namespace_stats.get(namespace)
        if stats is None:
            stats = AwsScanCacheStats()
            self._namespace_stats[namespace] = stats
        return stats

    def _record_consumer_status(
        self,
        consumer_id: str | None,
        namespace: str,
        status: CacheAccessStatus,
    ) -> None:
        if not consumer_id:
            return
        with self._lock:
            self._get_consumer_stats(consumer_id).record_status(namespace, status)

    def _record_consumer_error(
        self,
        consumer_id: str | None,
        namespace: str,
    ) -> None:
        if not consumer_id:
            return
        with self._lock:
            self._get_consumer_stats(consumer_id).record_error(namespace)

    def _get_consumer_stats(self, consumer_id: str) -> AwsScanCacheConsumerStats:
        stats = self._consumer_stats.get(consumer_id)
        if stats is None:
            stats = AwsScanCacheConsumerStats()
            self._consumer_stats[consumer_id] = stats
        return stats

    def _normalize_part(self, part: object) -> str:
        if isinstance(part, (list, tuple, set, frozenset)):
            return "[" + ",".join(self._normalize_part(item) for item in sorted(part, key=str)) + "]"
        return str(part)
