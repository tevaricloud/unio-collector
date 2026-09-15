from __future__ import annotations  # noqa: D100

import argparse
import json
from importlib import import_module
from pathlib import Path

VALIDATION_RUN_SCHEMA = 2


def main() -> int:
    """Build and validate the collector-only wheel."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="External absolute directory for collector wheel artifacts.",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output_dir = _resolve_external_output_dir(args.output, root)
    builder_type = import_module(
        "unio_collector.collector.package.wheel.builder",
    ).CollectorWheelBuilder
    result = builder_type().build(
        root=root,
        output_dir=output_dir,
    )
    print(result.wheel_path)  # noqa: T201
    print(  # noqa: T201
        f"validated {result.source_file_count} source files and {result.wheel_member_count} wheel members",
    )
    return 0


def _resolve_external_output_dir(output: Path, root: Path) -> Path:
    if not output.is_absolute():
        msg = "--output must be an external absolute path."
        raise SystemExit(msg)
    resolved_output = output.resolve()
    resolved_root = root.resolve()
    if (resolved_output == resolved_root or resolved_root in resolved_output.parents) and not _is_managed_packaging_output(resolved_output):
        msg = "--output must not resolve inside the repository checkout."
        raise SystemExit(msg)
    return resolved_output


def _is_managed_packaging_output(output: Path) -> bool:
    """Accept only authenticated retained packaging paths inside a checkout."""
    for candidate in output.parents:
        if candidate.parent.name != "validation-runs" or not (candidate / "run.json").is_file():
            continue
        try:
            payload = json.loads((candidate / "run.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        if not isinstance(payload, dict) or payload.get("schema_version") != VALIDATION_RUN_SCHEMA:
            return False
        if payload.get("run_id") != candidate.name:
            return False
        if payload.get("layout") != {"retained_root": "retained", "disposable_root": "ephemeral"}:
            return False
        packaging = (candidate / "retained" / "packaging").resolve()
        return output == packaging or output.is_relative_to(packaging)
    return False


if __name__ == "__main__":
    raise SystemExit(main())
