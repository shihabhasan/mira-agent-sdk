"""`mira-verify` — check an exported lineage bundle with no network.

    mira-verify bundle.json
    mira-verify bundle.json --json

Exit code 0 means every record verified; 1 means something did not. That makes
it usable as a CI gate, not just a human tool.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .verify import BundleResult, verify_bundle

_TICK = "✓"
_CROSS = "✗"


def _render(res: BundleResult, *, verbose: bool) -> str:
    lines: list[str] = []
    head = f"{_TICK} VERIFIED" if res.valid else f"{_CROSS} FAILED"
    lines.append(f"{head}  {res.txn_id}")
    lines.append("")
    cp = _TICK if res.checkpoint_signature_valid else _CROSS
    lines.append(f"  {cp} checkpoint signature")
    lines.append(f"  {len(res.records)} record(s)")

    bad = res.invalid_records
    if bad:
        lines.append("")
        for r in bad:
            lines.append(
                f"  {_CROSS} seq {r.seq} [{r.record_type}] {r.record_hash[:16]}…"
                f"  failed: {', '.join(r.failures())}"
            )
    elif verbose:
        lines.append("")
        for r in res.records:
            lines.append(
                f"  {_TICK} seq {r.seq:>3} [{r.record_type:<12}] "
                f"{(r.node or '-'):<18} {r.record_hash[:16]}…"
            )

    for err in res.errors:
        lines.append(f"  ! {err}")

    lines.append("")
    if res.valid:
        lines.append("  Every record's signature, chain link, sequence and inclusion")
        lines.append("  proof checks out against the signed checkpoint root.")
    else:
        lines.append("  This bundle does NOT verify. Treat it as untrustworthy.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="mira-verify",
        description="Verify a Mira lineage bundle offline. No network, no account.",
    )
    ap.add_argument("bundle", help="path to an exported bundle JSON file ('-' for stdin)")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="machine-readable output")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list every record, not just failures")
    args = ap.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.bundle == "-" else Path(args.bundle).read_text()
        bundle = json.loads(raw)
    except FileNotFoundError:
        print(f"no such file: {args.bundle}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"not valid JSON: {e}", file=sys.stderr)
        return 2

    res = verify_bundle(bundle)

    if args.as_json:
        print(json.dumps({
            "txn_id": res.txn_id,
            "valid": res.valid,
            "checkpoint_signature_valid": res.checkpoint_signature_valid,
            "errors": res.errors,
            "records": [
                {
                    "seq": r.seq, "record_hash": r.record_hash,
                    "record_type": r.record_type, "node": r.node,
                    "valid": r.valid, "failures": r.failures(),
                }
                for r in res.records
            ],
        }, indent=2))
    else:
        print(_render(res, verbose=args.verbose))

    return 0 if res.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
