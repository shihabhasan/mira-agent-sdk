"""Rebuilding the causal graph from receipts, gaps included.

Receipts arrive late, out of order, and sometimes not at all. The graph is
built from what arrived; what did not is reported as a gap, never stitched
over. Two kinds of gap are distinguishable, and both are detectable from the
evidence itself.

A missing parent: a receipt names an inbound commitment no receipt describes.
Something happened upstream that was never reported.

A missing successor: a receipt says it minted a successor for a destination,
and no receipt from that destination ever arrived. This is the terminal-hop
omission case. The last boundary in a chain cannot silently drop its receipt,
because the hop before it already committed to having handed authority on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mira_agent.msep.receipt import Receipt


@dataclass
class Lineage:
    receipts: list[Receipt]
    by_inbound: dict[str, list[Receipt]] = field(default_factory=dict)
    missing_parents: list[str] = field(default_factory=list)
    missing_successors: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.missing_parents and not self.missing_successors

    def roots(self) -> list[Receipt]:
        return [r for r in self.receipts if not r.parent_commitments]

    def children_of(self, receipt: Receipt) -> list[Receipt]:
        if not receipt.successor_commitment:
            return []
        return self.by_inbound.get(receipt.successor_commitment, [])


def reconstruct(receipts: list[Receipt]) -> Lineage:
    known_inbound = {r.inbound_commitment for r in receipts if r.inbound_commitment}
    known_successor = {r.successor_commitment for r in receipts if r.successor_commitment}
    by_inbound: dict[str, list[Receipt]] = {}
    for r in receipts:
        if r.inbound_commitment:
            by_inbound.setdefault(r.inbound_commitment, []).append(r)

    missing_parents = sorted({
        p for r in receipts for p in r.parent_commitments
        # A parent is accounted for if some receipt minted it as a successor,
        # or some receipt verified it as inbound. A root envelope has neither.
        if p not in known_successor and p not in known_inbound and r.parent_commitments
    })
    missing_successors = sorted({
        r.successor_commitment for r in receipts
        if r.successor_commitment and r.successor_commitment not in known_inbound
    })
    return Lineage(receipts, by_inbound, missing_parents, missing_successors)
