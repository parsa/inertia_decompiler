"""Bind balanced word far-return frames to current source.

Layer: Alias.
Responsibility: compose existing BP preservation and SP transfer proofs for
exact, unprefixed word RETF endpoints without publishing or repairing raw IR.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from inertia.frontend.x86_16.frontend_boundary_transport import (
    capture_function_boundary_8616,
    restore_function_boundary_8616,
)
from inertia.ir.function_ir_registry import registered_function_ir_artifact_8616
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from inertia.semantics.terminal_return_contract import WordFarReturnLayout8616

from .bp_preservation import prove_bp_preservation_8616
from .callee_stack_pointer import prove_callee_stack_pointer_8616


@dataclass(frozen=True)
class WordRetfEndpoint8616:
    """An exact terminal site with a decoded, unprefixed word RETF layout."""

    block_addr: int
    instruction_addr: int
    layout: WordFarReturnLayout8616


def prove_current_balanced_word_retf_exits_8616(
    project: object, function: object, function_addr: int,
    candidates: frozenset[WordRetfEndpoint8616],
) -> frozenset[WordRetfEndpoint8616]:
    """Prove exact endpoints for this observation only; refuse stale or missing source."""
    artifact = registered_function_ir_artifact_8616(project, function_addr).artifact
    if artifact is None:
        return frozenset()
    witness = capture_function_boundary_8616(project, function)
    boundary = None if witness is None else restore_function_boundary_8616(project, witness)
    if boundary is None or boundary.addr != function_addr:
        return frozenset()
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    bp = prove_bp_preservation_8616(coverage)
    sp = prove_callee_stack_pointer_8616(coverage)
    if not bp.complete or not sp.complete:
        return frozenset()

    deltas = dict(cast(tuple[tuple[int, int], ...], sp.return_transfers))
    restored = cast(tuple[int, ...], bp.return_block_addrs)
    terminals = {block.addr: block.instrs[-1].addr for block in artifact.blocks if block.addr in restored}
    return frozenset(
        candidate for candidate in candidates
        if terminals.get(candidate.block_addr) == candidate.instruction_addr
        and deltas.get(candidate.block_addr) == candidate.layout.sp_displacement
    )
