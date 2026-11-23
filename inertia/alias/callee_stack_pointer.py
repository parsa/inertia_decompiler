# cython: language_level=3, infer_types=True
"""Prove a leaf callee's returning SP transfer from its complete IR.

Layer: Alias.
Responsibility: consume authoritative instruction/CFG coverage and the existing
stack-state solver, retaining the SP displacement on every returning edge.
The displacement includes the machine RET updates already present in the IR.
It is not inferred from a return immediate or a calling-convention name.
Owns storage identity
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from contextvars import ContextVar

from inertia.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616

from .bp_preservation import _return_blocks_8616
from .segment_stack_restore import _solve_stack_states
import dataclasses
import operator


class CalleeStackPointerFailure8616(StrEnum):
    """Why a complete returning SP transfer could not be established."""

    COVERAGE_INCOMPLETE = "coverage_incomplete"
    ENTRY_REENTERED = "entry_reentered"
    EXTERNAL_EFFECT = "external_effect"
    RETURN_UNPROVEN = "return_unproven"
    STACK_POINTER_UNKNOWN = "stack_pointer_unknown"
    RETURN_DELTAS_DISAGREE = "return_deltas_disagree"


@cython.ccall
def _word_delta_8616(value: cython.longlong) -> cython.longlong:
    """Express one modular word displacement in signed affine coordinates."""
    return ((value + 0x8000) & 0xFFFF) - 0x8000


_NESTED_CALL_MAX_DEPTH_8616 = 8
_NESTED_CALL_ACTIVE_8616: ContextVar[tuple[int, ...]] = ContextVar(
    "_NESTED_CALL_ACTIVE_8616", default=(),
)


@dataclasses.dataclass(frozen=True)
class NestedCallStackTransfer8616:
    """Proven caller-visible SP delta of one nested CALL, with BP preservation."""

    sp_delta: int
    bp_preserved: bool


def _nested_call_deltas_8616(coverage: IRBoundaryCoverageResult8616) -> dict[int, int] | None:
    """Prove each nested direct CALL's caller-visible SP transfer, recursively.

    A CALL row already carrying its own proven effect keeps it (the solver
    authenticates that record). Otherwise the row must be a direct E8/9A
    call whose target binding and whole callee body are proven by the same
    Semantics owner used for top-level calls; the caller-visible transfer is
    ``callee entry->after RET`` minus the machine frame the CALL pushed.
    Cycles and depth beyond the bound refuse (``None``) instead of recursing.
    """
    from inertia.semantics.bp_call_preservation import prove_direct_bp_call_preservation_8616
    from inertia.semantics.callee_stack_effects import prove_direct_callee_stack_effect_8616
    from inertia.semantics.callsite_summary import CallsiteMachineFrameKind8616

    artifact = coverage.artifact
    project = getattr(coverage.boundary, "project", None)
    deltas: dict[int, int] = {}
    rows = [row for block in iter(artifact.blocks) for row in iter(block.instrs) if row.op == "CALL"]
    if not rows:
        return deltas
    active = _NESTED_CALL_ACTIVE_8616.get()
    if project is None or artifact.function_addr in active or len(active) >= _NESTED_CALL_MAX_DEPTH_8616:
        return None
    token = _NESTED_CALL_ACTIVE_8616.set(active + (artifact.function_addr,))
    try:
        for row in rows:
            if _nested_call_effect_bound_8616(row):
                continue
            if type(row.addr) is not int:
                return None
            # The CALL row is the instruction's own decoded head; its machine
            # encoding is re-read from the image (the row size may be elided).
            encoding = bytes(project.loader.memory.load(row.addr, 5))
            if len(encoding) == 5 and encoding[0] == 0xE8:
                frame, length = CallsiteMachineFrameKind8616.NEAR, 3
                target_addr = row.addr + 3 + int.from_bytes(encoding[1:3], "little", signed=True)
            elif len(encoding) == 5 and encoding[0] == 0x9A:
                frame, length = CallsiteMachineFrameKind8616.FAR, 5
                target_addr = (int.from_bytes(encoding[3:5], "little") << 4) + int.from_bytes(encoding[1:3], "little")
            else:
                return None
            if row.size not in (0, length):
                return None
            # Decoded coordinates only; prove_direct_callee_stack_effect_8616
            # still requires the target binding (selector window) to hold.
            result = prove_direct_callee_stack_effect_8616(
                project, row.addr, row.addr + length, target_addr, frame,
            )
            returned = result.return_sp_delta
            if returned is None:
                return None
            bp_proof = prove_direct_bp_call_preservation_8616(
                project, row.addr, row.addr + length, target_addr, frame,
            )
            bp_preserved = bool(bp_proof.complete)
            if not bp_preserved:
                from inertia.ir.far_call_return_premise import saved_bp_premise_refusal_8616
                row_addrs = {item.addr for block in iter(artifact.blocks) for item in iter(block.instrs)}
                push_cs = (
                    frame is CallsiteMachineFrameKind8616.NEAR
                    and (row.addr - 1) in row_addrs
                    and bytes(project.loader.memory.load(row.addr - 1, 1)) == b"\x0e"
                )
                bp_preserved = saved_bp_premise_refusal_8616(
                    project, row.addr, target_addr,
                    frame is CallsiteMachineFrameKind8616.FAR, push_cs,
                ) is None
            deltas[row.addr] = NestedCallStackTransfer8616(
                returned - frame.return_frame_width, bp_preserved,
            )
    finally:
        _NESTED_CALL_ACTIVE_8616.reset(token)
    return deltas


@cython.ccall
def _nested_call_effect_bound_8616(row: object) -> cython.bint:
    """Admit a CALL row's own record only when it carries a complete proven SP transfer.

    The shared stack solver re-authenticates the coordinates against the
    CALL row (callsite, bound target, delta agreement).
    """
    effect = row.call_stack_effect
    coordinates = getattr(effect, "stack_coordinates", None)
    return (
        effect is not None
        and effect.complete
        and effect.net_stack_delta is not None
        and coordinates is not None
        and coordinates.has_proven_sp_delta
        and coordinates.net_sp_delta is not None
        and operator.eq(coordinates.net_sp_delta, effect.net_stack_delta)
    )


def _return_transfers_8616(
    coverage: IRBoundaryCoverageResult8616,
) -> tuple[CalleeStackPointerFailure8616 | None, tuple[tuple[cython.longlong, cython.longlong], ...]]:
    """Collect a common returning delta without assuming balanced bodies."""
    delta: object
    exits: object
    block: object
    if not coverage.complete:
        return CalleeStackPointerFailure8616.COVERAGE_INCOMPLETE, ()
    artifact = coverage.artifact
    if any(artifact.function_addr in block.successor_addrs for block in iter(artifact.blocks)):
        return CalleeStackPointerFailure8616.ENTRY_REENTERED, ()
    if any(row.op in {"INT", "INTERRUPT", "SYSCALL", "IRET"}
           for block in iter(artifact.blocks) for row in iter(block.instrs)):
        return CalleeStackPointerFailure8616.EXTERNAL_EFFECT, ()
    call_deltas = _nested_call_deltas_8616(coverage)
    if call_deltas is None:
        return CalleeStackPointerFailure8616.EXTERNAL_EFFECT, ()
    exits = _return_blocks_8616(artifact)
    if exits is None:
        return CalleeStackPointerFailure8616.RETURN_UNPROVEN, ()
    states = _solve_stack_states(artifact, call_deltas=call_deltas or None)
    transfers: list[tuple[cython.longlong, cython.longlong]] = []
    for block in sorted(exits, key=lambda item: item.addr):
        delta = states[block.addr].sp_delta
        if delta is None:
            return CalleeStackPointerFailure8616.STACK_POINTER_UNKNOWN, ()
        transfers.append((block.addr, _word_delta_8616(delta)))
    retained = tuple(transfers)
    if len({delta for _, delta in iter(retained)}) != 1:
        return CalleeStackPointerFailure8616.RETURN_DELTAS_DISAGREE, retained
    return None, retained


@dataclasses.dataclass(frozen=True, )
class CalleeStackPointerResult8616:
    """A source-bound whole-callee transfer, or one explicit refusal."""

    coverage: IRBoundaryCoverageResult8616
    failure: CalleeStackPointerFailure8616 | None
    return_transfers: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    def _retained_transfer_is_accepted(self) -> cython.bint:
        """Require an accepted publication, independently of its current source."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        return bool(
            self.failure is None and counts == (1, 1, 1, 1, 0)
            and all(type(count) is int for count in iter(counts))
        )

    @property
    def complete(self) -> cython.bint:
        """Recheck body identity and transfers before authorizing a consumer."""
        failure: object
        if not self._retained_transfer_is_accepted():
            return False
        failure, transfers = _return_transfers_8616(self.coverage)
        return failure is None and operator.eq(transfers, self.return_transfers)

    @property
    def observed_return_sp_delta(self) -> int | None:
        """Expose the retained transfer value without authorizing its currency.

        Structural inventories may count this fact without replaying its proof.
        Consumers requiring a current effect must use return_sp_delta or complete.
        """
        if not self._retained_transfer_is_accepted() or not self.return_transfers:
            return None
        return self.return_transfers[0][1]

    @property
    def return_sp_delta(self) -> int | None:
        """Return the entry-to-after-RET displacement only with a valid proof."""
        return self.observed_return_sp_delta if self.complete else None


@cython.ccall
def prove_callee_stack_pointer_8616(
    coverage: IRBoundaryCoverageResult8616,
) -> CalleeStackPointerResult8616:
    """Publish one retained transfer or an atomic conservative non-result."""
    failure: object
    failure, transfers = _return_transfers_8616(coverage)
    accepted = int(failure is None)
    return CalleeStackPointerResult8616(
        coverage, failure, transfers, 1, 1, accepted, accepted, 1 - accepted,
    )
