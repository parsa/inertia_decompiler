# cython: language_level=3, infer_types=True
"""Consume alias-proven terminal far-return CS frame carriers.

Layer: Types/Lowering.
Responsibility: remove the structured CS-restore assignment of one
block-terminal RETF only when Alias, typed IR, and decoded terminal evidence
agree that the assignment is the machine far-return frame pop itself, so the
generated ``return`` owns the frame boundary instead of program-visible frame
reads. Incomplete evidence refuses and keeps every assignment.
Consumes alias facts, IR terminal control flow, and terminal decode evidence.
Do not infer return boundaries from opcodes, assembly text, or rendered C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

Dynamic boundary: third-party angr C-AST statements and codegen attachments
expose version-dependent tags and child containers.
"""

from __future__ import annotations
import typing
import cython

import logging
import os
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable

from inertia.alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreVerdict8616,
)
from inertia.ir.vex_control_flow import terminal_ret_instruction_addrs_8616
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.structured_tags import copy_structured_tags_8616
from angr.sim_type import SimTypeShort
from inertia.semantics.terminal_return_contract import TerminalReturnFrameKind8616, WordFarReturnLayout8616, WordNearReturnLayout8616
from inertia.semantics.terminal_return_contract import WordInterruptReturnLayout8616
from inertia.semantics.terminal_stack_cleanup import terminal_stack_cleanup_at_address_8616

from .segment_register_state import runtime_segment_name_for_variable_8616
from .gp_register_state import runtime_gp_name_for_variable_8616, runtime_gp_state_assignment_8616
import dataclasses
import operator
import builtins

__all__ = [
    "FarReturnBoundaryCarrierStats8616",
    "consume_terminal_far_return_boundary_carriers_8616",
    "bind_word_far_return_effect_8616",
    "word_far_return_pre_sp_8616",
]


def word_far_return_pre_sp_8616(
    assignment: structured_c.CAssignment, instruction_addr: int,
    layout: WordFarReturnLayout8616, sp_coordinate: tuple[int, int],
) -> structured_c.CExpression | None:
    """Recover the input of a typed terminal SP addition, without evaluating it."""
    if (
        assignment.tags.get("ins_addr") != instruction_addr
        or assignment.tags.get("inertia_gp_exit_coordinate") != sp_coordinate
    ):
        return None

    def uncast(value):
        while isinstance(value, structured_c.CTypeCast):
            if not isinstance(value.dst_type.size, int) or value.dst_type.size < 16:
                return None
            value = value.expr
        return value

    def constant_rhs(value, op, expected):
        value = uncast(value)
        if not isinstance(value, structured_c.CBinaryOp) or value.op != op:
            return None
        rhs = uncast(value.rhs)
        return value.lhs if isinstance(rhs, structured_c.CConstant) and rhs.value == expected else None

    rhs = uncast(assignment.rhs)
    if isinstance(rhs, structured_c.CBinaryOp) and rhs.op == "Or":
        if constant_rhs(rhs.lhs, "And", 0xFFFF0000) is None:
            return None
        rhs = constant_rhs(rhs.rhs, "And", 0xFFFF)
        if rhs is None:
            return None
    return constant_rhs(rhs, "Add", layout.sp_displacement)


def bind_word_far_return_effect_8616(
    codegen: object, function_addr: int, instruction_addr: int,
    layout: WordFarReturnLayout8616 | WordNearReturnLayout8616 | WordInterruptReturnLayout8616,
    ss: structured_c.CExpression, pre_sp: structured_c.CExpression,
) -> structured_c.CAssignment:
    """Bind an already-proved SS and pre-return SP to one architectural write."""
    word = SimTypeShort(signed=False).with_arch(codegen.project.arch)
    near = isinstance(layout, WordNearReturnLayout8616)
    interrupt = isinstance(layout, WordInterruptReturnLayout8616)
    key = ("inertia_word_interrupt_return" if interrupt else
           "inertia_word_near_return_cleanup" if near else "inertia_word_far_return_cleanup")
    tags = {"ins_addr": instruction_addr, key: 0 if interrupt else layout.cleanup}
    args = [ss, pre_sp]
    if not interrupt:
        args.append(structured_c.CConstant(layout.cleanup, word, codegen=codegen))
    call = structured_c.CFunctionCall(
        "inertia_iret_word" if interrupt else "inertia_ret_word" if near else "inertia_retf_word", None,
        args,
        codegen=codegen, tags=tags,
    )
    assignment = runtime_gp_state_assignment_8616(
        "sp", structured_c.CTypeCast(call.type, word, call, codegen=codegen),
        codegen=codegen, function_addr=function_addr, exit_only=True,
    )
    if assignment is None:
        raise ValueError("word far return could not publish SP")
    assignment.tags = {**assignment.tags, **tags}
    return assignment

_FAR_RETURN_BOUNDARY_RESTORE_REGISTER_8616 = "cs"
_FAR_RETURN_BOUNDARY_OPERAND_BITS_8616 = 16
_FAR_RETURN_BOUNDARY_CLEANUP_8616 = 0


def _supported_far_return_cleanup_8616(cleanup: object) -> cython.bint:
    """Accept one consistent word-aligned RETF imm16 cleanup.

    ``RETF imm16`` pops IP then CS from the same two frame words as a plain
    RETF and only afterwards adds ``imm16`` to SP, so the CS carrier is still
    exactly the machine frame pop; the cleanup belongs to the callee-pops
    interface, not to the CS restore.
    """
    return (
        type(cleanup) is int
        and _FAR_RETURN_BOUNDARY_CLEANUP_8616 <= cleanup <= 0xFFFF
        and cleanup % 2 == 0
    )


class FarReturnBoundaryRefusal8616(StrEnum):
    """Reason a terminal far-return CS carrier must stay in the AST."""

    NOT_TERMINAL_RET = "not_terminal_ret"
    NOT_FAR_RETURN_FRAME = "not_far_return_frame"
    UNSUPPORTED_WIDTH_OR_CLEANUP = "unsupported_width_or_cleanup"
    CARRIER_ABSENT = "carrier_absent"
    NOT_CS_STATE_CARRIER = "not_cs_state_carrier"
    FRAME_BYTES_DISAGREE = "frame_bytes_disagree"


class _FarReturnBoundaryCodegen8616(Protocol):
    """Owned fields consumed and published at the dynamic codegen boundary."""

    cfunc: _FarReturnBoundaryCFunction8616
    _inertia_vex_ir_artifact: object
    _inertia_segment_stack_restore_artifact: SegmentStackRestoreArtifact8616
    _inertia_far_return_boundary_consumed_restores_8616: object
    _inertia_far_return_boundary_carrier_stats_8616: FarReturnBoundaryCarrierStats8616
    _inertia_terminal_word_far_return_layouts_8616: object


class _FarReturnBoundaryCFunction8616(Protocol):
    """Owned C-function surface needed by the far-return carrier consumer."""

    statements: object


@dataclasses.dataclass(frozen=True, )
class FarReturnBoundaryCarrierStats8616:
    """Closed accounting for terminal far-return CS carrier consumption."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    already_materialized_count: cython.longlong
    failure_count: cython.longlong
    removed_assignment_count: cython.longlong
    refusals: tuple[tuple[cython.longlong, FarReturnBoundaryRefusal8616], ...] = ()

    @property
    def refused_candidate_count(self) -> cython.longlong:
        """Return candidates retained because boundary evidence is incomplete."""
        return len(self.refusals)

    @property
    def closed(self) -> cython.bint:
        """Return whether every candidate reached one terminal lane."""
        return bool(
            operator.eq(self.raw_fact_count, self.normalized_fact_count + self.failure_count)
            and operator.eq(self.normalized_fact_count, self.classified_fact_count + self.refused_candidate_count)
            and operator.eq(self.classified_fact_count, self.materialized_count + self.already_materialized_count)
        )


@cython.ccall
def _statement_instruction_addr_8616(statement: object) -> int | None:
    """Return one exact structured assignment instruction address."""
    instruction_addr: object
    tags: object
    tags = copy_structured_tags_8616(getattr(statement, "tags", None))
    if tags is not None:
        instruction_addr = tags.get("ins_addr")
        if isinstance(instruction_addr, int):
            return instruction_addr
    instruction_addr = getattr(statement, "ins_addr", None)
    return instruction_addr if isinstance(instruction_addr, int) else None


def _statement_lists_8616(root: object) -> tuple[list[object], ...]:
    """Collect mutable statement lists using the shared child schema once."""
    candidate: object
    lists = [root] if isinstance(root, list) else []
    roots = tuple(root) if isinstance(root, list) else (root,)
    seen: set[cython.longlong] = set()
    for candidate in roots:
        lists.extend(
            node.statements
            for node in builtins.iter(_iter_c_nodes_deep_8616(candidate, seen))
            if isinstance(node, structured_c.CStatements) and isinstance(node.statements, list)
        )
    return tuple(lists)


@cython.ccall
def _physical_cs_carrier_8616(variable: object, project: object) -> cython.bint:
    """Return whether one physical register variable is the architectural CS."""
    register_names: object
    if not isinstance(variable, SimRegisterVariable) or not isinstance(variable.reg, int):
        return False
    register_names = getattr(getattr(project, "arch", None), "register_names", None)
    register_name = register_names.get(variable.reg) if isinstance(register_names, dict) else None
    return isinstance(register_name, str) and operator.eq(register_name.lower(), _FAR_RETURN_BOUNDARY_RESTORE_REGISTER_8616)


@cython.ccall
def _cs_carrier_lhs_8616(lhs: object, project: object) -> cython.bint:
    """Return whether one assignment LHS carries the architectural CS state."""
    variable: object
    if not isinstance(lhs, structured_c.CVariable):
        return False
    for variable in (lhs.unified_variable, lhs.variable):
        if operator.eq(runtime_segment_name_for_variable_8616(variable), (
            _FAR_RETURN_BOUNDARY_RESTORE_REGISTER_8616
        )):
            return True
        if _physical_cs_carrier_8616(variable, project):
            return True
    return False


@dataclasses.dataclass(frozen=True, )
class _FarReturnClassification8616:
    """Terminal decision lanes for every candidate address of one function."""

    refusals: object
    removals_by_addr: object
    already: object


@cython.ccall
def _far_return_candidate_addrs_8616(
    artifact: SegmentStackRestoreArtifact8616,
) -> object:
    """Collect deduplicated far-return candidate restore addresses."""
    fact: object
    candidates: dict[cython.longlong, None] = {}
    for fact in artifact.facts:
        if (
            operator.eq(fact.restore_register, _FAR_RETURN_BOUNDARY_RESTORE_REGISTER_8616)
            and fact.saved_instruction_addr is None
            and fact.verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE
        ):
            candidates.setdefault(fact.restore_instruction_addr, None)
    return candidates


@cython.ccall
def _assignments_by_address_8616(
    statement_lists: object,
) -> object:
    """Index every structured assignment by its exact instruction address."""
    address: object
    statement: object
    statements: object
    assignments_by_addr: dict[cython.longlong, list[structured_c.CAssignment]] = {}
    for statements in statement_lists:
        for statement in statements:
            if not isinstance(statement, structured_c.CAssignment):
                continue
            address = _statement_instruction_addr_8616(statement)
            if address is not None:
                assignments_by_addr.setdefault(address, []).append(statement)
    return assignments_by_addr


@cython.ccall
def _far_return_evidence_refusal_8616(
    project: object,
    address: cython.longlong,
    terminal_rets: object,
) -> FarReturnBoundaryRefusal8616 | None:
    """Require terminal evidence corroborated by the exact loaded RETF."""
    if address not in terminal_rets:
        return FarReturnBoundaryRefusal8616.NOT_TERMINAL_RET
    evidence = terminal_stack_cleanup_at_address_8616(project, address)
    if (
        not evidence.complete
        or evidence.consistent_return_frame_kind is not TerminalReturnFrameKind8616.FAR
    ):
        return FarReturnBoundaryRefusal8616.NOT_FAR_RETURN_FRAME
    if (
        operator.ne(evidence.consistent_return_operand_bits, _FAR_RETURN_BOUNDARY_OPERAND_BITS_8616)
        or not _supported_far_return_cleanup_8616(evidence.consistent_cleanup)
    ):
        return FarReturnBoundaryRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP
    layout = _loaded_word_far_return_layout_8616(project, address)
    if layout is None or layout.cleanup != evidence.consistent_cleanup:
        return FarReturnBoundaryRefusal8616.FRAME_BYTES_DISAGREE
    return None


def _loaded_word_far_return_layout_8616(project: object, address: int) -> WordFarReturnLayout8616 | None:
    """Read only the bytes required by the selected unprefixed encoding."""
    try:
        memory = project.loader.memory
        opcode = bytes(memory.load(address, 1))
        encoding = bytes(memory.load(address, 3)) if opcode == b"\xca" else opcode
    except (AttributeError, KeyError, ValueError):
        return None
    return WordFarReturnLayout8616.from_encoding(encoding)


def _classify_far_return_candidates_8616(
    project: object,
    candidates: object,
    terminal_rets: object,
    assignments_by_addr: object,
    typed_prior: object,
) -> _FarReturnClassification8616:
    """Send every candidate to exactly one terminal decision lane."""
    assignments: object
    refusal: object
    address: object
    refusals: dict[cython.longlong, FarReturnBoundaryRefusal8616] = {}
    removals_by_addr: dict[cython.longlong, tuple[structured_c.CAssignment, ...]] = {}
    already: set[cython.longlong] = set()
    for address in candidates:
        refusal = _far_return_evidence_refusal_8616(project, address, terminal_rets)
        if refusal is not None:
            refusals[address] = refusal
            continue
        assignments = assignments_by_addr.get(address, [])
        if not assignments:
            if address in typed_prior:
                already.add(address)
            else:
                refusals[address] = FarReturnBoundaryRefusal8616.CARRIER_ABSENT
            continue
        cs_assignments = tuple(
            assignment for assignment in iter(assignments) if _cs_carrier_lhs_8616(assignment.lhs, project)
        )
        # RETF can also publish SP at this instruction. A sibling write is
        # neither a CS carrier nor evidence against the identified CS write.
        if not cs_assignments:
            if address in typed_prior:
                already.add(address)
                continue
            refusals[address] = FarReturnBoundaryRefusal8616.NOT_CS_STATE_CARRIER
            continue
        removals_by_addr[address] = cs_assignments
    return _FarReturnClassification8616(refusals, removals_by_addr, frozenset(already))


def _remove_proven_cs_carriers_8616(
    statement_lists: object,
    removals_by_addr: object,
) -> cython.longlong:
    """Remove proven carriers in place; return how many assignments were removed."""
    statements: object
    removed_assignment_count = 0
    if not removals_by_addr:
        return removed_assignment_count
    removal_ids = {
        id(carrier)
        for carriers in builtins.iter(removals_by_addr.values())
        for carrier in iter(carriers)
    }
    for statements in statement_lists:
        if not any(id(statement) in removal_ids for statement in iter(statements)):
            continue
        kept: list[object] = [
            statement
            for statement in iter(statements)
            if id(statement) not in removal_ids
        ]
        removed_assignment_count += len(statements) - len(kept)
        statements[:] = kept
    return removed_assignment_count


def _remove_superseded_far_return_sp_8616(statement_lists, approved_sites) -> int:
    """Replace adjacent native SP publication only at a byte-proved RETF."""
    removed = 0
    for statements in statement_lists:
        for index in range(len(statements) - 1, 0, -1):
            effect, candidate = statements[index], statements[index - 1]
            if not isinstance(effect, structured_c.CAssignment) or not isinstance(candidate, structured_c.CAssignment):
                continue
            site = _statement_instruction_addr_8616(effect)
            cleanup = effect.tags.get("inertia_word_far_return_cleanup")
            if site not in approved_sites or type(cleanup) is not int:
                continue
            if (
                _statement_instruction_addr_8616(candidate) != site
                or not isinstance(candidate.lhs, structured_c.CVariable)
                or runtime_gp_name_for_variable_8616(candidate.lhs.variable) != "esp"
                or "inertia_word_far_return_cleanup" in candidate.tags
            ):
                continue
            del statements[index - 1]
            removed += 1
    return removed


def _replace_near_return_sp_8616(project, statement_lists, terminal_rets) -> int:
    """Give the typed effect the original SP write's position."""
    count = 0
    key = "inertia_word_near_return_cleanup"
    for statements in statement_lists:
        for index in range(len(statements) - 1, -1, -1):
            effect = statements[index]
            if not isinstance(effect, structured_c.CAssignment) or key not in effect.tags:
                continue
            site = _statement_instruction_addr_8616(effect)
            if site not in terminal_rets:
                continue
            try:
                opcode = bytes(project.loader.memory.load(site, 1))
                encoding = bytes(project.loader.memory.load(site, 3)) if opcode == b"\xc2" else opcode
            except (KeyError, ValueError):
                continue
            layout = WordNearReturnLayout8616.from_encoding(encoding)
            if layout is None or layout.cleanup != effect.tags[key]:
                continue
            prior = [
                i for i, candidate in enumerate(statements[:index])
                if isinstance(candidate, structured_c.CAssignment)
                and _statement_instruction_addr_8616(candidate) == site
                and key not in candidate.tags
                and isinstance(candidate.lhs, structured_c.CVariable)
                and runtime_gp_name_for_variable_8616(candidate.lhs.variable) == "esp"
            ]
            if len(prior) == 1:
                statements[prior[0]] = effect
                del statements[index]
                count += 1
    return count


@cython.ccall
def consume_terminal_far_return_boundary_carriers_8616(project: object, codegen: object) -> cython.bint:
    """Remove exact terminal far-return CS carriers proven by complete evidence.

    A candidate is one Alias-refused CS stack restore with no in-function save
    pair: the RETF frame pop itself. It is consumed only when the restore
    instruction is a block-terminal RET, the decoded terminal evidence agrees
    on an unprefixed 16-bit far return frame, and the structured
    assignment at that instruction carries exactly the CS state. Anything less
    refuses and keeps the carrier.
    """
    prior: object
    boundary = cast(_FarReturnBoundaryCodegen8616, codegen)
    try:
        artifact = boundary._inertia_segment_stack_restore_artifact
        ir_artifact = boundary._inertia_vex_ir_artifact
        root = boundary.cfunc.statements
    except AttributeError:
        return False
    if not isinstance(artifact, SegmentStackRestoreArtifact8616):
        return False
    candidates = _far_return_candidate_addrs_8616(artifact)
    terminal_rets = terminal_ret_instruction_addrs_8616(ir_artifact)
    prior = getattr(
        boundary,
        "_inertia_far_return_boundary_consumed_restores_8616",
        frozenset(),
    )
    typed_prior: object = prior if isinstance(prior, frozenset) else frozenset()
    statement_lists = _statement_lists_8616(root)
    removed_near_sp = _replace_near_return_sp_8616(project, statement_lists, terminal_rets)
    classification = _classify_far_return_candidates_8616(
        project,
        candidates,
        terminal_rets,
        _assignments_by_address_8616(statement_lists),
        typed_prior,
    )
    removed_assignment_count = _remove_proven_cs_carriers_8616(
        statement_lists,
        classification.removals_by_addr,
    )

    consumed = frozenset(
        typed_prior | set(classification.removals_by_addr) | classification.already
    )
    removed_sp_count = _remove_superseded_far_return_sp_8616(
        statement_lists, set(classification.removals_by_addr) | classification.already,
    )
    stats = FarReturnBoundaryCarrierStats8616(
        raw_fact_count=len(candidates),
        normalized_fact_count=len(candidates),
        classified_fact_count=len(classification.removals_by_addr) + len(classification.already),
        materialized_count=len(classification.removals_by_addr),
        already_materialized_count=len(classification.already),
        failure_count=0,
        removed_assignment_count=removed_assignment_count,
        refusals=tuple(sorted(tuple(classification.refusals.items()))),
    )
    boundary._inertia_far_return_boundary_consumed_restores_8616 = consumed
    boundary._inertia_terminal_word_far_return_layouts_8616 = tuple(
        (address, layout)
        for address in sorted(set(classification.removals_by_addr) | classification.already)
        if (layout := _loaded_word_far_return_layout_8616(project, address)) is not None
    )
    boundary._inertia_far_return_boundary_carrier_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_FAR_RETURN_BOUNDARY"):
        logging.getLogger(__name__).warning(
            "[far-return-boundary] consumed=%s stats=%s",
            tuple(sorted(consumed)),
            stats,
        )
    return removed_assignment_count + removed_sp_count + removed_near_sp > 0
