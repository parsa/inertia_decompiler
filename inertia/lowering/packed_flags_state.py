# cython: language_level=3, infer_types=True
"""Lower proven packed-FLAGS entry dependencies to explicit runtime state.

Layer: Types/Lowering.
Responsibility: initialize exact packed-FLAGS SSA roots and inputs consumed by
updates whose frontend evidence proves preservation of architectural bits.

The live-in owner inventory is lowering evidence, not an unconditional DCE
root. Backward liveness retains an initializer while a proven consumer remains;
fixed-point cleanup may remove the initializer after its complete packed-FLAGS
chain becomes dead. Final projection replay rematerializes only still-consumed
live-ins.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

import copy
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from inertia.ir.status_flag_lift_context import (
    StatusFlagLiftArtifact8616,
    active_status_flag_lift_artifact_8616,
    resolve_status_flag_lift_artifact_8616,
)
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.semantics.expression_analysis import (
    VirtualValueIdentityKind8616,
    describe_virtual_value_identity_8616,
)

from .global_declarations import GlobalDeclarationCType8616, record_global_declaration_spec_8616
from .physical_registers import physical_register_view_8616
import dataclasses
import operator
import builtins

__all__ = ["PackedFlagsStateStats8616", "lower_packed_flags_live_in_8616"]

_RUNTIME_FLAGS_ADDRESS_8616 = 0x1_0018
_RUNTIME_FLAGS_NAME_8616 = "inertia_flags"


def packed_flags_exit_assignment_8616(
    codegen: object, function_addr: int, value: structured_c.CExpression,
) -> structured_c.CAssignment:
    """Publish the reaching packed FLAGS value at a structured exit."""
    record_global_declaration_spec_8616(
        codegen, ctype=GlobalDeclarationCType8616.UNSIGNED_SHORT,
        name=_RUNTIME_FLAGS_NAME_8616, array_len=None,
    )
    target = structured_c.CVariable(
        SimMemoryVariable(
            _RUNTIME_FLAGS_ADDRESS_8616, 2, name=_RUNTIME_FLAGS_NAME_8616,
            region=function_addr, category="inertia_flags_state",
        ),
        variable_type=SimTypeShort(False), codegen=codegen,
    )
    return structured_c.CAssignment(target, value, codegen=codegen)


def publish_loop_packed_flags_8616(codegen):
    """Publish a retained packed update before an effectful loop back edge."""
    if os.getenv("INERTIA_EXPERIMENTAL_FLAGS_EXIT_USE") != "1":
        return False
    function = codegen.cfunc
    flags_shape = codegen.project.arch.registers.get("flags")
    if function is None or flags_shape is None:
        return False
    artifact = active_status_flag_lift_artifact_8616(function.addr)
    if artifact is None:
        resolution = resolve_status_flag_lift_artifact_8616(codegen.project, function.addr)
        artifact = resolution.artifact if resolution is not None else None
    if artifact is None:
        return False
    from .call_stack_input_contracts import call_stack_context_layout_8616

    def call_free(node):
        return not any(isinstance(item, structured_c.CFunctionCall)
                       for item in _iter_c_nodes_deep_8616(node))

    def sequence(node):
        if isinstance(node, structured_c.CStatements):
            for stmt in node.statements:
                yield from sequence(stmt)
        else:
            yield node

    changed = False
    for loop in tuple(_iter_c_nodes_deep_8616(function.statements)):
        if not isinstance(loop, structured_c.CDoWhileLoop) or not isinstance(loop.body, structured_c.CStatements):
            continue
        statements = tuple(sequence(loop.body))
        if len(statements) < 2 or not call_free(loop.condition):
            continue
        update = statements[-1]
        if not isinstance(update, structured_c.CAssignment):
            continue
        identity = _identity_8616(update.lhs)
        if identity is None or identity[:2] != tuple(flags_shape[:2]):
            continue
        site = update.tags.get("ins_addr")
        if site not in artifact.packed_preservation_addresses:
            continue
        # Only a straight-line update suffix following a single owned CALL is
        # supported here. Its preserved bits must come from post-call FLAGS.
        if any(not isinstance(stmt, structured_c.CAssignment) for stmt in statements[:-1]):
            continue
        wrappers = [node for stmt in statements[:-1] for node in _iter_c_nodes_deep_8616(stmt)
                    if isinstance(node, structured_c.CMultiStatementExpression)
                    and call_stack_context_layout_8616(node) is not None]
        if len(wrappers) != 1 or statements[0].rhs is not wrappers[0]:
            continue
        if not all(call_free(stmt) for stmt in statements[1:]):
            continue
        rhs = update.rhs
        if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Or":
            continue
        preserved = rhs.lhs
        if (not isinstance(preserved, structured_c.CBinaryOp) or preserved.op != "And"
            or not isinstance(preserved.rhs, structured_c.CConstant)
            or (_identity_8616(preserved.lhs) or ())[:2] != tuple(flags_shape[:2])
            or _flags_inputs_8616(rhs.rhs, flags_shape[:2])):
            continue
        publish = packed_flags_exit_assignment_8616(codegen, function.addr, update.lhs)
        preserved.lhs = publish.lhs
        loop.body.statements.append(publish)
        changed = True
    return changed


class _FlagsArch8616(Protocol):
    """Architecture register map consumed at the third-party boundary."""

    registers: Mapping[str, tuple[cython.longlong, cython.longlong]]


class _FlagsProject8616(Protocol):
    """Project architecture consumed by packed-FLAGS lowering."""

    arch: _FlagsArch8616


class _FlagsCFunction8616(Protocol):
    """Structured function surface mutated by packed-FLAGS lowering."""

    addr: cython.longlong
    statements: object


class _FlagsCodegen8616(Protocol):
    """Dynamic codegen boundary consumed by packed-FLAGS lowering."""

    project: _FlagsProject8616 | None
    cfunc: _FlagsCFunction8616 | None
    _inertia_packed_flags_state_stats_8616: PackedFlagsStateStats8616
    _inertia_packed_flags_state_live_ins_8616: object


@dataclasses.dataclass(frozen=True, )
class PackedFlagsStateStats8616:
    """Closed evidence counters for packed-FLAGS live-in materialization."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong


@cython.ccall
def _identity_8616(node: object) -> object:
    """Return one exact structured register SSA identity."""
    identity: object
    view: object
    if isinstance(node, structured_c.CDirtyExpression):
        view = physical_register_view_8616(node)
        identity = describe_virtual_value_identity_8616(node)
        if (
            view is None
            or identity is None
            or identity.kind is not VirtualValueIdentityKind8616.VARIABLE_ID
        ):
            return None
        return view.reg_offset, view.width, 0, identity.value
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if not (
        isinstance(variable, SimRegisterVariable)
        and isinstance(variable.reg, int)
        and isinstance(variable.size, int)
        and isinstance(variable.region, int)
        and isinstance(variable.ident, (int, str))
    ):
        return None
    return variable.reg, variable.size, variable.region, variable.ident


@cython.ccall
def _flags_inputs_8616(
    root: object,
    flags_shape: object,
) -> object:
    """Return exact packed-FLAGS SSA identities read by one expression."""
    identity: object
    node: object
    inputs: dict[tuple[cython.longlong, cython.longlong, cython.longlong, int | str], structured_c.CExpression] = {}
    for node in _iter_c_nodes_deep_8616(root):
        identity = _identity_8616(node)
        if identity is not None and operator.eq(identity[:2], flags_shape):
            inputs.setdefault(identity, node)
    return inputs


_FlagsIdentity8616 = tuple[int, int, int, int | str]


def _lift_candidates_8616(
    statements: structured_c.CStatement,
    artifact: StatusFlagLiftArtifact8616,
    flags_shape: object,
) -> object:
    """Collect FLAGS-input exemplars at artifact-covered instruction sites."""
    instruction_addr: object
    lhs_identity: object
    node: object
    candidates: dict[_FlagsIdentity8616, structured_c.CExpression] = {}
    defined_identities: set[_FlagsIdentity8616] = set()
    definition_counts: dict[_FlagsIdentity8616, cython.longlong] = {}
    self_dependent_roots: dict[_FlagsIdentity8616, structured_c.CExpression] = {}
    # A packed update may already have been folded into a condition.
    # Scan structured reads as well as assignment RHSs, then subtract
    # locally defined identities before selecting entry roots.
    all_inputs = _flags_inputs_8616(statements, flags_shape)
    for node in _iter_c_nodes_deep_8616(statements):
        if not isinstance(node, structured_c.CAssignment):
            continue
        lhs_identity = _identity_8616(node.lhs)
        if lhs_identity is not None and operator.eq(lhs_identity[:2], flags_shape):
            defined_identities.add(lhs_identity)
            definition_counts[lhs_identity] = definition_counts.get(lhs_identity, 0) + 1
        rhs_inputs = _flags_inputs_8616(node.rhs, flags_shape)
        all_inputs.update(rhs_inputs)
        if lhs_identity is not None and lhs_identity in rhs_inputs:
            self_dependent_roots.setdefault(lhs_identity, rhs_inputs[lhs_identity])
        instruction_addr = node.tags.get("ins_addr")
        if (
            not isinstance(instruction_addr, int)
            or not artifact.covers_packed_preservation_8616(instruction_addr)
        ):
            continue
        candidates.update(rhs_inputs)
    candidates.update(
        (identity, exemplar)
        for identity, exemplar in builtins.iter(all_inputs.items())
        if identity not in defined_identities
    )
    candidates.update(
        (identity, exemplar)
        for identity, exemplar in builtins.iter(self_dependent_roots.items())
        if definition_counts.get(identity) == 1
    )
    return candidates


@cython.ccall
def _existing_flag_identities_8616(
    statements: structured_c.CStatement,
) -> set[_FlagsIdentity8616 | None]:
    """Return identities already bound to a runtime FLAGS-state variable."""
    return {
        _identity_8616(node.lhs)
        for node in builtins.iter(_iter_c_nodes_deep_8616(statements))
        if isinstance(node, structured_c.CAssignment)
        and isinstance(node.rhs, structured_c.CVariable)
        and isinstance(node.rhs.variable, SimMemoryVariable)
        and node.rhs.variable.category == "inertia_flags_state"
    }


def _materialize_flag_initializers_8616(
    codegen: object,
    cfunc: _FlagsCFunction8616,
    candidates: object,
    existing: object,
) -> cython.longlong:
    """Insert runtime FLAGS initializers for candidates not already bound."""
    exemplar: object
    identity: object
    materialized = 0
    initializers: list[structured_c.CAssignment] = []
    for identity, exemplar in sorted(tuple(candidates.items()), key=lambda item: repr(item[0])):
        if identity in existing:
            continue
        lhs = copy.copy(exemplar)
        rhs = structured_c.CVariable(
            SimMemoryVariable(
                _RUNTIME_FLAGS_ADDRESS_8616,
                2,
                name=_RUNTIME_FLAGS_NAME_8616,
                region=cfunc.addr,
                category="inertia_flags_state",
            ),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
        initializers.append(structured_c.CAssignment(lhs, rhs, codegen=codegen))
        materialized += 1
    if initializers:
        if isinstance(cfunc.statements, structured_c.CStatements):
            from .entry_stack_pointer_capture import is_entry_stack_pointer_capture_8616

            statements = cfunc.statements.statements
            after_capture = int(bool(statements) and is_entry_stack_pointer_capture_8616(statements[0]))
            statements[after_capture:after_capture] = initializers
        else:
            cfunc.statements = structured_c.CStatements(
                list(initializers) + [cfunc.statements],
                codegen=codegen,
            )
    return materialized


@cython.ccall
def _flags_live_in_owners_8616(statements: structured_c.CStatement) -> tuple[object, ...]:
    """Collect owners of every runtime FLAGS-state assignment."""
    node: object
    live_in_owners: list[object] = []
    for node in _iter_c_nodes_deep_8616(statements):
        if not (
            isinstance(node, structured_c.CAssignment)
            and isinstance(node.rhs, structured_c.CVariable)
            and isinstance(node.rhs.variable, SimMemoryVariable)
            and node.rhs.variable.category == "inertia_flags_state"
        ):
            continue
        live_in_owners.append(node.lhs)
        if isinstance(node.lhs, structured_c.CVariable) and isinstance(node.lhs.variable.ident, (int, str)):
            live_in_owners.append(node.lhs.variable.ident)
    return tuple(live_in_owners)


def _debug_packed_flags_8616(
    cfunc: _FlagsCFunction8616,
    artifact: StatusFlagLiftArtifact8616,
    flags_shape: object,
    candidates: object,
    existing: object,
    stats: PackedFlagsStateStats8616,
) -> None:
    """Emit the optional packed-FLAGS census dump for debugging."""
    logging.getLogger(__name__).warning(
        "[packed-flags-state] function=%#x sites=%s lift_candidates=%s candidates=%s existing=%s stats=%s assignments=%s",
        cfunc.addr,
        tuple(sorted(artifact.packed_preservation_addresses)),
        artifact.candidates,
        tuple(sorted(candidates, key=repr)),
        tuple(sorted((item for item in iter(existing) if item is not None), key=repr)),
        stats,
        tuple(
            (
                _identity_8616(node.lhs),
                node.tags.get("ins_addr"),
                tuple(sorted(tuple(_flags_inputs_8616(node.rhs, flags_shape)), key=repr)),
            )
            for node in builtins.iter(_iter_c_nodes_deep_8616(cfunc.statements))
            if isinstance(node, structured_c.CAssignment)
            and operator.eq((_identity_8616(node.lhs) or (None, None))[:2], flags_shape)
        ),
    )


@cython.ccall
def lower_packed_flags_live_in_8616(codegen: object) -> cython.bint:
    """Initialize proven packed-FLAGS update inputs from runtime FLAGS."""
    artifact: object
    cfunc: object
    project: object
    resolution: object
    shape: object
    boundary = cast(_FlagsCodegen8616, codegen)
    boundary._inertia_packed_flags_state_live_ins_8616 = ()
    project = boundary.project
    cfunc = boundary.cfunc
    empty = PackedFlagsStateStats8616(0, 0, 0, 0, 0)
    if (
        project is None
        or cfunc is None
        or not isinstance(cfunc.statements, structured_c.CStatement)
    ):
        boundary._inertia_packed_flags_state_stats_8616 = empty
        return False
    shape = project.arch.registers.get("flags")
    artifact = active_status_flag_lift_artifact_8616(cfunc.addr)
    if artifact is None:
        resolution = resolve_status_flag_lift_artifact_8616(project, cfunc.addr)
        artifact = resolution.artifact if resolution is not None else None
    if shape is None or len(shape) < 2 or artifact is None:
        boundary._inertia_packed_flags_state_stats_8616 = empty
        return False
    flags_shape = shape[:2]
    statements = cfunc.statements
    candidates = _lift_candidates_8616(statements, artifact, flags_shape)
    existing = _existing_flag_identities_8616(statements)
    materialized = _materialize_flag_initializers_8616(
        codegen, cfunc, candidates, existing
    )
    if materialized:
        record_global_declaration_spec_8616(
            codegen,
            ctype=GlobalDeclarationCType8616.UNSIGNED_SHORT,
            name=_RUNTIME_FLAGS_NAME_8616,
            array_len=None,
        )
    boundary._inertia_packed_flags_state_live_ins_8616 = _flags_live_in_owners_8616(
        cfunc.statements
    )
    count = len(candidates)
    boundary._inertia_packed_flags_state_stats_8616 = PackedFlagsStateStats8616(
        count,
        count,
        count,
        materialized,
        count - materialized if not existing else 0,
    )
    if os.environ.get("INERTIA_DEBUG_PACKED_FLAGS") == "1":
        _debug_packed_flags_8616(
            cfunc,
            artifact,
            flags_shape,
            candidates,
            existing,
            boundary._inertia_packed_flags_state_stats_8616,
        )
    return materialized > 0
