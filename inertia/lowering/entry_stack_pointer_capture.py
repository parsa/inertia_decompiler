# cython: language_level=3, infer_types=True
"""Capture one architectural entry-SP scalar for independent Types consumers.

Layer: Types/Lowering.
Responsibility: own the dominating immutable word capture, exact runtime input
expression and source-bound use census shared by return and call consumers.
Every retained use is freshly reproduced; a marker never supplies authority.
Consumes alias, widening, and typed facts
Do not recover semantics from COD, source, assembly, or rendered C text
"""
from __future__ import annotations

import builtins
import dataclasses
import logging
import operator
import os
import typing
from collections.abc import MutableMapping
from enum import StrEnum
from typing import Protocol, cast

import cython
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimType, SimTypeInt, SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimTemporaryVariable, SimVariable

from inertia.alias.call_stack_positions import (
    CallStackPosition8616,
    call_stack_position_is_current_8616,
)
from inertia.alias.numeric_stack_pointer_values import (
    TerminalStackPointerInput8616,
    prove_terminal_stack_pointer_input_8616,
)
from inertia.alias.scoped_call_stack_context import ScopedCallStackContext8616
from inertia.alias.scoped_call_stack_positions import (
    ScopedCallStackPositionResult8616,
    prove_scoped_call_stack_position_8616,
)
from inertia.alias.segment_stack_restore import (
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
    build_x86_16_stack_register_restore_artifact_8616,
)
from inertia.ir.core import IRFunctionArtifact
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.semantics.numeric_stack_pointer_returns import (
    NumericStackPointerReturn8616,
    prove_numeric_stack_pointer_return_8616,
)

from .c_ast_utils import _iter_c_node_occurrences_8616, _iter_c_nodes_deep_8616
from .gp_register_state import (
    _record_runtime_gp_global_8616,
    runtime_gp_state_expr_8616,
)

_CAPTURE_TAG = "inertia_entry_sp_capture_8616"


def is_entry_stack_pointer_capture_8616(node: object) -> bool:
    """Identify a capture owner for passes inserting other entry initializers."""
    return isinstance(node, c.CAssignment) and isinstance(
        node.tags.get(_CAPTURE_TAG), EntryStackPointerCapture8616,
    )
_WORD_MASK = 0xffff


class ScopedCallPositionAuthority8616:
    """Read-only scoped authority; projections never replace live Alias proof.

    A plain class, never a dataclass: ``dataclasses.asdict`` must not recurse
    the retained project/domain runtime objects. It retains a single
    ``ScopedCallStackPositionResult8616`` — the only source of coordinates
    and proof ownership — and projects it read-only. Copying retains the live
    handle; diagnostics are handled explicitly by the snapshot encoder.
    """

    __slots__ = ("_result",)

    def __init__(self, result: ScopedCallStackPositionResult8616) -> None:
        """Retain the single source of coordinates and proof ownership."""
        self._result = result

    @property
    def result(self) -> ScopedCallStackPositionResult8616:
        """Return the retained Alias publication without a separate scalar state."""
        return self._result

    @property
    def position(self) -> CallStackPosition8616 | None:
        """Project coordinates for layout; consumption still requires revalidation."""
        return self.result.proof

    def _identity_key(self) -> tuple[CallStackPosition8616 | None, cython.longlong, cython.longlong, cython.longlong, cython.longlong, cython.longlong, cython.longlong]:
        """Distinguish proof ownership even when all scalar coordinates agree."""
        result = self.result
        return (self.position, id(result.artifact), id(result.call), id(result.carrier),
                id(result.caller_scope), id(result.callee_scope), id(result.context))

    def __eq__(self, other: object) -> cython.bint:
        """Compare coordinates and every retained provenance identity."""
        return type(other) is ScopedCallPositionAuthority8616 and operator.eq(self._identity_key(), other._identity_key())

    def __hash__(self) -> cython.longlong:
        """Use the same live provenance identity as equality."""
        return hash(self._identity_key())

    def __copy__(self) -> ScopedCallPositionAuthority8616:
        """Keep the live authority when copying syntax in this process."""
        return self

    def __deepcopy__(self, memo: object) -> ScopedCallPositionAuthority8616:
        """Copy syntax without cloning or downgrading its proof capability."""
        memo[id(self)] = self
        return self

    def __repr__(self) -> str:
        """Keep runtime project and domain objects out of diagnostics."""
        return f"ScopedCallPositionAuthority8616(position={self.position!r})"

    def is_current_for(
        self, source: IRFunctionArtifact, *,
        scoped_context: object,
        scoped_caller_scope: Real16InvocationDomain8616 | None,
    ) -> cython.bint:
        """Authenticate retained and offered proof contexts against current Alias."""
        binding: object
        position: object
        result, position = self.result, self.position
        if position is None or result.artifact is not source:
            return False
        if scoped_context is None or type(scoped_context) is not ScopedCallStackContext8616:
            return False
        binding = scoped_context.for_callsite(position.callsite_addr)
        if binding is None or binding.carrier is not result.carrier:
            return False
        if operator.ne(result.position_for(scoped_caller_scope, binding.callee_scope), position):
            return False
        if scoped_context is result.context:
            return True
        fresh = prove_scoped_call_stack_position_8616(
            source, result.block_addr, result.instruction_index,
            scoped_caller_scope, binding.callee_scope, context=scoped_context,
        )
        return fresh.failure is None and operator.eq(fresh.proof, position)


EntryStackPointerUse8616 = typing.TypeAliasType("EntryStackPointerUse8616", (
    NumericStackPointerReturn8616
    | TerminalStackPointerInput8616
    | CallStackPosition8616
    | ScopedCallPositionAuthority8616
    | SegmentStackRestoreFact8616
))


class EntryStackPointerCaptureFailure8616(StrEnum):
    """Source or storage defects preventing a shared architectural capture."""

    SOURCE_CHANGED = "source_changed"
    FUNCTION_SCOPE_MISMATCH = "function_scope_mismatch"
    INVALID_CAPTURE = "invalid_capture"
    NO_ENTRY_SEQUENCE = "no_entry_sequence"


@dataclasses.dataclass(frozen=True, )
class EntryStackPointerCapture8616:
    """Candidate capture scope and uses; current source and initializer must verify."""

    function_addr: cython.longlong
    uses: object


@dataclasses.dataclass(frozen=True, )
class EntryStackPointerCaptureResult8616:
    """Closed outcome of one capture request without serializing native objects."""

    value: c.CVariable | None
    changed_count: cython.longlong
    source_proven: cython.bint
    failure: EntryStackPointerCaptureFailure8616 | None

    def to_dict(self) -> dict[str, object]:
        """Expose the source-to-storage census and typed failure to diagnostics."""
        return {
            "raw_fact_count": 1, "normalized_fact_count": 1,
            "classified_fact_count": int(self.source_proven),
            "materialized_count": int(self.value is not None),
            "failure_count": int(self.failure is not None),
            "changed_count": self.changed_count,
            "failure": self.failure.value if self.failure is not None else None,
        }


class _VariableManager8616(Protocol):
    """Native variable type publication boundary used by scalar capture."""

    def set_variable_type(self, variable: SimVariable, type_: SimType) -> None:
        """Register a newly materialized local with its exact storage type."""

    def get_variable_type(self, variable: SimVariable) -> SimType | None:
        """Read the actual local declaration used by native code generation."""
        ...



class StackPointerCaptureFunction8616(Protocol):
    """Native function declaration and entry-sequence boundary."""

    addr: cython.longlong
    statements: object
    variables_in_use: MutableMapping[SimVariable, c.CVariable]
    variable_manager: _VariableManager8616

    def refresh(self) -> None:
        """Rebuild local declarations after storage publication."""



@cython.ccall
def _unsigned_width(expression: c.CExpression, bits: cython.longlong) -> cython.bint:
    """Check an architecture-bound native unsigned scalar type."""
    type_ = expression.type
    return (isinstance(type_, SimTypeInt) and not type_.signed
            and type_._arch is not None and operator.eq(type_.size, bits))



@cython.ccall
def is_plain_integer_literal_8616(node: object, value: object) -> cython.bint:
    """Reject metadata that can change the integer emitted by angr."""
    if not isinstance(node, c.CConstant) or type(node) is not c.CConstant:
        return False
    if (type(node.value) is not int or not operator.eq(node.value, value)
            or node.reference_values is not None or node.collapsed
            or type(node.type) not in (SimTypeShort, SimTypeInt, SimTypeLong)):
        return False
    return not (getattr(node.codegen, "const_formats", None)
                and (node.fmt_neg or node.fmt_char or node.fmt_float or node.fmt_double))


@cython.ccall
def matches_entry_runtime_read_8616(actual: object, expected: object, depth: cython.longlong = 0) -> cython.bint:
    """Validate only the canonical runtime helper's bounded expression shape."""
    if depth > 3 or type(actual) is not type(expected):
        return False
    if isinstance(actual, c.CVariable) and isinstance(expected, c.CVariable):
        left, right = actual.variable, expected.variable
        return (isinstance(left, SimMemoryVariable) and isinstance(right, SimMemoryVariable)
                and actual.unified_variable is None and _unsigned_width(actual, 32)
                and (left.addr, left.size, left.name, left.region, left.category, left.ident)
                == (right.addr, right.size, right.name, right.region, right.category, right.ident))
    if isinstance(actual, c.CConstant) and isinstance(expected, c.CConstant):
        return is_plain_integer_literal_8616(actual, expected.value) and _unsigned_width(actual, 32)
    if isinstance(actual, c.CBinaryOp) and isinstance(expected, c.CBinaryOp):
        return (operator.eq(actual.op, expected.op)
                and matches_entry_runtime_read_8616(actual.lhs, expected.lhs, depth + 1)
                and matches_entry_runtime_read_8616(actual.rhs, expected.rhs, depth + 1))
    return False



@cython.ccall
def matches_entry_sp_local_8616(node: object, value: c.CVariable) -> cython.bint:
    """Match exact local temporary storage, never an architectural register name."""
    return (isinstance(node, c.CVariable) and isinstance(node.variable, SimTemporaryVariable)
            and isinstance(value.variable, SimTemporaryVariable)
            and operator.eq(node.variable.tmp_id, value.variable.tmp_id)
            and operator.eq(node.name, value.name)
            and node.variable.size == value.variable.size == 2
            and node.unified_variable is None and _unsigned_width(node, 16))



def _capture_is_immutable(root: object, assignment: c.CAssignment) -> cython.bint:
    """Require one dominating definition and no address-taking of the local."""
    node: object
    value = assignment.lhs
    if not isinstance(value, c.CVariable) or not matches_entry_sp_local_8616(value, value):
        return False
    writes = [node for node in builtins.iter(_iter_c_node_occurrences_8616(root))
              if isinstance(node, c.CAssignment) and matches_entry_sp_local_8616(node.lhs, value)]
    if writes != [assignment]:
        return False
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, c.CUnaryOp) and any(
            matches_entry_sp_local_8616(child, value) for child in builtins.iter(_iter_c_nodes_deep_8616(node))
        ):
            return False
    return True



@cython.ccall
def entry_stack_pointer_projection_8616(value: c.CVariable, offset: cython.longlong, codegen: object) -> c.CBinaryOp:
    """Emit exact modulo-16 addition without signed promotion or pointer recovery."""
    wide = SimTypeLong(False)
    added = c.CBinaryOp("Add", value, c.CConstant(offset & _WORD_MASK, wide, codegen=codegen), codegen=codegen)
    return c.CBinaryOp("And", added, c.CConstant(_WORD_MASK, wide, codegen=codegen), codegen=codegen)



@cython.ccall
def is_entry_stack_pointer_projection_8616(expression: object, value: c.CVariable, offset: cython.longlong) -> cython.bint:
    """Recognize only an already materialized exact owned scalar projection."""
    if not isinstance(expression, c.CBinaryOp) or expression.op != "And":
        return False
    added, mask = expression.lhs, expression.rhs
    if not isinstance(added, c.CBinaryOp) or added.op != "Add":
        return False
    delta = added.rhs
    return (is_plain_integer_literal_8616(mask, _WORD_MASK)
            and is_plain_integer_literal_8616(delta, offset & _WORD_MASK)
            and matches_entry_sp_local_8616(added.lhs, value) and _unsigned_width(mask, 32)
            and _unsigned_width(delta, 32))



@cython.ccall
def _existing_capture_value_8616(
    function: StackPointerCaptureFunction8616, assignment: c.CAssignment, expected: c.CExpression,
) -> c.CVariable | None:
    """Authenticate the initializer and storage without changing native state."""
    root = function.statements
    marker = assignment.tags[_CAPTURE_TAG]
    if (not isinstance(root, c.CStatements) or not root.statements
            or root.statements[0] is not assignment):
        return None
    if (not isinstance(marker, EntryStackPointerCapture8616)
            or operator.ne(marker.function_addr, function.addr) or not matches_entry_runtime_read_8616(assignment.rhs, expected)
            or not _capture_is_immutable(root, assignment)):
        return None
    return cast(c.CVariable, assignment.lhs)


def _prepare_entry_capture(
    codegen: object, function: StackPointerCaptureFunction8616, nodes: object,
    captures: object, ordered_proofs: object,
) -> tuple[c.CVariable | None, cython.longlong, EntryStackPointerCaptureFailure8616 | None]:
    """Verify an existing entry capture or publish one fresh scalar local."""
    expected: object
    value: object
    root = function.statements
    expected = runtime_gp_state_expr_8616("sp", codegen=codegen, function_addr=function.addr)
    if expected is None:
        return None, 0, EntryStackPointerCaptureFailure8616.NO_ENTRY_SEQUENCE
    if captures:
        assignment = captures[0]
        marker = assignment.tags[_CAPTURE_TAG]
        value = _existing_capture_value_8616(function, assignment, expected)
        if value is None or not isinstance(marker, EntryStackPointerCapture8616):
            return None, 0, EntryStackPointerCaptureFailure8616.INVALID_CAPTURE
        changed = int(operator.ne(marker.uses, ordered_proofs))
        if changed:
            assignment.tags[_CAPTURE_TAG] = EntryStackPointerCapture8616(function.addr, ordered_proofs)
    else:
        if not isinstance(root, c.CStatement):
            return None, 0, EntryStackPointerCaptureFailure8616.NO_ENTRY_SEQUENCE
        used = {node.variable.tmp_id for node in iter(nodes)
                if isinstance(node, c.CVariable) and isinstance(node.variable, SimTemporaryVariable)}
        used.update(var.tmp_id for var in iter(function.variables_in_use) if isinstance(var, SimTemporaryVariable))
        temporary = SimTemporaryVariable(max(used, default=-1) + 1, 2)
        word_type = SimTypeShort(False)
        value = c.CVariable(temporary, variable_type=word_type, codegen=codegen)
        assignment = c.CAssignment(value, expected, codegen=codegen,
                                  tags={_CAPTURE_TAG: EntryStackPointerCapture8616(function.addr, ordered_proofs)})
        if isinstance(root, c.CStatements):
            root.statements = [assignment, *root.statements]
        else:
            function.statements = c.CStatements([assignment, root], codegen=codegen)
        function.variables_in_use[temporary] = value
        assert value.variable_type is not None
        function.variable_manager.set_variable_type(temporary, value.variable_type)
        _record_runtime_gp_global_8616(codegen, "esp")
        changed = 1
    return value, changed, None



class _CodegenCapture8616(Protocol):
    """Native codegen boundary retaining its active function declaration."""

    cfunc: StackPointerCaptureFunction8616 | None
    _inertia_vex_ir_artifact: IRFunctionArtifact | None


@cython.ccall
def _published_source_is_current_8616(codegen: object, source: IRFunctionArtifact) -> cython.bint:
    """Require the current source publication at the dynamic native boundary."""
    try:
        published = cast(_CodegenCapture8616, codegen)._inertia_vex_ir_artifact
    except AttributeError:
        return False
    return published is source


@cython.ccall
def _use_position(use: EntryStackPointerUse8616) -> CallStackPosition8616 | None:
    """Project scalar coordinates for ordering; never authority by itself."""
    if isinstance(use, ScopedCallPositionAuthority8616):
        return use.position
    if isinstance(use, CallStackPosition8616):
        return use
    return None


@cython.ccall
def _use_order(use: EntryStackPointerUse8616) -> tuple[cython.longlong, cython.longlong, cython.longlong, cython.longlong, cython.longlong]:
    """Order uniquely reproduced source occurrences without caller iteration order."""
    position: object
    if isinstance(use, NumericStackPointerReturn8616):
        assignment = use.assignment
        return (0, assignment.block_addr, assignment.instruction_index, assignment.instruction_addr, use.path.return_addr)
    if isinstance(use, TerminalStackPointerInput8616):
        return (2, use.block_addr, 0, use.instruction_addr, 0)
    if isinstance(use, SegmentStackRestoreFact8616):
        return (3, use.block_addr, use.saved_instruction_addr or 0, use.restore_instruction_addr, 0)
    position = _use_position(use)
    if position is None:
        return (2, 0, 0, 0, 0)
    return (1, position.block_addr, position.instruction_index, position.callsite_addr, position.target_addr)


@cython.ccall
def _use_is_current(
    source: IRFunctionArtifact,
    use: EntryStackPointerUse8616,
    scoped_context: ScopedCallStackContext8616 | None,
    scoped_caller_scope: Real16InvocationDomain8616 | None,
) -> cython.bint:
    """Delegate current authority to the owning source proof, never the marker."""
    if isinstance(use, NumericStackPointerReturn8616):
        current = prove_numeric_stack_pointer_return_8616(source, use.assignment.block_addr, use.path.return_addr)
        return current == use
    if isinstance(use, TerminalStackPointerInput8616):
        return prove_terminal_stack_pointer_input_8616(source, use.block_addr, use.instruction_addr) == use
    if isinstance(use, ScopedCallPositionAuthority8616):
        return use.is_current_for(source, scoped_context=scoped_context,
                                  scoped_caller_scope=scoped_caller_scope)
    if isinstance(use, SegmentStackRestoreFact8616):
        return (use.verdict is SegmentStackRestoreVerdict8616.PROVEN
                and use.saved_instruction_addr is not None
                and use in build_x86_16_stack_register_restore_artifact_8616(
                    source, tracked_registers=frozenset({use.saved_register, use.restore_register}),
                ).facts)
    if not isinstance(use, CallStackPosition8616):
        return False
    return call_stack_position_is_current_8616(source, use)


def _retained_uses(captures: object) -> object:
    """Admit at most one explicit owned marker, preserving every prior consumer."""
    if not captures:
        return ()
    if len(captures) != 1:
        return None
    marker = captures[0].tags[_CAPTURE_TAG]
    if not isinstance(marker, EntryStackPointerCapture8616) or not isinstance(marker.uses, tuple):
        return None
    if not all(isinstance(use, (NumericStackPointerReturn8616, TerminalStackPointerInput8616, CallStackPosition8616,
                                ScopedCallPositionAuthority8616, SegmentStackRestoreFact8616))
               for use in iter(marker.uses)):
        return None
    return marker.uses


def prepare_entry_stack_pointer_capture_8616(
    codegen: object, source: IRFunctionArtifact, uses: object,
    *,
    scoped_context: ScopedCallStackContext8616 | None = None,
    scoped_caller_scope: Real16InvocationDomain8616 | None = None,
) -> EntryStackPointerCaptureResult8616 | None:
    """Share one dominating capture only after all retained and requested uses reprove.

    An empty request observes an existing capture but never creates one. Adding
    a second consumer extends the canonical use census without a second write
    or local variable. Invalidating either consumer invalidates reuse for both.
    Scoped uses revalidate only under the offered binding context and caller
    domain — omitting either keeps every retained scoped use unproven and
    refuses the capture.
    """
    function: object
    retained: object
    value: object
    function = cast(_CodegenCapture8616, codegen).cfunc
    if function is None:
        return None if not uses else EntryStackPointerCaptureResult8616(
            None, 0, False, EntryStackPointerCaptureFailure8616.NO_ENTRY_SEQUENCE,
        )
    nodes = tuple(_iter_c_nodes_deep_8616(function.statements))
    captures = [node for node in iter(nodes) if isinstance(node, c.CAssignment) and _CAPTURE_TAG in node.tags]
    if not captures and not uses:
        return None
    if operator.ne(function.addr, source.function_addr):
        return EntryStackPointerCaptureResult8616(None, 0, False, EntryStackPointerCaptureFailure8616.FUNCTION_SCOPE_MISMATCH)
    if not _published_source_is_current_8616(codegen, source):
        return EntryStackPointerCaptureResult8616(None, 0, False, EntryStackPointerCaptureFailure8616.SOURCE_CHANGED)
    retained = _retained_uses(captures)
    if retained is None:
        return EntryStackPointerCaptureResult8616(None, 0, False, EntryStackPointerCaptureFailure8616.INVALID_CAPTURE)
    combined_uses = {*retained, *uses}
    if not combined_uses or not all(
            _use_is_current(source, use, scoped_context, scoped_caller_scope) for use in iter(combined_uses)):
        return EntryStackPointerCaptureResult8616(None, 0, False, EntryStackPointerCaptureFailure8616.SOURCE_CHANGED)
    combined = tuple(sorted(combined_uses, key=_use_order))
    value, changed, failure = _prepare_entry_capture(codegen, function, nodes, captures, combined)
    if value is not None and changed:
        function.refresh()
    return EntryStackPointerCaptureResult8616(value, changed, True, failure)


@dataclasses.dataclass(frozen=True, )
class EntryStackPointerCaptureObservation8616:
    """Pure validated view for consumers that must never materialize or repair."""

    assignment: c.CAssignment
    value: c.CVariable
    uses: object


def observe_entry_stack_pointer_storage_8616(
    codegen: object, source: IRFunctionArtifact,
) -> c.CVariable | None:
    """Authenticate the immutable input without granting another consumer's scoped authority.

    Use only when the consumer independently proves its own entry-relative position.
    """
    function = cast(_CodegenCapture8616, codegen).cfunc
    if function is None or function.addr != source.function_addr or not _published_source_is_current_8616(codegen, source):
        return None
    captures = [node for node in _iter_c_node_occurrences_8616(function.statements)
                if is_entry_stack_pointer_capture_8616(node)]
    if len(captures) != 1 or not _retained_uses(captures):
        return None
    entry_sp = runtime_gp_state_expr_8616("sp", codegen=codegen, function_addr=function.addr)
    return None if entry_sp is None else _existing_capture_value_8616(function, captures[0], entry_sp)


def observe_entry_stack_pointer_capture_8616(
    codegen: object, source: IRFunctionArtifact,
    *,
    scoped_context: ScopedCallStackContext8616 | None = None,
    scoped_caller_scope: Real16InvocationDomain8616 | None = None,
) -> EntryStackPointerCaptureObservation8616 | None:
    """Reprove the current source and real capture without modifying either.

    Retained scoped uses revalidate only under the offered binding context
    and caller domain; without both a capture carrying scoped evidence
    observes as unproven.
    """
    expected: object
    function: object
    value: object
    function = cast(_CodegenCapture8616, codegen).cfunc
    if function is None or operator.ne(function.addr, source.function_addr) or not _published_source_is_current_8616(codegen, source):
        return None
    captures = [node for node in builtins.iter(_iter_c_nodes_deep_8616(function.statements))
                if isinstance(node, c.CAssignment) and _CAPTURE_TAG in node.tags]
    uses = _retained_uses(captures)
    if (len(captures) != 1 or not uses or not all(
            _use_is_current(source, use, scoped_context, scoped_caller_scope) for use in iter(uses))):
        if captures and os.environ.get("INERTIA_TRACE_CALL_STACK_POSITION") == "1":
            logging.getLogger(__name__).warning(
                "Entry SP capture authority stale: captures=%d uses=%r", len(captures), uses,
            )
        return None
    expected = runtime_gp_state_expr_8616("sp", codegen=codegen, function_addr=function.addr)
    if expected is None:
        return None
    value = _existing_capture_value_8616(function, captures[0], expected)
    if value is None and os.environ.get("INERTIA_TRACE_CALL_STACK_POSITION") == "1":
        assignment = captures[0]
        root = function.statements
        logging.getLogger(__name__).warning(
            "Entry SP capture shape stale: first=%s same_read=%s immutable=%s lhs_type=%s rhs_type=%s expected_type=%s",
            isinstance(root, c.CStatements) and bool(root.statements) and root.statements[0] is assignment,
            matches_entry_runtime_read_8616(assignment.rhs, expected), _capture_is_immutable(root, assignment),
            assignment.lhs.type, assignment.rhs.type, expected.type,
        )
    return None if value is None else EntryStackPointerCaptureObservation8616(captures[0], value, uses)
