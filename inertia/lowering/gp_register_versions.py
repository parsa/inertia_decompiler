# cython: language_level=3, infer_types=True
"""Preserve incoming and defined register values across architectural writes.

Layer: Types/Lowering.
Responsibility: retain exact C register identities before mutable runtime-state
projection. Consume existing typed definitions; never recover from names,
assembly, source sidecars, or rendered C. Ambiguous ordering refuses early.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable, MutableMapping
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CDirtyExpression,
    CExpression,
    CStatement,
    CWhileLoop,
    CStatements,
    CVariable,
)
from angr.sim_type import SimType, SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimTemporaryVariable, SimVariable
from archinfo import Arch

from inertia.lowering.c_ast_utils import (
    _iter_c_node_occurrences_8616,
    _iter_c_nodes_deep_8616,
    _replace_c_children_8616,
)
from inertia.pipeline.errors import PipelineHardError

from .gp_register_entry_flow import build_gp_entry_flow_8616
from .stack_value_projection import project_pointer_storage_value_8616
from .terminal_return_expressions import contains_register_clobbering_call_8616
import dataclasses
import operator
import builtins

RegisterIdentity8616 = typing.TypeAliasType("RegisterIdentity8616", tuple[int, int, int | str | None, int | None])
RegisterClassifier8616 = typing.TypeAliasType("RegisterClassifier8616", Callable[[object], tuple[RegisterIdentity8616, str] | None])
_CAPTURE_TAG: str = "inertia_gp_version_capture_8616"
_POINTER_WORD_BYTES: cython.longlong = 2
_STATEMENT_CENSUS_OCCURRENCE_MULTIPLIER: cython.longlong = 2


class _VariableManager8616(Protocol):
    """Type publication boundary of the angr variable manager."""

    def set_variable_type(self, variable: SimVariable, type_: SimType) -> None:
        """Publish a captured local's existing type."""


class _Function8616(Protocol):
    """Function storage and declaration surfaces required for capture."""

    addr: cython.longlong
    statements: object
    variables_in_use: MutableMapping[SimVariable, CVariable]
    variable_manager: _VariableManager8616

    def refresh(self) -> None:
        """Rebuild declarations from the published storage inventory."""


class _Project8616(Protocol):
    """Architecture used to bind machine-width capture types."""

    arch: Arch


class _Codegen8616(Protocol):
    """Owned capture counters attached at the codegen boundary."""

    cfunc: _Function8616
    project: _Project8616
    _inertia_gp_register_version_capture_stats_8616: GPVersionCaptureStats8616


@dataclasses.dataclass(frozen=True, )
class GPVersionCaptureStats8616:
    """Closed census of exact register definitions requiring value storage."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong


@dataclasses.dataclass(frozen=True, )
class _CapturePlan8616:
    """One exact version and, for a defined version, its dominating statement group."""

    identity: RegisterIdentity8616
    assignment: CAssignment | None
    group: CStatements | None
    source: CVariable | CDirtyExpression


@cython.ccall
def _occurrence_histogram(
    root: object, classify: RegisterClassifier8616,
) -> object:
    """Count classify-positive identities across every AST edge occurrence."""
    fact: object
    node: object
    counts: dict[RegisterIdentity8616, cython.longlong] = {}
    for node in _iter_c_node_occurrences_8616(root):
        fact = classify(node)
        if fact is not None:
            counts[fact[0]] = counts.get(fact[0], 0) + 1
    return counts


@cython.dataclasses.dataclass()
class _CaptureScan8616:
    """Bounded per-invocation census shared across candidate plans.

    One lazy whole-root occurrence histogram replaces a full re-scan per
    candidate identity. Per-statement histograms, owner groups, and effect
    checks are memoized by node identity for this single planning pass only;
    the tree is not mutated until every plan is selected, so each memoized
    answer stays exact. Retained histogram entries are bounded by the root's
    register occurrences, including repeated uses of an identity. This admits
    disjoint statement censuses without thrashing while overlapping nested
    scopes cannot accumulate quadratic storage.
    Nothing persists across capture invocations. The classifier must be a
    read-only projection of the unchanged tree during planning.
    """

    root: object
    classify: RegisterClassifier8616
    groups: object
    _occurrences: object = None
    _owners: object = None
    _statement_occurrences: object = field(
        default_factory=dict,
    )
    _statement_identity_entries: cython.longlong = 0
    _statement_identity_limit: cython.longlong = 0
    _effectful: object = field(default_factory=dict)
    _overwrites: object = field(default_factory=dict)

    @cython.ccall
    def total(self, identity: RegisterIdentity8616) -> cython.longlong:
        """Return the whole-root occurrence count, building the census once."""
        if self._occurrences is None:
            self._occurrences = _occurrence_histogram(self.root, self.classify)
            self._statement_identity_limit = (
                _STATEMENT_CENSUS_OCCURRENCE_MULTIPLIER * sum(self._occurrences.values())
            )
        return self._occurrences.get(identity, 0)

    @cython.ccall
    def owner_groups(self, assignment: CAssignment) -> tuple[CStatements, ...]:
        """Return deep-ordered statement groups directly listing the assignment."""
        group: object
        statement: object
        if self._owners is None:
            owners: dict[cython.longlong, list[CStatements]] = {}
            for group in self.groups:
                seen: set[cython.longlong] = set()
                for statement in group.statements:
                    marker = id(statement)
                    if marker in seen or not isinstance(statement, CAssignment):
                        continue
                    seen.add(marker)
                    owners.setdefault(marker, []).append(group)
            self._owners = owners
        return tuple(self._owners.get(id(assignment), ()))

    @cython.ccall
    def statement_reads(self, statement: object, identity: RegisterIdentity8616) -> cython.longlong:
        """Count a subtree with bounded temporary reuse of overlapping censuses."""
        cached: object
        marker = id(statement)
        cached = self._statement_occurrences.get(marker)
        if cached is None or cached[0] is not statement:
            cached = (statement, _occurrence_histogram(statement, self.classify))
            self.total(identity)
            assert self._occurrences is not None
            limit = self._statement_identity_limit
            entries = len(cached[1])
            if self._statement_identity_entries + entries > limit:
                self._statement_occurrences.clear()
                self._statement_identity_entries = 0
            if entries <= limit:
                self._statement_occurrences[marker] = cached
                self._statement_identity_entries += entries
        return cached[1].get(identity, 0)

    @cython.ccall
    def clobbers(self, statement: object) -> cython.bint:
        """Return whether the subtree may clobber GP state by calling guest code."""
        cached: object
        marker = id(statement)
        cached = self._effectful.get(marker)
        if cached is None or cached[0] is not statement:
            cached = (statement, contains_register_clobbering_call_8616(statement))
            self._effectful[marker] = cached
        return cached[1]

    @cython.ccall
    def overwrites(self, statement: object, parent: object) -> cython.bint:
        """Return whether the subtree may write the lane, memoized per node."""
        cached: object
        key = (id(statement), parent)
        cached = self._overwrites.get(key)
        if cached is None or cached[0] is not statement:
            cached = (statement, _may_overwrite_lane(statement, parent, self.classify))
            self._overwrites[key] = cached
        return cached[1]


def _capture_plan(
    scan: _CaptureScan8616, assignment: CAssignment, identity: RegisterIdentity8616,
) -> _CapturePlan8616 | None:
    """Require every read to follow the unique definition in its own group."""
    dominating: object
    total = scan.total(identity)
    if total <= 1:
        return None
    owners = scan.owner_groups(assignment)
    if len(owners) != 1:
        raise PipelineHardError(f"GP version capture: identity={identity!r}: ambiguous definition owner")
    group = owners[0]
    # A definition can dominate its own branch/loop body without dominating
    # the function. Count against the whole function to reject escaping reads.
    dominating = next(
        (scope for scope in iter(scan.groups) if _dominates_reads(scan, scope, assignment, identity, total)),
        None,
    )
    if dominating is None:
        if _is_loop_state_update_8616(scan, assignment, identity, total):
            return None
        raise PipelineHardError(f"GP version capture: identity={identity!r}: definition does not dominate every read")
    if not isinstance(assignment.lhs, CDirtyExpression) and not _outlives_register_value(
        scan, dominating, assignment, identity,
    ):
        return None
    return _CapturePlan8616(identity, assignment, group, cast(CVariable | CDirtyExpression, assignment.lhs))


def _is_loop_state_update_8616(scan, assignment, identity, total):
    """Keep a coalesced loop value in its architectural lane across iterations."""
    if (
        not isinstance(assignment.lhs, CVariable)
        or not isinstance(assignment.tags.get("vex_stmt_idx"), int)
        or not scan.statement_reads(assignment.rhs, identity)
    ):
        return False
    parent = scan.classify(assignment.lhs)[1]
    # A dirty definition can reserve the whole parent for snapshot lowering,
    # in which case this loop could not use the architectural lane.
    for node in _iter_c_nodes_deep_8616(scan.root):
        if isinstance(node, CAssignment) and isinstance(node.lhs, CDirtyExpression):
            target = scan.classify(node.lhs)
            if target is not None and target[1] == parent:
                return False
    for loop in _iter_c_nodes_deep_8616(scan.root):
        if not isinstance(loop, CWhileLoop) or scan.statement_reads(loop, identity) != total:
            continue
        if scan.clobbers(loop):
            continue
        nodes = tuple(_iter_c_nodes_deep_8616(loop))
        if not any(node is assignment for node in nodes):
            continue
        for node in nodes:
            if not isinstance(node, CAssignment) or node is assignment:
                continue
            target = scan.classify(node.lhs)
            if target is not None and target[1] == parent:
                break
            if isinstance(node.lhs, CVariable) and isinstance(node.lhs.variable, SimMemoryVariable):
                if node.lhs.variable.category == "inertia_gp_register_state":
                    break
        else:
            return True
    return False


@cython.ccall
def _may_overwrite_lane(statement: object, parent: object, classify: RegisterClassifier8616) -> cython.bint:
    """Keep unknown destinations conservative; distinguish known register lanes."""
    destination: object
    node: object
    for node in _iter_c_nodes_deep_8616(statement):
        if not isinstance(node, CAssignment):
            continue
        # Captures themselves write immutable locals, not architectural lanes.
        if (node.tags.get(_CAPTURE_TAG) is True
                and isinstance(node.lhs, CVariable) and isinstance(node.lhs.variable, SimTemporaryVariable)):
            continue
        destination = classify(node.lhs)
        if destination is None or operator.eq(destination[1], parent):
            return True
    return False


def _outlives_register_value(
    scan: _CaptureScan8616, scope: CStatements, assignment: CAssignment,
    identity: RegisterIdentity8616,
) -> cython.bint:
    """Capture only when a use can follow an overwrite or an effectful call.

    Pure generated memory helpers do not clobber registers. A compound statement
    can revisit reads on a backedge, so a nested overwrite is conservative even
    if its first read precedes the write. No assignments or effects are removed.
    """
    position: object
    source: object
    source = scan.classify(assignment.lhs)
    assert source is not None
    linear = _linear_sequence(scope)
    position = next(index for index, node in builtins.iter(enumerate(linear)) if node is assignment)
    return _reads_after_overwrite_8616(scan, linear[position + 1:], identity, source[1])


def _reads_after_overwrite_8616(
    scan: _CaptureScan8616, statements: tuple[object, ...], identity: RegisterIdentity8616, parent: str,
) -> bool:
    """Find stale reads, respecting RHS-before-store order for plain assignments."""
    clobbered = False
    for statement in statements:
        clobbered |= scan.clobbers(statement)
        overwrite = scan.overwrites(statement, parent)
        nested_overwrite = overwrite and not isinstance(statement, CAssignment)
        if (clobbered or nested_overwrite) and scan.statement_reads(statement, identity):
            return True
        clobbered |= overwrite
    return False


def _dominates_reads(
    scan: _CaptureScan8616, scope: CStatements, assignment: CAssignment,
    identity: RegisterIdentity8616, total: cython.longlong,
) -> cython.bint:
    """Prove all reads follow a definition without crossing a control boundary."""
    linear = _linear_sequence(scope)
    positions = tuple(index for index, statement in builtins.iter(enumerate(linear)) if statement is assignment)
    if len(positions) != 1:
        return False
    later_reads = sum(scan.statement_reads(statement, identity) for statement in iter(linear[positions[0] + 1:]))
    return operator.eq(total, later_reads + 1)


def _linear_sequence(root: object) -> tuple[object, ...]:
    """Flatten grouping only; never enter a conditional or loop body."""
    if isinstance(root, CStatements):
        return tuple(child for statement in iter(root.statements) for child in builtins.iter(_linear_sequence(statement)))
    return (root,)


def _first_entry_sp_capture_8616(root: CStatement) -> CAssignment | None:
    """Find the SP owner's first initializer without treating other stores as captures."""
    # The SP owner imports this backend's runtime GP projection.
    from .entry_stack_pointer_capture import is_entry_stack_pointer_capture_8616

    if isinstance(root, CStatements) and root.statements:
        first = root.statements[0]
        if isinstance(first, CAssignment) and is_entry_stack_pointer_capture_8616(first):
            return first
    return None


def _entry_capture_plans_8616(
    scan: _CaptureScan8616, candidates: dict[RegisterIdentity8616, tuple[CVariable, str]],
    definitions: dict[RegisterIdentity8616, list[CAssignment]],
) -> list[_CapturePlan8616]:
    """Plan snapshots of upward-exposed versions only when observed after a write."""
    root = scan.root
    upward_exposed = {identity: value for identity, value in candidates.items() if identity not in definitions}
    if not isinstance(root, CStatement) or not upward_exposed:
        return []
    flow = build_gp_entry_flow_8616(root)
    sp_capture = _first_entry_sp_capture_8616(root)
    if sp_capture is not None and not (
        isinstance(sp_capture.lhs, CVariable) and isinstance(sp_capture.lhs.variable, SimTemporaryVariable)
    ):
        sp_capture = None
    plans: list[_CapturePlan8616] = []
    for identity, (source, parent) in upward_exposed.items():
        if flow.reads_after_write(
            lambda node, version=identity: bool(scan.statement_reads(node, version)),
            lambda node, lane=parent: node is not sp_capture and scan.overwrites(node, lane),
            scan.clobbers,
        ):
            plans.append(_CapturePlan8616(identity, None, None, source))
    return plans


def _entry_version_source_8616(
    node: object, state_names: object, classify: RegisterClassifier8616,
) -> tuple[RegisterIdentity8616, tuple[CVariable, str]] | None:
    """Identify an SSA-backed carrier, not an unversioned register-shaped C variable."""
    if isinstance(node, CVariable) and node.vvar_id is not None:
        fact = classify(node)
        if fact is not None and fact[1] in state_names:
            return fact[0], (node, fact[1])
    return None


def _plans(
    root: object, state_names: object, classify: RegisterClassifier8616,
) -> tuple[_CapturePlan8616, ...]:
    """Select defined or upward-exposed versions that outlive a runtime lane."""
    fact: object
    plan: object
    assignments: object
    identity: object
    node: object
    definitions: dict[RegisterIdentity8616, list[CAssignment]] = {}
    entry_candidates: dict[RegisterIdentity8616, tuple[CVariable, str]] = {}
    parents: dict[RegisterIdentity8616, str] = {}
    groups: list[CStatements] = []
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CStatements):
            groups.append(node)
        if not isinstance(node, CAssignment):
            candidate = _entry_version_source_8616(node, state_names, classify)
            if candidate is not None:
                entry_candidates.setdefault(*candidate)
            continue
        fact = classify(node.lhs)
        if fact is not None and fact[1] in state_names:
            definitions.setdefault(fact[0], []).append(node)
            parents[fact[0]] = fact[1]
    scan = _CaptureScan8616(root, classify, tuple(groups))
    selected = _entry_capture_plans_8616(scan, entry_candidates, definitions)
    for identity, assignments in definitions.items():
        shares_lane = any(key != identity and operator.eq(parent, parents[identity]) for key, parent in builtins.iter(parents.items()))
        if len(assignments) != 1:
            continue
        if not shares_lane and not isinstance(assignments[0].lhs, CDirtyExpression):
            continue
        plan = _capture_plan(scan, assignments[0], identity)
        if plan is not None:
            selected.append(plan)
    return tuple(selected)



@cython.ccall
def _capture_storage_type_8616(plan: _CapturePlan8616, codegen: _Codegen8616) -> SimType:
    """Preserve entry projection arithmetic or the defined value's owned width."""
    if plan.assignment is None:
        # Runtime GP reads use unsigned parent arithmetic even for word/byte views.
        return SimTypeLong(False).with_arch(codegen.project.arch)
    if isinstance(plan.source, CVariable):
        return plan.source.variable_type
    types: dict[cython.longlong, SimType] = {
        1: SimTypeChar(False), 2: SimTypeShort(False), 4: SimTypeLong(False),
    }
    size = plan.identity[1]
    if size not in types:
        raise PipelineHardError(f"GP version capture: unsupported register width {size}")
    return types[size].with_arch(codegen.project.arch)


def capture_gp_register_versions_8616(
    codegen: object, state_names: object, classify: RegisterClassifier8616,
) -> cython.bint:
    """Keep incoming or defined GP versions stable across architectural writes."""
    position: object
    projected: object
    plan: object
    publication: object
    boundary = cast(_Codegen8616, codegen)
    function = boundary.cfunc
    root = function.statements
    try:
        plans = _plans(root, state_names, classify)
    except PipelineHardError as error:
        boundary._inertia_gp_register_version_capture_stats_8616 = GPVersionCaptureStats8616(1, 1, 0, 0, 1)
        raise PipelineHardError(f"GP version capture function={function.addr:#x}: {error}") from error
    existing = sum(
        isinstance(node, CAssignment) and node.tags.get(_CAPTURE_TAG) is True
        for node in builtins.iter(_iter_c_nodes_deep_8616(root))
    )
    if not plans:
        boundary._inertia_gp_register_version_capture_stats_8616 = GPVersionCaptureStats8616(
            existing, existing, existing, existing, 0,
        )
        return False
    used_ids = {
        node.variable.tmp_id for node in builtins.iter(_iter_c_nodes_deep_8616(root))
        if isinstance(node, CVariable) and isinstance(node.variable, SimTemporaryVariable)
    }
    used_ids.update(variable.tmp_id for variable in iter(function.variables_in_use) if isinstance(variable, SimTemporaryVariable))
    next_id = max(used_ids, default=-1) + 1
    replacements: dict[RegisterIdentity8616, CVariable] = {}
    publications: list[tuple[_CapturePlan8616, CAssignment]] = []
    entry_captures: list[CAssignment] = []

    def replace_version(node: object) -> object:
        """Project selected full identities without merging architectural lanes."""
        fact: object
        fact = classify(node)
        return replacements.get(fact[0], node) if fact is not None else node

    for plan in plans:
        capture_type = _capture_storage_type_8616(plan, boundary)
        storage_bytes = capture_type.size // 8 if plan.assignment is None else plan.identity[1]
        temporary = SimTemporaryVariable(next_id, storage_bytes)
        next_id += 1
        value = CVariable(temporary, variable_type=capture_type, codegen=codegen)
        function.variables_in_use[temporary] = value
        function.variable_manager.set_variable_type(temporary, capture_type)
        if plan.assignment is None:
            replacements[plan.identity] = value
            entry_captures.append(CAssignment(value, plan.source, codegen=codegen, tags={_CAPTURE_TAG: True}))
            continue
        # A scalar register snapshot stores guest offset bits, not a host C
        # pointer. Reuse the architectural-write owner's exact projection.
        # Earlier captures must already be visible to this RHS's type query.
        # Visit only this expression now; replace the complete function once
        # after every plan is prepared, before adding architectural publications.
        rhs = cast(CExpression, replace_version(plan.assignment.rhs))
        _replace_c_children_8616(rhs, replace_version)
        projected = project_pointer_storage_value_8616(
            codegen, rhs, max(plan.identity[1], _POINTER_WORD_BYTES),
        )
        assert projected is not None
        plan.assignment.rhs = projected

        replacements[plan.identity] = value
        # Evaluate the RHS once into the local, then publish that exact value.
        publication = CAssignment(plan.source, value, codegen=codegen, tags=dict(plan.assignment.tags))
        plan.assignment.tags[_CAPTURE_TAG] = True
        publications.append((plan, publication))
    _replace_c_children_8616(root, replace_version)
    if entry_captures:
        assert isinstance(root, CStatement)
        if isinstance(root, CStatements):
            after_sp = int(_first_entry_sp_capture_8616(root) is not None)
            root.statements[after_sp:after_sp] = entry_captures
        else:
            function.statements = CStatements([*entry_captures, root], codegen=codegen)
    for plan, publication in publications:
        group = plan.group
        assert group is not None
        position = next(index for index, statement in builtins.iter(enumerate(group.statements)) if statement is plan.assignment)
        group.statements = [*group.statements[:position + 1], publication, *group.statements[position + 1:]]
    function.refresh()
    count = existing + len(plans)
    boundary._inertia_gp_register_version_capture_stats_8616 = GPVersionCaptureStats8616(count, count, count, count, 0)
    return True
