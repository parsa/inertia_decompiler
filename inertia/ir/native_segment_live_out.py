# cython: language_level=3, infer_types=True
"""Preserve architectural segment outputs in native SSA reaching definitions.

Layer: IR/native SSA adapter.
Responsibility: publish segment return uses, retain stack-backed GP outputs
until owned Alias/Lowering can discharge their segmented restore effects, and
retain reaching register definitions at unmodeled tail exits.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Segment state is caller-visible independently of a source-language return type
or a general-purpose callee-saved register convention. Native DCE must consume
these uses before deleting definitions. Existing IR state and lowering retain
ownership of segment values and their C projection; this pass recovers neither.

Only reaching definitions are retained, not every historical segment write.
This boundary does not claim interprocedural call-clobber recovery or repair
effects already lost upstream. No assembly, rendered C, names or sidecars are
used as evidence.

Native stack-SSA conversion does not prove that segmented register-save areas
were removed. Retain reaching GP definitions that still read negative entry-SP
storage with authoritative native address provenance. This is conservative
retention, not proof that a value equals its entry value or permission to prune
its save. Arithmetic-only outputs are not retained by this additional guard.

A terminal Jump or ConditionalJump whose target has no matching graph
successor leaves the modeled control domain: the unknown destination carries
no callee or caller evidence that could prove a reaching architectural
definition dead, so every observed reaching register view stays
observable. Constant targets matching graph successors remain subject to ordinary
dead-definition analysis. A symbolic target remains unknown even with graph
edges: those edges alone do not prove exhaustive successor coverage. This is
conservative retention only — it invents no control domain, no CS value and
no ABI contract for the unknown destination.
"""

from __future__ import annotations
import typing
import cython
import os

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Protocol, cast

import networkx as nx
from angr.ailment import Block
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    Tmp,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label, Return, SideEffectStatement, Statement
from angr.analyses.decompiler.ail_simplifier import AILSimplifier
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.s_reaching_definitions.s_rda_view import SRDAView
from angr.analyses.s_reaching_definitions.s_reaching_definitions import SReachingDefinitions
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions.constants import ObservationPoint, ObservationPointType

from .native_stack_anchor import native_stack_anchor_8616
from .segment_state_transfer import SEGMENT_REGISTERS
from inertia.semantics.terminal_return_contract import WordFarReturnLayout8616, WordNearReturnLayout8616
from inertia.semantics.terminal_return_contract import WordInterruptReturnLayout8616
import dataclasses
import operator
import builtins


@dataclasses.dataclass(frozen=True, )
class NativeSegmentLiveOutReport8616:
    """Native boundary-use census split by retained output kind."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0
    stack_output_count: cython.longlong = 0
    unknown_exit_output_count: cython.longlong = 0


@cython.cclass
class _StackLoadAnchorViewer8616:
    """Find proven negative entry-SP origins inside native memory-load addresses."""
    _viewer = cython.declare(object, visibility = "public")
    has_stack_load = cython.declare(cython.bint, visibility = "public")
    load_depth = cython.declare(cython.longlong, visibility = "public")

    def __init__(self) -> None:
        """Start one source-expression inspection with no load context."""
        self._viewer: AILBlockViewer = AILBlockViewer()
        self._viewer.expr_handlers[Load] = self._handle_Load
        self._viewer.expr_handlers[UnaryOp] = self._handle_UnaryOp
        self.load_depth: cython.longlong = 0
        self.has_stack_load: cython.bint = False

    @cython.ccall
    def walk_expression(self, expression: Expression) -> None:
        """Visit one expression using the native walker's complete child schema."""
        self._viewer.walk_expression(expression)

    @cython.ccall
    def _handle_Load(
        self, expr_idx: cython.longlong, expr: Load, stmt_idx: cython.longlong,
        stmt: Statement | None, block: Block | None,
    ) -> None:
        """Restrict provenance inspection to actual native load addresses."""
        self.load_depth += 1
        try:
            self._viewer._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
        finally:
            self.load_depth -= 1

    @cython.ccall
    def _handle_UnaryOp(
        self, expr_idx: cython.longlong, expr: UnaryOp, stmt_idx: cython.longlong,
        stmt: Statement | None, block: Block | None,
    ) -> None:
        """Consume the frontend's coordinate tag, never apparent local offsets."""
        anchor: object
        anchor = native_stack_anchor_8616(expr.tags)
        if self.load_depth and anchor is not None and anchor.entry_sp_offset < 0:
            self.has_stack_load = True
        self._viewer._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)


@cython.ccall
def _stack_output_ids_8616(analysis: SReachingDefinitions) -> frozenset[cython.longlong]:
    """Find remaining stack-backed GP definitions without inventing save pairs."""
    graph: object
    block: object
    statement: object
    graph = analysis.func_graph
    if graph is None:
        return frozenset()
    arch = analysis.project.arch
    frame_offsets = {arch.sp_offset, arch.bp_offset, arch.ip_offset}
    offsets = {
        reg.vex_offset for reg in iter(arch.register_list)
        if reg.general_purpose and reg.vex_offset not in frame_offsets
    }
    candidates: set[cython.longlong] = set()
    for block in graph:
        for statement in block.statements:
            if not isinstance(statement, Assignment):
                continue
            destination = statement.dst
            if not isinstance(destination, VirtualVariable):
                continue
            if operator.ne(destination.category, VirtualVariableCategory.REGISTER) or destination.oident not in offsets:
                continue
            viewer = _StackLoadAnchorViewer8616()
            viewer.walk_expression(statement.src)
            if viewer.has_stack_load:
                candidates.add(destination.varid)
    return frozenset(candidates)


class _NativeSegmentBoundary8616(Protocol):
    """Owned report attached to the dynamic third-party analysis instance."""

    _inertia_segment_live_out_report_8616: NativeSegmentLiveOutReport8616


def _unmodeled_exit_8616(graph: nx.DiGraph, block: Block) -> cython.bint:
    """Whether a terminator transition lacks a matching graph successor."""
    successors = tuple(graph.successors(block))
    if not successors or any(not successor.statements for successor in iter(successors)):
        # A missing terminal or an empty successor supplies no dead-output
        # evidence. Observe the last represented instruction before the gap.
        return True
    terminal = block.statements[-1]
    targets: object
    if isinstance(terminal, Jump):
        targets = ((terminal.target, terminal.target_idx),)
    elif isinstance(terminal, ConditionalJump):
        targets = (
            (terminal.true_target, terminal.true_target_idx),
            (terminal.false_target, terminal.false_target_idx),
        )
    else:
        # No modeled control exit: with no successor there is no callee or
        # caller evidence proving the reaching definitions dead.
        return False
    successor_keys = {(successor.addr, successor.idx) for successor in iter(successors)}
    return any(
        not isinstance(target, Const) or (target.value_int, target_idx) not in successor_keys
        for target, target_idx in iter(targets)
    )


@cython.ccall
def _return_output_ids_8616(
    analysis: SReachingDefinitions,
    registers: object,
    stack_outputs: object,
) -> tuple[set[cython.longlong], cython.longlong]:
    """Select existing segment and unresolved stack-backed Return outputs."""
    name: object
    outputs = {
        varid for views in builtins.iter(registers.values()) for varid in builtins.iter(views.values())
        if varid in stack_outputs
    }
    stack_count = len(outputs)
    for name in SEGMENT_REGISTERS:
        offset, _size = analysis.project.arch.registers[name]
        # Every observed width remains live; a partial view is not dead proof.
        outputs.update(registers.get(offset, {}).values())
    return outputs, stack_count


@cython.ccall
def _boundary_observation_points_8616(graph: nx.DiGraph) -> object:
    """Observe Returns and exits without exhaustive modeled successors."""
    block: object
    points: list[ObservationPoint] = []
    for block in graph:
        if not block.statements:
            continue
        if isinstance(block.statements[-1], Return) or _unmodeled_exit_8616(graph, block):
            points.append(("node", (block.addr, block.idx), ObservationPointType.OP_AFTER))
    return points


@cython.ccall
def preserve_native_segment_live_outs_8616(analysis: SReachingDefinitions) -> NativeSegmentLiveOutReport8616:
    """Retain reaching segments, stack outputs and unmodeled-exit registers."""
    graph: object
    _: object
    key: object
    registers: object
    variable_id: object
    graph = analysis.func_graph
    if analysis.project.arch.name != "86_16" or analysis.func is None or graph is None:
        return NativeSegmentLiveOutReport8616()
    blocks = {(block.addr, block.idx): block for block in iter(graph)}
    points = _boundary_observation_points_8616(graph)
    if not points:
        return NativeSegmentLiveOutReport8616()
    observations = SRDAView(analysis.model).observe(
        points, entry=blocks.get((analysis.func_addr, None))
    )
    count = 0
    stack_count = 0
    unknown_count = 0
    stack_outputs = _stack_output_ids_8616(analysis)
    for (_, key, _), registers in observations.items():
        block = blocks[key]
        terminal = block.statements[-1]
        location = AILCodeLocation(
            block.addr, block.idx, len(block.statements) - 1, terminal.tags.get("ins_addr")
        )
        if isinstance(terminal, Return):
            outputs, reaching_stack_count = _return_output_ids_8616(analysis, registers, stack_outputs)
            stack_count += reaching_stack_count
        else:
            outputs = {varid for views in builtins.iter(registers.values()) for varid in builtins.iter(views.values())}
            unknown_count += len(outputs)
        for variable_id in outputs:
            if (None, location) not in analysis.model.all_vvar_uses[variable_id]:
                analysis.model.add_vvar_use(variable_id, None, location)
        count += len(outputs)
    return NativeSegmentLiveOutReport8616(count, count, count, count, 0, stack_count, unknown_count)


def apply_native_segment_live_out_compatibility_8616() -> None:
    """Install segment-use publication after native SSA model construction."""
    original = cast(Callable[[SReachingDefinitions], None], SReachingDefinitions._analyze)
    if original.__name__ == "_analyze_with_segment_live_outs_8616":
        return

    def _analyze_with_segment_live_outs_8616(self: SReachingDefinitions) -> None:
        """Keep native analysis intact and publish the architecture's outputs."""
        original(self)
        report = preserve_native_segment_live_outs_8616(self)
        cast(_NativeSegmentBoundary8616, self)._inertia_segment_live_out_report_8616 = report

    SReachingDefinitions._analyze = _analyze_with_segment_live_outs_8616
    _apply_native_gp_return_dce_guard_8616()
    _apply_native_gp_merge_after_ssa0_8616()


@dataclass(frozen=True)
class NativeGPExitDefinition8616:
    """One candidate reaching register view at a particular SSA exit."""

    exit_key: tuple[int, int | None]
    register_offset: int
    byte_width: int
    variable_id: int
    definition: AILCodeLocation


    def bind_operand(self, blocks: Mapping[tuple[int, int | None], Block]) -> VirtualVariable | None:
        """Bind to the exact current SSA register operand or refuse a stale record.

        The caller must separately establish that the observation and its CFG
        are current. This projection never substitutes the defining expression.
        """
        exit_block = blocks.get(self.exit_key)
        if exit_block is None or not exit_block.statements or not isinstance(exit_block.statements[-1], Return):
            return None
        source = self.definition
        owner = blocks.get((source.block_addr, source.block_idx))
        index = source.stmt_idx
        if owner is None or not isinstance(index, int) or not 0 <= index < len(owner.statements):
            return None
        statement = owner.statements[index]
        if not isinstance(statement, Assignment):
            return None
        value = statement.dst
        if (
            not isinstance(value, VirtualVariable)
            or value.category is not VirtualVariableCategory.REGISTER
            or value.varid != self.variable_id
            or value.oident != self.register_offset
            or value.size != self.byte_width
        ):
            return None
        return value.copy()

    def bind_exit_use(
        self, blocks: Mapping[tuple[int, int | None], Block],
        next_atom: Callable[[], int],
    ) -> SideEffectStatement | None:
        """Build an explicit SSA consumer without modifying the return payload."""
        value = self.bind_operand(blocks)
        if value is None:
            return None
        terminal = blocks[self.exit_key].statements[-1]
        tags = {
            **terminal.tags,
            "inertia_gp_exit_coordinate": (self.register_offset, self.byte_width),
        }
        effect = Call(
            next_atom(), "inertia_architectural_gp_exit", args=[value], bits=0, **tags,
        )
        return SideEffectStatement(next_atom(), effect, **tags)


def _native_gp_exit_definitions_8616(
    observations: Mapping[ObservationPoint, Mapping[int, Mapping[int, int]]],
    definitions: Mapping[int, AILCodeLocation],
    offsets: set[int],
) -> Iterator[NativeGPExitDefinition8616]:
    """Enumerate per-exit reaching views without conflating different returns.

    This selects SSA liveness candidates. Consumers that publish runtime
    state must also validate lane composition and the structured exit binding.
    """
    for point, registers in observations.items():
        exit_key = point[1]
        for offset in offsets:
            views = registers.get(offset, {})
            for width, varid in views.items():
                source = definitions.get(varid)
                if source is None or source.is_extern:
                    continue
                # Width-specific histories can include a write killed by
                # a later wider write. Only discard it when both occur in
                # this exit block in a known order.
                if (
                    (source.block_addr, source.block_idx) == exit_key
                    and isinstance(source.stmt_idx, int)
                    and any(
                        wider > width
                        and (writer := definitions.get(other)) is not None
                        and not writer.is_extern
                        and (writer.block_addr, writer.block_idx) == exit_key
                        and isinstance(writer.stmt_idx, int)
                        and writer.stmt_idx > source.stmt_idx
                        for wider, other in views.items()
                    )
                ):
                    continue
                yield NativeGPExitDefinition8616(exit_key, offset, width, varid, source)


def _flags_phi_input_producers_8616(fact, blocks, definitions, *, carry_sources=None):
    """Encode exact native producer locations for a same-block exit phi."""
    loc = fact.definition
    if (loc.block_addr, loc.block_idx) != fact.exit_key:
        return ()
    phi = blocks[fact.exit_key].statements[loc.stmt_idx].src
    if not isinstance(phi, Phi):
        return ()
    rows = []
    for (pred, pred_idx), value in phi.src_and_vvars:
        if pred_idx is not None or not isinstance(value, VirtualVariable):
            return ()
        source = definitions.get(value.varid)
        if source is None or source.is_extern:
            return ()
        block = blocks.get((source.block_addr, source.block_idx))
        if block is None or not isinstance(source.stmt_idx, int) or not 0 <= source.stmt_idx < len(block.statements):
            return ()
        stmt = block.statements[source.stmt_idx]
        ip = stmt.tags.get("ins_addr")
        if (not isinstance(stmt, Assignment) or not isinstance(stmt.dst, VirtualVariable)
            or stmt.dst.varid != value.varid or isinstance(stmt.src, Phi) or not isinstance(ip, int)):
            return ()
        rows.append((pred, value.varid, ip))
        if carry_sources is not None:
            carry = _packed_carry_source_8616(stmt.src)
            if isinstance(carry, VirtualVariable) and carry.was_reg and carry.oident == fact.register_offset:
                prior = definitions.get(carry.varid)
                if (prior is not None and not prior.is_extern
                    and (prior.block_addr, prior.block_idx) == (source.block_addr, source.block_idx)
                    and isinstance(prior.stmt_idx, int) and 0 <= prior.stmt_idx < source.stmt_idx):
                    writer = block.statements[prior.stmt_idx]
                    if isinstance(writer, Assignment) and isinstance(writer.dst, VirtualVariable) and writer.dst.varid == carry.varid:
                        bit = _packed_carry_source_8616(writer.src)
                        addr = writer.tags.get("ins_addr")
                        if type(bit) is int and isinstance(addr, int) and addr < ip:
                            carry_sources[pred] = (addr, bit)
    return tuple(sorted(rows))


def _packed_carry_source_8616(expr):
    """Reduce bit zero through masks without following other FLAGS bits."""
    if isinstance(expr, Const):
        return expr.value_int & 1
    if isinstance(expr, VirtualVariable):
        return expr
    if not isinstance(expr, BinaryOp) or expr.op not in {"And", "Or"}:
        return None
    left, right = expr.operands
    identity = int(expr.op == "And")
    # Consider literal masks first; an opaque masked-off arm is safe.
    for literal, other in ((left, right), (right, left)):
        if isinstance(literal, Const):
            bit = literal.value_int & 1
            return _packed_carry_source_8616(other) if bit == identity else bit
    left_bit = _packed_carry_source_8616(left)
    right_bit = _packed_carry_source_8616(right)
    if type(left_bit) is int:
        return right_bit if left_bit == identity else left_bit
    if type(right_bit) is int:
        return left_bit if right_bit == identity else right_bit
    return None


def _straight_line_gp_exit_definitions_8616(block, coordinates):
    return _ordered_gp_exit_definitions_8616((block,), coordinates)


def _ordered_gp_exit_definitions_8616(path, coordinates):
    """Retain the last owner of each byte along an unjoined SSA path."""
    owners = {}
    order = {}
    exit_block = path[-1]
    key = (exit_block.addr, exit_block.idx)
    for block in path:
        if not _apply_gp_lane_writes_8616(block, coordinates, key, owners, order):
            return None
    return tuple(sorted(set(owners.values()), key=order.__getitem__))


def _apply_gp_lane_writes_8616(block, coordinates, key, owners, order, incoming=None):
    for index, stmt in enumerate(block.statements[:-1]):
        if (isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call)
                and stmt.expr.target == "inertia_architectural_gp_exit"
                and "inertia_gp_exit_coordinate" in stmt.tags):
            # A previous DCE round has already made this observation
            # explicit. It reads a lane and creates no new native writer.
            continue
        if isinstance(stmt, (SideEffectStatement, ConditionalJump, Jump, Return)) or (
            isinstance(stmt, Assignment) and isinstance(stmt.src, Call)
        ):
            return False
        if not isinstance(stmt, Assignment) or not isinstance(stmt.dst, VirtualVariable):
            continue
        dst = stmt.dst
        if dst.category is not VirtualVariableCategory.REGISTER:
            continue
        if (dst.oident, dst.size) not in coordinates:
            continue
        if isinstance(stmt.src, Phi) and not _gp_lane_phi_matches_8616(stmt.src, dst, incoming):
            # A phi is an SSA view, not a physical write. An unbound
            # view cannot resolve lane ownership or kill an older byte.
            continue
        location = AILCodeLocation(block.addr, block_idx=block.idx, stmt_idx=index)
        fact = NativeGPExitDefinition8616(key, dst.oident, dst.size, dst.varid, location)
        order[fact] = len(order)
        for lane in range(dst.oident, dst.oident + dst.size):
            owners[lane] = fact
    return True


def _gp_lane_phi_matches_8616(phi, dst, incoming):
    """Authenticate each complete register view against its predecessor."""
    if not incoming or len(phi.src_and_vvars) != len(incoming):
        return False
    seen = set()
    for source, value in phi.src_and_vvars:
        if source in seen or source not in incoming or not isinstance(value, VirtualVariable):
            return False
        seen.add(source)
        if (value.category is not VirtualVariableCategory.REGISTER
                or (value.oident, value.size) != (dst.oident, dst.size)):
            return False
        state = incoming[source]
        for lane in range(dst.oident, dst.oident + dst.size):
            owner = state.get(lane)
            if (not isinstance(owner, NativeGPExitDefinition8616)
                    or (owner.register_offset, owner.byte_width, owner.variable_id)
                    != (dst.oident, dst.size, value.varid)):
                return False
    return True


def _unjoined_gp_exit_path_8616(graph, entry, exit_block):
    """Recover a unique, fully executed path, rejecting joins and back edges."""
    path = [exit_block]
    seen = {exit_block}
    while path[-1] is not entry:
        predecessors = tuple(graph.predecessors(path[-1]))
        if len(predecessors) != 1:
            return None
        block = predecessors[0]
        if (block in seen or not block.statements
                or not isinstance(block.statements[-1], (Jump, ConditionalJump))):
            return None
        path.append(block)
        seen.add(block)
    if graph.in_degree(entry):
        return None
    return tuple(reversed(path))


def _gp_exit_edge_slices_8616(incoming, register_offset, byte_width):
    """Describe all byte offsets explicitly before constructing an SSA merge.

    Each row records source definition, source byte, destination byte and
    length. Untouched entry bytes and unresolved older joins require a
    distinct SSA input proof; neither can be filled with a constant here.
    """
    if len(incoming) < 2 or byte_width <= 0:
        return None
    result = {}
    for predecessor, owners in incoming.items():
        slices = []
        for dst_byte in range(byte_width):
            lane = register_offset + dst_byte
            fact = owners.get(lane)
            if not isinstance(fact, NativeGPExitDefinition8616):
                return None
            src_byte = lane - fact.register_offset
            if not 0 <= src_byte < fact.byte_width:
                return None
            if slices:
                owner, source, dest, count = slices[-1]
                if owner == fact and src_byte == source + count:
                    slices[-1] = owner, source, dest, count + 1
                    continue
            slices.append((fact, src_byte, dst_byte, 1))
        result[predecessor] = tuple(slices)
    return result


def _build_gp_exit_merge_8616(plan, coordinate, blocks, exit_key, next_atom, next_var):
    """Build edge assignments and a phi without mutating the graph.

    The caller owns fresh SSA IDs and insertion. Inserting before a plain
    jump requires that the caller also verify its only CFG successor.
    """
    offset, width = coordinate
    bits = width * 8
    edge_assignments = {}
    inputs = []
    for key, parts in sorted(plan.items(), key=lambda item: (item[0][0], item[0][1] or -1)):
        block = blocks.get(key)
        if block is None or not block.statements or not isinstance(block.statements[-1], Jump):
            return None
        jump = block.statements[-1]
        if not isinstance(jump.target, Const) or (jump.target.value, jump.target_idx) != exit_key:
            return None
        value = None
        covered = 0
        for fact, source, dest, count in parts:
            if (
                count <= 0 or dest != covered or dest + count > width
                or not 0 <= source <= fact.byte_width - count
                or fact.register_offset + source != offset + dest
                or fact.exit_key != exit_key
            ):
                return None
            covered += count
            part = fact.bind_operand(blocks)
            if part is None:
                return None
            if source:
                part = BinaryOp(next_atom(), "Shr", [part, Const(None, 8 * source, 8)], False)
            if part.bits != 8 * count:
                part = Convert(next_atom(), part.bits, 8 * count, False, part)
            if part.bits != bits:
                part = Convert(next_atom(), part.bits, bits, False, part)
            if dest:
                part = BinaryOp(next_atom(), "Shl", [part, Const(None, 8 * dest, 8)], False)
            value = part if value is None else BinaryOp(next_atom(), "Or", [value, part], False)
        if value is None or covered != width:
            return None
        operand = VirtualVariable(next_atom(), next_var(), bits, VirtualVariableCategory.REGISTER, oident=offset)
        edge_assignments[key] = Assignment(next_atom(), operand, value, **jump.tags)
        inputs.append((key, operand.copy()))
    if len(inputs) < 2:
        return None
    output = VirtualVariable(next_atom(), next_var(), bits, VirtualVariableCategory.REGISTER, oident=offset)
    tags = blocks[exit_key].statements[-1].tags
    return edge_assignments, Assignment(next_atom(), output, Phi(next_atom(), bits, inputs), **tags)


def _insert_native_gp_exit_merge_8616(graph, entry, exit_block, coordinates, coordinate, next_atom, next_var):
    """Materialize a missing word view on direct incoming edges of a return."""
    if not exit_block.statements or not isinstance(exit_block.statements[-1], Return):
        return False
    preds = tuple(graph.predecessors(exit_block))
    if len(preds) < 2 or any(set(graph.successors(pred)) != {exit_block} for pred in preds):
        return False
    offset, width = coordinate
    for stmt in exit_block.statements[:-1]:
        if isinstance(stmt, Label):
            continue
        if isinstance(stmt, Assignment) and isinstance(stmt.dst, Tmp) and not isinstance(stmt.src, Call):
            continue
        if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and not isinstance(stmt.src, Call):
            if stmt.dst.category is not VirtualVariableCategory.REGISTER:
                continue
            start, size = stmt.dst.oident, stmt.dst.size
        elif isinstance(stmt, SideEffectStatement) and "inertia_gp_exit_coordinate" in stmt.tags:
            start, size = stmt.tags["inertia_gp_exit_coordinate"]
        else:
            return False
        if start < offset + width and offset < start + size:
            return False
    incoming = {}
    if _agreed_gp_exit_definitions_8616(graph, entry, exit_block, coordinates, exit_inputs=incoming) is not None:
        return False
    plan = _gp_exit_edge_slices_8616(incoming, offset, width)
    if plan is None:
        return False
    blocks = {(block.addr, block.idx): block for block in graph}
    exit_key = (exit_block.addr, exit_block.idx)
    built = _build_gp_exit_merge_8616(plan, coordinate, blocks, exit_key, next_atom, next_var)
    if built is None:
        return False
    assignments, phi = built
    terminal = exit_block.statements[-1]
    tags = {**terminal.tags, "inertia_gp_exit_coordinate": coordinate}
    effect = Call(next_atom(), "inertia_architectural_gp_exit", args=[phi.dst.copy()], bits=0, **tags)
    publisher = SideEffectStatement(next_atom(), effect, **tags)
    for key, assignment in assignments.items():
        blocks[key].statements.insert(-1, assignment)
    # The merged value depends only on the incoming edges. Publish it before
    # the return's own assignments, which must stay beside the typed RETF.
    insert_at = next(
        i for i, stmt in enumerate(exit_block.statements)
        if not (isinstance(stmt, Label) or isinstance(stmt, Assignment) and isinstance(stmt.src, Phi))
    )
    exit_block.statements.insert(insert_at, phi)
    exit_block.statements.insert(insert_at + 1, publisher)
    return True


def _apply_native_gp_merge_after_ssa0_8616():
    original = Clinic._transform_to_ssa_level0
    if original.__name__ == "_ssa0_with_gp_exit_merges_8616":
        return

    def _ssa0_with_gp_exit_merges_8616(self, ail_graph, func_args):
        ail_graph = original(self, ail_graph, func_args)
        arch = self.project.arch
        if (
            arch.name == "86_16"
            and os.getenv("INERTIA_EXPERIMENTAL_GP_EXIT_USES") == "1"
            and os.getenv("INERTIA_EXPERIMENTAL_GP_EXIT_LANES") == "1"
        ):
            entry = next((b for b in ail_graph if (b.addr, b.idx) == self.entry_node_addr), None)

            def next_var():
                varid = self.vvar_id_start
                self.vvar_id_start += 1
                return varid

            if entry is not None:
                if os.getenv("INERTIA_DEBUG_GP_EXIT_MERGE") == "1":
                    for block in ail_graph:
                        print("[gp-exit-merge-input]", block, tuple(map(str, block.statements)), tuple(ail_graph.successors(block)))
                for block in ail_graph:
                    for name in ("a", "b", "c", "d"):
                        word = arch.registers[name + "x"]
                        coords = {arch.registers[reg] for reg in ("e" + name + "x", name + "x", name + "l", name + "h")}
                        inserted = _insert_native_gp_exit_merge_8616(
                            ail_graph, entry, block, coords, word, self._ail_manager.next_atom, next_var,
                        )
                        if inserted and os.getenv("INERTIA_DEBUG_GP_EXIT_MERGE") == "1":
                            print("[gp-exit-merge-inserted]", block.addr, word)
        return ail_graph

    Clinic._transform_to_ssa_level0 = _ssa0_with_gp_exit_merges_8616


def _agreed_gp_exit_definitions_8616(graph, entry, exit_block, coordinates, *, exit_inputs=None):
    """Join identical ordered byte owners; differing owners require a phi."""
    if graph.in_degree(entry):
        return None
    cone = graph.subgraph(nx.ancestors(graph, exit_block) | {exit_block})
    if entry not in cone:
        return None
    # A differing byte owner survives as a conflict unless a later write
    # replaces that byte. Keep untouched entry bytes distinct from conflicts.
    conflict = object()
    outgoing = {}
    order = {}
    key = (exit_block.addr, exit_block.idx)
    try:
        traversal = tuple(nx.topological_sort(cone))
    except nx.NetworkXUnfeasible:
        return _cyclic_gp_exit_definitions_8616(cone, entry, exit_block, coordinates, conflict)
    for block in traversal:
        predecessors = tuple(cone.predecessors(block))
        if block is not entry and not predecessors:
            return None
        if block is not exit_block and (
            not block.statements or not isinstance(block.statements[-1], (Jump, ConditionalJump))
        ):
            return None
        owners = {}
        if predecessors:
            states = [outgoing[pred] for pred in predecessors]
            for lane in set().union(*states):
                first = states[0].get(lane)
                owners[lane] = first if all(state.get(lane) == first for state in states) else conflict
        incoming = {(pred.addr, pred.idx): outgoing[pred] for pred in predecessors}
        if len(incoming) != len(predecessors):
            return None
        if not _apply_gp_lane_writes_8616(block, coordinates, key, owners, order, incoming):
            return None
        if block is exit_block and exit_inputs is not None:
            exit_inputs.update(incoming)
        outgoing[block] = owners
    facts = set(outgoing[exit_block].values())
    if conflict in facts:
        return None
    return tuple(sorted(facts, key=order.__getitem__))


def _cyclic_gp_exit_definitions_8616(cone, entry, exit_block, coordinates, conflict):
    """Solve byte ownership on loop edges and publish only a closed solution."""
    reachable = nx.descendants(cone, entry) | {entry}
    if len(reachable) != len(cone):
        return None
    traversal = (entry, *nx.dfs_preorder_nodes(cone, entry))
    traversal = tuple(dict.fromkeys(traversal))
    outgoing = {}
    order = {}
    key = (exit_block.addr, exit_block.idx)
    for _ in range(2 * len(traversal) + 1):
        changed = False
        for block in traversal:
            if block is not exit_block and (
                not block.statements or not isinstance(block.statements[-1], (Jump, ConditionalJump))
            ):
                return None
            predecessors = tuple(cone.predecessors(block))
            known = tuple(pred for pred in predecessors if pred in outgoing)
            if block is not entry and not known:
                continue
            incoming = {(pred.addr, pred.idx): outgoing[pred] for pred in known}
            if len(incoming) != len(known):
                return None
            states = tuple(incoming.values())
            owners = {}
            if states:
                for lane in set().union(*states):
                    first = states[0].get(lane)
                    owners[lane] = first if all(state.get(lane) == first for state in states) else conflict
            # Provisional predecessor states can seed the iteration, but
            # can never authenticate an incomplete phi.
            complete = len(known) == len(predecessors)
            if not _apply_gp_lane_writes_8616(block, coordinates, key, owners, order, incoming if complete else None):
                return None
            if block not in outgoing or outgoing[block] != owners:
                outgoing[block] = owners
                changed = True
        if not changed:
            if len(outgoing) != len(traversal):
                return None
            facts = set(outgoing[exit_block].values())
            if conflict in facts:
                return None
            # A write in a loop may follow a wider write from the preceding
            # iteration. Publish a wider view before its narrower overrides.
            return tuple(sorted(facts, key=lambda fact: (-fact.byte_width, order[fact])))
    return None


def _gp_exit_edge_observations_8616(graph, view, entry, observations, definitions):
    """Correct block-end views for the sole incoming edge of a return.

    A lifted REP can branch out before the statements that update its
    backedge. Those writes dominate the return in the block graph, but
    do not execute on the outgoing edge.
    """
    points = {}
    for block in graph:
        key = (block.addr, block.idx)
        point = ("node", key, ObservationPointType.OP_AFTER)
        if point not in observations or graph.in_degree(block) != 1:
            continue
        predecessor = next(iter(graph.predecessors(block)))
        pred_key = (predecessor.addr, predecessor.idx)
        if (
            predecessor is block or block.idx is not None or predecessor.idx is not None
            or set(graph.successors(predecessor)) != {predecessor, block}
        ):
            continue
        transfers = [(index, stmt) for index, stmt in enumerate(predecessor.statements)
                     if isinstance(stmt, (ConditionalJump, Jump, Return))]
        if len(transfers) != 1:
            continue
        index, transfer = transfers[0]
        if not isinstance(transfer, ConditionalJump) or index == len(predecessor.statements) - 1:
            continue
        targets = (transfer.true_target, transfer.false_target)
        if all(isinstance(target, Const) for target in targets) and {
            target.value for target in targets
        } == {predecessor.addr, block.addr}:
            edge = ("stmt", (pred_key, index), ObservationPointType.OP_BEFORE)
            points[point] = edge
    if not points:
        return observations
    edge_states = view.observe(list(points.values()), entry=entry)
    result = dict(observations)
    for point, edge in points.items():
        pred_key, index = edge[1]
        edge_state = edge_states.get(edge, {})
        widths = {}
        for offset, views in observations[point].items():
            current = {}
            for width, varid in views.items():
                source = definitions.get(varid)
                if (
                    source is not None and (source.block_addr, source.block_idx) == pred_key
                    and isinstance(source.stmt_idx, int) and source.stmt_idx >= index
                ):
                    varid = edge_state.get(offset, {}).get(width)
                if varid is not None:
                    current[width] = varid
            widths[offset] = current
        result[point] = widths
    return result


@dataclass(frozen=True)
class NativeWordFarReturnInput8616:
    """The reaching SP definition before the exact RETF instruction."""

    site: int
    layout: WordFarReturnLayout8616 | WordNearReturnLayout8616 | WordInterruptReturnLayout8616
    definition: NativeGPExitDefinition8616
    incoming_operand: VirtualVariable | None = None


def _native_word_far_return_inputs_8616(project, graph, view, entry, definitions):
    """Observe the instruction input, separate from the terminal SP write."""
    sites = {}
    blocks = {(block.addr, block.idx): block for block in graph}
    for block in graph:
        if not block.statements or not isinstance(block.statements[-1], Return):
            continue
        site = block.statements[-1].tags.get("ins_addr")
        if type(site) is not int:
            continue
        # Use a block/statement point so cloned or split exits sharing an
        # instruction address cannot borrow one another's reaching state.
        first = next((i for i, stmt in enumerate(block.statements) if stmt.tags.get("ins_addr") == site), None)
        if os.getenv("INERTIA_DEBUG_WORD_FAR_RETURN"):
            print("[return-observation-site]", hex(block.addr), hex(site), first)
        if first is None:
            continue
        try:
            opcode = bytes(project.loader.memory.load(site, 1))
            encoding = bytes(project.loader.memory.load(site, 3)) if opcode in (b"\xca", b"\xc2") else opcode
        except (KeyError, ValueError):
            continue
        layout = (WordFarReturnLayout8616.from_encoding(encoding)
                  or WordNearReturnLayout8616.from_encoding(encoding)
                  or WordInterruptReturnLayout8616.from_encoding(encoding))
        if layout is not None:
            sites[("stmt", ((block.addr, block.idx), first), ObservationPointType.OP_BEFORE)] = (site, layout)
    if not sites:
        return ()
    observations = view.observe(list(sites), entry=entry)
    offset, width = project.arch.registers["sp"]
    bindings = []
    for point, state in observations.items():
        varid = state.get(offset, {}).get(width)
        source = definitions.get(varid)
        if os.getenv("INERTIA_DEBUG_WORD_FAR_RETURN"):
            print("[return-observation-sp]", point, varid, source)
            if source is None and os.getenv("INERTIA_DEBUG_WORD_FAR_RETURN") == "2":
                for candidate in graph:
                    print("[return-observation-block]", hex(candidate.addr), [(str(s), s.tags) for s in candidate.statements])
        exit_key, first = point[1]
        site, layout = sites[point]
        if source is None or source.is_extern:
            # SRDA can omit an incoming lane until its first use. Require
            # the exact decoded return's stack increment to name that operand.
            if entry is None or graph.in_degree(entry):
                continue
            exit_block = blocks[exit_key]
            increments = [
                stmt for stmt in exit_block.statements[first:]
                if stmt.tags.get("ins_addr") == site and isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.category is VirtualVariableCategory.REGISTER
                and stmt.dst.oident == offset and stmt.dst.size == width
            ]
            interrupt = isinstance(layout, WordInterruptReturnLayout8616)
            if not increments or (not interrupt and len(increments) != 1):
                continue
            stmt = increments[0]
            rhs = stmt.src
            if not isinstance(rhs, BinaryOp) or rhs.op != "Add":
                continue
            pre, amount = rhs.operands
            if (
                not isinstance(pre, VirtualVariable) or pre.category is not VirtualVariableCategory.REGISTER
                or pre.oident != offset or pre.size != width
                or not isinstance(amount, Const)
                or amount.value not in ((2, 6) if interrupt else (layout.sp_displacement,))
                or not isinstance(stmt.dst, VirtualVariable) or stmt.dst.oident != offset or stmt.dst.size != width
                or any(
                    isinstance(s, Assignment) and isinstance(s.dst, VirtualVariable)
                    and s.dst.category is VirtualVariableCategory.REGISTER
                    and s.dst.oident < offset + width and offset < s.dst.oident + s.dst.size
                    for key, block in blocks.items()
                    for s in (block.statements[:first] if key == exit_key else block.statements)
                )
            ):
                continue
            pre_origin = definitions.get(pre.varid)
            if pre_origin is not None and not pre_origin.is_extern:
                continue
            # The terminal definition is retained as provenance; the true
            # input is the operand of that definition.
            terminal_origin = definitions.get(stmt.dst.varid)
            if terminal_origin is None:
                continue
            bindings.append(NativeWordFarReturnInput8616(
                site, layout, NativeGPExitDefinition8616(exit_key, offset, width, stmt.dst.varid, terminal_origin),
                pre.copy(),
            ))
            continue
        if source is None or source.is_extern:
            continue
        bindings.append(NativeWordFarReturnInput8616(
            site, layout, NativeGPExitDefinition8616(exit_key, offset, width, varid, source),
        ))
    return tuple(bindings)


def _apply_native_gp_return_dce_guard_8616() -> None:
    """Retain actual reaching GP writes at native return points during DCE."""
    original = AILSimplifier._remove_dead_assignments
    if original.__name__ == "_remove_dead_with_gp_returns_8616":
        return

    def _remove_dead_with_gp_returns_8616(
        self: AILSimplifier,
    ) -> tuple[bool, set[tuple[int, int | None]]]:
        """Protect exact SSA register definitions, not hypothetical ABI values."""
        arch = self.project.arch
        graph = self.func_graph
        if arch.name != "86_16" or graph is None or self.func is None:
            return original(self)
        points = [
            ("node", (block.addr, block.idx), ObservationPointType.OP_AFTER)
            for block in graph if block.statements and isinstance(block.statements[-1], Return)
        ]
        if not points:
            return original(self)
        model = self._compute_reaching_definitions()
        entry = next((block for block in graph if block.addr == self.func.addr and block.idx is None), None)
        view = SRDAView(model)
        observations = view.observe(points, entry=entry)
        frame_offsets = {arch.sp_offset, arch.bp_offset, arch.ip_offset}
        stack_exit = os.getenv("INERTIA_EXPERIMENTAL_STACK_EXIT_USE") == "1"
        frame_base_exit = os.getenv("INERTIA_EXPERIMENTAL_BP_EXIT_USE") == "1"
        if stack_exit:
            frame_offsets.discard(arch.sp_offset)
        if frame_base_exit:
            frame_offsets.discard(arch.bp_offset)
        offsets = {reg.vex_offset for reg in arch.register_list
                   if reg.general_purpose and reg.vex_offset not in frame_offsets}
        flags_exit = os.getenv("INERTIA_EXPERIMENTAL_FLAGS_EXIT_USE") == "1"
        if flags_exit:
            offsets.add(arch.registers["flags"][0])
        if os.getenv("INERTIA_EXPERIMENTAL_GP_EXIT_USES") == "1":
            observations = _gp_exit_edge_observations_8616(
                graph, view, entry, observations, model.all_vvar_definitions,
            )
        facts = tuple(_native_gp_exit_definitions_8616(
            observations, model.all_vvar_definitions, offsets,
        ))
        retained = {fact.variable_id for fact in facts}
        if os.getenv("INERTIA_DEBUG_WORD_FAR_RETURN"):
            blocks = {(block.addr, block.idx): block for block in graph}
            for fact in _native_word_far_return_inputs_8616(self.project, graph, view, entry, model.all_vvar_definitions):
                if fact.definition.bind_operand(blocks) is not None:
                    print("[word-far-return-input]", fact)
        if os.getenv("INERTIA_EXPERIMENTAL_GP_EXIT_USES") == "1":
            blocks = {(block.addr, block.idx): block for block in graph}
            coordinates = {arch.registers[name] for name in ("bx", "cx", "dx")}
            if stack_exit:
                coordinates.add(arch.registers["sp"])
            if frame_base_exit:
                coordinates.add(arch.registers["bp"])
            if flags_exit:
                coordinates.add(arch.registers["flags"])
            proven_flags = set()
            if flags_exit:
                if entry is not None:
                    flag_coordinate = arch.registers["flags"]
                    for exit_block in graph:
                        if not exit_block.statements or not isinstance(exit_block.statements[-1], Return):
                            continue
                        key = (exit_block.addr, exit_block.idx)
                        edge_facts = _agreed_gp_exit_definitions_8616(
                            graph, entry, exit_block, {flag_coordinate},
                        )
                        observed = tuple(
                            fact for fact in facts if fact.exit_key == key
                            and (fact.register_offset, fact.byte_width) == flag_coordinate
                        )
                        if os.getenv("INERTIA_DEBUG_FLAGS_EXIT_BINDING") == "1":
                            print("[flags-exit-binding]", key, "observed", observed, "edge", edge_facts)
                        if edge_facts is not None:
                            proven_flags.update(edge_facts)
                        if edge_facts is not None and edge_facts != observed:
                            # Prefer the exact edge-authenticated value over
                            # the block-end observation when the CFG admits
                            # a complete lane proof.
                            facts = (
                                *tuple(fact for fact in facts if fact.exit_key != key
                                       or (fact.register_offset, fact.byte_width) != flag_coordinate),
                                *edge_facts,
                            )
                            retained.update(fact.variable_id for fact in edge_facts)
            if (
                os.getenv("INERTIA_EXPERIMENTAL_GP_EXIT_LANES") == "1"
                and entry is not None
            ):
                gp_names = (
                    "eax", "ax", "al", "ah", "ebx", "bx", "bl", "bh",
                    "ecx", "cx", "cl", "ch", "edx", "dx", "dl", "dh",
                    "esi", "si", "edi", "di",
                )
                gp_coordinates = {arch.registers[name] for name in gp_names}
                for exit_block in graph:
                    if not exit_block.statements or not isinstance(exit_block.statements[-1], Return):
                        continue
                    path = _unjoined_gp_exit_path_8616(graph, entry, exit_block)
                    lane_facts = (
                        _agreed_gp_exit_definitions_8616(graph, entry, exit_block, gp_coordinates)
                        if path is None else _ordered_gp_exit_definitions_8616(path, gp_coordinates)
                    )
                    if lane_facts is None:
                        continue
                    key = (exit_block.addr, exit_block.idx)
                    facts = (*tuple(fact for fact in facts if fact.exit_key != key or
                                    (fact.register_offset, fact.byte_width) not in gp_coordinates),
                             *lane_facts)
                    retained.update(fact.variable_id for fact in lane_facts)
                    coordinates.update(gp_coordinates)
            modified = False
            pending: dict[tuple[int, int | None], list[SideEffectStatement]] = {}
            replaced_interrupt_sites: dict[tuple[int, int | None], int] = {}
            published = {
                key: {
                    tuple(stmt.tags["inertia_gp_exit_coordinate"])
                    for stmt in block.statements
                    if "inertia_gp_exit_coordinate" in stmt.tags
                }
                for key, block in blocks.items()
            }
            if os.getenv("INERTIA_EXPERIMENTAL_WORD_FAR_RETURN") == "1":
                for frame in _native_word_far_return_inputs_8616(
                    self.project, graph, view, entry, model.all_vvar_definitions,
                ):
                    key = frame.definition.exit_key
                    sp_coordinate = arch.registers["sp"]
                    if sp_coordinate in published[key]:
                        continue
                    pre_sp = frame.definition.bind_operand(blocks)
                    incoming = frame.incoming_operand is not None
                    if incoming:
                        pre_sp = frame.incoming_operand
                    if pre_sp is None:
                        continue
                    interrupt = isinstance(frame.layout, WordInterruptReturnLayout8616)
                    tags = {
                        **blocks[key].statements[-1].tags,
                        "inertia_gp_exit_coordinate": sp_coordinate,
                        ("inertia_word_interrupt_return" if interrupt else
                         "inertia_word_near_return_cleanup" if isinstance(frame.layout, WordNearReturnLayout8616)
                         else "inertia_word_far_return_cleanup"): 0 if interrupt else frame.layout.cleanup,
                        "inertia_return_sp_is_incoming": incoming,
                    }
                    atom = self._ail_manager.next_atom
                    call = Call(atom(), "inertia_architectural_gp_exit", args=[pre_sp], bits=0, **tags)
                    pending.setdefault(key, []).append(SideEffectStatement(atom(), call, **tags))
                    published[key].add(sp_coordinate)
                    if interrupt:
                        published[key].add(arch.registers["flags"])
                        replaced_interrupt_sites[key] = frame.site
            for fact in facts:
                coordinate = (fact.register_offset, fact.byte_width)
                if coordinate not in coordinates or coordinate in published[fact.exit_key]:
                    continue
                use = fact.bind_exit_use(blocks, self._ail_manager.next_atom)
                if use is not None:
                    if fact in proven_flags:
                        carry_sources = {}
                        rows = _flags_phi_input_producers_8616(
                            fact, blocks, model.all_vvar_definitions, carry_sources=carry_sources,
                        )
                        if rows:
                            use.tags["inertia_flags_phi_input_producers"] = rows
                            use.tags["inertia_flags_phi_carry_sources"] = tuple(sorted(carry_sources.items()))
                        if os.getenv("INERTIA_DEBUG_FLAGS_EXIT_BINDING") == "2":
                            print("[flags-phi-inputs]", fact, rows)
                            for block in blocks.values():
                                for stmt in block.statements:
                                    if (isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)
                                        and stmt.dst.was_reg and stmt.dst.oident == coordinate[0]):
                                            print("[flags-ssa]", hex(block.addr), stmt.tags.get("ins_addr"),
                                                  stmt, "carry", _packed_carry_source_8616(stmt.src))
                    pending.setdefault(fact.exit_key, []).append(use)
                    published[fact.exit_key].add(coordinate)
            for key, uses in pending.items():
                block = blocks[key]
                terminal = block.statements[-1]
                prefix = block.statements[:-1]
                if key in replaced_interrupt_sites:
                    site = replaced_interrupt_sites[key]
                    # The decoded IRET is now represented by one effect.
                    # Keep labels and statements from all other instructions.
                    prefix = [
                        stmt for stmt in prefix
                        if stmt.tags.get("ins_addr") != site or not isinstance(stmt, Assignment)
                    ]
                block.statements = [*prefix, *uses, terminal]
                modified = True
            if modified:
                self._clear_cache()
        previous = self._avoid_vvar_ids
        self._avoid_vvar_ids = previous | retained
        try:
            return original(self)
        finally:
            self._avoid_vvar_ids = previous

    AILSimplifier._remove_dead_assignments = _remove_dead_with_gp_returns_8616
