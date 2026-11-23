"""Retain architectural SS writes when proved GP saves use private C locals.

Layer: Types/Lowering.
Responsibility: bind an existing Alias save fact to its decoded PUSH and
preserve the physical effect independently of its C value representation.
"""

from __future__ import annotations

from enum import Enum, auto
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c
from angr.errors import AngrError
from angr.project import Project
from angr.sim_type import SimTypeShort
from angr.sim_variable import (
    SimRegisterVariable,
    SimStackVariable,
    SimTemporaryVariable,
)
from capstone import CsError, CsInsn
from capstone.x86_const import X86_INS_PUSH, X86_OP_IMM, X86_OP_REG

from inertia.alias.segment_stack_restore import (
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
    build_x86_16_stack_register_restore_artifact_8616,
)
from inertia.alias.word_bp_frame import prove_word_bp_frame_8616
from inertia.ir.core import IRFunctionArtifact
from inertia.pipeline.errors import PipelineHardError

from .c_ast_utils import _iter_c_node_occurrences_8616
from .entry_stack_pointer_capture import (
    entry_stack_pointer_projection_8616,
    is_entry_stack_pointer_capture_8616,
    is_entry_stack_pointer_projection_8616,
    is_plain_integer_literal_8616,
    matches_entry_runtime_read_8616,
    matches_entry_sp_local_8616,
    observe_entry_stack_pointer_storage_8616,
    prepare_entry_stack_pointer_capture_8616,
)
from .gp_register_state import (
    _record_runtime_gp_global_8616,
    runtime_gp_expression_view_8616,
    runtime_gp_state_expr_8616,
)
from .gp_stack_restore_identity import _stack_write_offsets_8616
from .segment_access_policy import instruction_addrs_from_node_8616
from .segment_register_state import (
    runtime_segment_state_cvar_8616,
    runtime_segment_state_variable_matches_8616,
)

PUSH_WORD_HELPER_8616 = "inertia_push_word"
_PHYSICAL_PUSH_SITE = "inertia_physical_gp_push_8616"


class _Codegen(Protocol):
    """Codegen boundary retaining the function and live machine evidence."""

    project: Project
    cfunc: c.CFunction | None
    _inertia_vex_ir_artifact: IRFunctionArtifact


class GPPushStoreResult8616(Enum):
    """Terminal physical-effect status independent of the POP projection."""

    NOT_PUSH = auto()
    RETAINED = auto()
    INSERTED = auto()


def tag_physical_gp_push_8616(call: c.CFunctionCall, site: int) -> None:
    """Record the exact machine store site on an owned runtime PUSH call."""
    call.tags = {**call.tags, _PHYSICAL_PUSH_SITE: site}


def _decoded_instruction(project: Project, source: IRFunctionArtifact, site: int) -> CsInsn | None:
    """Decode only a machine address represented by the retained IR artifact."""
    if not any(item.addr == site for block in source.blocks for item in block.instrs):
        return None
    try:
        wrappers = project.factory.block(site, num_inst=1, opt_level=0).capstone.insns
        if len(wrappers) == 1 and wrappers[0].insn.address == site:
            return wrappers[0].insn
    except (AngrError, CsError, KeyError, ValueError):
        return None
    return None


def _entry_push_sites(project: Project, source: IRFunctionArtifact) -> tuple[int, ...]:
    """Decode a contiguous word-PUSH prefix with no alternate entry edge."""
    entries = [block for block in source.blocks if block.addr == source.function_addr]
    if len(entries) != 1 or entries[0].refusals:
        return ()
    entry = entries[0]
    addresses = tuple(dict.fromkeys(item.addr for item in entry.instrs if item.addr is not None))
    targets = {target for block in source.blocks for target in block.successor_addrs}
    targets.update(block.addr for block in source.blocks if block is not entry)
    site = source.function_addr
    sites = []
    for addr in addresses:
        if addr != site or site in targets:
            break
        insn = _decoded_instruction(project, source, site)
        if insn is None or insn.id != X86_INS_PUSH:
            break
        operands = insn.operands
        if (len(operands) != 1 or operands[0].size != 2
                or operands[0].type not in (X86_OP_REG, X86_OP_IMM)
                or (operands[0].type == X86_OP_REG and insn.reg_name(operands[0].reg) == "sp")):
            break
        sites.append(site)
        site += insn.size
    return tuple(sites)


def _is_physical_push_call(node: object, site: int | None) -> bool:
    """Recognize the owned machine-store projection, not an arbitrary call."""
    return (site is not None and isinstance(node, c.CFunctionCall)
            and node.callee_target == PUSH_WORD_HELPER_8616 and node.callee_func is None
            and len(node.args) == 3 and node.tags.get(_PHYSICAL_PUSH_SITE) == site)


def is_physical_gp_push_call_8616(node: c.CFunctionCall) -> bool:
    """Identify a tagged store-only runtime call, not an opaque guest CALL."""
    site = node.tags.get(_PHYSICAL_PUSH_SITE)
    return isinstance(site, int) and _is_physical_push_call(node, site)


def _bp_install_push(statement: c.CAssignment, site: int, function_addr: int) -> c.CFunctionCall | None:
    """Match word_bp_frame's canonical EBP merge with no other evaluated effects."""
    codegen = statement.codegen
    ebp = runtime_gp_state_expr_8616("ebp", codegen=codegen, function_addr=function_addr)
    if ebp is None or not matches_entry_runtime_read_8616(statement.lhs, ebp):
        return None
    rhs = statement.rhs
    if not isinstance(rhs, c.CBinaryOp) or rhs.op != "Or":
        return None
    preserved = c.CBinaryOp("And", ebp, c.CConstant(0xffff0000, ebp.type, codegen=codegen), codegen=codegen)
    if not matches_entry_runtime_read_8616(rhs.lhs, preserved):
        return None
    inserted = rhs.rhs
    if (not isinstance(inserted, c.CBinaryOp) or inserted.op != "And"
            or not matches_entry_runtime_read_8616(inserted.rhs, c.CConstant(0xffff, ebp.type, codegen=codegen))):
        return None
    value = inserted.lhs
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    if not isinstance(value, c.CTypeCast) or value.dst_type != word or value.type != word:
        return None
    push = value.expr
    if not isinstance(push, c.CFunctionCall) or not _is_physical_push_call(push, site):
        return None
    bp = runtime_gp_expression_view_8616(push.args[2])
    return push if bp is not None and bp.register_name == "bp" else None


def _standalone_push_owner(statement: c.CExpressionStatement, sites: tuple[int, ...]) -> c.CFunctionCall | None:
    site = statement.tags.get("ins_addr")
    return statement.expr if site in sites and _is_physical_push_call(statement.expr, site) else None


def _entry_push_owner(
    statement: object, sites: tuple[int, ...], codegen: _Codegen, source: IRFunctionArtifact,
) -> c.CFunctionCall | None:
    """Recognize a standalone store or bind an embedded install to the live machine frame."""
    if isinstance(statement, c.CExpressionStatement):
        return _standalone_push_owner(statement, sites)
    if not isinstance(statement, c.CAssignment) or not sites:
        return None
    call = _bp_install_push(statement, sites[0], source.function_addr)
    if call is None:
        return None
    frame = prove_word_bp_frame_8616(codegen.project, source)
    if frame is None or frame.push != sites[0] or frame.set_bp != statement.tags.get("ins_addr"):
        return None
    return call


def _is_unbound_boundary_write(
    statement: object, sites: tuple[int, ...], codegen: _Codegen, source: IRFunctionArtifact,
) -> bool:
    """An adjacent physical lvalue may alias an owned slot without a distinct machine STORE."""
    if not isinstance(statement, c.CAssignment):
        return False
    lhs = statement.lhs
    if not (isinstance(lhs, c.CFunctionCall) and lhs.callee_target in {"SEG_U8", "SEG_U16", "SEG_U32"}
            or isinstance(lhs, c.CUnaryOp) and lhs.op == "Dereference"
            or isinstance(lhs, c.CIndexedVariable) and not _is_local_or_register(codegen, lhs)):
        return False
    site = statement.tags.get("ins_addr")
    return site is None or site in sites or not any(
        item.op == "STORE" and item.addr == site for block in source.blocks for item in block.instrs
    )


def _push_value(codegen: _Codegen, insn: CsInsn, function_addr: int) -> c.CExpression | None:
    """Materialize the decoded PUSH's architectural input, never an unrelated local."""
    op = insn.operands[0]
    if op.type == X86_OP_IMM:
        word = SimTypeShort(False).with_arch(codegen.project.arch)
        return c.CConstant(op.imm & 0xffff, word, codegen=codegen)
    return runtime_gp_state_expr_8616(insn.reg_name(op.reg), codegen=codegen, function_addr=function_addr)


def _verified_entry_owners(
    codegen: _Codegen, source: IRFunctionArtifact, root: c.CStatements,
    sites: tuple[int, ...], nodes: tuple[object, ...],
) -> tuple[tuple[int, c.CStatement], ...] | None:
    """Authenticate one rendered occurrence per owner, including untagged calls in the census."""
    calls = [id(node) for node in nodes
             if isinstance(node, c.CFunctionCall) and node.callee_target == PUSH_WORD_HELPER_8616]
    if not calls:
        return ()
    capture = observe_entry_stack_pointer_storage_8616(codegen, source)
    if capture is None:
        return None
    owners = []
    owned_calls = []
    for statement in root.statements[1:]:
        call = _entry_push_owner(statement, sites, codegen, source)
        if call is None:
            if owners and _is_unbound_boundary_write(statement, sites, codegen, source):
                return None
            break
        site = call.tags[_PHYSICAL_PUSH_SITE]
        if owners and site <= owners[-1][0]:
            return None
        ss, sp, value = call.args
        if (not isinstance(ss, c.CVariable) or ss.unified_variable is not None
                or not isinstance(ss.type, SimTypeShort) or ss.type.signed is not False
                or not runtime_segment_state_variable_matches_8616(ss.variable, "ss", source.function_addr)):
            return None
        displacement = -2 * sites.index(site)
        if not (is_entry_stack_pointer_projection_8616(sp, capture, displacement) if displacement
                else matches_entry_sp_local_8616(sp, capture)):
            return None
        insn = _decoded_instruction(codegen.project, source, site)
        if insn is None:
            return None
        expected = _push_value(codegen, insn, source.function_addr)
        if isinstance(expected, c.CConstant):
            if not (is_plain_integer_literal_8616(value, expected.value) and isinstance(value.type, SimTypeShort)
                    and value.type.signed is False):
                return None
        elif expected is None or not matches_entry_runtime_read_8616(value, expected):
            return None
        owners.append((site, statement))
        owned_calls.append(id(call))
    return tuple(owners) if calls == owned_calls else None


def authenticated_entry_push_statements_8616(
    codegen: object, source: IRFunctionArtifact,
) -> frozenset[int]:
    """Observe only standalone, physically authenticated entry stores for local-return proof."""
    boundary = cast(_Codegen, codegen)
    function = boundary.cfunc
    if function is None or not isinstance(function.statements, c.CStatements):
        return frozenset()
    root = function.statements
    nodes = tuple(_iter_c_node_occurrences_8616(root))
    if not any(isinstance(node, c.CFunctionCall) and node.callee_target == PUSH_WORD_HELPER_8616 for node in nodes):
        return frozenset()
    sites = _entry_push_sites(boundary.project, source)
    owners = _verified_entry_owners(boundary, source, root, sites, nodes)
    return frozenset(id(stmt) for _, stmt in owners or () if isinstance(stmt, c.CExpressionStatement))


def _is_local_or_register(codegen: object, node: object) -> bool:
    """Separate private scalar and byte-local lvalues from possible guest writes."""
    if isinstance(node, c.CVariable):
        return (isinstance(node.variable, (SimStackVariable, SimRegisterVariable, SimTemporaryVariable))
                or runtime_gp_expression_view_8616(node) is not None)
    return isinstance(node, c.CIndexedVariable) and _stack_write_offsets_8616(codegen, node) is not None


def preserve_gp_push_store_8616(
    codegen: object, source: IRFunctionArtifact | None, fact: SegmentStackRestoreFact8616,
) -> GPPushStoreResult8616:
    """Emit the word store at a proved entry PUSH, or refuse an unsafe placement.

    The runtime helper takes the pre-PUSH SP and writes low then high through
    the existing frame-write hook; its returned SP is deliberately unused.
    GP/stack exit lowering remains responsible for architectural SP values.
    """
    boundary = cast(_Codegen, codegen)
    function = boundary.cfunc
    assert function is not None
    site = fact.saved_instruction_addr

    def refuse(reason: str) -> PipelineHardError:
        return PipelineHardError(
            "GP save physical PUSH store unproven", layer="stack_lowering",
            function_addr=function.addr, details={"save_addr": site, "reason": reason},
        )

    if (not isinstance(source, IRFunctionArtifact) or source.function_addr != function.addr
            or fact.verdict is not SegmentStackRestoreVerdict8616.PROVEN or site is None):
        raise refuse("no bound machine save")
    instruction = _decoded_instruction(boundary.project, source, site)
    if instruction is None:
        raise refuse("no exact decoded save instruction")
    if instruction.id != X86_INS_PUSH:
        return GPPushStoreResult8616.NOT_PUSH
    operands = instruction.operands
    if len(operands) != 1 or operands[0].size != 2:
        raise refuse("unsupported PUSH width")
    operand = operands[0]
    register_matches = operand.type == X86_OP_REG and instruction.reg_name(operand.reg) == fact.saved_register
    immediate_matches = (operand.type == X86_OP_IMM and fact.constant_value is not None
                         and (operand.imm & 0xffff) == fact.constant_value)
    if not (register_matches or immediate_matches):
        raise refuse("PUSH operand does not match the proved saved word")

    root = function.statements
    nodes = tuple(_iter_c_node_occurrences_8616(root))
    retained = [node for node in nodes if _is_physical_push_call(node, site)]
    sites = _entry_push_sites(boundary.project, source)
    preceding_sites = set(sites[:sites.index(site) + 1]) if site in sites else {site}
    ambiguous = any(
        (isinstance(node, c.CFunctionCall) and not any(_is_physical_push_call(node, addr) for addr in preceding_sites)
         or isinstance(node, c.CExpressionStatement) and isinstance(node.expr, c.CFunctionCall)
         and _standalone_push_owner(node, sites) is None
         or isinstance(node, c.CAssignment) and not _is_local_or_register(codegen, node.lhs))
        and not preceding_sites.isdisjoint(instruction_addrs_from_node_8616(node))
        for node in nodes
    )
    if len(retained) > 1 or ambiguous:
        raise refuse("ambiguous existing PUSH store")
    displacement = -2 * sites.index(site) if site in sites else None
    if (displacement is None or fact.stack_offsets != (displacement - 2, displacement - 1)
            or not isinstance(root, c.CStatements)):
        raise refuse("no exact entry PUSH placement")

    owners = _verified_entry_owners(boundary, source, root, sites, nodes)
    if owners is None:
        raise refuse("existing PUSH has no authenticated entry owner, capture or operands")
    owner_sites = [owner_site for owner_site, _ in owners]
    if retained:
        return GPPushStoreResult8616.RETAINED
    if any(isinstance(node, (c.CGoto, c.CLabel)) for node in nodes):
        raise refuse("no exact entry PUSH placement")

    word = SimTypeShort(False).with_arch(boundary.project.arch)
    ss = runtime_segment_state_cvar_8616("ss", codegen=codegen, variable_type=word, function_addr=function.addr)
    entry_sp = observe_entry_stack_pointer_storage_8616(codegen, source)
    if entry_sp is None:
        if any(is_entry_stack_pointer_capture_8616(node) for node in nodes):
            raise refuse("invalid existing entry SP capture")
        capture = prepare_entry_stack_pointer_capture_8616(codegen, source, (fact,))
        if capture is None or capture.value is None:
            raise refuse("missing proved entry SP capture")
        entry_sp = capture.value
    sp = entry_stack_pointer_projection_8616(entry_sp, displacement, codegen) if displacement else entry_sp
    value = _push_value(boundary, instruction, function.addr)
    if ss is None or sp is None or value is None:
        raise refuse("missing runtime source state")
    push = c.CFunctionCall(PUSH_WORD_HELPER_8616, None, [ss, sp, value], codegen=codegen)
    tag_physical_gp_push_8616(push, site)
    stmt = c.CExpressionStatement(push, codegen=codegen, tags={"ins_addr": site})
    root.statements.insert(_entry_store_index(root) + sum(addr < site for addr in owner_sites), stmt)
    _record_runtime_gp_global_8616(codegen, "esp")
    register_view = runtime_gp_expression_view_8616(value)
    if register_view is not None:
        _record_runtime_gp_global_8616(codegen, register_view.parent_name)
    return GPPushStoreResult8616.INSERTED


def _entry_store_index(root: c.CStatements) -> int:
    """Keep the immutable entry-SP capture first, if it is already present."""
    return int(bool(root.statements and is_entry_stack_pointer_capture_8616(root.statements[0])))


def preserve_entry_bp_push_store_8616(codegen: object) -> bool:
    """Cover the separate BP frame lane without changing any BP restore proof."""
    boundary = cast(_Codegen, codegen)
    try:
        source = boundary._inertia_vex_ir_artifact
    except AttributeError:
        return False
    if not isinstance(source, IRFunctionArtifact) or boundary.cfunc is None:
        return False
    instruction = _decoded_instruction(boundary.project, source, source.function_addr)
    if instruction is None or instruction.id != X86_INS_PUSH:
        return False
    operands = instruction.operands
    if len(operands) != 1:
        return False
    operand = operands[0]
    if operand.size != 2 or operand.type != X86_OP_REG or instruction.reg_name(operand.reg) != "bp":
        return False
    artifact = build_x86_16_stack_register_restore_artifact_8616(source, tracked_registers=frozenset({"bp"}))
    for fact in artifact.facts:
        if (fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
                and fact.saved_instruction_addr == source.function_addr and fact.saved_register == "bp"):
            return preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.INSERTED
    return False
