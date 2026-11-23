"""Retain physical SS accesses for a proven word BP frame.

Layer: Types/Lowering.
Responsibility: project the Alias-proven frame's physical save and reload.
"""
import os

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable

from inertia.alias.word_bp_frame import prove_word_bp_frame_8616
from .c_ast_utils import _iter_c_nodes_deep_8616, iter_c_direct_children_8616
from .entry_stack_pointer_capture import (
    entry_stack_pointer_projection_8616,
    observe_entry_stack_pointer_capture_8616,
)
from .gp_push_store import PUSH_WORD_HELPER_8616, tag_physical_gp_push_8616
from .gp_register_state import runtime_gp_state_assignment_8616, runtime_gp_state_expr_8616
from .segment_register_state import runtime_segment_state_cvar_8616


def lower_word_bp_frame_8616(codegen: c.CStructuredCodeGenerator) -> bool:
    """Replace a pair of private byte carriers and their only restore."""
    if os.getenv("INERTIA_EXPERIMENTAL_WORD_FAR_RETURN") != "1":
        return False
    source = getattr(codegen, "_inertia_vex_ir_artifact", None)
    if source is None:
        return False
    frame = prove_word_bp_frame_8616(codegen.project, source)
    if frame is None:
        return False
    capture = observe_entry_stack_pointer_capture_8616(codegen, source)
    if capture is None:
        return False
    function = codegen.cfunc
    nodes = tuple(_iter_c_nodes_deep_8616(function.statements))
    containers = [node for node in nodes if isinstance(node, c.CStatements)]
    saves, pops = [], []
    for container in containers:
        for index, stmt in enumerate(container.statements):
            if not isinstance(stmt, c.CAssignment):
                continue
            site = stmt.tags.get("ins_addr")
            if site == frame.push:
                saves.append((container, index, stmt))
            if site == frame.pop:
                pops.append((container, index, stmt))
    if len(saves) != 2 or len(pops) != 1:
        return False
    owner, index, lo = saves[0]
    second_owner, second_index, hi = saves[1]
    pop_owner, pop_index, pop = pops[0]
    if (second_owner is not owner or second_index != index + 1
        or not all(isinstance(stmt.lhs, c.CVariable)
                   and isinstance(stmt.lhs.variable, SimStackVariable) for stmt in (lo, hi))):
        return False
    variables = [lo.lhs.variable, hi.lhs.variable]
    if variables[0].offset + 1 != variables[1].offset:
        return False
    for variable in variables:
        uses = [child for node in nodes for child in iter_c_direct_children_8616(node)
                if isinstance(child, c.CVariable) and child.variable == variable]
        restore_uses = [node for node in _iter_c_nodes_deep_8616(pop.rhs)
                        if isinstance(node, c.CVariable) and node.variable == variable]
        if len(uses) != 2 or len(restore_uses) != 1:
            return False
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    ss = runtime_segment_state_cvar_8616("ss", codegen=codegen, variable_type=word, function_addr=function.addr)
    bp = runtime_gp_state_expr_8616("bp", codegen=codegen, function_addr=function.addr)
    if ss is None or bp is None:
        return False
    push = c.CFunctionCall(PUSH_WORD_HELPER_8616, None, [ss, capture.value, bp], codegen=codegen)
    tag_physical_gp_push_8616(push, frame.push)
    install = runtime_gp_state_assignment_8616(
        "bp", c.CTypeCast(push.type, word, push, codegen=codegen),
        codegen=codegen, function_addr=function.addr,
    )
    if install is None:
        return False
    install.tags = {**install.tags, "ins_addr": frame.set_bp}
    slot = entry_stack_pointer_projection_8616(capture.value, frame.saved_word_offset, codegen)
    read = c.CFunctionCall("inertia_stack_read_word", None, [ss, slot], codegen=codegen)
    restore = runtime_gp_state_assignment_8616(
        "bp", c.CTypeCast(read.type, word, read, codegen=codegen),
        codegen=codegen, function_addr=function.addr,
    )
    if restore is None:
        return False
    restore.tags = {**restore.tags, "ins_addr": frame.pop}
    pop_owner.statements[pop_index] = restore
    owner.statements[index:index + 2] = [install]
    return True
