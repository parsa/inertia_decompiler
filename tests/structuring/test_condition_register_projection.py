from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from inertia.structuring.condition_lowering import (
    SameBlockRegisterAssignment8616,
    SameBlockRegisterAssignmentIndex8616,
    SameBlockRegisterProjectionVerdict8616,
    materialize_same_block_register_projection_8616,
)


def _project(*, aliases_destination: bool, affine_update: bool, coalesced: bool = False):
    block = 0x1000
    offset = 12
    project = SimpleNamespace(arch=SimpleNamespace(registers={"bx": (offset, 2)}))
    codegen = SimpleNamespace(
        project=project, next_ident=lambda name: name, next_node_idx=lambda: 1, cstyle_null_cmp=False,
    )
    type_ = SimTypeShort(False)
    storage = SimRegisterVariable(offset, 2, ident="bx", region=block)
    old_storage = storage if aliases_destination else SimRegisterVariable(0, 2, ident="source", region=block)
    unified = SimRegisterVariable(offset, 2, ident="unified", region=block) if coalesced else None
    destination = CVariable(storage, unified_variable=unified, variable_type=type_, codegen=codegen)
    old_value = CVariable(old_storage, unified_variable=unified, variable_type=type_, codegen=codegen)
    constant = CConstant(64, type_, codegen=codegen)
    rhs = CBinaryOp("Add", old_value, constant, codegen=codegen) if affine_update else constant
    update = SameBlockRegisterAssignment8616(block, destination, rhs, offset, 2)
    value = IRValue(MemSpace.REG, name="bx", offset=offset, size=2)
    condition = ConditionIR("ult", value, block_addr=block, producer_insn=block + 3)
    index = SameBlockRegisterAssignmentIndex8616(((block, (update,)),))
    result = materialize_same_block_register_projection_8616(value, condition, project, codegen, assignment_index=index)
    assert result.verdict is SameBlockRegisterProjectionVerdict8616.MATERIALIZED
    return result.expression, destination, rhs


def test_condition_reads_recurrent_update_destination_instead_of_replay():
    expression, destination, _ = _project(aliases_destination=True, affine_update=True)
    assert expression is destination


def test_condition_reads_destination_when_distinct_ssa_values_share_storage():
    expression, destination, _ = _project(aliases_destination=False, affine_update=True, coalesced=True)
    assert expression is destination


def test_condition_preserves_nonself_referential_projection():
    expression, _, rhs = _project(aliases_destination=False, affine_update=True)
    assert expression is rhs


def test_condition_preserves_nonloop_constant_projection():
    expression, _, rhs = _project(aliases_destination=True, affine_update=False)
    assert expression is rhs
