from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CContinue,
    CForLoop,
    CGoto,
    CIfElse,
    CLabel,
    CReturn,
    CStatements,
    CSwitchCase,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimTemporaryVariable

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.entry_stack_pointer_capture import _existing_capture_value_8616, _prepare_entry_capture
from inertia.lowering.gp_register_state import _c_register_identity_8616, runtime_gp_state_expr_8616
from inertia.lowering.gp_register_versions import capture_gp_register_versions_8616


def _fixture(return_entry: bool, *, identified: bool = True):
    arch = Arch86_16()
    address = 0x10000
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch), next_ident=lambda name: name, next_node_idx=lambda: 1,
        cstyle_null_cmp=False,
    )
    type_ = SimTypeShort(False).with_arch(arch)
    offset, width = arch.registers["ax"]
    entry = CVariable(
        SimRegisterVariable(offset, width, ident="entry", region=address),
        variable_type=type_, vvar_id=0 if identified else None, codegen=codegen,
    )
    updated = CVariable(
        SimRegisterVariable(offset, width, ident="updated", region=address),
        variable_type=type_, vvar_id=1, codegen=codegen,
    )
    new_value = CConstant(0x1234, type_, codegen=codegen) if return_entry else entry
    write = CAssignment(updated, new_value, codegen=codegen)
    terminal = CReturn(entry if return_entry else updated, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=address, statements=CStatements([write, terminal], codegen=codegen),
        variables_in_use={entry.variable: entry, updated.variable: updated},
        variable_manager=SimpleNamespace(set_variable_type=lambda *_: None),
        refresh=lambda: None,
    )
    return codegen, entry, write, terminal


def _capture(codegen, *parents):
    return capture_gp_register_versions_8616(
        codegen, frozenset(parents or ("eax",)), lambda node: _c_register_identity_8616(node, codegen.project),
    )


def _condition(codegen, entry):
    offset, width = codegen.project.arch.registers["bx"]
    return CVariable(
        SimRegisterVariable(offset, width, ident="condition", region=codegen.cfunc.addr),
        variable_type=entry.variable_type, vvar_id=2, codegen=codegen,
    )


def test_entry_version_survives_architectural_overwrite():
    codegen, entry, write, terminal = _fixture(return_entry=True)
    assert _capture(codegen)
    snapshot, rewritten, returned = codegen.cfunc.statements.statements
    assert rewritten is write and returned is terminal
    assert snapshot.rhs is entry
    assert isinstance(snapshot.lhs.variable, SimTemporaryVariable)
    assert isinstance(write.rhs, CConstant)
    assert terminal.retval is snapshot.lhs
    assert snapshot.lhs.variable_type.size == 32
    assert not _capture(codegen)
    stats = codegen._inertia_gp_register_version_capture_stats_8616
    assert (
        stats.raw_fact_count, stats.normalized_fact_count, stats.classified_fact_count,
        stats.materialized_count, stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_entry_version_read_before_same_statement_write_needs_no_snapshot():
    codegen, _, _, _ = _fixture(return_entry=False)
    assert not _capture(codegen)


def test_entry_version_without_ssa_identity_is_not_captured():
    codegen, _, _, _ = _fixture(return_entry=True, identified=False)
    assert not _capture(codegen)


def test_mutually_exclusive_write_does_not_dirty_entry_read():
    codegen, entry, write, terminal = _fixture(return_entry=True)
    branch = CIfElse([(_condition(codegen, entry), write)], terminal, codegen=codegen)
    codegen.cfunc.statements.statements = [branch]
    assert not _capture(codegen)
    assert terminal.retval is entry


def test_may_write_in_one_arm_dirties_entry_read_after_join():
    codegen, entry, write, terminal = _fixture(return_entry=True)
    branch = CIfElse([(_condition(codegen, entry), write)], codegen=codegen)
    codegen.cfunc.statements.statements = [branch, terminal]
    assert _capture(codegen)
    assert terminal.retval is codegen.cfunc.statements.statements[0].lhs


def test_loop_backedge_dirties_entry_read_in_an_exclusive_arm():
    codegen, entry, write, terminal = _fixture(return_entry=True)
    condition = _condition(codegen, entry)
    branch = CIfElse([(condition, write)], terminal, codegen=codegen)
    loop = CWhileLoop(condition, branch, codegen=codegen)
    codegen.cfunc.statements.statements = [loop]
    assert _capture(codegen)
    assert terminal.retval is codegen.cfunc.statements.statements[0].lhs


def test_break_prevents_lane_write_from_reaching_the_next_iteration():
    codegen, entry, write, terminal = _fixture(return_entry=True)
    condition = _condition(codegen, entry)
    break_after_write = CStatements([write, CBreak(codegen=codegen)], codegen=codegen)
    branch = CIfElse([(condition, break_after_write)], terminal, codegen=codegen)
    codegen.cfunc.statements.statements = [CWhileLoop(condition, branch, codegen=codegen)]
    assert not _capture(codegen)
    assert terminal.retval is entry


def test_goto_backedge_reaches_entry_version_read_before_lexical_write():
    codegen, entry, write, terminal = _fixture(return_entry=True)
    label = CLabel("again", codegen=codegen)
    codegen.map_addr_to_label = {(0x10004, None): label}
    branch = CIfElse([(_condition(codegen, entry), terminal)], codegen=codegen)
    jump = CGoto(0x10004, None, codegen=codegen)
    codegen.cfunc.statements.statements = [label, branch, write, jump]
    assert _capture(codegen)
    assert terminal.retval is codegen.cfunc.statements.statements[0].lhs


def test_forward_goto_skips_unreachable_write():
    codegen, entry, write, terminal = _fixture(return_entry=True)
    label = CLabel("after_write", tags={"ins_addr": 0x10004, "block_idx": 3}, codegen=codegen)
    jump = CGoto(0x10004, 3, codegen=codegen)
    codegen.cfunc.statements.statements = [jump, write, label, terminal]
    assert not _capture(codegen)
    assert terminal.retval is entry


def test_for_continue_runs_iterator_before_revisiting_entry_read():
    codegen, entry, write, _ = _fixture(return_entry=True)
    loop = CForLoop(None, entry, write, CContinue(codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements = [loop]
    assert _capture(codegen)
    assert loop.condition is codegen.cfunc.statements.statements[0].lhs


def test_switch_break_keeps_cases_exclusive_but_fallthrough_dirties_a_read():
    codegen, entry, write, terminal = _fixture(return_entry=True)
    arm = CStatements([write, CBreak(codegen=codegen)], codegen=codegen)
    switch = CSwitchCase(_condition(codegen, entry), [(0, arm), (1, terminal)], None, codegen=codegen)
    codegen.cfunc.statements.statements = [switch]
    assert not _capture(codegen)
    assert terminal.retval is entry
    arm.statements = [write]
    assert _capture(codegen)
    assert terminal.retval is codegen.cfunc.statements.statements[0].lhs


def _install_entry_sp_capture(codegen):
    function = codegen.cfunc
    nodes = tuple(_iter_c_nodes_deep_8616(function.statements))
    value, changed, failure = _prepare_entry_capture(codegen, function, nodes, [], ())
    assert value is not None and changed == 1 and failure is None
    assignment = function.statements.statements[0]
    expected = runtime_gp_state_expr_8616("sp", codegen=codegen, function_addr=function.addr)
    assert _existing_capture_value_8616(function, assignment, expected) is value
    return assignment, expected, value


def test_gp_snapshot_preserves_first_authenticated_sp_capture():
    codegen, _, write, terminal = _fixture(return_entry=True)
    sp_capture, expected, sp_value = _install_entry_sp_capture(codegen)
    assert _capture(codegen)
    first, gp_snapshot, retained_write, retained_return = codegen.cfunc.statements.statements
    assert first is sp_capture
    assert _existing_capture_value_8616(codegen.cfunc, first, expected) is sp_value
    assert retained_write is write and retained_return is terminal
    assert terminal.retval is gp_snapshot.lhs
    assert not _capture(codegen)


def test_entry_sp_snapshot_alone_does_not_dirty_gp_entry():
    codegen, entry, _, terminal = _fixture(return_entry=True)
    codegen.cfunc.statements.statements = [terminal]
    sp_capture, _, _ = _install_entry_sp_capture(codegen)
    assert not _capture(codegen)
    assert codegen.cfunc.statements.statements == [sp_capture, terminal]
    assert terminal.retval is entry


def test_bare_loop_root_wraps_for_entry_snapshot():
    codegen, entry, write, terminal = _fixture(return_entry=True)
    condition = _condition(codegen, entry)
    body = CIfElse([(condition, write)], terminal, codegen=codegen)
    loop = CWhileLoop(condition, body, codegen=codegen)
    codegen.cfunc.statements = loop
    assert _capture(codegen)
    snapshot, kept_loop = codegen.cfunc.statements.statements
    assert kept_loop is loop and terminal.retval is snapshot.lhs
    assert not _capture(codegen)


def test_bare_loop_root_is_not_wrapped_without_entry_snapshot():
    codegen, entry, _, terminal = _fixture(return_entry=True)
    loop = CWhileLoop(_condition(codegen, entry), terminal, codegen=codegen)
    codegen.cfunc.statements = loop
    assert not _capture(codegen)
    assert codegen.cfunc.statements is loop and terminal.retval is entry


def test_two_lane_entry_snapshots_remain_idempotent():
    codegen, ax, write_ax, terminal = _fixture(return_entry=True)
    offset, width = codegen.project.arch.registers["dx"]
    dx, updated_dx = (
        CVariable(
            SimRegisterVariable(offset, width, ident=name, region=codegen.cfunc.addr),
            variable_type=ax.variable_type, vvar_id=varid, codegen=codegen,
        )
        for varid, name in ((2, "dx_entry"), (3, "dx_updated"))
    )
    write_dx = CAssignment(updated_dx, CConstant(0x5678, ax.variable_type, codegen=codegen), codegen=codegen)
    terminal.retval = CBinaryOp("Add", ax, dx, codegen=codegen)
    codegen.cfunc.statements.statements = [write_ax, write_dx, terminal]
    assert _capture(codegen, "eax", "edx")
    statements = tuple(codegen.cfunc.statements.statements)
    assert len(statements) == 5
    assert not _capture(codegen, "eax", "edx")
    assert tuple(codegen.cfunc.statements.statements) == statements
    stats = codegen._inertia_gp_register_version_capture_stats_8616
    assert (stats.classified_fact_count, stats.materialized_count, stats.failure_count) == (2, 2, 0)
