from dataclasses import replace
from io import BytesIO
from types import SimpleNamespace

import angr
import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable, SimTemporaryVariable
from capstone import CS_ARCH_X86, CS_MODE_16, Cs

from inertia.alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
    build_x86_16_stack_register_restore_artifact_8616,
)
from inertia.alias.word_bp_frame import prove_word_bp_frame_8616
from inertia.frontend.x86_16 import lift_86_16  # noqa: F401 -- register the native lifter
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.frontend_boundary_transport import (
    capture_function_boundary_8616,
    restore_function_boundary_8616,
)
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.lowering import entry_stack_pointer_capture, gp_stack_restore
from inertia.lowering.call_stack_inputs import lower_call_stack_inputs_8616
from inertia.lowering.gp_push_store import (
    GPPushStoreResult8616,
    preserve_gp_push_store_8616,
    tag_physical_gp_push_8616,
)
from inertia.lowering.gp_register_state import (
    runtime_gp_expression_view_8616,
    runtime_gp_state_assignment_8616,
    runtime_gp_state_expr_8616,
)
from inertia.lowering.gp_stack_local_return import has_materialized_gp_local_return_8616
from inertia.lowering.segment_register_state import runtime_segment_state_cvar_8616
from inertia.lowering.terminal_return_expressions import (
    contains_effectful_call_8616,
    contains_register_clobbering_call_8616,
)
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.call_stack_effect_pipeline import (
    build_semantic_function_ssa_8616,
)


def _fixture(*, delta=0, machine=b"\x53", successor=(), register="bx", addr=0x10000):
    site = addr + delta
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True

    def block(address, **_):
        instruction = next(decoder.disasm(machine[address - site:], address))
        return SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(insn=instruction)]))

    arch = Arch86_16()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch, factory=SimpleNamespace(block=block)),
        next_ident=lambda name: name, next_node_idx=lambda: 1, cstyle_null_cmp=False, const_formats={},
    )
    word = SimTypeShort(False).with_arch(arch)
    snapshot = c.CVariable(SimStackVariable(-2, 2, region=addr), variable_type=word, codegen=codegen)
    consumer = c.CReturn(snapshot, codegen=codegen, tags={"ins_addr": site + 2})
    codegen.cfunc = SimpleNamespace(
        addr=addr, statements=c.CStatements([consumer], codegen=codegen), variables_in_use={},
        variable_manager=SimpleNamespace(set_variable_type=lambda *_: None), refresh=lambda: None,
    )
    instructions = tuple(IRInstr("STORE", None, (), addr=insn.address) for insn in decoder.disasm(machine, site))
    source = IRFunctionArtifact(addr, (IRBlock(addr, instructions, successor_addrs=successor),))
    codegen._inertia_vex_ir_artifact = source
    fact = SegmentStackRestoreFact8616(addr, site + 1, register, site, register, (-2, -1),
                                      SegmentStackRestoreVerdict8616.PROVEN)
    codegen._inertia_stack_register_restore_artifact_8616 = SegmentStackRestoreArtifact8616(
        facts=(fact,), source_artifact=source,
    )
    return codegen, source, fact, consumer


def _allow_fixture_capture(monkeypatch, source, *facts):
    monkeypatch.setattr(entry_stack_pointer_capture, "build_x86_16_stack_register_restore_artifact_8616",
                        lambda *_, **__: SegmentStackRestoreArtifact8616(facts=facts, source_artifact=source))


def _real_source_fixture(machine, *, with_call=False):
    apply_x86_16_bootstrap()
    addr = 0x1000
    project = angr.Project(BytesIO(bytes.fromhex(machine)), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": addr, "entry_point": addr,
    })
    cfg = project.analyses.CFGFast(normalize=True)
    function = cfg.functions[addr]
    boundary = restore_function_boundary_8616(project, capture_function_boundary_8616(project, function))
    assert boundary is not None
    source = build_x86_16_ir_function_artifact(project, boundary)
    if with_call:
        source = build_semantic_function_ssa_8616(project, boundary, ir_artifact=source)[0].function
    codegen, _, _, consumer = _fixture(addr=addr)
    codegen.project = project
    codegen._inertia_vex_ir_artifact = source
    artifact = build_x86_16_stack_register_restore_artifact_8616(source, tracked_registers={"ax", "bp", "bx", "dx"})
    facts = {fact.saved_register: fact for fact in artifact.facts
             if fact.verdict is SegmentStackRestoreVerdict8616.PROVEN}
    return codegen, source, facts, consumer, cfg


@pytest.mark.parametrize("shortcut", [
    "has_materialized_gp_stack_bytes_8616",
    "has_materialized_gp_local_reload_8616",
    "has_materialized_gp_local_return_8616",
])
def test_gp_stack_restore_shortcut_still_writes_entry_push_once(monkeypatch, shortcut):
    codegen, source, fact, consumer = _fixture()
    _allow_fixture_capture(monkeypatch, source, fact)
    monkeypatch.setattr(gp_stack_restore, shortcut, lambda *_: True)
    assert gp_stack_restore.materialize_gp_stack_restores_8616(codegen)
    capture, push, after = codegen.cfunc.statements.statements
    assert after is consumer
    assert push.expr.callee_target == "inertia_push_word"
    assert push.tags["ins_addr"] == fact.saved_instruction_addr
    ss, sp, value = push.expr.args
    assert ss.variable.name == "inertia_ss"
    assert sp is capture.lhs
    assert runtime_gp_expression_view_8616(capture.rhs).register_name == "sp"
    assert runtime_gp_expression_view_8616(value).register_name == "bx"
    assert not gp_stack_restore.materialize_gp_stack_restores_8616(codegen)
    assert codegen.cfunc.statements.statements == [capture, push, consumer]


@pytest.mark.parametrize("fixture, reason", [
    ({"delta": 1}, "no exact entry PUSH placement"),
    ({"successor": (0x10000,)}, "no exact entry PUSH placement"),
    ({"machine": b"\x66\x53"}, "unsupported PUSH width"),
    ({"machine": b"\x50"}, "PUSH operand does not match"),
])
def test_gp_push_store_refuses_unproved_placement_or_source(fixture, reason):
    codegen, source, fact, consumer = _fixture(**fixture)
    with pytest.raises(PipelineHardError, match="GP save physical PUSH store unproven") as exc:
        preserve_gp_push_store_8616(codegen, source, fact)
    assert reason in exc.value.details["reason"]
    assert codegen.cfunc.statements.statements == [consumer]


def test_gp_push_store_refuses_ambiguous_existing_physical_assignment():
    codegen, source, fact, consumer = _fixture()
    runtime = c.CFunctionCall("SEG_U8", None, [], codegen=codegen)
    write = c.CAssignment(runtime, consumer.retval, codegen=codegen,
                          tags={"ins_addr": fact.saved_instruction_addr})
    codegen.cfunc.statements.statements.insert(0, write)
    with pytest.raises(PipelineHardError, match="GP save physical PUSH store unproven") as exc:
        preserve_gp_push_store_8616(codegen, source, fact)
    assert exc.value.details["reason"] == "ambiguous existing PUSH store"
    assert codegen.cfunc.statements.statements == [write, consumer]


def test_gp_stack_restore_cannot_bypass_refusal_with_local_return(monkeypatch):
    codegen, _source, _fact, consumer = _fixture(delta=1)
    monkeypatch.setattr(gp_stack_restore, "has_materialized_gp_local_return_8616", lambda *_: True)
    with pytest.raises(PipelineHardError, match="GP save physical PUSH store unproven"):
        gp_stack_restore.materialize_gp_stack_restores_8616(codegen)
    assert codegen.cfunc.statements.statements == [consumer]


def _embedded_bp_install(codegen, source, fact, monkeypatch):
    _allow_fixture_capture(monkeypatch, source, fact)
    capture = entry_stack_pointer_capture.prepare_entry_stack_pointer_capture_8616(codegen, source, (fact,))
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    ss = runtime_segment_state_cvar_8616("ss", codegen=codegen, function_addr=codegen.cfunc.addr, variable_type=word)
    bp = runtime_gp_state_expr_8616("bp", codegen=codegen, function_addr=codegen.cfunc.addr)
    runtime = c.CFunctionCall("inertia_push_word", None, [ss, capture.value, bp], codegen=codegen)
    tag_physical_gp_push_8616(runtime, fact.saved_instruction_addr)
    install = runtime_gp_state_assignment_8616(
        "bp", c.CTypeCast(runtime.type, word, runtime, codegen=codegen),
        codegen=codegen, function_addr=codegen.cfunc.addr,
    )
    install.tags["ins_addr"] = fact.saved_instruction_addr + 1
    return install


@pytest.fixture
def proved_bp_frame():
    codegen, source, facts, consumer, _ = _real_source_fixture(
        "55 89 e5 e8 08 00 09 c0 74 f9 89 ec 5d cb c3", with_call=True,
    )
    frame = prove_word_bp_frame_8616(codegen.project, source)
    assert frame is not None and frame.set_bp == frame.push + 1
    return codegen, source, facts["bp"], consumer


def test_gp_push_store_recognizes_the_existing_frame_runtime_projection(monkeypatch, proved_bp_frame):
    codegen, source, fact, consumer = proved_bp_frame
    install = _embedded_bp_install(codegen, source, fact, monkeypatch)
    codegen.cfunc.statements.statements.insert(1, install)
    assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.RETAINED
    assert codegen.cfunc.statements.statements[1:] == [install, consumer]


def test_gp_push_store_refuses_an_embedded_bp_install_without_machine_setter(monkeypatch):
    codegen, source, fact, _ = _fixture(machine=b"\x55\x90", register="bp")
    install = _embedded_bp_install(codegen, source, fact, monkeypatch)
    codegen.cfunc.statements.statements.insert(1, install)
    with pytest.raises(PipelineHardError, match="GP save physical PUSH store unproven"):
        preserve_gp_push_store_8616(codegen, source, fact)


def test_gp_push_store_refuses_an_embedded_bp_install_moved_under_if(monkeypatch, proved_bp_frame):
    codegen, source, fact, consumer = proved_bp_frame
    install = _embedded_bp_install(codegen, source, fact, monkeypatch)
    conditional = c.CIfElse([(consumer.retval, install)], None, codegen=codegen)
    codegen.cfunc.statements.statements.insert(1, conditional)
    with pytest.raises(PipelineHardError) as exc:
        preserve_gp_push_store_8616(codegen, source, fact)
    assert "no authenticated entry owner" in exc.value.details["reason"]


def test_gp_push_store_refuses_an_embedded_bp_install_with_an_extra_call(monkeypatch, proved_bp_frame):
    codegen, source, fact, _consumer = proved_bp_frame
    install = _embedded_bp_install(codegen, source, fact, monkeypatch)
    unowned = c.CFunctionCall("change_ss", None, [], codegen=codegen)
    install.rhs = c.CBinaryOp("Or", install.rhs, unowned, codegen=codegen)
    codegen.cfunc.statements.statements.insert(1, install)
    with pytest.raises(PipelineHardError) as exc:
        preserve_gp_push_store_8616(codegen, source, fact)
    assert "no authenticated entry owner" in exc.value.details["reason"]


def test_gp_push_store_refuses_repeated_statement_reference(monkeypatch):
    codegen, source, fact, _consumer = _fixture()
    _allow_fixture_capture(monkeypatch, source, fact)
    assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.INSERTED
    body = codegen.cfunc.statements.statements
    body.append(body[1])
    with pytest.raises(PipelineHardError) as exc:
        preserve_gp_push_store_8616(codegen, source, fact)
    assert exc.value.details["reason"] == "ambiguous existing PUSH store"


@pytest.mark.parametrize("reverse", [False, True])
def test_gp_push_store_uses_one_entry_sp_capture_for_ordered_push_prefix(monkeypatch, reverse):
    codegen, source, bx, consumer = _fixture(machine=b"\x53\x52")
    dx = replace(bx, saved_instruction_addr=bx.saved_instruction_addr + 1,
                 restore_instruction_addr=bx.restore_instruction_addr + 1,
                 saved_register="dx", restore_register="dx", stack_offsets=(-4, -3))
    _allow_fixture_capture(monkeypatch, source, bx, dx)
    facts = (dx, bx) if reverse else (bx, dx)
    for fact in facts:
        assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.INSERTED
    capture, first, second, after = codegen.cfunc.statements.statements
    assert after is consumer
    assert runtime_gp_expression_view_8616(capture.rhs).register_name == "sp"
    assert first.expr.args[1] is capture.lhs
    assert entry_stack_pointer_capture.is_entry_stack_pointer_projection_8616(second.expr.args[1], capture.lhs, -2)
    assert tuple(runtime_gp_expression_view_8616(push.expr.args[2]).register_name for push in (first, second)) == (
        "bx", "dx",
    )
    for fact in facts:
        assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.RETAINED
    assert codegen.cfunc.statements.statements == [capture, first, second, consumer]


@pytest.mark.parametrize("override", ["reference-value", "format-as-char"])
def test_gp_push_store_refuses_a_second_push_displacement_rendering_override(monkeypatch, override):
    codegen, source, bx, _ = _fixture(machine=b"\x53\x52")
    dx = replace(bx, saved_instruction_addr=bx.saved_instruction_addr + 1,
                 restore_instruction_addr=bx.restore_instruction_addr + 1,
                 saved_register="dx", restore_register="dx", stack_offsets=(-4, -3))
    _allow_fixture_capture(monkeypatch, source, bx, dx)
    for fact in (bx, dx):
        assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.INSERTED
    second_push = codegen.cfunc.statements.statements[2]
    delta = second_push.expr.args[1].lhs.rhs
    assert delta.value == 0xfffe
    if override == "reference-value":
        delta.reference_values = {delta.type: 0}
    else:
        delta.fmt_char = True
    with pytest.raises(PipelineHardError, match="GP save physical PUSH store unproven"):
        preserve_gp_push_store_8616(codegen, source, dx)


@pytest.mark.parametrize("operand", ["capture-mask", "immediate"])
def test_gp_push_store_refuses_rendering_override_in_capture_or_immediate(monkeypatch, operand):
    codegen, source, fact, _ = _fixture(machine=b"\x68\x34\x12")
    fact = replace(fact, constant_value=0x1234)
    _allow_fixture_capture(monkeypatch, source, fact)
    assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.INSERTED
    capture, push, _ = codegen.cfunc.statements.statements
    literal = capture.rhs.rhs if operand == "capture-mask" else push.expr.args[2]
    literal.reference_values = {literal.type: 0}
    with pytest.raises(PipelineHardError, match="GP save physical PUSH store unproven"):
        preserve_gp_push_store_8616(codegen, source, fact)


def test_gp_push_store_refuses_unbound_physical_write_at_owner_boundary(monkeypatch):
    codegen, source, fact, _ = _fixture()
    _allow_fixture_capture(monkeypatch, source, fact)
    assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.INSERTED
    body = codegen.cfunc.statements.statements
    capture, push, _ = body
    ss, _, value = push.expr.args
    offset = entry_stack_pointer_capture.entry_stack_pointer_projection_8616(capture.lhs, -2, codegen)
    slot = c.CFunctionCall("SEG_U8", None, [ss, offset], codegen=codegen)
    body.insert(2, c.CAssignment(slot, value, codegen=codegen))
    with pytest.raises(PipelineHardError, match="GP save physical PUSH store unproven"):
        preserve_gp_push_store_8616(codegen, source, fact)


@pytest.mark.parametrize(("machine", "delta", "offsets", "targets"), [
    (b"\x53\x52", 1, (-2, -1), ()),
    (b"\x53\x90\x52", 2, (-4, -3), ()),
    (b"\x53\x52", 1, (-4, -3), (0x10001,)),
])
def test_gp_push_store_refuses_unproved_second_push(machine, delta, offsets, targets):
    codegen, source, bx, consumer = _fixture(machine=machine, successor=targets)
    dx = replace(bx, saved_instruction_addr=bx.saved_instruction_addr + delta,
                 saved_register="dx", restore_register="dx", stack_offsets=offsets)
    with pytest.raises(PipelineHardError) as exc:
        preserve_gp_push_store_8616(codegen, source, dx)
    assert exc.value.details["reason"] == "no exact entry PUSH placement"
    assert codegen.cfunc.statements.statements == [consumer]


def test_gp_push_store_refuses_to_accept_a_moved_standalone_store(monkeypatch):
    codegen, source, fact, consumer = _fixture()
    _allow_fixture_capture(monkeypatch, source, fact)
    assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.INSERTED
    body = codegen.cfunc.statements.statements
    capture = body[0]
    push = body.pop(1)
    body.append(push)
    with pytest.raises(PipelineHardError, match="GP save physical PUSH store unproven") as exc:
        preserve_gp_push_store_8616(codegen, source, fact)
    assert "no authenticated entry owner" in exc.value.details["reason"]
    assert body == [capture, consumer, push]


def test_gp_push_store_is_a_memory_effect_without_an_opaque_gp_clobber(monkeypatch):
    codegen, source, fact, _consumer = _fixture()
    _allow_fixture_capture(monkeypatch, source, fact)
    assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.INSERTED
    push = codegen.cfunc.statements.statements[1]
    assert contains_effectful_call_8616(push)
    assert not contains_register_clobbering_call_8616(push)
    unknown = c.CFunctionCall(push.expr.callee_target, None, push.expr.args, codegen=codegen)
    assert contains_register_clobbering_call_8616(unknown)


def test_gp_push_store_leaves_non_push_fact_to_existing_restore_proof():
    codegen, source, fact, consumer = _fixture(machine=b"\x89\x1e\x00\x00")
    assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.NOT_PUSH
    assert codegen.cfunc.statements.statements == [consumer]


@pytest.mark.parametrize("defect", [
    "moved-capture", "initializer", "ss", "sp", "same-id-named-sp", "value", "lost-tag", "duplicate", "owner-origin",
])
def test_gp_push_store_replay_refuses_unauthenticated_live_projection(monkeypatch, defect):
    codegen, source, fact, consumer = _fixture()
    _allow_fixture_capture(monkeypatch, source, fact)
    assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.INSERTED
    body = codegen.cfunc.statements.statements
    capture, push, _ = body
    if defect == "moved-capture":
        body[:2] = [push, capture]
    elif defect == "initializer":
        capture.rhs = push.expr.args[2]
    elif defect in ("ss", "sp", "value"):
        push.expr.args[("ss", "sp", "value").index(defect)] = consumer.retval
    elif defect == "same-id-named-sp":
        local = capture.lhs.variable
        renamed = SimTemporaryVariable(local.tmp_id, local.size)
        renamed.name = "inertia_ss"
        push.expr.args[1] = c.CVariable(renamed, variable_type=capture.lhs.type, codegen=codegen)
    elif defect == "lost-tag":
        push.expr.tags.clear()
    elif defect == "owner-origin":
        push.tags["ins_addr"] += 1
    elif defect == "duplicate":
        copy = c.CFunctionCall(push.expr.callee_target, None, push.expr.args, codegen=codegen)
        body.append(c.CExpressionStatement(copy, codegen=codegen, tags=dict(push.tags)))
    before = list(body)
    with pytest.raises(PipelineHardError, match="GP save physical PUSH store unproven"):
        preserve_gp_push_store_8616(codegen, source, fact)
    assert body == before


def test_single_gp_push_restored_before_proved_call_shares_entry_capture():
    codegen, source, facts, consumer, cfg = _real_source_fixture("53 5b e8 01 00 c3 c3", with_call=True)
    callee = cfg.functions[0x1006]
    callee.prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(codegen.project.arch)
    call = c.CFunctionCall(0x1006, callee, [], codegen=codegen, tags={"ins_addr": 0x1002})
    codegen.cfunc.statements.statements.insert(0, c.CExpressionStatement(call, codegen=codegen))
    fact = facts["bx"]
    assert fact.restore_instruction_addr == 0x1001
    assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.INSERTED
    capture, push, *_ = codegen.cfunc.statements.statements
    result = lower_call_stack_inputs_8616(codegen)
    assert result.stats.materialized_count == 1, result
    assert codegen.cfunc.statements.statements[:2] == [capture, push]
    assert push.expr.args[1] is capture.lhs
    assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.RETAINED
    assert codegen.cfunc.statements.statements[-1] is consumer


def test_whole_word_ax_return_proof_skips_both_authenticated_pushes():
    codegen, source, facts, consumer, _ = _real_source_fixture("50 52 5a 58 c3")
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    codegen.cfunc.functy = SimTypeFunction([], word).with_arch(codegen.project.arch)
    consumer.tags["ins_addr"] = 0x1004
    snapshot = c.CAssignment(consumer.retval, runtime_gp_state_expr_8616(
        "ax", codegen=codegen, function_addr=source.function_addr,
    ), codegen=codegen, tags={"ins_addr": 0x1000})
    root = codegen.cfunc.statements
    root.statements.insert(0, snapshot)
    for fact in facts.values():
        assert preserve_gp_push_store_8616(codegen, source, fact) is GPPushStoreResult8616.INSERTED
    assert has_materialized_gp_local_return_8616(codegen, (root,), facts["ax"])
    root.statements[2].tags["ins_addr"] = 0x1004
    assert not has_materialized_gp_local_return_8616(codegen, (root,), facts["ax"])
