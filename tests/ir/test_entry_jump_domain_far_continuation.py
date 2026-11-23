from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from inertia.cli.project_loading import _build_project
from inertia.frontend.real16_dosbox_entry_policy import DosBoxInt21EntryPolicy8616
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.declared_function_entry import (
    DeclaredEntryMemory8616,
    DeclaredEntryReturn8616,
    DeclaredEntryReturnKind8616,
    DeclaredFunctionEntryAdmission8616,
    DeclaredFunctionEntrySpec8616,
    admit_declared_function_entry_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    mapped_entry_function_boundary_8616,
)
from inertia.ir import entry_jump_domain
from inertia.ir.core import MemSpace
from inertia.ir.entry_jump_domain import (
    EntryJumpDomainApplicationStatus8616,
    EntryJumpDomainBudget8616,
    EntryJumpDomainRefusal8616,
    _ProofRun8616,
    apply_entry_jump_domain_8616,
    prove_entry_jump_domains_8616,
)
from inertia.ir.real16_declared_interrupt8616 import declared_environment_digest_8616
from inertia.ir.real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    prove_real16_declared_function_entry_domain_8616,
)
from inertia.ir.vex_import import (
    build_x86_16_ir_function_artifact,
    raw_x86_16_import_bundle_for_artifact_8616,
)
from tools.dosunit.runtime.real16_program_boot import (
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.runtime.real16_program_memory import InitialMemoryRegion
from tools.dosunit.runtime.real16_program_vectors import VectorPolicy, vector_bytes
from tools.dosunit.runtime.real16_replay_model import SegOffset


@pytest.fixture
def boot_recompute_callbacks():
    return []


@pytest.fixture
def resident_far_call_scope(request, boot_recompute_callbacks):
    apply_x86_16_bootstrap()
    executable = next(
        (parent / "exe/PRINCE.EXE" for parent in Path(__file__).resolve().parents
         if (parent / "exe/PRINCE.EXE").is_file()),
        None,
    )
    if executable is None:
        pytest.skip("resident Prince executable is not available")
    project = _build_project(executable, force_blob=False, base_addr=0x10000,
                             entry_point=0, base_addr_is_linear=True)
    source = executable.read_bytes()
    psp = 0xFF0  # Its module is loaded at 0x1000:0000.
    dos_entry = SegOffset(0xF000, 0xF100)
    ivt = bytearray(0x400)
    ivt[0x84:0x88] = vector_bytes(dos_entry)
    registers = tuple((name, 0) for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"))
    environment = ProgramEnvironment(
        psp, bytes(0x70000), (*registers, ("eflags", 2)), 0, 0,
        dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(psp),
        vector_policy=VectorPolicy(dos_entry),
        extra_memory=(InitialMemoryRegion(SegOffset(0, 0), bytes(ivt)),),
    )

    def recompute(boot):
        rebuilt = program_from_mz_bytes(boot.source, boot.environment)
        if boot_recompute_callbacks:
            boot_recompute_callbacks.pop()()
        return rebuilt

    boot = program_from_mz_bytes(source, environment)
    module = boot.image.chunks[0][1]
    root = request.param
    boundary = mapped_entry_function_boundary_8616(project, root)
    assert boundary is not None
    body = bytes(project.loader.memory.load(boundary.addr, boundary.size))
    environment_digest = declared_environment_digest_8616(environment)
    # The declaration is a local proof premise only; nothing runs from MZ boot to it.
    spec = DeclaredFunctionEntrySpec8616(
        version=1, source_sha256=sha256(source).hexdigest(), relocated_sha256=sha256(module).hexdigest(),
        load_segment=0x1000, entry_segment=0x2FE6, entry_offset=root - 0x2FE60,
        range_start=boundary.addr, range_end=boundary.addr + boundary.size,
        native_sha256=sha256(body).hexdigest(), environment_sha256=environment_digest,
        use_environment_memory=False,
        registers=(("ss", 0x5000), ("sp", 0x8000), ("ds", 0x6000),
                   ("bp", 0x8888), ("di", 0x40), ("si", 0x20)),
        memory=(DeclaredEntryMemory8616(0x58000, bytes.fromhex("10 00 00 10 01 00 40 00 00 40 20 00 00 60")),),
        return_boundary=DeclaredEntryReturn8616(DeclaredEntryReturnKind8616.FAR, 0x1000, 0x10),
    )
    admission = admit_declared_function_entry_8616(
        spec, source=source, loaded_module=module, environment_sha256=environment_digest,
    )
    assert isinstance(admission, DeclaredFunctionEntryAdmission8616)
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    bundle = raw_x86_16_import_bundle_for_artifact_8616(project, boundary, artifact)
    assert bundle is not None
    scope = prove_real16_declared_function_entry_domain_8616(
        project, DeclaredFunctionEntryLink8616(admission, artifact, boundary), 0x31E4C,
        boot=boot, boot_recompute=recompute,
    )
    assert scope.complete
    assert dict(scope.callsite_call_state)["sp"] == (0x7FEC if root == 0x31E32 else 0x7FFC)
    return project, bundle, scope


@pytest.mark.parametrize("resident_far_call_scope", [0x31E32], indirect=True)
def test_only_exact_conditional_far_frame_clears_the_first_cs_interference_gate(
    resident_far_call_scope, monkeypatch,
):
    monkeypatch.delenv("INERTIA_OPUS_FAR_RETURN_PREMISE", raising=False)
    project, bundle, scope = resident_far_call_scope

    def prove(offered):
        return prove_entry_jump_domains_8616(
            bundle.artifact, bundle.terminal_evidence, project=project, offered_invocation_scope=offered,
        )

    def reason(proof):
        return next((row.kind for row in proof.refusals if row.block_addr == 0x31E3F), None)

    memory = scope.callsite_memory
    assert memory is not None
    known = dict(memory.known)
    bad_frame = scope.stack_segment * 16 + dict(scope.callsite_call_state)["sp"]
    interference = EntryJumpDomainRefusal8616.CS_WRITE_INTERFERENCE
    negatives = [None, replace(scope, callsite_addr=scope.callsite_addr + 1), replace(scope, project=object())]
    for address in (bad_frame, bad_frame + 2):
        changed = known | {address: known[address] ^ 1}
        negatives.append(replace(scope, callsite_memory=replace(memory, known=tuple(sorted(changed.items())))))
    for offered in negatives:
        proof = prove(offered)
        assert reason(proof) == interference
        assert proof.far_continuation is None
    proof = prove(scope)
    assert reason(proof) != interference  # Later independent jump gates may still refuse.
    continuation = proof.far_continuation
    assert continuation is not None
    assert proof.invocation_scope is scope
    assert (continuation.callsite_addr, continuation.cs, continuation.ip, continuation.sp) == (
        0x31E4C, 0x2FE6, 0x1FF1, 0x7FF8,
    )
    # The segment solver tracks general-register copies of segment identities.
    # Leaving one such copy live would allow it to resurrect a killed identity.
    artifact = bundle.artifact
    run = _ProofRun8616(
        artifact, {}, 0, 0, project, proof.source_binding, EntryJumpDomainBudget8616(),
        offered_invocation_scope=scope,
    )
    view = run._call_preservation_view_8616(artifact.blocks)
    unknown_writes = {
        instr.dst.name for block in view for instr in block.instrs
        if instr.addr == continuation.callsite_addr and instr.op == "MOV"
        and instr.args and instr.args[0].space is MemSpace.UNKNOWN
    }
    assert {"ax", "ss", "ds", "es", "sp"} <= unknown_writes
    assert "cs" not in unknown_writes


@pytest.mark.parametrize("resident_far_call_scope", [0x31E4C], indirect=True)
def test_application_rechecks_the_current_far_callee_bytes(resident_far_call_scope, monkeypatch):
    monkeypatch.delenv("INERTIA_OPUS_FAR_RETURN_PREMISE", raising=False)
    project, bundle, scope = resident_far_call_scope
    artifact = bundle.artifact
    proof = prove_entry_jump_domains_8616(
        artifact, bundle.terminal_evidence, project=project, offered_invocation_scope=scope,
    )
    assert proof.far_continuation is not None and proof.admitted
    application = apply_entry_jump_domain_8616(artifact, proof, invocation_scope=scope)
    assert application.status is EntryJumpDomainApplicationStatus8616.APPLIED, application.refusals
    call_rows = tuple(instr for block in artifact.blocks for instr in block.instrs if instr.addr == 0x31E4C)
    applied_rows = tuple(instr for block in application.blocks for instr in block.instrs if instr.addr == 0x31E4C)
    assert call_rows and len(call_rows) == len(applied_rows)
    assert all(before is after for before, after in zip(call_rows, applied_rows, strict=True))
    original = project.loader.memory.load(0x3156B, 1)
    try:
        project.loader.memory.store(0x3156B, b"\x06")  # Change RETF 8 to RETF 6 in this image only.
        assert apply_entry_jump_domain_8616(artifact, proof, invocation_scope=scope).status is (
            EntryJumpDomainApplicationStatus8616.STALE_INPUT
        )
    finally:
        project.loader.memory.store(0x3156B, original)


@pytest.mark.parametrize("resident_far_call_scope", [0x31E4C], indirect=True)
@pytest.mark.parametrize("field", ["invocation_scope", "far_continuation", "source_binding", "blocks"])
def test_far_application_rejects_input_changes_during_late_boot_recompute(
    resident_far_call_scope, boot_recompute_callbacks, monkeypatch, field,
):
    monkeypatch.delenv("INERTIA_OPUS_FAR_RETURN_PREMISE", raising=False)
    project, bundle, scope = resident_far_call_scope
    artifact = bundle.artifact
    proof = prove_entry_jump_domains_8616(
        artifact, bundle.terminal_evidence, project=project, offered_invocation_scope=scope,
    )
    assert proof.far_continuation is not None and proof.admitted
    assert apply_entry_jump_domain_8616(artifact, proof, invocation_scope=scope).status is (
        EntryJumpDomainApplicationStatus8616.APPLIED
    )

    did_mutate = False

    def mutate():
        nonlocal did_mutate
        did_mutate = True
        if field == "blocks":
            object.__setattr__(artifact, "blocks", tuple(reversed(artifact.blocks)))
        else:
            object.__setattr__(proof, field, replace(getattr(proof, field)))

    real_replay = entry_jump_domain._declared_far_continuation_8616

    def late_replay(*args):
        # Leave all earlier application checks alone. The genuine boot
        # authority callback changes an input while the final replay is live.
        boot_recompute_callbacks.append(mutate)
        return real_replay(*args)

    monkeypatch.setattr(entry_jump_domain, "_declared_far_continuation_8616", late_replay)
    application = apply_entry_jump_domain_8616(artifact, proof, invocation_scope=scope)
    assert did_mutate
    assert application.status is EntryJumpDomainApplicationStatus8616.STALE_INPUT
    assert not application.applied and application.blocks is artifact.blocks
