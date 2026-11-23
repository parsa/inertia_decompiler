from dataclasses import replace
from pathlib import Path

import pytest

from inertia.cli.project_loading import _build_project, _build_project_from_bytes
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.semantics.callee_stack_effects import (
    CallsiteMachineFrameKind8616,
    prove_direct_callee_stack_effect_8616,
    prove_far_call_entry_8616,
)


@pytest.fixture(scope="module")
def prince_project():
    apply_x86_16_bootstrap()
    source = next(
        (parent / "exe/PRINCE.EXE" for parent in Path(__file__).resolve().parents
         if (parent / "exe/PRINCE.EXE").is_file()),
        None,
    )
    if source is None:
        pytest.skip("resident Prince executable is not available")
    return _build_project(source, force_blob=False, base_addr=0x10000,
                          entry_point=0, base_addr_is_linear=True)


@pytest.mark.parametrize("pre_call_sp", [0x8000, 5, 2])
def test_resident_far_return_preserves_the_exact_saved_words(prince_project, pre_call_sp):
    site = 0x31E4C
    target = 0x31542
    entry = prove_far_call_entry_8616(
        prince_project, callsite_addr=site, target_addr=target,
        caller_cs=0x3000, stack_segment=0x5000, pre_call_sp=pre_call_sp,
    )
    assert entry is not None
    assert (entry.callee_cs, entry.callee_ip, entry.callee_sp) == (
        0x2FE6, 0x16E2, (pre_call_sp - 4) & 0xFFFF,
    )
    result = prove_direct_callee_stack_effect_8616(
        prince_project, site, site + 5, target, CallsiteMachineFrameKind8616.FAR,
    )
    assert result.return_sp_delta == 12
    frame = entry.saved_frame
    continuation = result.preserved_frame_far_continuation(frame)
    assert continuation is not None
    assert (continuation.cs, continuation.ip, continuation.sp) == (
        0x3000, 0x1E51, (pre_call_sp + 8) & 0xFFFF,
    )
    assert continuation.cleanup == 8
    assert continuation.return_instructions == (0x3156A,)
    assert result.preserved_frame_far_continuation(replace(frame, return_ip=frame.return_ip + 1)) is None
    assert result.preserved_frame_far_continuation(replace(frame, caller_cs=frame.caller_cs + 1)) is None


@pytest.mark.parametrize(
    "body, stack_segment, pre_call_sp, return_delta, preserves_frame",
    [
        ("55 5d cb", 0x5000, 4, 4, True),  # push bp; pop bp; retf
        ("44 55 5d 4c cb", 0x5000, 4, 4, False),  # inc sp; push bp; pop bp; dec sp; retf
        ("c6 07 00 cb", 0x5000, 4, 4, False),  # mov byte [bx], 0; retf
        ("75 01 cb f4", 0x5000, 4, None, False),  # jne hlt; retf; hlt
        ("55 5d cb", 0x1000, 0x14, 4, False),  # incoming far frame overwrites code
        ("55 5d cb", 0x1000, 0x18, 4, False),  # disjoint push overwrites the RETF
    ],
)
def test_saved_frame_requires_non_aliasing_stores_and_a_closed_return_body(
    body, stack_segment, pre_call_sp, return_delta, preserves_frame,
):
    apply_x86_16_bootstrap()
    code = bytes.fromhex("9a 10 00 00 10 f4") + b"\x90" * 10 + bytes.fromhex(body)
    project = _build_project_from_bytes(code, base_addr=0x10000, entry_point=0)
    entry = prove_far_call_entry_8616(
        project, callsite_addr=0x10000, target_addr=0x10010,
        caller_cs=0x1000, stack_segment=stack_segment, pre_call_sp=pre_call_sp,
    )
    assert entry is not None
    result = prove_direct_callee_stack_effect_8616(
        project, 0x10000, 0x10005, 0x10010, CallsiteMachineFrameKind8616.FAR,
    )
    assert result.return_sp_delta == return_delta
    assert (result.preserved_frame_far_continuation(entry.saved_frame) is not None) is preserves_frame
