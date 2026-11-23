"""Exercise the native immediate far-jump obligation at raw IR admission."""

from io import BytesIO

import angr
import pytest

from inertia.frontend.x86_16 import lift_86_16  # noqa: F401 -- register the native lifter
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir.vex_import import build_x86_16_ir_function_artifact, raw_x86_16_function_bundle_8616


def _project(code: bytes, entry: int) -> angr.Project:
    apply_x86_16_bootstrap()
    arch = Arch86_16()
    arch.bits = 32  # Execution-linear addresses can exceed a 16-bit IP.
    return angr.Project(
        BytesIO(code),
        main_opts={"backend": "blob", "arch": arch, "base_addr": entry, "entry_point": entry},
        auto_load_libs=False,
    )


@pytest.mark.parametrize(
    ("entry", "code", "target"),
    [(0x312A0, "ea 3b 00 e6 2f", 0x2FE9B), (0x312A6, "ea 1a 00 e6 2f", 0x2FE7A)],
    ids=["312A0", "312A6"],
)
def test_native_immediate_far_jump_outside_function_refuses_raw_ir(entry: int, code: str, target: int) -> None:
    # The released thunks after the MZ loader applies the selector relocation.
    project = _project(bytes.fromhex(code), entry)
    cfg = project.analyses.CFGFast(normalize=True)
    function = cfg.functions[entry]
    assert function.block_addrs_set == {entry}

    raw = raw_x86_16_function_bundle_8616(project, function).artifact
    published = build_x86_16_ir_function_artifact(project, function)
    for artifact in (raw, published):
        refusals = [refusal for refusal in artifact.refusals if refusal.kind == "terminal_far_jump_unmodeled"]
        assert len(refusals) == 1, artifact.refusals
        refusal = refusals[0]
        assert refusal.block_addr == entry
        assert f"{target:#x}" in refusal.detail
        assert refusal in artifact.blocks[0].refusals


def test_native_immediate_far_jump_on_closed_in_body_edge_retains_transfer() -> None:
    entry, target = 0x1000, 0x1010
    project = _project(bytes.fromhex("ea 10 00 00 01") + b"\x90" * 11 + b"\xc3", entry)
    function = exact_function_range_boundary_8616(project, entry, target + 1)
    assert function is not None

    artifact = raw_x86_16_function_bundle_8616(project, function).artifact
    assert not artifact.refusals
    entry_block = artifact.blocks[0]
    assert entry_block.successor_addrs == (target,)
    jumps = [instr for instr in entry_block.instrs if instr.op == "JMP"]
    assert len(jumps) == 1
    jump = jumps[0]
    assert jump.addr == entry
    assert jump.args[0].const == target
