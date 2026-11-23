"""Exercise proof-scoped word RETF exit effects through Clinic with default settings."""

from io import BytesIO
from typing import Literal

import angr
import pytest
from angr.ailment.expression import Call, VirtualVariable
from angr.ailment.statement import SideEffectStatement

from inertia.frontend.x86_16 import lift_86_16  # noqa: F401 -- register the native lifter
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.frontend_boundary_transport import (
    capture_function_boundary_8616,
    restore_function_boundary_8616,
)
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact


def _exit_effects(
    code: str, monkeypatch: pytest.MonkeyPatch, *, source: Literal["absent", "current", "stale"] = "absent",
) -> list[SideEffectStatement]:
    for name in (
        "STACK_EXIT_USE", "BP_EXIT_USE", "FLAGS_EXIT_USE", "GP_EXIT_USES",
        "GP_EXIT_LANES", "WORD_FAR_RETURN",
    ):
        monkeypatch.delenv(f"INERTIA_EXPERIMENTAL_{name}", raising=False)
    apply_x86_16_bootstrap()
    project = angr.Project(
        BytesIO(bytes.fromhex(code)),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )
    cfg = project.analyses.CFGFast(normalize=True)
    function = cfg.functions[0x1000]
    if source != "absent":
        witness = capture_function_boundary_8616(project, function)
        assert witness is not None
        boundary = restore_function_boundary_8616(project, witness)
        assert boundary is not None
        raw = build_x86_16_ir_function_artifact(project, boundary)
        assert publish_function_ir_artifact_8616(project, raw).verdict is FunctionIRArtifactVerdict8616.PROVEN
        if source == "stale":
            # Change only the immediate operand in the synthetic function body.
            project.loader.memory.store(0x1004, b"\x78")
            assert registered_function_ir_artifact_8616(project, 0x1000).failure is (
                FunctionIRArtifactFailure8616.SOURCE_REVISION_CHANGED
            )
    clinic = project.analyses.Clinic(function)
    return [
        statement for block in clinic.graph for statement in block.statements
        if isinstance(statement, SideEffectStatement) and isinstance(statement.expr, Call)
        and statement.expr.target == "inertia_architectural_gp_exit"
    ]


def _return_effects(code: str, monkeypatch: pytest.MonkeyPatch) -> list[SideEffectStatement]:
    return [
        statement for statement in _exit_effects(code, monkeypatch)
        if tuple(statement.tags["inertia_gp_exit_coordinate"]) == Arch86_16().registers["sp"]
    ]


@pytest.mark.parametrize(("code", "cleanup"), [("bb 34 12 cb", 0), ("bb 34 12 ca 02 00", 2)])
def test_native_word_far_return_keeps_proven_incoming_sp(
    code: str, cleanup: int, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (effect,) = _return_effects(code, monkeypatch)
    assert effect.tags["inertia_word_far_return_cleanup"] == cleanup
    assert effect.tags["inertia_return_sp_is_incoming"] is True
    assert effect.expr.args is not None and len(effect.expr.args) == 1
    assert isinstance(effect.expr.args[0], VirtualVariable)


@pytest.mark.parametrize("code", ["bb 34 12 c3", "bb 34 12 c2 02 00", "bb 34 12 cf", "bb 34 12 66 cb"])
def test_native_word_far_return_does_not_enable_other_terminal_layouts(
    code: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _return_effects(code, monkeypatch) == []


def test_native_word_far_return_refuses_an_unclosed_private_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    # push bp; mov bp, sp; mov bx, 1234h; pop bp; retf
    assert _return_effects("55 89 e5 bb 34 12 5d cb", monkeypatch) == []


@pytest.mark.parametrize("source", ["current", "stale"])
def test_native_word_far_return_binds_computed_sp_bp_and_flags_together(
    source: Literal["current", "stale"], monkeypatch: pytest.MonkeyPatch,
) -> None:
    # push bp; mov bp, sp; mov bx, 1234h; test bx,bx; pop bp; retf 2
    effects = _exit_effects("55 89 e5 bb 34 12 85 db 5d ca 02 00", monkeypatch, source=source)
    registers = Arch86_16().registers
    by_coordinate = {tuple(effect.tags["inertia_gp_exit_coordinate"]): effect for effect in effects}
    if source == "stale":
        assert set(by_coordinate).isdisjoint({registers[name] for name in ("sp", "bp", "flags")})
    else:
        assert len(by_coordinate) == len(effects)
        assert set(by_coordinate) == {registers[name] for name in ("sp", "bp", "bx", "flags")}
        frame = by_coordinate[registers["sp"]]
        assert frame.tags["inertia_word_far_return_cleanup"] == 2
        assert frame.tags["inertia_return_sp_is_incoming"] is False


@pytest.mark.parametrize("write", ["66 bb 34 12 78 56", "b3 34"])
def test_native_word_far_return_refuses_an_unhandled_gp_view(
    write: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # push bp; mov bp, sp; mov ebx/bl, imm; pop bp; retf
    effects = _exit_effects(f"55 89 e5 {write} 5d cb", monkeypatch, source="current")
    registers = Arch86_16().registers
    assert all(tuple(effect.tags["inertia_gp_exit_coordinate"]) != registers["sp"] for effect in effects)


def test_native_word_far_return_refuses_a_surviving_upper_esp_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    # push bp; mov bp,sp; mov esp,12345678h; mov sp,bp; pop bp; retf
    effects = _exit_effects("55 89 e5 66 bc 78 56 34 12 89 ec 5d cb", monkeypatch, source="current")
    registers = Arch86_16().registers
    assert {tuple(effect.tags["inertia_gp_exit_coordinate"]) for effect in effects}.isdisjoint(
        {registers["sp"], registers["bp"]},
    )


@pytest.mark.parametrize("ending", ["5e cb", "5d 83 ec 02 cb"])
def test_native_word_far_return_refuses_unbalanced_bp_or_sp(
    ending: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # End with a pop that does not restore BP, or leave SP two bytes below entry.
    effects = _exit_effects(f"55 89 e5 bb 34 12 {ending}", monkeypatch, source="current")
    registers = Arch86_16().registers
    assert all(tuple(effect.tags["inertia_gp_exit_coordinate"]) != registers["sp"] for effect in effects)
