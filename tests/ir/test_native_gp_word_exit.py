"""Check default native GP exit consumers through the real Clinic pipeline."""

from io import BytesIO

import angr
import pytest
from angr.ailment.expression import Call, Const
from angr.ailment.statement import SideEffectStatement

from inertia.frontend.x86_16 import lift_86_16  # noqa: F401 -- register the native lifter
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap


def _exit_values(code: str, monkeypatch: pytest.MonkeyPatch) -> list[tuple[tuple[int, int], int]]:
    monkeypatch.delenv("INERTIA_EXPERIMENTAL_GP_EXIT_USES", raising=False)
    monkeypatch.delenv("INERTIA_EXPERIMENTAL_GP_EXIT_LANES", raising=False)
    apply_x86_16_bootstrap()
    project = angr.Project(
        BytesIO(bytes.fromhex(code)),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )
    cfg = project.analyses.CFGFast(normalize=True)
    clinic = project.analyses.Clinic(cfg.functions[0x1000])
    values = []
    for block in clinic.graph:
        for stmt in block.statements:
            if (
                isinstance(stmt, SideEffectStatement)
                and isinstance(stmt.expr, Call)
                and stmt.expr.target == "inertia_architectural_gp_exit"
                and "inertia_word_far_return_cleanup" not in stmt.tags
            ):
                offset, width = stmt.tags["inertia_gp_exit_coordinate"]
                assert stmt.expr.args is not None and len(stmt.expr.args) == 1
                operand = stmt.expr.args[0]
                assert isinstance(operand, Const)
                values.append(((offset, width), operand.value))
    return sorted(values)


def test_native_gp_word_exit_publishes_proven_bx_dx_through_join(monkeypatch: pytest.MonkeyPatch) -> None:
    # mov bx, 1234h; mov dx, 5678h; mov cx, 3fh; test ax, ax; jz exit; dec ax; exit: retf
    registers = Arch86_16().registers
    assert _exit_values("bb3412 ba7856 b93f00 85c0 7401 48 cb", monkeypatch) == sorted(
        [(registers["bx"], 0x1234), (registers["dx"], 0x5678)]
    )


def test_native_gp_word_exit_preserves_unwritten_dx(monkeypatch: pytest.MonkeyPatch) -> None:
    # mov bx, 1234h; retf
    assert _exit_values("bb3412 cb", monkeypatch) == [(Arch86_16().registers["bx"], 0x1234)]


def test_native_gp_word_exit_keeps_each_return_operand(monkeypatch: pytest.MonkeyPatch) -> None:
    # test ax, ax; jz other; mov bx, 1234h; retf; other: mov bx, 5678h; retf
    bx = Arch86_16().registers["bx"]
    assert _exit_values("85c0 7404 bb3412 cb bb7856 cb", monkeypatch) == [(bx, 0x1234), (bx, 0x5678)]


def test_native_gp_word_exit_refuses_non_word_bx_owners(monkeypatch: pytest.MonkeyPatch) -> None:
    # mov ebx, aaaa1234h; retf -- a 32-bit write is not a 16-bit exit value.
    assert _exit_values("66bb3412aaaa cb", monkeypatch) == []
