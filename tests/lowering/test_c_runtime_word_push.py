import pytest

from inertia.cli import recompile_check
from inertia.lowering.c_runtime_header import render_c_runtime_header_8616


@pytest.mark.parametrize("target", ["portable-flat", "msc-dos"])
def test_default_runtime_header_compiles_word_push_body_without_injection(monkeypatch, target):
    header = render_c_runtime_header_8616(target)
    payload = header + "\nvoid save_word(void) { inertia_push_word(inertia_ss, 1u, 0x1234u); }\n"
    assert "static uint16_t inertia_retf_word(" not in header

    def unexpected_header(*_, **__):
        pytest.fail("checker tried to add runtime code to the complete header/body")

    monkeypatch.setattr(recompile_check, "render_c_runtime_header_8616", unexpected_header)
    result = recompile_check.check_c_recompiles_8616(payload, target=target)
    if result.outcome is recompile_check.RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE:
        pytest.skip(f"optional {target} compiler is unavailable: {result.stderr}")
    assert result.passed, result.stderr or result.stdout
    assert result.checked_payload == payload
