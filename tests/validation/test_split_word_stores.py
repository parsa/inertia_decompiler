from types import SimpleNamespace

import pytest

from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
)
from inertia.validation import validation_required_memory_effects as effects


def _address(size, space=MemSpace.DS, base=("bx",)):
    return IRAddress(
        space=space,
        base=base,
        offset=0x26,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def _access(insn, ordinal=0, kind=IRMemoryAccessKind8616.WRITE, size=2, space=MemSpace.DS, base=("bx",)):
    logical = _address(size, space, base)
    slices = tuple(
        IRMemoryExecutionSlice8616(
            0x100,
            index,
            insn,
            index,
            IRAddress(
                space=space,
                base=base,
                offset=logical.offset + index,
                size=1,
                status=AddressStatus.STABLE,
                segment_origin=SegmentOrigin.PROVEN,
            ),
        )
        for index in range(size)
    )
    return IRLogicalMemoryAccess8616(
        IRLogicalMemoryAccessKey8616(0x100, 0x100, insn, ordinal), kind, logical, 16, slices
    )


def _write(width, ins_addr, offset=None):
    return effects._FinalSegmentedWrite8616(
        MemSpace.DS, offset, width, affine_base=0x26 if offset is None else None, ins_addr=ins_addr
    )


def _tokens(accesses, writes):
    return [issue.token() for issue in effects.split_word_store_issues_8616(accesses, writes)]


def test_access_fixture_is_complete():
    assert _access(0x10).complete


def test_register_word_store_projected_as_two_byte_stores_is_refused():
    assert _tokens([_access(0x10)], [_write(1, 0x10), _write(1, 0x10)]) == [
        "split-word-store:block=0x100:ins=0x10:access=0"
    ]


def test_each_split_word_store_is_refused_independently():
    accesses = [_access(0x10), _access(0x20)]
    writes = [_write(1, 0x10), _write(1, 0x10), _write(1, 0x20), _write(1, 0x20)]
    assert len(_tokens(accesses, writes)) == 2


def test_native_word_assignment_is_accepted():
    assert _tokens([_access(0x10)], [_write(2, 0x10)]) == []


def test_one_word_store_covers_only_one_access_of_the_instruction():
    accesses = [_access(0x10, 0), _access(0x10, 1)]
    assert len(_tokens(accesses, [_write(2, 0x10), _write(1, 0x10), _write(1, 0x10)])) == 1


def test_byte_stores_from_other_instructions_do_not_count():
    assert _tokens([_access(0x10)], [_write(1, 0x11), _write(1, 0x12)]) == []


def test_untagged_byte_stores_are_not_attributed():
    assert _tokens([_access(0x10)], [_write(1, None), _write(1, None)]) == []


def test_native_byte_store_and_reads_are_not_word_stores():
    assert _tokens([_access(0x10, size=1)], [_write(1, 0x10), _write(1, 0x10)]) == []
    read = _access(0x10, kind=IRMemoryAccessKind8616.READ)
    assert _tokens([read], [_write(1, 0x10), _write(1, 0x10)]) == []


def test_direct_and_stack_word_stores_are_owned_elsewhere():
    assert _tokens([_access(0x10, base=())], [_write(1, 0x10), _write(1, 0x10)]) == []
    assert _tokens([_access(0x10, space=MemSpace.SS, base=("bp",))], [_write(1, 0x10), _write(1, 0x10)]) == []


def test_split_issue_fails_report():
    issues = effects.split_word_store_issues_8616([_access(0x10)], [_write(1, 0x10), _write(1, 0x10)])
    report = effects.RequiredMemoryEffectValidationReport8616(failure_count=1, issues=issues)
    assert not report.passed


@pytest.mark.parametrize("proven,closed", [(True, True), (True, False), (False, True)])
def test_required_memory_gate_uses_only_closed_proven_artifact(monkeypatch, proven, closed):
    project = object()
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x100))
    writes = (_write(1, 0x10), _write(1, 0x10))
    logical = SimpleNamespace(closed=closed, accesses=(_access(0x10),))

    def resolve(actual_project, address):
        assert actual_project is project and address == 0x100
        verdict = effects.FunctionSSAArtifactVerdict8616.PROVEN if proven else None
        return SimpleNamespace(verdict=verdict, artifact=SimpleNamespace(logical_memory=logical))

    monkeypatch.setattr(effects, "registered_function_ssa_artifact_8616", resolve)
    monkeypatch.setattr(effects, "_final_segmented_writes_8616", lambda *_: writes)
    report = effects.validate_required_memory_effects_8616(project, codegen, object())
    assert report.passed == (not (proven and closed))
    assert [issue.token() for issue in report.issues] == (
        ["split-word-store:block=0x100:ins=0x10:access=0"] if proven and closed else []
    )
