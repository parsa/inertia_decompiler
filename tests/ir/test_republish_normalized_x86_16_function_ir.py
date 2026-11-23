"""Check the raw-IR producer handoff separately from consumer admission."""

from types import SimpleNamespace

import pytest

from inertia.ir import vex_import
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    FunctionIRArtifactResolution8616,
    FunctionIRArtifactVerdict8616,
)

ADDRESS = 0x1000


def _refusal(failure: FunctionIRArtifactFailure8616) -> FunctionIRArtifactResolution8616:
    return FunctionIRArtifactResolution8616(ADDRESS, FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE, None, failure)


@pytest.mark.parametrize("failure", [
    FunctionIRArtifactFailure8616.NOT_REGISTERED,
    FunctionIRArtifactFailure8616.SOURCE_REVISION_CONFLICT,
    FunctionIRArtifactFailure8616.SOURCE_UNAVAILABLE,
])
def test_normalized_x86_16_producer_does_not_retry_unrelated_refusals(
    monkeypatch: pytest.MonkeyPatch, failure: FunctionIRArtifactFailure8616,
) -> None:
    original = _refusal(failure)
    monkeypatch.setattr(vex_import, "registered_function_ir_artifact_8616", lambda _project, _addr: original)
    monkeypatch.setattr(vex_import, "capture_function_boundary_8616", lambda *_: pytest.fail("unexpected rebuild"))

    assert vex_import.republish_normalized_x86_16_function_ir_8616(object(), ADDRESS, object()) is original


@pytest.mark.parametrize("destination", [None, ADDRESS + 1, ADDRESS])
def test_normalized_x86_16_producer_rebuilds_only_from_the_current_matching_boundary(
    monkeypatch: pytest.MonkeyPatch, destination: int | None,
) -> None:
    project, function, witness, fresh_artifact = object(), object(), object(), object()
    original = _refusal(FunctionIRArtifactFailure8616.SOURCE_REVISION_CHANGED)
    published = FunctionIRArtifactResolution8616(ADDRESS, FunctionIRArtifactVerdict8616.PROVEN, fresh_artifact, None)
    boundary = None if destination is None else SimpleNamespace(addr=destination)
    events = []

    def capture(seen_project: object, seen_function: object) -> object:
        assert seen_project is project and seen_function is function
        return witness

    def restore(seen_project: object, seen_witness: object) -> object:
        assert seen_project is project and seen_witness is witness
        return boundary

    def build(seen_project: object, seen_boundary: object) -> object:
        assert seen_project is project and seen_boundary is boundary
        events.append("build-current")
        return fresh_artifact

    def publish(seen_project: object, artifact: object) -> FunctionIRArtifactResolution8616:
        assert seen_project is project and artifact is fresh_artifact
        events.append("publish-fresh")
        return published

    monkeypatch.setattr(vex_import, "registered_function_ir_artifact_8616", lambda _project, _addr: original)
    monkeypatch.setattr(vex_import, "capture_function_boundary_8616", capture)
    monkeypatch.setattr(vex_import, "restore_function_boundary_8616", restore)
    monkeypatch.setattr(vex_import, "build_x86_16_ir_function_artifact", build)
    monkeypatch.setattr(vex_import, "publish_function_ir_artifact_8616", publish)

    result = vex_import.republish_normalized_x86_16_function_ir_8616(project, ADDRESS, function)
    if destination == ADDRESS:
        assert result is published and events == ["build-current", "publish-fresh"]
    else:
        assert result is original and not events
