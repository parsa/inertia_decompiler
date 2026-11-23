"""Late Rewrite must consume current evidence before it can publish its own AST."""

from contextvars import copy_context
from itertools import count
from types import SimpleNamespace

import angr
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeShort

from inertia.cli import cli_decompilation
from inertia.cli.project_loading import _build_project_from_bytes
from inertia.ir.function_lifecycle import (
    FunctionStageFailure8616,
    FunctionStageVerdict8616,
    existing_function_lifecycle_state_8616,
)
from inertia.ir.function_readiness_contracts import FUNCTION_LIFECYCLE_STAGES_8616, FunctionLifecycleStage8616
from inertia.ir.function_ssa_registry import function_ssa_artifact_at_address_8616
from inertia.pipeline import function_readiness as readiness
from inertia.pipeline.errors import PipelineHardError
from inertia.pipeline.render_authority import require_codegen_render_integrity_8616
from inertia.structuring.return_chain_integrity import install_materialized_return_chain_integrity_guard_8616

BASE = 0x10000
REWRITE = FunctionLifecycleStage8616.REWRITE
STRUCTURING = FunctionLifecycleStage8616.STRUCTURING


def _published_rewrite() -> tuple[angr.Project, SimpleNamespace, structured_c.CConstant]:
    project = _build_project_from_bytes(bytes.fromhex("89d8c3"), base_addr=BASE, entry_point=BASE)
    project.analyses.CFGFast(normalize=True)
    assert function_ssa_artifact_at_address_8616(project, BASE).artifact is not None
    for stage in FUNCTION_LIFECYCLE_STAGES_8616[:4]:
        readiness.record_function_stage_evidence_8616(project, BASE, stage, producer="prefix", outputs=(stage,))
    codegen = SimpleNamespace(project=project, next_node_idx=count().__next__, next_ident=lambda name: name)
    manager = SimpleNamespace(types=SimpleNamespace(iter_own=lambda: ()), get_variable_type=lambda variable: None)
    value_type = SimTypeShort(signed=False).with_arch(project.arch)
    constant = structured_c.CConstant(3, value_type, codegen=codegen)
    codegen.cfunc = structured_c.CFunction(
        BASE, "rewrite_fixture", SimTypeFunction([], value_type).with_arch(project.arch),
        [], structured_c.CReturn(constant, codegen=codegen), {}, manager, codegen=codegen,
    )
    readiness.record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen, producer="structuring",
    )
    with readiness.function_rewrite_production_scope_8616(project, BASE, codegen):
        readiness.record_function_rewrite_completion_8616(
            project, BASE, codegen, producer="initial_rewrite", outputs=("original proof receipt",),
        )
    return project, codegen, constant


@pytest.mark.parametrize("case", ["passed", "stale", "foreign_owner", "failed_proof"])
def test_produce_function_rewrite_continuation_checks_ownership_and_proof(case: str) -> None:
    """Only the current AST owner may mutate, and then publish only after a passing guard."""
    project, codegen, constant = _published_rewrite()
    previous = readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE]
    operations = []

    def mutate() -> bool:
        operations.append("mutate")
        constant.value = 5
        return True

    def validate() -> bool:
        operations.append("validate")
        assert constant.value == 5
        assert readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE] is previous
        return case == "passed"

    def produce() -> bool:
        return readiness.produce_function_rewrite_continuation_8616(
            project, BASE, codegen, producer="late_rewrite", mutate=mutate, validate=validate,
        )

    if case == "stale":
        constant.value = 4
    if case == "foreign_owner":
        codegen = SimpleNamespace(cfunc=codegen.cfunc)
    if case != "passed":
        with pytest.raises(PipelineHardError):
            produce()
        assert operations == (["mutate", "validate"] if case == "failed_proof" else [])
        assert readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE] is previous
        return

    assert produce()
    assert operations == ["mutate", "validate"]
    current = readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE]
    assert current.producer == "late_rewrite"
    assert current.outputs_digest != previous.outputs_digest
    assert current.source_revision is previous.source_revision
    assert current.inputs is previous.inputs
    assert "original proof receipt" in current.live_outputs
    final = readiness.assert_function_ast_consumer_ready_8616(project, BASE, REWRITE, codegen, layer="final")
    assert final.verdict is FunctionStageVerdict8616.CURRENT
    constant.value = 6
    with pytest.raises(PipelineHardError):
        readiness.assert_function_ast_consumer_ready_8616(project, BASE, REWRITE, codegen, layer="final")


@pytest.mark.parametrize("replacement_value", [3, 17])
def test_produce_function_rewrite_continuation_refuses_replaced_upstream(replacement_value: int) -> None:
    """A new valid Structuring publication cannot become the input of work already done."""
    project, codegen, constant = _published_rewrite()
    previous = readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE]
    _, replacement_codegen, replacement = _published_rewrite()
    replacement.value = replacement_value

    def mutate() -> bool:
        constant.value = 5
        return True

    def replace_upstream() -> bool:
        readiness.record_function_ast_stage_evidence_8616(
            project, BASE, STRUCTURING, replacement_codegen, producer="replacement_structuring",
        )
        readiness.handoff_function_ast_to_rewrite_8616(project, BASE, replacement_codegen)
        state = existing_function_lifecycle_state_8616(project, BASE)
        assert state is not None
        # Preserve the exact Rewrite record to exercise upstream checking independently
        # of the existing check that detects dropped or replaced Rewrite records.
        state.publications[REWRITE] = previous
        assert readiness.function_stage_readiness_8616(project, BASE, STRUCTURING).verdict is (
            FunctionStageVerdict8616.CURRENT
        )
        return True

    with pytest.raises(PipelineHardError) as refusal:
        readiness.produce_function_rewrite_continuation_8616(
            project, BASE, codegen, producer="late_rewrite", mutate=mutate, validate=replace_upstream,
        )
    assert refusal.value.details["failure"] == FunctionStageFailure8616.UPSTREAM_EVIDENCE_CHANGED.value
    assert readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE] is previous


def test_produce_function_rewrite_continuation_refuses_changed_source() -> None:
    """Re-observe the source after the proof callback before sealing the changed AST."""
    project, codegen, constant = _published_rewrite()

    def mutate() -> bool:
        constant.value = 5
        return True

    def change_source() -> bool:
        project.loader.memory.store(BASE, bytes.fromhex("89d0c3"))
        return True

    with pytest.raises(PipelineHardError) as refusal:
        readiness.produce_function_rewrite_continuation_8616(
            project, BASE, codegen, producer="late_rewrite", mutate=mutate, validate=change_source,
        )
    assert refusal.value.details["failure"] == FunctionStageFailure8616.SOURCE_REVISION_CHANGED.value


@pytest.mark.parametrize("exit_kind", ["abort", "exception"])
def test_rewrite_continuation_render_lease_cannot_escape_failed_callback(exit_kind: str) -> None:
    """Only internal rendering may use pending ASTs; incomplete phases never publish."""
    project, codegen, constant = _published_rewrite()
    previous = readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE]
    foreign = SimpleNamespace(cfunc=codegen.cfunc)
    copied_context = None

    def mutate() -> None:
        nonlocal copied_context
        constant.value = 5
        copied_context = copy_context()
        assert readiness.function_render_required_stage_8616(project, codegen) is FunctionLifecycleStage8616.TYPES
        assert readiness.function_render_required_stage_8616(project, foreign) is REWRITE
        with pytest.raises(PipelineHardError):
            readiness.assert_function_ast_consumer_ready_8616(project, BASE, REWRITE, codegen, layer="final")
        if exit_kind == "exception":
            raise ValueError("failed callback")

    def validate() -> bool:
        pytest.fail("an incomplete callback must not request publication")

    def produce() -> bool:
        return readiness.produce_function_rewrite_continuation_8616(
            project, BASE, codegen, producer="late_rewrite", mutate=mutate, validate=validate,
        )

    if exit_kind == "exception":
        with pytest.raises(ValueError, match="failed callback"):
            produce()
    else:
        assert not produce()
    assert copied_context is not None
    assert copied_context.run(readiness.function_render_required_stage_8616, project, codegen) is REWRITE
    assert readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE] is previous


def test_codegen_regeneration_failure_cannot_publish_rewrite(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even if regeneration changed the AST, a failed callback cannot seal it."""
    project, codegen, constant = _published_rewrite()
    previous = readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE]

    def fail(*_args: object, **_kwargs: object) -> None:
        constant.value = 5
        raise ValueError("regeneration failed")

    monkeypatch.setattr(cli_decompilation, "_regenerate_codegen_text_safely_impl", fail)
    with pytest.raises(ValueError, match="regeneration failed"):
        cli_decompilation._regenerate_codegen_text_safely(codegen, context="fixture")
    assert readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE] is previous


def test_post_regeneration_integrity_refusal_cannot_publish_rewrite(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real fallback rejects a changed return AST even when cached C is available."""
    project, codegen, constant = _published_rewrite()
    previous = readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE]
    codegen.text = "unsigned int rewrite_fixture(void) { return 3; }"
    codegen._inertia_return_chain_flattened_8616 = False
    codegen._inertia_return_chain_suffix_materialized_8616 = True
    codegen._inertia_return_chain_materialized_values_8616 = (3,)
    codegen._inertia_return_chain_final_value_8616 = 3
    install_materialized_return_chain_integrity_guard_8616(codegen)
    require_codegen_render_integrity_8616(codegen, context="original")
    validation_calls: list[bool] = []

    def finish_regeneration(_ctx: object) -> None:
        constant.value = 5  # No immediate render result: continue into the real fallback.

    def mutate() -> bool:
        cli_decompilation._regenerate_codegen_text_safely(codegen, context="post-regen fixture")
        return True

    def validate() -> bool:
        validation_calls.append(True)
        return True

    monkeypatch.setattr(cli_decompilation._RegenRunCtx8616, "run_regen_pipeline", finish_regeneration)
    with pytest.raises(PipelineHardError, match="lost CFG-proven return-chain values") as refusal:
        readiness.produce_function_rewrite_continuation_8616(
            project, BASE, codegen, producer="late_rewrite", mutate=mutate, validate=validate,
        )

    assert refusal.value.details["context"] == "post-regen fixture"
    assert refusal.value.details["missing_values"] == (3,)
    assert constant.value == 5
    assert not validation_calls
    assert readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE] is previous


@pytest.mark.parametrize("step", ["direct_stack", "late_ast"])
def test_cli_late_cleanup_checks_owner_before_mutation_and_dependent_prune(
    step: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI mutations that expose a prune must be published as a single checked result."""
    project, codegen, constant = _published_rewrite()
    previous = readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE]
    run = cli_decompilation._DecompileRun8616(project, None, project.kb.functions[BASE], 0, "c")
    run.dec = SimpleNamespace(codegen=codegen)
    run.pointer_memory_contract_active = step != "direct_stack"
    run.call_loss_guard_active = False
    operations: list[str] = []

    def begin_mutation() -> None:
        current = readiness.function_stage_readiness_8616(project, BASE, REWRITE)
        assert current.verdict is FunctionStageVerdict8616.CURRENT
        operations.append("mutation")
        constant.value = 5

    def direct_stack(*_args: object, **_kwargs: object) -> SimpleNamespace:
        assert step == "direct_stack"
        begin_mutation()
        return SimpleNamespace(direct_stack_mov_changed=True, changed=True)

    def late_ast(*_args: object) -> SimpleNamespace:
        if step == "late_ast":
            begin_mutation()
        return SimpleNamespace(changed=step == "late_ast", requires_dce_after_cleanup=step == "late_ast")

    def prune(_codegen: object) -> bool:
        if constant.value != 5:
            return False  # The unconditional standalone prune is a no-op in this fixture.
        operations.append("prune")
        constant.value = 6
        return True

    def validate(*_args: object, **_kwargs: object) -> SimpleNamespace:
        assert readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE] is previous
        assert constant.value == 6
        operations.append("validate")
        return SimpleNamespace(passed=True)

    monkeypatch.setattr(cli_decompilation, "run_direct_instruction_materialization_8616", direct_stack)
    monkeypatch.setattr(cli_decompilation, "finalize_late_ast_cleanup_8616", late_ast)
    monkeypatch.setattr(cli_decompilation, "_prune_dead_local_assignments", prune)
    monkeypatch.setattr(cli_decompilation, "_prune_unused_local_declarations", lambda _: False)
    monkeypatch.setattr(cli_decompilation, "format_stack_probe_fact_stats_8616", lambda _: None)
    monkeypatch.setattr(cli_decompilation, "refresh_x86_16_final_semantic_validation_8616", validate)

    run._run_cli_ast_phases_8616((run._cleanup_dead_local_and_stats_8616,))

    assert operations == ["mutation", "prune", "validate"]
    final = readiness.assert_function_ast_consumer_ready_8616(project, BASE, REWRITE, codegen, layer="final")
    assert final.verdict is FunctionStageVerdict8616.CURRENT


def test_cli_counted_loop_repair_with_noop_direct_stack(monkeypatch: pytest.MonkeyPatch) -> None:
    """Repair must be owned before it changes the AST, even if direct-stack work does nothing."""
    project, codegen, constant = _published_rewrite()
    previous = readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE]
    run_type = cli_decompilation._DecompileRun8616
    run = run_type(project, None, project.kb.functions[BASE], 0, "c")
    run.dec = SimpleNamespace(codegen=codegen)
    run.current_func_addr = BASE
    operations: list[str] = []

    def repair(*_args: object) -> bool:
        operations.append("repair")
        constant.value = 5
        return True

    def direct_stack(*_args: object, **kwargs: object) -> SimpleNamespace:
        if kwargs.get("include_direct_global_incdec") is False:
            assert constant.value == 5
            operations.append("direct_stack_noop")
        return SimpleNamespace(changed=False, direct_stack_mov_changed=False, direct_global_incdec_changed=False)

    def validate(*_args: object, **_kwargs: object) -> SimpleNamespace:
        assert readiness.function_stage_evidence_map_8616(project, BASE)[REWRITE] is previous
        operations.append("validate")
        return SimpleNamespace(passed=True)

    for phase in (
        "phase_setup_8616", "phase_prep_span_8616", "phase_guards_8616", "phase_decompiler_run_8616",
        "phase_no_postprocess_lane_8616", "phase_postprocess_setup_8616", "phase_rewrite_registry_8616",
        "phase_rewrite_dispatch_8616", "_rewrite_safe_dce_and_gate_8616", "phase_callsite_guard_8616",
        "phase_late_lowering_8616", "phase_cleanup_finalize_8616", "phase_render_refresh_8616",
        "phase_emit_retry_8616", "phase_text_normalize_8616", "phase_final_cleanup_8616",
    ):
        monkeypatch.setattr(run_type, phase, lambda _self: None)
    monkeypatch.setattr(run_type, "_rewrite_round_8616", lambda _self, _round: False)
    monkeypatch.setattr(run_type, "phase_finish_8616", lambda _self: ("ok", "fixture"))
    for helper in (
        "materialize_named_segmented_global_loads_8616", "materialize_compare_register_global_carriers_8616",
        "materialize_direct_global_symbol_stores_8616", "materialize_indexed_segmented_global_loads_8616",
        "_rehydrate_missing_evidenced_calls_on_live_codegen_8616",
    ):
        monkeypatch.setattr(cli_decompilation, helper, lambda *_args, **_kwargs: False)
    monkeypatch.setattr(cli_decompilation, "repair_empty_counted_loop_body_from_evidence_8616", repair)
    monkeypatch.setattr(cli_decompilation, "run_direct_instruction_materialization_8616", direct_stack)
    monkeypatch.setattr(cli_decompilation, "refresh_x86_16_final_semantic_validation_8616", validate)

    assert run.run_8616() == ("ok", "fixture")
    assert operations == ["repair", "direct_stack_noop", "validate"]
    final = readiness.assert_function_ast_consumer_ready_8616(project, BASE, REWRITE, codegen, layer="final")
    assert final.verdict is FunctionStageVerdict8616.CURRENT
