# Physical GP PUSH v5 evidence

Workdir: `stack-write-tree/`. Patch `../stack-write-v5.patch` SHA-256: `62290b41e3043315e8442a0f5fd4061e4b67a07e4ad9acec1a33aebf8b991c57`. Patches v1–v4 retain their previous SHA-256 hashes, and no staging was performed (the isolated patch tree is not a Git checkout).

## Review findings and tests

- P0: Require canonical plain integer literals for owned masks, displacements, and immediates. Reject `reference_values` and integer-format overrides that can change the emitted value. The two-PUSH fixture exercises `reference_values={delta.type: 0}` and character formatting; separate cases mutate the capture mask and immediate operand.
- P1: Refuse a potentially aliasing physical assignment adjacent to the verified entry-PUSH owner sequence if it has no distinct machine STORE in the retained IR. The regression uses an untagged `SEG_U8(ss, (entry_sp + 0xfffe) & 0xffff)` lvalue at that boundary.
- P1: Require the same live word BP frame proof as the producer and bind both PUSH and setter addresses. The positive fixture lifts a real framed CALL loop; the negative fixture puts NOP at the purported setter and uses an otherwise canonical tagged BP install.

`.work/pytest-v5-red.log` recorded all three reviewer counterexamples failing on v4 (did not raise), with the real-frame control passing. `.work/pytest-v5.log` records 67 focused tests passing. The full suite passed 143 tests in 314.84 s with one upstream deprecation warning (`.work/pytest-v5-full.log`).

## Commands

```bash
bash .work/test.sh -k 'without_machine_setter or referenced_second_push or unbound_physical_write or existing_frame_runtime'  # before source edits and final test names
bash .work/test.sh tests/ir/test_native_gp_word_exit.py tests/ir/test_native_gp_exit_operand_guard.py
bash .work/test.sh tests -v
TIMEOUT=330 JOBS=2 bash .work/run-v2.sh v5 29b99:28 325b7:16 19452:39 13dc2:48 148fe:18
bash .work/check-v5.sh WRAPPER_DRIVER_PID
source .work/env.sh
$PY .work/make-patch.py > ../stack-write-v5.patch
git apply --reverse --check ../stack-write-v5.patch
(cd .work/old-guarded && git apply --check ../../../stack-write-v5.patch)
RUFF_CACHE_DIR="$PWD/.work/ruff-cache" ruff check inertia/lowering/{gp_push_store,entry_stack_pointer_capture}.py tests/lowering/test_gp_push_store.py
```

`.work/check-v5.sh` checks wrapper statuses and byte identity against v4, compiles the exact fresh bodies using the normal CLI-emitted header for portable-flat and MSC-DOS without checker injection, and reruns the lookup alias and two disjoint harnesses. The full-profile bodies require the existing word-frame option in the normal CLI header; the unoptioned common default header is checked on both targets by pytest and on the archived GP-only `2fbb6` wrapper body. Exact compiler receipts are `.work/v5-*.compilers.jsonl`. These witnesses test observed accesses, not whole-function equivalence.

All five v5 wrappers validated and were byte-identical to v4. All 12 exact compiler checks passed (five fresh v5 bodies plus one archived GP-only body, each on both targets). Native and emitted lookup matched AX=`0177`, slot=`7777`; the emitted witness wrote both bytes before the aliased read (`.work/lookup-v5.log`). Both disjoint harnesses passed (`.work/disjoint-v5.log`).

| Address | Wrapper C body SHA-256 |
|---|---|
| `29b99` | `6c78535abd9a92e3a70b03eeda5af70c043983ce9f85060753c8b32d245dabc6` |
| `325b7` | `cfcfd243fa18c1f96542d0e9e534a58e0e272582d8af9a5d32236e6cf79e9eb3` |
| `19452` | `b4e038e1a4c00a53a5ecc070c0223a5e9140fd155b8d93cd4db11744a180f1f4` |
| `13dc2` | `f837731f1327b87f26ffd12013470dab6f1007f3f564cd91e8f7837d8485f0c8` |
| `148fe` | `80ecd9963514553f7a7f602d916696da59e011f6c91086ec0cea3e03cb82514b` |
