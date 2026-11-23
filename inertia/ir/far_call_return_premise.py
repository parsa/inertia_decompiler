# cython: language_level=3, infer_types=True
"""Conditional far-CALL normal-return premise for entry-domain CS preservation.

Layer: IR.
Responsibility: decide whether one immediate ``9A`` CALL may be modelled as
restoring the caller's CS under the *explicit normal-return premise*: the
callee returns through RETF with SP at exactly its entry SP, so RETF pops the
caller-pushed CS:IP. Integrity of that 4-byte return slot is NOT proven: with
DS == SS any store through an unresolved pointer may alias it. Every admission
is recorded on the project as a named premise so dependent output is labelled
conditional. Opt-in only through ``INERTIA_OPUS_FAR_RETURN_PREMISE=1``.

Refusals (never premised): non-RETF or disagreeing exits, SP not balanced at
RETF, non-canonical BP frames, BP-relative stores overlapping a return slot or
with an unresolved index, nested indirect calls, unproven nested callees.
"""
from __future__ import annotations

import os
import sys
from contextvars import ContextVar

import capstone
from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_REG_BP, X86_REG_INVALID, X86_REG_SP

FAR_RETURN_PREMISE_ENV_8616 = "INERTIA_OPUS_FAR_RETURN_PREMISE"
FAR_RETURN_PREMISE_NAME_8616 = "far_call_normal_return"
_MAX_DEPTH_8616 = 8
_active_targets_8616: ContextVar[tuple[int, ...]] = ContextVar("_far_return_premise_active_8616", default=())
_WRITE_MNEMONICS_8616 = frozenset({
    "mov", "add", "sub", "adc", "sbb", "and", "or", "xor", "inc", "dec", "neg", "not",
    "shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr", "xchg", "pop", "stosb", "stosw",
    "movsb", "movsw", "les", "lds",
})
_DISASSEMBLER_8616 = None


def far_return_premise_enabled_8616() -> bool:
    return os.environ.get(FAR_RETURN_PREMISE_ENV_8616) == "1"


def _disassembler_8616() -> object:
    global _DISASSEMBLER_8616
    if _DISASSEMBLER_8616 is None:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        md.detail = True
        _DISASSEMBLER_8616 = md
    return _DISASSEMBLER_8616


def _decode_8616(project: object, addr: int) -> object:
    try:
        code = bytes(project.loader.memory.load(addr, 8))
    except Exception:
        return None
    for insn in _disassembler_8616().disasm(code, addr, 1):
        return insn
    return None


def _immediate_far_target_8616(insn: object) -> int | None:
    raw = bytes(insn.bytes)
    if len(raw) != 5 or raw[0] != 0x9A:
        return None
    return int.from_bytes(raw[3:5], "little") * 16 + int.from_bytes(raw[1:3], "little")


def _instruction_addrs_8616(artifact: object) -> tuple[int, ...]:
    return tuple(sorted({
        row.addr for block in artifact.blocks for row in block.instrs if type(row.addr) is int
    }))


def _memory_write_operands_8616(insn: capstone.CsInsn) -> tuple[object, ...]:
    """Collect explicit writes, including a memory XCHG operand in either slot."""
    return tuple(
        operand for index, operand in enumerate(insn.operands)
        if operand.type == X86_OP_MEM and (
            operand.access & capstone.CS_AC_WRITE
            or (index == 0 and insn.mnemonic in _WRITE_MNEMONICS_8616)
            or insn.mnemonic == "xchg"
        )
    )


def _saved_slot_overlap_8616(offset: int, size: int, slot_size: int) -> bool:
    """Detect overlap with the saved slots in modular 16-bit BP coordinates."""
    return size <= 0 or offset % 0x10000 < slot_size or -offset % 0x10000 < size


def _frame_refusal_8616(project: object, addrs: tuple[int, ...], entry: int, *, frame_bytes: int,
                        cleanup: int | None, nested: bool) -> str | None:
    """Check canonical BP usage and BP-relative stores against return slots.

    With a canonical ``push bp; mov bp, sp`` prologue the own return slot is
    ``[bp+2, bp+2+frame_bytes)``. A nested callee may also write its own
    callee-cleaned argument block; anything above that could reach an outer
    frame's return slot and refuses.
    """
    insns = []
    for addr in addrs:
        insn = _decode_8616(project, addr)
        if insn is None:
            return f"undecodable instruction at {addr:#x}"
        insns.append(insn)
    by_addr = {insn.address: insn for insn in insns}
    first = by_addr.get(entry)
    canonical = False
    if first is not None and bytes(first.bytes) == b"\x55":
        second = by_addr.get(entry + 1)
        canonical = second is not None and bytes(second.bytes) in (b"\x8b\xec", b"\x89\xe5")
    # [bp+0, bp+2) is the saved caller BP: also restored only under the premise.
    slot_hi = 2 + frame_bytes
    args_hi = slot_hi + (cleanup or 0)
    for insn in insns:
        raw = bytes(insn.bytes)
        writes_bp = any(
            op.type == X86_OP_REG and op.reg == X86_REG_BP for op in insn.operands[:1]
        ) and insn.mnemonic not in {"cmp", "test", "push"}
        if writes_bp:
            allowed = (
                (canonical and insn.address == entry + 1)
                or raw == b"\x5d"  # pop bp restores the caller's BP
            )
            if not allowed:
                return f"non-canonical bp write at {insn.address:#x}"
        if insn.mnemonic in {"movsb", "movsw", "stosb", "stosw"}:
            # ES:DI target: unresolved pointer, covered only by the premise.
            continue
        for operand in _memory_write_operands_8616(insn):
            mem = operand.mem
            if mem.base == X86_REG_SP or mem.index == X86_REG_SP:
                return f"sp-relative store at {insn.address:#x}"
            if mem.base != X86_REG_BP and mem.index != X86_REG_BP:
                continue  # unresolved DS/ES pointer: premise, not proof
            if not canonical:
                return f"bp-relative store without canonical frame at {insn.address:#x}"
            if mem.base != X86_REG_BP or mem.index != X86_REG_INVALID:
                return f"bp-relative store with unresolved index at {insn.address:#x}"
            lo = mem.disp
            hi = lo + operand.size
            if _saved_slot_overlap_8616(lo, operand.size, slot_hi):
                return f"store overlaps return slot at {insn.address:#x}"
            if nested and hi > args_hi and lo >= slot_hi:
                return f"nested store above own argument block at {insn.address:#x}"
    return None


def _callee_refusal_8616(project: object, callsite: int, target: int, far: bool, depth: int,
                         push_cs: bool = False) -> str | None:
    """Check one callee; ``push_cs`` marks ``push cs; call near`` (a RETF frame)."""
    from inertia.semantics.callee_stack_effects import prove_direct_callee_stack_effect_8616
    from inertia.semantics.callsite_summary import CallsiteMachineFrameKind8616

    active = _active_targets_8616.get()
    if target in active:
        return f"recursive callee {target:#x}"
    if depth > _MAX_DEPTH_8616:
        return "nesting depth exceeded"
    frame = CallsiteMachineFrameKind8616.FAR if far else CallsiteMachineFrameKind8616.NEAR
    length = 5 if far else 3
    result = prove_direct_callee_stack_effect_8616(project, callsite, callsite + length, target, frame)
    delta = result.return_sp_delta
    if delta is None or result.body is None:
        body_failure = None if result.body is None else result.body.failure
        return f"callee {target:#x} stack effect unproven ({result.failure}/{body_failure})"
    artifact = result.body.coverage.artifact
    retf_frame = far or push_cs
    frame_bytes = 4 if retf_frame else 2
    cleanups = set()
    for block in artifact.blocks:
        if block.successor_addrs or not block.instrs:
            continue
        last = block.instrs[-1]
        insn = _decode_8616(project, last.addr) if type(last.addr) is int else None
        raw = b"" if insn is None else bytes(insn.bytes)
        if retf_frame and raw[:1] == b"\xcb":
            cleanups.add(0)
        elif retf_frame and raw[:1] == b"\xca" and len(raw) == 3:
            cleanups.add(int.from_bytes(raw[1:3], "little"))
        elif not retf_frame and raw[:1] == b"\xc3":
            cleanups.add(0)
        elif not retf_frame and raw[:1] == b"\xc2" and len(raw) == 3:
            cleanups.add(int.from_bytes(raw[1:3], "little"))
        else:
            return f"callee {target:#x} exit {last.addr} is not a {'RETF' if retf_frame else 'RET'}"
    if len(cleanups) != 1:
        return f"callee {target:#x} exits disagree on cleanup"
    cleanup = cleanups.pop()
    # Measured from callee entry; a push-cs frame's CS word was pushed before
    # the CALL, so RETF pops one word more than the CALL pushed.
    if delta != frame_bytes + cleanup:
        return f"callee {target:#x} SP at return is not its entry SP"
    addrs = _instruction_addrs_8616(artifact)
    refusal = _frame_refusal_8616(project, addrs, target, frame_bytes=frame_bytes,
                                  cleanup=cleanup, nested=depth > 0)
    if refusal is not None:
        return refusal
    token = _active_targets_8616.set(active + (target,))
    try:
        for addr in addrs:
            insn = _decode_8616(project, addr)
            if insn is None or insn.mnemonic not in {"call", "lcall"}:
                continue
            raw = bytes(insn.bytes)
            if raw[:1] == b"\xe8" and len(raw) == 3:
                nested_target = addr + 3 + int.from_bytes(raw[1:3], "little", signed=True)
                pushed_cs = (addr - 1) in addrs and bytes(project.loader.memory.load(addr - 1, 1)) == b"\x0e"
                refusal = _callee_refusal_8616(project, addr, nested_target, False, depth + 1, pushed_cs)
            elif raw[:1] == b"\x9a":
                refusal = _callee_refusal_8616(project, addr, _immediate_far_target_8616(insn), True, depth + 1)
            else:
                refusal = f"nested indirect call at {addr:#x}"
            if refusal is not None:
                return refusal
    finally:
        _active_targets_8616.reset(token)
    return None


def saved_bp_premise_refusal_8616(project: object, callsite: int, target: int, far: bool,
                                  push_cs: bool = False) -> str | None:
    """Admit a nested callee's BP restore under the recorded normal-frame premise.

    Requires a canonical ``push bp; mov bp, sp`` frame with no BP-relative
    store reaching the saved-BP or return slot; the restore through ``pop bp``
    is then exact unless an unresolved pointer aliases the slot (premise).
    """
    if not far_return_premise_enabled_8616():
        return "premise disabled"
    entry = _decode_8616(project, target)
    if entry is None or bytes(entry.bytes) != b"\x55":
        return "callee has no canonical frame"
    refusal = _callee_refusal_8616(project, callsite, target, far, 1, push_cs)
    if refusal is None:
        _record_premise_8616(project, callsite, target, "nested_saved_bp_restore")
    return refusal


def far_call_return_premise_refusal_8616(project: object, callsite_addr: int) -> str | None:
    """Return None when the premise admits this far CALL, else the refusal."""
    if project is None or type(callsite_addr) is not int:
        return "no project or callsite"
    try:
        cache = project._inertia_far_return_premise_cache_8616
    except AttributeError:
        cache = {}
        project._inertia_far_return_premise_cache_8616 = cache
    if callsite_addr not in cache:
        cache[callsite_addr] = _far_call_return_premise_refusal_uncached_8616(project, callsite_addr)
    return cache[callsite_addr]


def _far_call_return_premise_refusal_uncached_8616(project: object, callsite_addr: int) -> str | None:
    insn = _decode_8616(project, callsite_addr)
    if insn is None:
        return "undecodable callsite"
    target = _immediate_far_target_8616(insn)
    if target is None:
        return "not an immediate far call"
    refusal = _callee_refusal_8616(project, callsite_addr, target, True, 0)
    if refusal is None:
        _record_premise_8616(project, callsite_addr, target)
    return refusal


def _record_premise_8616(project: object, callsite_addr: int, target: int,
                         name: str = FAR_RETURN_PREMISE_NAME_8616) -> None:
    try:
        ledger = project._inertia_far_return_premises_8616
    except AttributeError:
        ledger = set()
        project._inertia_far_return_premises_8616 = ledger
    key = (name, callsite_addr, target)
    if key not in ledger:
        ledger.add(key)
        print(f"[premise] {name} callsite={callsite_addr:#x} target={target:#x}",
              file=sys.stderr, flush=True)
