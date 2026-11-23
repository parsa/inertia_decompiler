"""Prove an exact exit against Inertia’s DOS model.

Layer: IR.
Responsibility: bind a decoded terminal interrupt to the modeled DOS exit.
"""

from dataclasses import dataclass
from typing import Any

import claripy

from angr.engines.successors import SimSuccessors

from inertia.frontend.x86_16.frontend_instruction_reachability import (
    ConditionalDosExit8616,
    _matches_conditional_dos_exit_8616,
)
from inertia.frontend.x86_16.load_dos_mz import DOSMZ
from inertia.frontend.x86_16.mz_invocation_source import authenticate_loaded_mz_boot_8616
from inertia.frontend.x86_16.simos_86_16 import DOSInt21, get_interrupt_handler_class


@dataclass(frozen=True)
class ModeledDosExit8616:
    """Process termination; status is unknown for an AH-only setup."""
    block_addr: int
    instruction_addr: int
    status: int | None
    platform: str = "inertia_dos_int21"


def prove_modeled_dos_exit_8616(project: Any, boundary: Any, edge: ConditionalDosExit8616) -> ModeledDosExit8616 | None:
    """Replay the shipped model for a current, source-bound DOS exit row.

    This record is usable only when the consuming invocation explicitly
    authorizes the DOS model. In particular, it does not prove that the
    program left the guest's interrupt-vector table unchanged.
    """
    if (
        boundary.project is not project or edge not in boundary.conditional_edges
        or not isinstance(project.loader.main_object, DOSMZ)
        or get_interrupt_handler_class(0x21) is not DOSInt21
    ):
        return None
    blocks = [block for block in boundary.blocks if block.addr == edge.block_addr]
    if len(blocks) != 1 or not _matches_conditional_dos_exit_8616(blocks[0], blocks[0].instructions, edge):
        return None
    block = blocks[0]
    cursor = block.addr
    raw = bytearray()
    for instruction in block.instructions:
        encoded = bytes(instruction.bytes)
        if instruction.address != cursor or not encoded or len(encoded) != instruction.size:
            return None
        raw.extend(encoded)
        cursor += instruction.size
    if cursor != block.addr + block.size:
        return None
    try:
        if bytes(project.loader.memory.load(block.addr, len(raw))) != bytes(raw):
            return None
    except KeyError:
        return None
    encoding = bytes(block.instructions[-2].bytes)
    status = encoding[1] if encoding[0] == 0xB8 else None
    low = claripy.BVV(status, 8) if status is not None else claripy.BVS("dos_exit_status", 8)
    state = project.factory.blank_state()
    state.regs.ax = claripy.Concat(claripy.BVV(0x4C, 8), low)
    state.regs.flags = 0x0202
    successors = SimSuccessors(edge.instruction_addr, state)
    DOSInt21(project=project).execute(
        state, successors=successors, arguments=[], ret_to=edge.instruction_addr + 2,
    )
    if len(successors.flat_successors) != 1 or successors.unconstrained_successors:
        return None
    stop = successors.flat_successors[0]
    if stop.history.jumpkind != "Ijk_Exit":
        return None
    events = [event for event in stop.history.events if event.type == "terminate"]
    if len(events) != 1 or not stop.solver.is_true(events[0].objects["exit_code"] == claripy.ZeroExt(8, low)):
        return None
    return ModeledDosExit8616(edge.block_addr, edge.instruction_addr, status)


def consume_mz_boot_dos_exits_8616(
    project: Any, source: bytes, boundary: Any, *, assume_dos_int21: bool = False,
) -> tuple[ModeledDosExit8616, ...] | None:
    """Discharge DOS exits privately under an explicit interrupt-model premise.

    The result identifies terminal sites if reached through their proved
    setup blocks. It neither changes raw IR nor proves a particular path
    reaches one of the sites.
    """
    if assume_dos_int21 is not True or boundary.project is not project:
        return None
    boot = authenticate_loaded_mz_boot_8616(project, source)
    if boot is None:
        return None
    selector = boot.entry_segment
    entry_writes: set[int] = set()
    if boundary.addr != boot.entry_linear:
        from inertia.semantics.callee_stack_effects import prove_mz_boot_far_call_entry_8616

        call = prove_mz_boot_far_call_entry_8616(project, source)
        if call is None or boundary.addr != (call.callee_cs << 4) + call.callee_ip:
            return None
        selector = call.callee_cs
        frame = call.saved_frame
        entry_writes = {
            ((frame.stack_segment << 4) + ((frame.ip_slot + lane) & 0xFFFF)) & 0xFFFFF
            for lane in range(4)
        }
    # Byte and selector authority must cover the entire setup block, since
    # the interrupt's AH premise comes from the preceding instruction.
    base = selector << 4
    results: list[ModeledDosExit8616] = []
    for edge in boundary.conditional_edges:
        if not isinstance(edge, ConditionalDosExit8616):
            continue
        result = prove_modeled_dos_exit_8616(project, boundary, edge)
        if result is None:
            return None
        block = next(block for block in boundary.blocks if block.addr == edge.block_addr)
        offset = block.addr - boot.module_base
        end = edge.instruction_addr + 2
        if not (base <= block.addr < end <= base + 0x10000 and 0 <= offset <= len(boot.module) - block.size):
            return None
        if boot.module[offset:offset + block.size] != b"".join(bytes(ins.bytes) for ins in block.instructions):
            return None
        if any((address & 0xFFFFF) in entry_writes for address in range(block.addr, end)):
            return None
        results.append(result)
    return tuple(results)
