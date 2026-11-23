"""Prove the coordinates of a framed word CALL and matching BP epilogue."""
from dataclasses import dataclass

from .call_stack_positions import prove_call_stack_position_8616
from .numeric_stack_pointer_values import prove_terminal_stack_pointer_input_8616
from .segment_stack_restore import _predecessor_map, _solve_stack_states, _transfer_block
from .stack_restore_state import join_stack_restore_states_8616


@dataclass(frozen=True)
class WordBPFrame8616:
    push: int
    set_bp: int
    restore_sp: int
    pop: int
    ret: int
    saved_word_offset: int


def prove_word_bp_frame_8616(project, artifact):
    """Recognize a BP frame around a single proved call and terminal RET.

    This proves coordinates, not that the saved word remained unchanged.
    A consumer must load the actual word from SS at POP.
    """
    blocks = {block.addr: block for block in artifact.blocks}
    entry = blocks.get(artifact.function_addr)
    if entry is None or artifact.refusals or len(blocks) != len(artifact.blocks):
        return None
    if any(block.refusals or any(target not in blocks for target in block.successor_addrs)
           for block in blocks.values()):
        return None
    if any(entry.addr in block.successor_addrs for block in blocks.values()):
        return None
    calls = [(block, i, insn) for block in blocks.values()
             for i, insn in enumerate(block.instrs) if insn.op == "CALL"]
    exits = [block for block in blocks.values() if not block.successor_addrs]
    if len(calls) != 1 or len(exits) != 1:
        return None
    call_block, call_index, call = calls[0]
    epilogue = exits[0]
    if not epilogue.instrs or epilogue.instrs[-1].op != "RET":
        return None
    ret = epilogue.instrs[-1].addr
    if not isinstance(ret, int) or ret != epilogue.addr + 3:
        return None
    if tuple(entry.successor_addrs) != (call_block.addr,) or call.addr != entry.addr + 3:
        return None
    if {i.addr for i in entry.instrs} != {entry.addr, entry.addr + 1}:
        return None
    if {i.addr for i in epilogue.instrs} != {epilogue.addr, epilogue.addr + 2, ret}:
        return None
    memory = project.loader.memory
    try:
        prefix = bytes(memory.load(entry.addr, 3))
        suffix = bytes(memory.load(epilogue.addr, 4))
    except (KeyError, ValueError):
        return None
    if prefix not in (b"\x55\x8b\xec", b"\x55\x89\xe5"):
        return None
    if suffix not in (b"\x8b\xe5\x5d\xcb", b"\x89\xec\x5d\xcb"):
        return None
    position = prove_call_stack_position_8616(artifact, call_block.addr, call_index).proof
    terminal = prove_terminal_stack_pointer_input_8616(artifact, epilogue.addr, ret)
    if (position is None or position.caller_before_offset != -2
        or position.caller_after_offset != -2
        or terminal is None or terminal.entry_sp_offset != 0):
        return None
    # SP is represented by the call and terminal boundaries. Between them
    # this first consumer supports only the register test and its back edge.
    test = blocks.get(position.return_addr)
    if (len(blocks) != 4 or test is None or epilogue.addr != test.addr + 4
        or tuple(call_block.successor_addrs) != (test.addr,)
        or set(test.successor_addrs) != {call_block.addr, epilogue.addr}):
        return None
    branch_delta = call_block.addr - epilogue.addr
    if not -128 <= branch_delta <= 127:
        return None
    try:
        test_bytes = bytes(memory.load(test.addr, 4))
    except (KeyError, ValueError):
        return None
    if test_bytes[:2] not in (b"\x0b\xc0", b"\x09\xc0") or test_bytes[2:] != bytes((0x74, branch_delta & 0xff)):
        return None
    states = _solve_stack_states(artifact)
    incoming = tuple(states[pred] for pred in _predecessor_map(artifact)[call_block.addr])
    if not incoming:
        return None
    first_call_operation = next(i for i, item in enumerate(call_block.instrs) if item.addr == call.addr)
    _, before_call = _transfer_block(
        call_block.addr, call_block.instrs[:first_call_operation],
        join_stack_restore_states_8616(incoming),
    )
    if before_call.bp_delta != -2:
        return None
    return WordBPFrame8616(entry.addr, entry.addr + 1, epilogue.addr, epilogue.addr + 2, ret, -2)
