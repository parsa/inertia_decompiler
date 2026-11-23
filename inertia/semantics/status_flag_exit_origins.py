"""Propagate correlated status-bit origins through a closed instruction CFG."""
from collections import deque
from dataclasses import dataclass

from .status_flag_contracts import STATUS_FLAGS_8616, DecodedStatusFlagInstruction8616, StatusFlag8616
from .status_flag_liveness import (
    _COUNTED_ROTATE_MNEMONICS_8616,
    _COUNTED_SHIFT_MNEMONICS_8616,
    _LOGICAL_WRITER_MNEMONICS_8616,
    _REPEAT_COMPARE_MNEMONICS_8616,
    status_flag_effect_8616,
)

_BITS = tuple(bit for bit in StatusFlag8616 if bit & STATUS_FLAGS_8616)


@dataclass(frozen=True)
class StatusFlagOrigin8616:
    """Producer instruction, or entry when producer is None."""

    producer: int | None
    defined: bool


@dataclass(frozen=True)
class StatusFlagExitState8616:
    """One correlated set of flag values that can reach an exit."""

    origins: tuple[StatusFlagOrigin8616, ...]

    @property
    def defined_mask(self) -> StatusFlag8616:
        return StatusFlag8616(sum(int(bit) for bit, origin in zip(_BITS, self.origins, strict=True) if origin.defined))

    def origin(self, bit: StatusFlag8616) -> StatusFlagOrigin8616:
        return self.origins[_BITS.index(bit)]


@dataclass(frozen=True)
class StatusFlagOriginBlock8616:
    instructions: tuple[tuple[int, DecodedStatusFlagInstruction8616], ...]
    successors: tuple[int, ...]
    returns: bool = False


def _write_alternatives(instruction):
    """Return alternative (defined, undefined) masks; None means unknown."""
    mnemonic = instruction.mnemonic
    if mnemonic in {"div", "idiv"}:
        return ((StatusFlag8616.NONE, STATUS_FLAGS_8616),)
    if mnemonic in {"mul", "imul"}:
        defined = StatusFlag8616.CARRY | StatusFlag8616.OVERFLOW
        return ((defined, STATUS_FLAGS_8616 & ~defined),)
    if mnemonic in _COUNTED_SHIFT_MNEMONICS_8616 | _COUNTED_ROTATE_MNEMONICS_8616:
        # Width and effective count matter; liveness overwrites cannot
        # establish defined output for large or variable counts.
        return ((StatusFlag8616.NONE, StatusFlag8616.NONE),) if instruction.immediate_count == 0 else None
    if mnemonic in _LOGICAL_WRITER_MNEMONICS_8616:
        return ((STATUS_FLAGS_8616 & ~StatusFlag8616.AUXILIARY, StatusFlag8616.AUXILIARY),)
    if instruction.repeat_prefix and mnemonic in _REPEAT_COMPARE_MNEMONICS_8616:
        return ((StatusFlag8616.NONE, StatusFlag8616.NONE), (STATUS_FLAGS_8616, StatusFlag8616.NONE))
    effect = status_flag_effect_8616(instruction)
    return None if effect is None else ((effect.overwrites, StatusFlag8616.NONE),)


def status_flag_exit_origins_8616(blocks, entry, *, max_states=4096, incoming_edges=None):
    """Return the alternatives at each return, or refuse an open proof.

    Each work item retains a whole vector, so a join never invents combinations
    of producers from mutually exclusive paths. A loop revisits a vector only
    when one of its bit origins changes. When requested, also publish the
    vectors on edges entering a return block, before its own instructions.
    The output mapping is updated only after the entire proof succeeds.
    """
    if entry not in blocks or max_states < 1:
        return None
    initial = StatusFlagExitState8616(tuple(StatusFlagOrigin8616(None, True) for _ in _BITS))
    pending = deque([(entry, initial)])
    seen = {(entry, initial)}
    exits = {}
    edges = {} if incoming_edges is not None else None
    edge_size = 0
    while pending:
        address, incoming = pending.popleft()
        block = blocks.get(address)
        if block is None or block.returns == bool(block.successors):
            return None
        states = {incoming}
        for ip, instruction in block.instructions:
            alternatives = _write_alternatives(instruction)
            if alternatives is None:
                return None
            states = {
                StatusFlagExitState8616(tuple(
                    StatusFlagOrigin8616(ip, bool(bit & defined))
                    if bit & (defined | undefined) else origin
                    for bit, origin in zip(_BITS, state.origins, strict=True)
                ))
                for state in states
                for defined, undefined in alternatives
            }
            if len(states) > max_states:
                return None
        if block.returns:
            exits.setdefault(address, set()).update(states)
            if len(exits[address]) > max_states:
                return None
        for successor in block.successors:
            if edges is not None and successor in blocks and blocks[successor].returns:
                values = edges.setdefault((address, successor), set())
                edge_size += len(states - values)
                if edge_size > max_states:
                    return None
                values.update(states)
            for state in states:
                item = successor, state
                if item not in seen:
                    if len(seen) >= max_states:
                        return None
                    seen.add(item)
                    pending.append(item)
    if edges is not None:
        incoming_edges.update({edge: frozenset(states) for edge, states in edges.items()})
    return {address: frozenset(states) for address, states in exits.items()}
