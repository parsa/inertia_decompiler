"""Opt-in conditional CS census (scratch experiment; never a universal proof).

``INERTIA_OPUS_CS_CENSUS`` names a document produced by
``opus-pass/cs_census.py``: per function linear range, the selectors its
entries are reached under, collected from MZ-relocated far references and
near transfers. The decompiler does not prove that premise, so any output
produced while it is set is conditional and must not be published.
"""
from __future__ import annotations

import json
import os

_CACHE: dict[str, tuple[tuple[int, int, tuple[int, ...]], ...]] = {}
_OVERLAY: dict[str, tuple[int, int, tuple[int, ...]]] = {}


def census_selectors_8616(linear: int) -> tuple[int, ...]:
    """Selectors censused for the function range containing ``linear``; () if none."""
    path = os.environ.get("INERTIA_OPUS_CS_CENSUS")
    if not path:
        return ()
    rows = _CACHE.get(path)
    if rows is None:
        with open(path) as handle:
            document = json.load(handle)
        rows = tuple(
            (row["start"], row["end"], tuple(row["selectors"])) for row in document["functions"]
        )
        _CACHE[path] = rows
        if "overlay_selectors" in document:
            lo, hi = document["overlay_range"]
            _OVERLAY[path] = (lo, hi, tuple(document["overlay_selectors"]))
    for start, end, selectors in rows:
        if start <= linear < end:
            return selectors
    lo, hi, overlay = _OVERLAY.get(path, (0, 0, ()))
    if lo <= linear < hi:
        # Overlay fallback premise: entered only under censused overlay selectors.
        return tuple(s for s in overlay if (s << 4) <= linear <= (s << 4) + 0xFFFF)
    return ()


def censused_closed_cycle_8616(project: object, entry: int) -> bool:
    """Under the selector premise, prove a closed body has no ordinary exit.

    A closed native census includes the continuation of each ordinary call.
    Refuse open edges, interrupts, indirect calls, far jumps and any return.
    This is conditional on the offered selector and ordinary nested-call
    continuations, and supplies no stack delta or unwind claim.
    """
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return False
    selectors = census_selectors_8616(entry)
    if len(selectors) != 1:
        return False
    from .frontend_function_boundary import mapped_entry_function_boundary_8616
    from .relative_control_edge import DecodedRelativeEdge, decode_relative_edge

    boundary = mapped_entry_function_boundary_8616(project, entry)
    if boundary is None:
        return False
    base = selectors[0] << 4
    edges = dict.fromkeys(boundary.block_addrs_set)
    for addr, target in boundary.successor_edges:
        if target not in edges:
            return False
        edges[addr] = True
    if not edges or not all(edges.values()):
        return False
    for block in boundary.blocks:
        for insn in block.instructions:
            if not base <= insn.address < insn.address + insn.size <= base + 0xffff:
                return False
            name = insn.mnemonic
            if name.startswith(("ret", "iret", "int")) or name in {"ljmp", "hlt", "syscall", "sysenter"}:
                return False
            if name in {"call", "lcall"} and insn.bytes[0] not in {0xe8, 0x9a}:
                return False
            if name.startswith(("j", "loop")):
                edge = decode_relative_edge(insn.address, insn.bytes)
                if not isinstance(edge, DecodedRelativeEdge):
                    return False
                target = insn.address + insn.size + edge.displacement
                if (block.addr, target) not in boundary.successor_edges:
                    return False
    return True
