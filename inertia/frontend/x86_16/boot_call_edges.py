"""Expose proved far CALL and RETF edges for one DOS boot invocation.

Layer: Frontend.
Responsibility: project the semantic proof into instruction-address edges.
Relative edges at callee entry stay private to the same invocation.
"""

from __future__ import annotations

import angr
import networkx as nx

from inertia.semantics.callee_stack_effects import FarCallEntry8616, prove_mz_boot_far_call_effect_8616
from .mz_invocation_source import authenticate_loaded_mz_boot_8616
from .relative_control_edge import (
    DecodedRelativeEdge, RelativeEdgeForm, bounded_relative_destination, decode_relative_edge,
)
from .frontend_function_boundary import ExactFunctionRangeBoundary8616


def _add_callee_entry_branch(
    project: angr.Project, source: bytes, graph: nx.MultiDiGraph, entry: FarCallEntry8616,
) -> None:
    """Project a relative transfer before any callee instruction mutates CS."""
    boot = authenticate_loaded_mz_boot_8616(project, source)
    if boot is None:
        return
    frame = entry.saved_frame
    base = entry.callee_cs << 4
    head = base + entry.callee_ip
    if not boot.module_base <= head < boot.module_base + len(boot.module):
        return
    block = project.factory.block(head, num_inst=1, opt_level=0)
    offset = head - boot.module_base
    encoding = boot.module[offset:offset + block.size]
    if len(encoding) != block.size or encoding != bytes(block.bytes):
        return
    edge = decode_relative_edge(head, encoding)
    if not isinstance(edge, DecodedRelativeEdge) or edge.form in {
        RelativeEdgeForm.CALL_REL16, RelativeEdgeForm.CALL_REL32,
    }:
        return
    call_writes = {
        ((frame.stack_segment << 4) + ((frame.ip_slot + lane) & 0xFFFF)) & 0xFFFFF
        for lane in range(4)
    }
    if any((head + lane) & 0xFFFFF in call_writes for lane in range(len(encoding))):
        return
    taken = bounded_relative_destination(edge, entry.callee_cs, entry.callee_cs).target
    if taken is None:
        return
    graph.add_edge(head, taken, key="taken", jumpkind="Ijk_Boring", selector=entry.callee_cs)
    if edge.form not in {RelativeEdgeForm.JMP_REL8, RelativeEdgeForm.JMP_REL16, RelativeEdgeForm.JMP_REL32}:
        fallthrough = base + ((entry.callee_ip + block.size) & 0xFFFF)
        graph.add_edge(head, fallthrough, key="fallthrough", jumpkind="Ijk_Boring", selector=entry.callee_cs)


def discover_mz_boot_call_edges_8616(
    project: angr.Project, source: bytes, *,
    callee_boundary: ExactFunctionRangeBoundary8616 | None = None,
    assume_dos_int21: bool = False,
) -> nx.MultiDiGraph | None:
    """Return a private graph of authenticated entry and continuation edges.

    Nodes are loader-linear instruction addresses. The call edge carries
    the callee selector and frame, and each return edge carries its caller
    coordinates and cleanup. Unresolved returns contribute no edge.
    """
    effect = prove_mz_boot_far_call_effect_8616(project, source)
    if effect is None:
        return None
    entry = effect.entry
    frame = entry.saved_frame
    graph = nx.MultiDiGraph()
    graph.add_edge(
        frame.callsite_addr, (entry.callee_cs << 4) + entry.callee_ip,
        key="Ijk_Call", jumpkind="Ijk_Call", effect=entry,
    )
    _add_callee_entry_branch(project, source, graph, entry)
    continuation = effect.continuation
    if (
        callee_boundary is not None
        and callee_boundary.addr == (entry.callee_cs << 4) + entry.callee_ip
        and assume_dos_int21 is True
    ):
        from inertia.ir.dos_exit_evidence import consume_mz_boot_dos_exits_8616

        exits = consume_mz_boot_dos_exits_8616(
            project, source, callee_boundary, assume_dos_int21=True,
        )
        for exit_site in exits or ():
            # This annotates the terminal instruction conditional on reaching
            # its setup block; it does not add arbitrary callee body edges.
            graph.add_node(exit_site.instruction_addr, dos_exit=exit_site)
        if continuation is None and exits:
            from inertia.semantics.callee_stack_effects import prove_mz_boot_dos_scoped_return_8616

            continuation = prove_mz_boot_dos_scoped_return_8616(
                project, source, callee_boundary, assume_dos_int21=True,
            )
    if continuation is not None:
        target = (continuation.cs << 4) + continuation.ip
        for instruction in continuation.return_instructions:
            graph.add_edge(instruction, target, key="Ijk_Ret", jumpkind="Ijk_Ret", effect=continuation)
    return nx.freeze(graph)
