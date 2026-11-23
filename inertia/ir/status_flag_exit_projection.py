"""Bind exit status-bit origins to the current function's decoded blocks."""
from types import SimpleNamespace

from .function_ir_registry import FunctionIRArtifactVerdict8616, registered_function_ir_artifact_8616
from inertia.semantics.status_flag_exit_origins import StatusFlagOriginBlock8616, status_flag_exit_origins_8616
from inertia.semantics.status_flag_contracts import STATUS_FLAGS_8616, StatusFlag8616
from inertia.semantics.status_flag_liveness import decoded_status_flag_instruction_8616


def bind_status_flag_phi_origins_8616(rows, incoming_edges, exit_states, site, *, carry_sources=None, native_carry=None):
    """Match numeric phi inputs to complete native vectors by predecessor."""
    if not rows or not exit_states:
        return ()
    incoming = {pred: states for (pred, ret), states in incoming_edges.items() if ret == site}
    if (
        len(incoming) != len(rows)
        or set(incoming) != {pred for pred, _, _ in rows}
        or frozenset().union(*incoming.values()) != exit_states
    ):
        return ()
    bits = tuple(bit for bit in StatusFlag8616 if bit & STATUS_FLAGS_8616)
    for pred, _, ip in rows:
        if not incoming[pred]:
            return ()
        for state in incoming[pred]:
            for bit in bits:
                origin = state.origin(bit)
                if origin.producer == ip:
                    continue
                candidate = (carry_sources or {}).get(pred)
                if (bit != StatusFlag8616.CARRY or not origin.defined or candidate is None
                    or candidate[0] != origin.producer or (native_carry or {}).get(candidate[0]) != candidate[1]):
                    return ()
    return tuple(sorted(rows))


def function_status_flag_exit_origins_8616(project, function, *, incoming_edges=None, native_carry=None):
    """Use only an attested, closed IR graph and complete matching decodes."""
    resolution = registered_function_ir_artifact_8616(project, function.addr)
    artifact = resolution.artifact
    if resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN:
        # Clinic can normalize the native function after the earlier artifact
        # was published. Read the current surface; never reuse the old graph.
        from .vex_import import raw_x86_16_function_bundle_8616

        artifact = raw_x86_16_function_bundle_8616(project, function).artifact
    if artifact is None or artifact.refusals:
        return None
    graph = {}
    sites = {}
    carry_constants = {}
    try:
        native = {block.addr: block for block in function.blocks}
        for block in artifact.blocks:
            if block.refusals or block.addr in graph:
                return None
            raw = native.get(block.addr)
            if raw is None:
                return None
            cursor = block.addr
            instructions = []
            source_bytes = bytes(raw.bytes)
            for wrapped in raw.capstone.insns:
                if wrapped.address != cursor or wrapped.size <= 0:
                    return None
                offset = cursor - block.addr
                if bytes(wrapped.insn.bytes) != source_bytes[offset:offset + wrapped.size]:
                    return None
                decoded = decoded_status_flag_instruction_8616(SimpleNamespace(cs=wrapped.insn))
                if decoded is None:
                    return None
                instructions.append((cursor, decoded))
                if decoded.mnemonic in {"stc", "clc"}:
                    carry_constants[cursor] = int(decoded.mnemonic == "stc")
                cursor += wrapped.size
            if not instructions or cursor != block.addr + raw.size:
                return None
            if any(instr.addr is not None and not block.addr <= instr.addr < cursor for instr in block.instrs):
                return None
            ip, terminal = instructions[-1]
            returns = terminal.mnemonic in {"ret", "retn", "retf"}
            if returns:
                sites[block.addr] = ip
            graph[block.addr] = StatusFlagOriginBlock8616(tuple(instructions), block.successor_addrs, returns)
    except (AttributeError, TypeError, ValueError):
        return None
    edges = {} if incoming_edges is not None else None
    origins = status_flag_exit_origins_8616(graph, artifact.function_addr, incoming_edges=edges)
    if origins is not None and edges is not None:
        incoming_edges.update({(pred, sites[block]): states for (pred, block), states in edges.items()})
    if origins is not None and native_carry is not None:
        native_carry.update(carry_constants)
    return None if origins is None else {sites[addr]: states for addr, states in origins.items()}
