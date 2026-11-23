# cython: language_level=3, infer_types=True
"""Discover source-bound near JMP edges without changing execution VEX.

Layer: Frontend/CFG adapter.
Responsibility: supply angr CFG discovery with the existing exact-byte,
full-width terminal-JMP proof. The shared graph requires agreement across all
feasible selectors. A private graph may apply a source-authenticated bound for
one entry block, without proving that the invocation executes.
"""
from __future__ import annotations

import operator
import typing
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

import angr
import cle
import cython
import pyvex
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.analyses.cfg.indirect_jump_resolvers.default_resolvers import (
    DEFAULT_RESOLVERS,
    default_indirect_jump_resolvers,
)
from angr.analyses.cfg.indirect_jump_resolvers.resolver import IndirectJumpResolver
from angr.knowledge_base import KnowledgeBase
from pyvex.errors import PyVEXError

from .arch_86_16 import Arch86_16
from .control_coordinates import ControlAddressDomain
from .frontend_instruction_reachability import ConditionalRelativeEdge8616
from .load_dos_mz import DOSMZ
from .mz_invocation_source import authenticate_loaded_mz_boot_8616
from .relative_control_edge import (
    DecodedRelativeEdge,
    RelativeDestinationVerdict,
    bounded_relative_destination,
    decode_relative_edge,
    invariant_relative_destination,
)

if typing.TYPE_CHECKING:
    from .frontend_near_return_continuation import NearCallFramePremise8616
    from .near_call_selector_window import NearCallSelectorWindow8616

__all__ = [
    "NativeDirectJumpResolver8616",
    "discover_near_call_context_cfg_8616",
    "prove_near_call_relative_edge_8616",
    "register_native_direct_jump_resolver_8616",
]

_MAX_NATIVE_BLOCK_BYTES_8616: cython.longlong = 4096


def _instruction_marks_8616(block: pyvex.IRSB) -> tuple[tuple[cython.longlong, cython.longlong, cython.longlong], ...]:
    """Bind discovery coordinates to the instruction stream read from the image."""
    return tuple(
        (row.addr, row.delta, row.len) for row in iter(block.statements)
        if isinstance(row, pyvex.stmt.IMark)
    )


def _straight_block_selector_max_8616(
    block: pyvex.IRSB, arch: Arch86_16,
) -> int | None:
    """Bound CS by the first byte only when the block preserves entry CS."""
    marks = _instruction_marks_8616(block)
    cursor = block.addr
    for addr, delta, size in marks:
        if delta != 0 or addr != cursor or size <= 0:
            return None
        cursor += size
    if not marks or cursor != block.addr + block.size:
        return None
    cs, width = arch.registers["cs"]
    for row in block.statements:
        if isinstance(row, pyvex.stmt.Put):
            bits = row.data.result_size(block.tyenv)
            if bits <= 0 or bits % 8 or (row.offset < cs + width and cs < row.offset + bits // 8):
                return None
        elif not isinstance(row, (pyvex.stmt.IMark, pyvex.stmt.WrTmp, pyvex.stmt.NoOp)):
            return None
    return min(0xFFFF, int(block.addr) // 16)


@dataclass(frozen=True)
class ScopedJumpSelectorBounds8616:
    """Caller-supplied selector premise for one block in a private CFG."""

    project: angr.Project
    entry: int
    block_addr: int
    block_bytes: bytes
    minimum: int
    maximum: int


class NativeDirectJumpResolver8616(IndirectJumpResolver):  # type: ignore[misc]  # dynamic angr base
    """A state-independent adapter consuming the native terminal proof owner."""

    def __init__(self, project: angr.Project, scope: ScopedJumpSelectorBounds8616 | None = None) -> None:
        """Bind this third-party CFG adapter to one loaded project."""
        super().__init__(project, timeless=True)
        self.scope = scope
        self.scoped_cfg: object | None = None

    def filter(self, cfg: object, addr: cython.longlong, func_addr: cython.longlong,
               block: object, jumpkind: object) -> cython.bint:
        """Keep other architectures, call sites and return sites untouched."""
        return (
            isinstance(self.project.arch, Arch86_16)
            and self.project.arch.control_address_domain is ControlAddressDomain.LOADER_LINEAR
            and jumpkind == "Ijk_Boring"
            and isinstance(block, pyvex.IRSB)
        )

    def _bind_scope_8616(
        self, cfg: object, addr: int, func_addr: int, block_size: int, encoding: bytes,
    ) -> ScopedJumpSelectorBounds8616 | None:
        """Bind this exact block's premise to one private analysis instance."""
        scope = self.scope
        if scope is None or scope.project is not self.project:
            return None
        # The dynamic angr resolver boundary need not provide a knowledge base.
        kb = getattr(cfg, "kb", None)
        if kb is None or kb is self.project.kb or (self.scoped_cfg is not None and self.scoped_cfg is not cfg):
            return None
        if (scope.entry, scope.block_addr, scope.block_bytes, len(scope.block_bytes)) != (
            func_addr, addr, encoding, block_size,
        ):
            return None
        self.scoped_cfg = cfg
        return scope

    def resolve(self, cfg: object, addr: cython.longlong, func_addr: cython.longlong,
                block: pyvex.IRSB, jumpkind: object,
                func_graph_complete: bool = True,
                **kwargs: object) -> tuple[cython.bint, list[cython.longlong]]:
        """Bind the supplied discovery operand to the native terminal theorem."""
        target: object
        # angr supplies this callback argument; a native instruction theorem
        # does not depend on whether discovery has completed the CFG.
        _ = func_graph_complete
        if not self.filter(cfg, addr, func_addr, block, jumpkind):
            return False, []
        if not 0 < block.size <= _MAX_NATIVE_BLOCK_BYTES_8616:
            return False, []
        native = self.project.factory.block(addr, size=block.size, opt_level=0)
        if (
            not isinstance(native.vex, pyvex.IRSB)
            or operator.ne(block.addr, native.addr)
            or operator.ne(block.jumpkind, native.vex.jumpkind)
            or operator.ne(_instruction_marks_8616(block), _instruction_marks_8616(native.vex))
        ):
            return False, []
        marks = [row for row in iter(native.vex.statements) if isinstance(row, pyvex.stmt.IMark)]
        if not marks:
            return False, []
        last = marks[-1]
        expressions = {
            row.tmp: row.data for row in iter(native.vex.statements)
            if isinstance(row, pyvex.stmt.WrTmp)
        }
        # Defer the IR import until analysis: package bootstrap installs the
        # third-party adapter before the IR package is necessarily initialized.
        from inertia.ir.vex_terminal_jump import terminal_direct_jump_evidence_8616

        native_maximum = _straight_block_selector_max_8616(native.vex, self.project.arch)
        supplied_maximum = _straight_block_selector_max_8616(block, self.project.arch)
        maximum = min(bound for bound in (native_maximum, supplied_maximum, 0xFFFF) if bound is not None)
        bounds = (0, maximum)
        scope = self._bind_scope_8616(cfg, addr, func_addr, block.size, native.bytes)
        if scope is not None:
            bounds = (scope.minimum, min(scope.maximum, maximum))
        evidence = terminal_direct_jump_evidence_8616(
            native, native.vex, instruction_addr=last.addr + last.delta,
            instruction_size=last.len, tmp_exprs=expressions,
            type_environment=native.vex.tyenv, selector_bounds=bounds,
        )
        target = evidence.proven_target
        if evidence.failure is not None or target is None:
            return False, []
        # The native theorem also discharges the selector fetch domain. A
        # separate proof over the supplied operand prevents fresh source IR
        # from authorizing an altered discovery operand or temporary producer.
        supplied = terminal_direct_jump_evidence_8616(
            native, block, instruction_addr=last.addr + last.delta,
            instruction_size=last.len,
            tmp_exprs={row.tmp: row.data for row in iter(block.statements)
                       if isinstance(row, pyvex.stmt.WrTmp)},
            type_environment=block.tyenv, selector_bounds=bounds,
        )
        if supplied.failure is not None or operator.ne(supplied.proven_target, target):
            return False, []
        if not self._is_target_valid(cfg, target):
            return False, []
        return True, [target]


@cython.ccall
def register_native_direct_jump_resolver_8616() -> None:
    """Supplement only the x86-16 default third-party resolver registry.

    The registry is angr's plugin boundary, not an owned semantic state.
    Preserve existing resolvers and avoid duplicates across bootstrap calls.
    """
    existing: object
    backend_resolvers = DEFAULT_RESOLVERS.setdefault(Arch86_16.name, {})
    existing = backend_resolvers.get(cle.Backend, ())
    if NativeDirectJumpResolver8616 not in existing:
        backend_resolvers[cle.Backend] = [NativeDirectJumpResolver8616, *existing]


def mz_boot_jump_scope_8616(
    project: angr.Project, source: bytes,
) -> ScopedJumpSelectorBounds8616 | None:
    """Bind the DOS entry selector to its first instruction in live mapped bytes.

    This premise is specific to boot. It cannot establish the selector of
    later instructions or of another invocation of the same code.
    """
    boot = authenticate_loaded_mz_boot_8616(project, source)
    if boot is None:
        return None
    entry = boot.entry_linear
    native = project.factory.block(entry, num_inst=1, opt_level=0)
    offset = entry - boot.module_base
    if (
        native.instructions != 1 or native.size <= 0
        or boot.entry_offset + native.size > 0x10000
        or native.bytes != boot.module[offset:offset + native.size]
    ):
        return None
    return ScopedJumpSelectorBounds8616(
        project, entry, entry, native.bytes, boot.entry_segment, boot.entry_segment,
    )


def discover_mz_boot_cfg_8616(
    project: angr.Project, *, regions: list[tuple[int, int]] | None = None,
) -> CFGFast | None:
    """Run invocation-specific discovery in a fresh KB when boot CS resolves a JMP."""
    main = project.loader.main_object
    if not isinstance(main, DOSMZ) or not isinstance(main.binary, str):
        return None
    try:
        source = Path(main.binary).read_bytes()
    except OSError:
        return None
    scope = mz_boot_jump_scope_8616(project, source)
    if scope is None:
        return None
    from inertia.ir.vex_terminal_jump import _UNCONDITIONAL_JUMP_FORMS_8616
    decoded = decode_relative_edge(scope.entry, scope.block_bytes)
    if (
        not isinstance(decoded, DecodedRelativeEdge)
        or decoded.form not in _UNCONDITIONAL_JUMP_FORMS_8616
        or invariant_relative_destination(decoded).verdict is not RelativeDestinationVerdict.SELECTOR_DEPENDENT
    ):
        return None
    return _discover_scoped_cfg_8616(scope, regions)


def _discover_scoped_cfg_8616(
    scope: ScopedJumpSelectorBounds8616, regions: list[tuple[int, int]] | None,
) -> CFGFast:
    """Install the scoped resolver in this analysis and KB only."""
    project = scope.project
    resolvers = [
        NativeDirectJumpResolver8616(project, scope),
        *(resolver for resolver in default_indirect_jump_resolvers(project.loader.main_object, project)
          if not isinstance(resolver, NativeDirectJumpResolver8616)),
    ]
    return project.analyses.CFGFast(
        kb=KnowledgeBase(project), start_at_entry=False, function_starts=[scope.entry],
        regions=regions, normalize=True, data_references=False,
        force_complete_scan=False, force_smart_scan=False, indirect_jump_resolvers=resolvers,
    )


@dataclass(frozen=True)
class _MappedSpan8616:
    """A live byte span covered by exactly one CLE backend."""

    owner: cle.Backend
    encoding: bytes


def _mapped_span_8616(project: angr.Project, addr: int, size: int) -> _MappedSpan8616 | None:
    """Require one owner for every byte and agreement with the flat loader."""
    end = addr + size
    owner: cle.Backend | None = None
    for candidate in project.loader.all_objects:
        start = max(addr, candidate.min_addr)
        limit = min(end, candidate.max_addr + 1)
        covered = sum(candidate.contains_addr(address) for address in range(start, limit))
        if not covered:
            continue
        if owner is not None or covered != size:
            return None
        owner = candidate
    if owner is None or not owner.has_memory:
        return None
    try:
        encoding = bytes(owner.memory.load(addr - owner.mapped_base, size))
        flat = project.loader.memory.load(addr, size)
    except KeyError:
        return None
    if len(encoding) != size or encoding != flat:
        return None
    return _MappedSpan8616(owner, encoding)


def _isolated_entry_project_8616(
    project: angr.Project, owner: cle.Backend, entry: int,
) -> angr.Project:
    """Copy the live entry object's mapped bytes into a detached analysis project."""
    data = bytearray()
    segments = []
    for rva, backer in owner.memory.backers():
        segments.append((len(data), owner.mapped_base + rva, len(backer)))
        data.extend(backer)
    return angr.Project(
        BytesIO(data),
        auto_load_libs=False,
        use_sim_procedures=False,
        translation_cache=False,
        main_opts={
            "backend": "blob",
            "arch": project.arch.copy(),
            "base_addr": owner.mapped_base,
            "entry_point": entry,
            "segments": segments,
        },
    )


def _isolated_entry_block_8616(
    project: angr.Project, entry: int,
) -> tuple[angr.Project, angr.block.Block, _MappedSpan8616] | None:
    """Lift one isolated entry and bind its complete extent on the source."""
    head = _mapped_span_8616(project, entry, 1)
    if head is None:
        return None
    isolated = _isolated_entry_project_8616(project, head.owner, entry)
    native = isolated.factory.block(entry, opt_level=0)
    if not 0 < native.size <= _MAX_NATIVE_BLOCK_BYTES_8616:
        return None
    mapped = _mapped_span_8616(project, entry, native.size)
    if mapped is None or mapped.owner is not head.owner or mapped.encoding != native.bytes:
        return None
    if any(project.is_hooked(addr) for addr in native.instruction_addrs):
        return None
    return isolated, native, mapped


def _reauthenticate_near_call_window_8616(
    project: angr.Project, premise: NearCallFramePremise8616,
) -> tuple[NearCallSelectorWindow8616, _MappedSpan8616] | None:
    """Reprove the interval against a retained project index and live CALL."""
    from .frontend_direct_callsite_index import registered_decoded_callsite_index_8616
    from .near_call_selector_window import (
        NearCallSelectorWindow8616,
        project_near_call_selector_window_8616,
    )

    if project.selfmodifying_code or project.kb.patches.items():
        return None
    window = project_near_call_selector_window_8616(premise)
    if not isinstance(window, NearCallSelectorWindow8616) or window.target_addr != window.callee_addr:
        return None
    record = registered_decoded_callsite_index_8616(project, premise.caller_start)
    if record is None or record.boundary.project is not project or record.index is not premise.callsite_index:
        return None
    row = premise.callsite
    instructions = typing.cast(tuple[angr.block.CapstoneInsn, ...], row.instructions)
    encoding = bytes(instructions[row.instruction_index].bytes)
    mapped = _mapped_span_8616(project, premise.callsite_addr, len(encoding))
    if mapped is None or mapped.encoding != encoding or project.is_hooked(premise.callsite_addr):
        return None
    return window, mapped


def _cfg_matches_live_source_8616(
    project: angr.Project, cfg: CFGFast, owner: cle.Backend, entry: int, target: int,
) -> bool:
    """Require a decoded target and authenticate every decoded graph span."""
    entry_node = cfg.model.get_any_node(entry)
    if entry_node is None or not any(
        successor.addr == target and successor.size and not successor.is_simprocedure
        for successor in cfg.graph.successors(entry_node)
    ):
        return False
    for node in cfg.graph.nodes:
        if node.is_simprocedure or not node.size:
            continue  # Synthetic nodes have no decoded source span.
        span = _mapped_span_8616(project, node.addr, node.size)
        if span is None or span.owner is not owner or span.encoding != node.byte_string:
            return False
        if any(project.is_hooked(addr) for addr in node.instruction_addrs):
            return False
    return True


def _entry_relative_edge_8616(
    project: angr.Project, premise: NearCallFramePremise8616, window: NearCallSelectorWindow8616,
    vex: pyvex.IRSB, mapped: _MappedSpan8616,
) -> tuple[ConditionalRelativeEdge8616, int] | None:
    """Prove the single entry JMP candidate and return its joint selector ceiling."""
    from inertia.ir.vex_terminal_jump import _UNCONDITIONAL_JUMP_FORMS_8616

    arch = project.arch
    if (not isinstance(arch, Arch86_16) or arch.control_address_domain is not ControlAddressDomain.LOADER_LINEAR
            or vex.jumpkind != "Ijk_Boring"):
        return None
    maximum = _straight_block_selector_max_8616(vex, arch)
    if maximum is None:
        return None
    entry = window.callee_addr
    head, _, size = _instruction_marks_8616(vex)[-1]
    if vex.addr != entry or any(project.is_hooked(addr) for addr, _, _ in _instruction_marks_8616(vex)):
        return None
    decoded = decode_relative_edge(head, mapped.encoding[head - entry:head - entry + size])
    if (
        not isinstance(decoded, DecodedRelativeEdge)
        or decoded.form not in _UNCONDITIONAL_JUMP_FORMS_8616
        or bounded_relative_destination(decoded, 0, maximum).verdict
        is not RelativeDestinationVerdict.SELECTOR_DEPENDENT
    ):
        return None
    maximum = min(maximum, window.selector_high)
    target = bounded_relative_destination(decoded, window.selector_low, maximum).target
    if target is None:
        return None
    target_span = _mapped_span_8616(project, target, 1)
    if target_span is None or target_span.owner is not mapped.owner or project.is_hooked(target):
        return None
    return ConditionalRelativeEdge8616(project, entry, head, target, decoded, mapped.encoding, premise), maximum


def prove_near_call_relative_edge_8616(
    project: angr.Project, premise: NearCallFramePremise8616,
) -> ConditionalRelativeEdge8616 | None:
    """Lift only the source entry bytes to prove a request-local census edge."""
    from . import lift_86_16  # noqa: F401  # Register the canonical lifter on a cold project.

    arch = project.arch
    if not isinstance(arch, Arch86_16) or arch.control_address_domain is not ControlAddressDomain.LOADER_LINEAR:
        return None
    call = _reauthenticate_near_call_window_8616(project, premise)
    if call is None:
        return None
    window, _ = call
    entry = window.callee_addr
    head = _mapped_span_8616(project, entry, 1)
    if head is None:
        return None
    limit = min(_MAX_NATIVE_BLOCK_BYTES_8616, head.owner.max_addr + 1 - entry)
    try:
        encoding = bytes(head.owner.memory.load(entry - head.owner.mapped_base, limit))
        vex = pyvex.lift(encoding, entry, arch, max_bytes=len(encoding), opt_level=0)
    except (KeyError, PyVEXError):
        return None
    if not 0 < vex.size <= len(encoding):
        return None
    span = _mapped_span_8616(project, entry, vex.size)
    if span is None or span.owner is not head.owner or span.encoding != encoding[:vex.size]:
        return None
    proved = _entry_relative_edge_8616(project, premise, window, vex, span)
    if proved is None or _reauthenticate_near_call_window_8616(project, premise) != call:
        return None
    return proved[0]


def discover_near_call_context_cfg_8616(
    project: angr.Project,
    premise: NearCallFramePremise8616,
    *,
    regions: list[tuple[int, int]] | None = None,
) -> CFGFast | None:
    """Discover a private CFG conditional on this exact near CALL executing.

    The premise must match the project's retained caller index and live CALL
    bytes. Only a selector-dependent terminal JMP in the callee's entry block
    gains the projected CS bound. Discovery runs on a detached byte snapshot
    of the entry's mapped object, never through the source project's factory.
    Every decoded graph span must still match that live mapping. Neither
    execution reachability nor a reusable source boundary is implied.
    """
    arch = project.arch
    if not isinstance(arch, Arch86_16) or arch.control_address_domain is not ControlAddressDomain.LOADER_LINEAR:
        return None
    call = _reauthenticate_near_call_window_8616(project, premise)
    if call is None:
        return None
    window, _ = call
    entry = window.callee_addr
    lift = _isolated_entry_block_8616(project, entry)
    if lift is None:
        return None
    isolated, native, mapped = lift
    vex = native.vex
    if not isinstance(vex, pyvex.IRSB):
        return None
    proved = _entry_relative_edge_8616(project, premise, window, vex, mapped)
    if proved is None:
        return None
    edge, maximum = proved
    scope = ScopedJumpSelectorBounds8616(isolated, entry, entry, mapped.encoding, window.selector_low, maximum)
    cfg = _discover_scoped_cfg_8616(scope, regions)
    if not _cfg_matches_live_source_8616(project, cfg, mapped.owner, entry, edge.target_addr):
        return None
    if (
        _reauthenticate_near_call_window_8616(project, premise) != call
        or _mapped_span_8616(project, entry, len(mapped.encoding)) != mapped
        or any(project.is_hooked(addr) for addr in native.instruction_addrs)
    ):
        return None
    return cfg
