# cython: language_level=3, infer_types=True
"""Discover source-bound near JMP edges without changing execution VEX.

Layer: Frontend/CFG adapter.
Responsibility: supply angr CFG discovery with the existing exact-byte,
full-width terminal-JMP proof. A target is accepted only across every selector
capable of fetching its verified byte stream; selector-dependent wrap stays unresolved.
This discovers edges, not whole-function equivalence or register preservation.
"""
from __future__ import annotations
import typing
import cython

import angr
import cle
import pyvex
from pathlib import Path
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.knowledge_base import KnowledgeBase
from angr.analyses.cfg.indirect_jump_resolvers.default_resolvers import (
    DEFAULT_RESOLVERS, default_indirect_jump_resolvers,
)
from angr.analyses.cfg.indirect_jump_resolvers.resolver import IndirectJumpResolver

from .arch_86_16 import Arch86_16
from .control_coordinates import ControlAddressDomain
from .load_dos_mz import DOSMZ
from .mz_invocation_source import authenticate_loaded_mz_boot_8616
from .relative_control_edge import (
    DecodedRelativeEdge, RelativeDestinationVerdict, decode_relative_edge, invariant_relative_destination,
)
import operator
from dataclasses import dataclass

__all__ = ["NativeDirectJumpResolver8616", "register_native_direct_jump_resolver_8616"]

_MAX_NATIVE_BLOCK_BYTES_8616: cython.longlong = 4096


def _instruction_marks_8616(block: pyvex.IRSB) -> tuple[tuple[cython.longlong, cython.longlong, cython.longlong], ...]:
    """Bind discovery coordinates to the instruction stream read from the image."""
    return tuple(
        (row.addr, row.delta, row.len) for row in iter(block.statements)
        if isinstance(row, pyvex.stmt.IMark)
    )


def _straight_block_selector_max_8616(
    block: pyvex.IRSB, arch: Arch86_16,
) -> int:
    """Bound CS by the first byte of a verified straight-line native block."""
    marks = _instruction_marks_8616(block)
    cursor = block.addr
    for addr, delta, size in marks:
        if delta != 0 or addr != cursor or size <= 0:
            return 0xFFFF
        cursor += size
    if not marks or cursor != block.addr + block.size:
        return 0xFFFF
    cs, width = arch.registers["cs"]
    for row in block.statements:
        if isinstance(row, pyvex.stmt.Put):
            bits = row.data.result_size(block.tyenv)
            if bits <= 0 or bits % 8 or (row.offset < cs + width and cs < row.offset + bits // 8):
                return 0xFFFF
        elif not isinstance(row, (pyvex.stmt.IMark, pyvex.stmt.WrTmp, pyvex.stmt.NoOp)):
            return 0xFFFF
    return  min(0xFFFF, block.addr // 16)


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

    def resolve(self, cfg: object, addr: cython.longlong, func_addr: cython.longlong,
                block: pyvex.IRSB, jumpkind: object,
                func_graph_complete = True,
                **kwargs: object) -> tuple[cython.bint, list[cython.longlong]]:
        """Bind the supplied discovery operand to the native terminal theorem."""
        target: object
        # angr supplies this callback argument; a native instruction theorem
        # does not depend on whether discovery has completed the CFG.
        del func_graph_complete
        if not self.filter(cfg, addr, func_addr, block, jumpkind):
            return False, []
        if not 0 < block.size <= _MAX_NATIVE_BLOCK_BYTES_8616:
            return False, []
        native = self.project.factory.block(addr, size=block.size, opt_level=0)
        if not isinstance(native.vex, pyvex.IRSB):
            return False, []
        if operator.ne(block.addr, native.addr) or operator.ne(block.jumpkind, native.vex.jumpkind):
            return False, []
        if operator.ne(_instruction_marks_8616(block), _instruction_marks_8616(native.vex)):
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

        maximum =  min(
            _straight_block_selector_max_8616(native.vex, self.project.arch),
            _straight_block_selector_max_8616(block, self.project.arch),
        )
        bounds = (0, maximum)
        scope = self.scope
        if (
            scope is not None and scope.project is self.project
            and getattr(cfg, "kb", None) is not None
            and cfg.kb is not self.project.kb
            and scope.entry == func_addr and scope.block_addr == addr
            and scope.block_bytes == native.bytes
            and len(scope.block_bytes) == block.size
            and (self.scoped_cfg is None or self.scoped_cfg is cfg)
        ):
            self.scoped_cfg = cfg
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
    scoped = NativeDirectJumpResolver8616(project, scope)
    resolvers = [
        scoped,
        *(resolver for resolver in default_indirect_jump_resolvers(main, project)
          if not isinstance(resolver, NativeDirectJumpResolver8616)),
    ]
    return project.analyses.CFGFast(
        kb=KnowledgeBase(project), start_at_entry=False, function_starts=[scope.entry],
        regions=regions, normalize=True, data_references=False,
        force_complete_scan=False, force_smart_scan=False, indirect_jump_resolvers=resolvers,
    )
