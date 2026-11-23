# cython: language_level=3, infer_types=True
"""Bind a real word CALL to its callee's retained returning SP proof.

Layer: Semantics.
Responsibility: authenticate the physical transfer and consume Alias-owned
callee SP dataflow over registered, fully covered raw IR. No convention,
prototype, source listing, or return-immediate shortcut supplies the effect.
Owns instruction effects, flags, branch meaning, and expression interpretation
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import operator
import os
from bisect import bisect_left
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import pairwise
from pathlib import Path

import angr
import cython
import pyvex
from capstone import CS_GRP_JUMP

from inertia.alias.callee_stack_pointer import (
    CalleeStackPointerResult8616,
    prove_callee_stack_pointer_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
)
from inertia.frontend.x86_16.mz_invocation_source import MzInvocationSource8616
from inertia.frontend.x86_16.relative_control_edge import (
    DecodedRelativeEdge,
    RelativeEdgeForm,
    bounded_relative_destination,
    decode_relative_edge,
)
from inertia.frontend.x86_16.synthetic_call_stub_evidence import is_synthetic_call_stub_8616
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from inertia.ir.vex_import import build_x86_16_ir_function_artifact

from .bp_call_preservation import _exact_boundary_8616
from .callsite_summary import CallsiteMachineFrameKind8616
from .direct_ret_call_effect import direct_call_target_is_bound_8616
from .terminal_return_contract import WordFarReturnLayout8616


class CalleeStackCallFailure8616(StrEnum):
    """Typed reason a call cannot consume a complete callee SP proof."""

    CALL_TARGET_UNPROVEN = "call_target_unproven"
    SYNTHETIC_BODY = "synthetic_body"
    BOUNDARY_MISSING = "boundary_missing"
    IR_UNAVAILABLE = "ir_unavailable"
    BODY_REFUSED = "body_refused"


_PRINCE_TRACE_SHA256 = "22c4f1a9127646b6d389266a40f22defc7e8bd807c989aca55dfab30c7660eee"
_PRINCE_OVERLAY_IMAGE_SHA256 = "dc0ae563d73067426782c7d8acfa3a7afe347a2426d4b6f5716ff11eee3e1560"
_PRINCE_MODELED_RECEIPT_SHA256 = "7dad0807d56d28d36f1e73395782aa6db4b984281dbf0f7c9eded913fd5b3103"


def _prince_modeled_return_layout_8616(path: str) -> tuple[int, int] | None:
    """Reconsume the exact scoped replay receipt, not arbitrary JSON facts."""
    try:
        payload = Path(path).read_bytes()
        if hashlib.sha256(payload).hexdigest() != _PRINCE_MODELED_RECEIPT_SHA256:
            return None
        receipt = json.loads(payload)
    except (OSError, ValueError):
        return None
    if (
        not isinstance(receipt, dict)
        or receipt.get("evidence") != "modeled_dos_replay"
        or receipt.get("image_sha256") != _PRINCE_OVERLAY_IMAGE_SHA256
        or (receipt.get("thunk_entry"), receipt.get("overlay_entry"), receipt.get("return_target"))
           != (0x32ced, 0x335ac, 0x10006)
    ):
        return None
    frame = bytes.fromhex(receipt["incoming_frame"])
    ip, cs = int.from_bytes(frame[:2], "little"), int.from_bytes(frame[2:], "little")
    before, after = receipt["entry_sp"], receipt["returned_sp"]
    if len(frame) != 4 or (cs << 4) + ip != receipt["return_target"]:
        return None
    return (((after - before) & 0xffff) - len(frame), 0)


def _prince_startup_trace_layout_8616(site: int, frame_kind) -> tuple[int, int] | None:
    """Replay the exact normal-path register receipt; never infer other paths."""
    trace_path = os.environ.get("INERTIA_OPUS_PRINCE_STARTUP_TRACE")
    if not trace_path:
        return None
    try:
        trace = Path(trace_path).read_bytes()
    except OSError:
        return None
    if hashlib.sha256(trace).hexdigest() != _PRINCE_TRACE_SHA256:
        return None
    # Snapshots at PUSH CS and PUSH [SI] precede the machine CALL by one push.
    # The resource call occurs twice; both transfers must match.
    points = {
        0x10001: (0x01, 0x06, 0, 1),
        0x10006: (0x06, 0x0b, 0, 1),
        0x1000c: (0x0b, 0x0f, 2, 1),
        0x10014: (0x12, 0x19, 2, 2),
        0x10025: (0x25, 0x2a, 0, 1),
    }
    if site not in points:
        return None
    start, end, pushed_before_call, count = points[site]
    pairs = []
    entry = None
    for line in trace.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) != 14 or not fields[0].startswith("0824:"):
            continue
        regs = tuple(int(field, 16) for field in fields[1:])
        if regs[0] != 0x0824 or fields[0] != f"0824:{regs[1]:04X}":
            return None
        ss, sp = regs[-2:]
        if regs[1] == start:
            if entry is not None:
                return None
            entry = (ss, sp)
        elif regs[1] == end:
            if entry is None or entry[0] != ss:
                return None
            pairs.append((sp - entry[1] + pushed_before_call) & 0xffff)
            entry = None
    if entry is not None or len(pairs) != count or len(set(pairs)) != 1:
        return None
    extra = pushed_before_call if frame_kind is CallsiteMachineFrameKind8616.NEAR else 0
    if pairs[0] < extra:
        return None
    layout = pairs[0] - extra, extra
    modeled = os.environ.get("INERTIA_OPUS_PRINCE_MODELED_RETURN")
    if site == 0x10001 and modeled is not None and _prince_modeled_return_layout_8616(modeled) != layout:
        return None
    return layout


@dataclass(frozen=True)
class PrinceStartupDispatchPremise8616:
    """Opt-in stack transfer for one observed startup call continuation."""

    project: object
    callsite_addr: int
    return_addr: int
    target_addr: int
    frame_kind: CallsiteMachineFrameKind8616
    purge: int
    extra: int

    @property
    def complete(self) -> bool:
        from inertia.frontend.x86_16.opus_cs_census import census_selectors_8616

        return (
            os.environ.get("INERTIA_OPUS_PRINCE_STARTUP_RETURN") == "1"
            and census_selectors_8616(self.callsite_addr) == (0x1000,)
            and census_selectors_8616(self.return_addr) == (0x1000,)
            and _prince_startup_trace_layout_8616(self.callsite_addr, self.frame_kind) == (self.purge, self.extra)
            and direct_call_target_is_bound_8616(
                self.project, self.callsite_addr, self.return_addr, self.target_addr, self.frame_kind,
            )
        )

    @property
    def observed_return_sp_delta(self) -> int:
        return self.frame_kind.return_frame_width + self.purge + self.extra

    @property
    def return_sp_delta(self) -> int | None:
        return self.observed_return_sp_delta if self.complete else None


def prince_startup_dispatch_premise_8616(project, site, continuation, target, frame, *, report=True):
    """Bind the experiment to the exact section-02 image and observed calls."""
    if os.environ.get("INERTIA_OPUS_PRINCE_STARTUP_RETURN") != "1":
        return None
    # Require a paired instruction/continuation in the normal-path receipt.
    # Do not assign an effect to the final call: it has no observed return.
    far, near = CallsiteMachineFrameKind8616.FAR, CallsiteMachineFrameKind8616.NEAR
    calls = {
        (0x10001, 0x10006, 0x32ced, far),
        (0x10006, 0x1000b, 0x174d0, far),
        (0x1000c, 0x1000f, 0x10116, near),
        (0x10014, 0x10019, 0x2e07a, far),
        (0x10025, 0x1002a, 0x2f6a0, far),
    }
    if (site, continuation, target, frame) not in calls:
        return None
    layout = _prince_startup_trace_layout_8616(site, frame)
    if layout is None:
        return None
    try:
        if hashlib.sha256(Path(project.filename).read_bytes()).hexdigest() != _PRINCE_OVERLAY_IMAGE_SHA256:
            return None
    except (OSError, TypeError, AttributeError):
        return None
    result = PrinceStartupDispatchPremise8616(project, site, continuation, target, frame, *layout)
    if not result.complete:
        return None
    if report:
        logging.getLogger(__name__).warning(
            "[premise] prince_startup_normal_return: %#x -> %#x; delta=%d", site, target, sum(layout)
        )
    return result


@dataclasses.dataclass(frozen=True, )
class CalleeStackCallResult8616:
    """Physical call identity and a retained whole-body Alias result."""

    project: object = field(compare=False, repr=False)
    callsite_addr: int | None
    return_addr: int | None
    target_addr: int | None
    frame_kind: CallsiteMachineFrameKind8616 | None
    body: CalleeStackPointerResult8616 | None
    failure: CalleeStackCallFailure8616 | None
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    def _retained_call_is_accepted(self) -> cython.bint:
        """Require published call evidence rather than a retained refusal detail."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        return bool(
            self.failure is None and counts == (1, 1, 1, 1, 0)
            and all(type(count) is int for count in iter(counts))
        )

    def _call_identity_is_current(self) -> cython.bint:
        """Check the retained result and physical call before consuming Alias."""
        if not self._retained_call_is_accepted() or self.body is None:
            return False
        if self.target_addr is None or is_synthetic_call_stub_8616(self.project, self.target_addr):
            return False
        coverage = self.body.coverage
        return bool(
            coverage.boundary.project is self.project
            and operator.eq(coverage.artifact.function_addr, self.target_addr)
            and direct_call_target_is_bound_8616(
                self.project, self.callsite_addr, self.return_addr, self.target_addr, self.frame_kind,
            )
        )

    @property
    def complete(self) -> cython.bint:
        """Recheck source, registry identity, call bytes and Alias evidence."""
        return bool(
            self._call_identity_is_current()
            and self.body is not None
            and self.body.complete
        )

    @property
    def observed_return_sp_delta(self) -> int | None:
        """Expose accepted retained Alias data, without granting current authority."""
        if not self._retained_call_is_accepted() or self.body is None:
            return None
        return self.body.observed_return_sp_delta

    @property
    def return_sp_delta(self) -> int | None:
        """Project the displacement after one current call and body observation.

        Alias owns the source-bound transfer check in its projection accessor.
        Calling this result's complete property first would repeat that exact
        whole-body proof. Each new projection still checks both boundaries.
        """
        if not self._call_identity_is_current() or self.body is None:
            return None
        return self.body.return_sp_delta


    def _saved_frame_matches_call_8616(self, frame: SavedFarReturnFrame8616) -> bool:
        """Bind the supplied caller selector and saved IP to this physical CALL."""
        if (
            self.callsite_addr is None or self.return_addr is None
            or frame.callsite_addr != self.callsite_addr or frame.frame_kind is not self.frame_kind
            or not 0 <= frame.caller_cs <= 0xFFFF or not 0 <= frame.return_ip <= 0xFFFF
        ):
            return False
        base = frame.caller_cs << 4
        entry_ip = self.callsite_addr - base
        size = 3 if self.frame_kind is CallsiteMachineFrameKind8616.NEAR else 5
        if (
            not 0 <= entry_ip <= 0x10000 - size
            or (entry_ip + size) & 0xFFFF != frame.return_ip
            or base + frame.return_ip != self.return_addr
        ):
            return False
        if self.frame_kind is CallsiteMachineFrameKind8616.FAR:
            if self.target_addr is None:
                return False
            transfer = prove_far_call_entry_8616(
                self.project, callsite_addr=self.callsite_addr, target_addr=self.target_addr,
                caller_cs=frame.caller_cs, stack_segment=frame.stack_segment,
                pre_call_sp=(frame.ip_slot + 4) & 0xFFFF,
            )
            return transfer is not None and transfer.saved_frame == frame
        encoding = bytes(self.project.loader.memory.load(self.callsite_addr, size))
        decoded = decode_relative_edge(self.callsite_addr, encoding)
        return (
            isinstance(decoded, DecodedRelativeEdge)
            and bounded_relative_destination(decoded, frame.caller_cs, frame.caller_cs).target == self.target_addr
        )

    def immediate_far_continuation(
        self, frame: SavedFarReturnFrame8616,
    ) -> FarReturnContinuation8616 | None:
        """Consume current source and stack evidence for a one-instruction RETF body."""
        if (
            not self._call_identity_is_current()
            or self.body is None or self.target_addr is None
            or not self._saved_frame_matches_call_8616(frame)
        ):
            return None
        boundary = self.body.coverage.boundary
        if (
            boundary.addr != self.target_addr or boundary.size not in (1, 3)
            or set(boundary.reachable_instruction_addrs) != {self.target_addr}
        ):
            return None
        delta = self.body.return_sp_delta
        if delta is None:
            return None
        # The call proof above binds this dynamic loader boundary to the callee.
        exact_body = bytes(self.project.loader.memory.load(self.target_addr, boundary.size))
        continuation = prove_immediate_far_return_8616(frame, exact_body)
        if continuation is None or (delta & 0xFFFF) != (4 + continuation.cleanup) & 0xFFFF:
            return None
        return dataclasses.replace(continuation, return_instructions=(self.target_addr,))


    def preserved_frame_far_continuation(
        self, frame: SavedFarReturnFrame8616, *, image: MzInvocationSource8616 | None = None,
    ) -> FarReturnContinuation8616 | None:
        """Prove each reachable RETF reads the saved words, respecting any supplied image."""
        if (
            not self._call_identity_is_current() or self.body is None
            or not self._saved_frame_matches_call_8616(frame)
        ):
            return None
        delta = self.body.return_sp_delta
        if delta is None:
            return None
        return _prove_saved_frame_returns_8616(
            self.project, self.body.coverage.boundary, frame, delta, image=image,
        )


@dataclass(frozen=True)
class _StackByteAddress8616:
    """A byte in the proved entry SS at a modular offset from instruction-entry SP."""

    sp_delta: int


@dataclass(frozen=True)
class _SavedFrameByteStore8616:
    """One lifted byte store; a plain integer address is loader-linear."""

    address: int | _StackByteAddress8616
    value: int | None


def _prove_saved_frame_returns_8616(
    project: angr.Project, boundary: ExactFunctionRangeBoundary8616, frame: SavedFarReturnFrame8616,
    delta: int | None, *, dos_sites: frozenset[int] = frozenset(), image: MzInvocationSource8616 | None = None,
) -> FarReturnContinuation8616 | None:
    """Check saved words over the exact selector-bound body graph."""
    sp_offset, sp_size = project.arch.registers["sp"]
    ss_offset, ss_size = project.arch.registers["ss"]
    cs_offset, cs_size = project.arch.registers["cs"]
    continuations: set[FarReturnContinuation8616] = set()
    return_instructions: set[int] = set()
    callee_cs = frame.caller_cs
    if frame.frame_kind is CallsiteMachineFrameKind8616.FAR:
        operand = bytes(project.loader.memory.load(frame.callsite_addr, 5))
        callee_cs = int.from_bytes(operand[3:5], "little")
    callee_base = callee_cs << 4
    saved_bytes = {
        (((frame.stack_segment << 4) + ((frame.ip_slot + index) & 0xFFFF)) & 0xFFFFF): (index, byte)
        for index, byte in enumerate(frame.return_ip.to_bytes(2, "little") + frame.caller_cs.to_bytes(2, "little"))
    }
    writes: dict[int, list[_SavedFrameByteStore8616]] = {}
    expected_edges: dict[int, set[int]] = {}
    sp_steps: dict[int, tuple[int, int]] = {}
    fetch_bytes: set[int] = set()
    for addr in boundary.reachable_instruction_addrs:
        native = project.factory.block(addr, num_inst=1, opt_level=0)
        fetch_bytes.update((addr + lane) & 0xFFFFF for lane in range(native.size))
        if image is not None:
            offset = addr - image.module_base
            if (
                not 0 <= offset <= len(image.module) - native.size
                or image.module[offset:offset + native.size] != bytes(native.bytes)
            ):
                return None
        if addr in dos_sites:
            if bytes(native.bytes) != b"\xcd\x21":
                return None
            writes[addr] = []
            continue
        vex = native.vex
        if vex.jumpkind not in {"Ijk_Boring", "Ijk_Ret"}:
            return None
        returning = vex.jumpkind == "Ijk_Ret"
        # The body inventory is expressed in contiguous loader coordinates.
        # Do not use it if execution can leave those coordinates by IP wrap.
        offset = addr - callee_base
        end = offset + native.size
        if offset < 0 or native.size <= 0 or end > 0x10000 or (not returning and end == 0x10000):
            return None
        if not returning:
            edge = decode_relative_edge(addr, bytes(native.bytes))
            fallthrough = addr + native.size
            if isinstance(edge, DecodedRelativeEdge):
                destination = bounded_relative_destination(edge, callee_cs, callee_cs).target
                if destination is None or edge.form in {RelativeEdgeForm.CALL_REL16, RelativeEdgeForm.CALL_REL32}:
                    return None
                expected_edges[addr] = {destination}
                if edge.form not in {RelativeEdgeForm.JMP_REL8, RelativeEdgeForm.JMP_REL16, RelativeEdgeForm.JMP_REL32}:
                    expected_edges[addr].add(fallthrough)
            else:
                decoded = native.capstone.insns
                if len(decoded) != 1 or decoded[0].insn.group(CS_GRP_JUMP):
                    return None
                expected_edges[addr] = {fallthrough}
        temporaries: dict[int, pyvex.expr.IRExpr] = {}
        stores: list[_SavedFrameByteStore8616] = []
        for row in vex.statements:
            if addr in sp_steps and any(
                isinstance(expr, pyvex.expr.Get) and expr.offset == sp_offset
                for expr in row.child_expressions
            ):
                # SSA temporaries read before PUT(SP) are still valid, but a
                # new GET(SP) no longer denotes the instruction-entry word.
                return None
            if isinstance(row, pyvex.stmt.Store):
                if row.data.result_size(vex.tyenv) != 8:
                    return None
                head: int | _StackByteAddress8616 | None = _frame_store_constant_8616(
                    row.addr, temporaries, ss_offset, frame.stack_segment,
                )
                if head is None:
                    head = _frame_stack_byte_address_8616(row.addr, temporaries, ss_offset, sp_offset)
                    if head is None:
                        return None
                value = _frame_store_constant_8616(row.data, temporaries, ss_offset, frame.stack_segment)
                stores.append(_SavedFrameByteStore8616(head, value))
                continue
            if isinstance(row, pyvex.stmt.WrTmp):
                temporaries[row.tmp] = row.data
            if not isinstance(row, (pyvex.stmt.IMark, pyvex.stmt.NoOp,
                                   pyvex.stmt.WrTmp, pyvex.stmt.Put, pyvex.stmt.Exit)):
                return None
            if isinstance(row, pyvex.stmt.Exit) and row.jumpkind != "Ijk_Boring":
                return None
            if isinstance(row, pyvex.stmt.Put):
                bits = row.data.result_size(vex.tyenv)
                if bits <= 0 or bits % 8:
                    return None
                end = row.offset + bits // 8
                if row.offset < ss_offset + ss_size and ss_offset < end:
                    return None
                if not returning and row.offset < sp_offset + sp_size and sp_offset < end:
                    if addr in sp_steps or (row.offset, bits) != (sp_offset, 16):
                        return None
                    affine = _affine_sp_word_8616(row.data, temporaries, sp_offset)
                    if affine is None:
                        return None
                    sp_steps[addr] = affine
                if not returning and row.offset < cs_offset + cs_size and cs_offset < end:
                    return None
        writes[addr] = stores
        if returning:
            continuation = prove_immediate_far_return_8616(frame, native.bytes)
            if continuation is None or (delta is not None and (delta & 0xFFFF) != ((4 + continuation.cleanup) & 0xFFFF)):
                return None
            continuations.add(continuation)
            return_instructions.add(addr)
    if len(continuations) != 1 or not fetch_bytes.isdisjoint(saved_bytes):
        return None
    if not _saved_bytes_match_at_returns_8616(
        boundary, writes, return_instructions, expected_edges, sp_steps, frame, saved_bytes, fetch_bytes, image,
    ):
        return None
    return dataclasses.replace(
        next(iter(continuations)), return_instructions=tuple(sorted(return_instructions)),
    )


def _affine_sp_word_8616(
    value: pyvex.expr.IRExpr, temporaries: dict[int, pyvex.expr.IRExpr],
    sp_offset: int, depth: int = 20,
) -> tuple[int, int] | None:
    """Classify a word expression as coefficient * incoming SP + constant."""
    if depth <= 0:
        return None
    if isinstance(value, pyvex.expr.Get):
        return (1, 0) if value.offset == sp_offset and value.ty == "Ity_I16" else None
    if isinstance(value, pyvex.expr.Const):
        return (0, value.con.value & 0xFFFF) if value.con.type == "Ity_I16" else None
    if isinstance(value, pyvex.expr.RdTmp):
        producer = temporaries.get(value.tmp)
        return None if producer is None else _affine_sp_word_8616(producer, temporaries, sp_offset, depth - 1)
    if isinstance(value, pyvex.expr.Binop) and value.op in {"Iop_Add16", "Iop_Sub16"}:
        left = _affine_sp_word_8616(value.args[0], temporaries, sp_offset, depth - 1)
        right = _affine_sp_word_8616(value.args[1], temporaries, sp_offset, depth - 1)
        if left is not None and right is not None:
            sign = 1 if value.op == "Iop_Add16" else -1
            return ((left[0] + sign * right[0]) & 0xFFFF, (left[1] + sign * right[1]) & 0xFFFF)
    return None


def _frame_stack_byte_address_8616(
    value: pyvex.expr.IRExpr, temporaries: dict[int, pyvex.expr.IRExpr],
    ss_offset: int, sp_offset: int,
) -> _StackByteAddress8616 | None:
    """Recognize exactly (SS << 4) + zero-extended affine word SP."""
    def producer(expr: pyvex.expr.IRExpr) -> pyvex.expr.IRExpr | None:
        for _ in range(20):
            if not isinstance(expr, pyvex.expr.RdTmp):
                return expr
            source = temporaries.get(expr.tmp)
            if source is None:
                return None
            expr = source
        return None

    address = producer(value)
    if not isinstance(address, pyvex.expr.Binop) or address.op != "Iop_Add32":
        return None
    for base_arg, word_arg in (address.args, tuple(reversed(address.args))):
        base, word = producer(base_arg), producer(word_arg)
        if not isinstance(base, pyvex.expr.Binop) or base.op != "Iop_Shl32":
            continue
        shift = producer(base.args[1])
        if not isinstance(shift, pyvex.expr.Const) or shift.con.value != 4:
            continue
        segment = producer(base.args[0])
        if not isinstance(segment, pyvex.expr.Unop) or segment.op != "Iop_16Uto32":
            continue
        ss = producer(segment.args[0])
        if not isinstance(ss, pyvex.expr.Get) or (ss.offset, ss.ty) != (ss_offset, "Ity_I16"):
            continue
        if not isinstance(word, pyvex.expr.Unop) or word.op != "Iop_16Uto32":
            continue
        affine = _affine_sp_word_8616(word.args[0], temporaries, sp_offset)
        if affine is not None and affine[0] == 1:
            return _StackByteAddress8616(affine[1])
    return None


def _saved_bytes_match_at_returns_8616(
    boundary: ExactFunctionRangeBoundary8616, writes: dict[int, list[_SavedFrameByteStore8616]], returns: set[int],
    expected_edges: dict[int, set[int]], sp_steps: dict[int, tuple[int, int]],
    frame: SavedFarReturnFrame8616, saved_bytes: dict[int, tuple[int, int]],
    fetch_bytes: set[int], image: MzInvocationSource8616 | None,
) -> bool:
    """Propagate possibly changed byte lanes over the certified body graph."""
    instructions = sorted(writes)
    blocks = {}
    covered = set()
    for block in boundary.blocks:
        start = bisect_left(instructions, block.addr)
        end = bisect_left(instructions, block.addr + block.size, lo=start)
        sites = instructions[start:end]
        if not sites or sites[0] != block.addr or covered.intersection(sites):
            return False
        covered.update(sites)
        blocks[block.addr] = sites
    if covered != set(writes) or set(blocks) != set(boundary.block_addrs_set):
        return False
    successors = {addr: [] for addr in blocks}
    for origin, target in boundary.successor_edges:
        successors[origin].append(target)
    for addr, sites in blocks.items():
        for site, following in pairwise(sites):
            if expected_edges.get(site) != {following}:
                return False
        if expected_edges.get(sites[-1], set()) != set(successors[addr]):
            return False
    entry_sp = frame.ip_slot
    incoming: dict[int, tuple[int, int | None]] = {boundary.addr: (0, entry_sp)}
    pending = [boundary.addr]
    checked_returns = set()
    while pending:
        addr = pending.pop()
        changed, sp = incoming[addr]
        for site in blocks[addr]:
            if site in returns:
                if changed or sp != entry_sp or writes[site] or site != blocks[addr][-1] or successors[addr]:
                    return False
                checked_returns.add(site)
            for store in writes[site]:
                address = store.address
                if isinstance(address, _StackByteAddress8616):
                    if sp is None:
                        return False
                    address = (frame.stack_segment << 4) + ((sp + address.sp_delta) & 0xFFFF)
                physical = address & 0xFFFFF
                if physical in fetch_bytes:
                    return False
                if image is not None and any(
                    image.module_base <= candidate < image.module_base + len(image.module)
                    for candidate in (physical, physical + 0x100000)
                ):
                    return False
                aliased = saved_bytes.get(physical)
                if aliased is not None:
                    lane, original = aliased
                    if store.value == original:
                        changed &= ~(1 << lane)
                    else:
                        changed |= 1 << lane
            if site in sp_steps:
                coefficient, constant = sp_steps[site]
                if coefficient == 0:
                    sp = constant
                elif sp is not None:
                    sp = (coefficient * sp + constant) & 0xFFFF
        for successor in successors[addr]:
            previous = incoming.get(successor)
            merged = (changed, sp) if previous is None else (
                previous[0] | changed, sp if previous[1] == sp else None,
            )
            if merged != previous:
                incoming[successor] = merged
                pending.append(successor)
    return checked_returns == returns


@cython.ccall
def _body_stack_proof_8616(
    project: object, target: cython.longlong,
) -> tuple[CalleeStackPointerResult8616 | None, CalleeStackCallFailure8616 | None]:
    """Consume or import one raw bounded body without recursive decompilation."""
    artifact: object
    boundary: object
    boundary = _exact_boundary_8616(project, target)
    if boundary is None:
        return None, CalleeStackCallFailure8616.BOUNDARY_MISSING
    resolution = registered_function_ir_artifact_8616(project, target)
    artifact = resolution.artifact
    if artifact is None:
        if resolution.failure is not FunctionIRArtifactFailure8616.NOT_REGISTERED:
            return None, CalleeStackCallFailure8616.IR_UNAVAILABLE
        artifact = build_x86_16_ir_function_artifact(project, boundary)
        publication = publish_function_ir_artifact_8616(project, artifact)
        if publication.artifact is None:
            return None, CalleeStackCallFailure8616.IR_UNAVAILABLE
    body = prove_callee_stack_pointer_8616(prove_ir_boundary_coverage_8616(project, boundary, artifact))
    return body, None if body.complete else CalleeStackCallFailure8616.BODY_REFUSED


@cython.ccall
def prove_direct_callee_stack_effect_8616(
    project: object, callsite_addr: int | None, return_addr: int | None,
    target_addr: object, frame_kind: CallsiteMachineFrameKind8616 | None,
) -> CalleeStackCallResult8616:
    """Publish a source-bound returning effect or a typed non-result."""
    failure: object
    body = None
    failure = CalleeStackCallFailure8616.CALL_TARGET_UNPROVEN
    if target_addr is not None and is_synthetic_call_stub_8616(project, target_addr):
        failure = CalleeStackCallFailure8616.SYNTHETIC_BODY
    elif direct_call_target_is_bound_8616(
        project, callsite_addr, return_addr, target_addr, frame_kind,
    ):
        assert target_addr is not None
        body, failure = _body_stack_proof_8616(project, target_addr)
    accepted = int(failure is None)
    if failure is not None and os.environ.get("INERTIA_TRACE_CALL_STACK_POSITION") == "1":
        logging.getLogger(__name__).warning(
            "Callee SP refused: site=%s target=%s reason=%s body=%s coverage=%s ir=%s",
            hex(callsite_addr) if callsite_addr is not None else None,
            hex(target_addr) if type(target_addr) is int else None,
            failure, body.failure if body is not None else None,
            body.coverage.failure if body is not None else None,
            body.coverage.artifact.refusals if body is not None else None,
        )
    return CalleeStackCallResult8616(
        project, callsite_addr, return_addr, target_addr, frame_kind, body, failure,
        1, 1, accepted, accepted, 1 - accepted,
    )


@dataclass(frozen=True)
class FarReturnStackEffect8616:
    """Ordered word slots and final SP for a 16-bit RETF on a 16-bit stack."""

    ip_slot: int
    cs_slot: int
    final_sp: int

    @classmethod
    def from_pre_return_sp(cls, sp: int, cleanup: int) -> FarReturnStackEffect8616:
        """Locate both pops before applying unsigned immediate cleanup."""
        if not (0 <= sp <= 0xFFFF and 0 <= cleanup <= 0xFFFF):
            raise ValueError("RETF requires 16-bit SP and cleanup")
        layout = WordFarReturnLayout8616(cleanup)
        return cls(sp, (sp + layout.cs_displacement) & 0xFFFF, (sp + layout.sp_displacement) & 0xFFFF)


@dataclass(frozen=True)
class SavedFarReturnFrame8616:
    """Word identities and stack coordinates at entry to a far-returning body."""

    callsite_addr: int
    caller_cs: int
    return_ip: int
    stack_segment: int
    ip_slot: int
    frame_kind: CallsiteMachineFrameKind8616

    @property
    def cs_slot(self) -> int:
        """Locate the caller selector word relative to the saved IP word."""
        return FarReturnStackEffect8616.from_pre_return_sp(self.ip_slot, 0).cs_slot

    def match_return(
        self, *, stack_segment: int, stack_offset: int,
        popped_ip: int | None, popped_cs: int | None, cleanup: int,
    ) -> FarReturnContinuation8616 | None:
        """Project a word RETF only after its two stack reads are established."""
        if (
            stack_segment != self.stack_segment or stack_offset != self.ip_slot
            or popped_ip != self.return_ip or popped_cs != self.caller_cs
            or not 0 <= cleanup <= 0xFFFF
        ):
            return None
        stack = FarReturnStackEffect8616.from_pre_return_sp(stack_offset, cleanup)
        return FarReturnContinuation8616(
            self.callsite_addr, self.caller_cs, self.return_ip,
            stack.final_sp, cleanup,
        )


@dataclass(frozen=True)
class FarReturnContinuation8616:
    """Caller control and SP on a matching return edge; other state is unknown."""

    callsite_addr: int
    cs: int
    ip: int
    sp: int
    cleanup: int
    return_instructions: tuple[int, ...] = ()


def saved_far_return_frame_8616(
    *,
    callsite_addr: int,
    caller_cs: int,
    return_ip: int,
    stack_segment: int,
    pre_call_sp: int,
    frame_kind: CallsiteMachineFrameKind8616,
    pushed_cs: int | None = None,
) -> SavedFarReturnFrame8616 | None:
    """Record an actual far CALL frame or a near CALL over a proven CS word.

    For a near CALL, pre_call_sp points to the word established by PUSH CS.
    The caller must establish that word's provenance at the CALL, not merely
    find a PUSH encoding before it in the image.
    """
    if not all(0 <= word <= 0xFFFF for word in (caller_cs, return_ip, stack_segment, pre_call_sp)):
        return None
    if frame_kind is CallsiteMachineFrameKind8616.FAR:
        pushed_bytes = 4
    elif frame_kind is CallsiteMachineFrameKind8616.NEAR and pushed_cs == caller_cs:
        pushed_bytes = 2
    else:
        return None
    return SavedFarReturnFrame8616(
        callsite_addr, caller_cs, return_ip, stack_segment,
        (pre_call_sp - pushed_bytes) & 0xFFFF, frame_kind,
    )


def prove_immediate_far_return_8616(
    frame: SavedFarReturnFrame8616, exact_body: bytes,
) -> FarReturnContinuation8616 | None:
    """Prove a continuation for a callee consisting solely of one word RETF.

    The caller must establish the call target and load its exact body from
    the same image. No intervening instruction can change SS, SP or either
    saved word. Other bodies require path-sensitive frame dataflow.
    """
    layout = WordFarReturnLayout8616.from_encoding(exact_body)
    if layout is None:
        return None
    return frame.match_return(
        stack_segment=frame.stack_segment, stack_offset=frame.ip_slot,
        popped_ip=frame.return_ip, popped_cs=frame.caller_cs, cleanup=layout.cleanup,
    )


def _frame_store_constant_8616(
    expression: pyvex.expr.IRExpr, temporaries: dict[int, pyvex.expr.IRExpr],
    ss_offset: int, stack_segment: int, *, depth: int = 20,
) -> int | None:
    """Evaluate a lifted byte-store operand using only constants and entry SS.

    Any other register, memory read, or unmodeled operator leaves the address
    unknown. Temporary producers are taken from the prefix of this instruction.
    """
    if depth <= 0:
        return None
    if isinstance(expression, pyvex.expr.Const):
        return expression.con.value
    if isinstance(expression, pyvex.expr.Get):
        return stack_segment if expression.offset == ss_offset and expression.ty == "Ity_I16" else None
    if isinstance(expression, pyvex.expr.RdTmp):
        producer = temporaries.get(expression.tmp)
        if producer is None:
            return None
        return _frame_store_constant_8616(producer, temporaries, ss_offset, stack_segment, depth=depth - 1)
    if isinstance(expression, pyvex.expr.Unop) and expression.op in {"Iop_16Uto32", "Iop_16to8"}:
        operand = _frame_store_constant_8616(
            expression.args[0], temporaries, ss_offset, stack_segment, depth=depth - 1,
        )
        return None if operand is None else operand & (0xFF if expression.op == "Iop_16to8" else 0xFFFF)
    if isinstance(expression, pyvex.expr.Binop) and expression.op in {"Iop_Add16", "Iop_Add32", "Iop_Shl32", "Iop_Shr16"}:
        left, right = (
            _frame_store_constant_8616(arg, temporaries, ss_offset, stack_segment, depth=depth - 1)
            for arg in expression.args
        )
        if left is None or right is None:
            return None
        if expression.op == "Iop_Add16":
            return (left + right) & 0xFFFF
        if expression.op == "Iop_Add32":
            return (left + right) & 0xFFFFFFFF
        if expression.op == "Iop_Shr16":
            return (left & 0xFFFF) >> right if 0 <= right < 16 else None
        if 0 <= right < 32:
            return (left << right) & 0xFFFFFFFF
    return None


@dataclass(frozen=True)
class FarCallEntry8616:
    """Callee CS:IP and saved words after a physical immediate far CALL."""

    callee_cs: int
    callee_ip: int
    saved_frame: SavedFarReturnFrame8616

    @property
    def callee_sp(self) -> int:
        """The call leaves SP pointing at the saved caller IP."""
        return self.saved_frame.ip_slot


@dataclass(frozen=True)
class ImmediateFarCallSite8616:
    """Loaded direct CALL operands, independent of runtime caller registers."""

    callsite_addr: int
    return_addr: int
    callee_cs: int
    callee_ip: int

    def saved_ip(self, caller_cs: int) -> int | None:
        """Translate the linear continuation under the actual caller selector."""
        if not 0 <= caller_cs <= 0xffff:
            return None
        offset = self.return_addr - (caller_cs << 4)
        if not 5 <= offset <= 0xffff:
            return None
        return offset


def bind_immediate_far_call_site_8616(
    project: object, *, callsite_addr: int, target_addr: int, return_addr: int,
) -> ImmediateFarCallSite8616 | None:
    """Bind a five-byte CALL to its loaded target and lexical continuation."""
    if return_addr != callsite_addr + 5 or not direct_call_target_is_bound_8616(
        project, callsite_addr, return_addr, target_addr, CallsiteMachineFrameKind8616.FAR,
    ):
        return None
    encoding = bytes(project.loader.memory.load(callsite_addr, 5))
    return ImmediateFarCallSite8616(
        callsite_addr, return_addr,
        int.from_bytes(encoding[3:5], "little"), int.from_bytes(encoding[1:3], "little"),
    )


def prove_far_call_entry_8616(
    project: object, *, callsite_addr: int, target_addr: int, caller_cs: int,
    stack_segment: int, pre_call_sp: int,
) -> FarCallEntry8616 | None:
    """Bind loaded CALL bytes to callee coordinates and their caller frame.

    Caller CS and stack state are premises. Callee bytes and return behavior
    play no role in this transfer proof.
    """
    site = bind_immediate_far_call_site_8616(
        project, callsite_addr=callsite_addr, target_addr=target_addr, return_addr=callsite_addr + 5,
    )
    return_ip = None if site is None else site.saved_ip(caller_cs)
    if site is None or return_ip is None:
        return None
    kind = CallsiteMachineFrameKind8616.FAR
    frame = saved_far_return_frame_8616(
        callsite_addr=callsite_addr, caller_cs=caller_cs, return_ip=return_ip,
        stack_segment=stack_segment, pre_call_sp=pre_call_sp, frame_kind=kind,
    )
    if frame is None:
        return None
    return FarCallEntry8616(site.callee_cs, site.callee_ip, frame)


def prove_mz_boot_far_call_entry_8616(
    project: angr.Project, source: bytes,
) -> FarCallEntry8616 | None:
    """Prove an immediate far CALL executed as the authenticated MZ entry."""
    from inertia.frontend.x86_16.mz_invocation_source import authenticate_loaded_mz_boot_8616

    boot = authenticate_loaded_mz_boot_8616(project, source)
    if boot is None:
        return None
    offset = boot.entry_linear - boot.module_base
    encoding = boot.module[offset:offset + 5]
    if len(encoding) != 5 or encoding[0] != 0x9A:
        return None
    target = (int.from_bytes(encoding[3:], "little") << 4) + int.from_bytes(encoding[1:3], "little")
    return prove_far_call_entry_8616(
        project, callsite_addr=boot.entry_linear, target_addr=target, caller_cs=boot.entry_segment,
        stack_segment=boot.stack_segment, pre_call_sp=boot.stack_offset,
    )


@dataclass(frozen=True)
class MzBootFarCallEffect8616:
    """Source-scoped boot CALL entry and its separately proved continuation."""

    entry: FarCallEntry8616
    continuation: FarReturnContinuation8616 | None


def prove_mz_boot_dos_scoped_return_8616(project, source, boundary, *, assume_dos_int21=False):
    """Prove a returning edge alongside modeled DOS exits, without publishing it."""
    from inertia.frontend.x86_16.mz_invocation_source import authenticate_loaded_mz_boot_8616
    from inertia.ir.dos_exit_evidence import consume_mz_boot_dos_exits_8616

    exits = consume_mz_boot_dos_exits_8616(project, source, boundary, assume_dos_int21=assume_dos_int21)
    if not exits:
        return None
    image = authenticate_loaded_mz_boot_8616(project, source)
    entry = prove_mz_boot_far_call_entry_8616(project, source)
    if image is None or entry is None or boundary.addr != (entry.callee_cs << 4) + entry.callee_ip:
        return None
    # Track lifted affine word SP assignments over this private graph.
    # More general stack updates still need an invocation-bound Alias proof.
    return _prove_saved_frame_returns_8616(
        project, boundary, entry.saved_frame, None,
        dos_sites=frozenset(site.instruction_addr for site in exits), image=image,
    )


def prove_mz_boot_far_call_effect_8616(
    project: angr.Project, source: bytes,
) -> MzBootFarCallEffect8616 | None:
    """Connect an authenticated boot call with current saved-word return evidence.

    An absent continuation leaves return behavior unresolved; it does not
    prove the callee never returns. Nothing is published as an unconditional
    caller or function summary.
    """
    entry = prove_mz_boot_far_call_entry_8616(project, source)
    if entry is None:
        return None
    frame = entry.saved_frame
    result = prove_direct_callee_stack_effect_8616(
        project, frame.callsite_addr, (frame.caller_cs << 4) + frame.return_ip,
        (entry.callee_cs << 4) + entry.callee_ip, frame.frame_kind,
    )
    return MzBootFarCallEffect8616(entry, result.preserved_frame_far_continuation(frame))
