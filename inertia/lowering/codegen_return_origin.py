# cython: language_level=3, infer_types=True
"""Transport return-value origins across native AIL-to-C conversion.

Layer: Types/Lowering.
Responsibility: preserve per-use instruction provenance on C returns and
lower explicit architectural exit consumers. Exit consumers carry the IR-proven
value and exact destination view; C lowering does not infer either one.
Other consumers must join origin metadata to IR/CFG and Alias evidence before
accepting a value. No path, storage, signature or return expression is recovered here.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import dataclasses
import os
from collections.abc import Callable, Mapping
from typing import Protocol, cast

import cython
from angr import ailment
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CExpression,
    CReturn,
    CStructuredCodeGenerator,
    CTypeCast,
)
from angr.sim_type import SimTypeInt, SimTypeShort

_ORIGIN_TAG = "inertia_x86_16_return_value_origin"


@dataclasses.dataclass(frozen=True, )
class ReturnValueOrigin8616:
    """Value origin and independently observed return site for one C use.

    A propagated expression can retain an earlier instruction's location.
    Optional statement coordinates identify the actual return and must never
    be inferred from that expression location.
    """

    instruction_addr: cython.longlong
    block_addr: cython.longlong
    width_bits: cython.longlong
    return_instruction_addr: int | None = None
    return_block_addr: int | None = None


class _ValueSurface8616(Protocol):
    """Native Python/Rust AIL expression fields consumed without interpretation."""

    tags: Mapping[str, object]
    bits: object


@cython.ccall
def _nonnegative_integer(value: object) -> int | None:
    """Reject malformed metadata, including Boolean values disguised as integers."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


@cython.ccall
def _ail_value_origin(statement: ailment.Stmt.Return) -> ReturnValueOrigin8616 | None:
    """Read complete source metadata for exactly one returned AIL value."""
    block: object
    instruction: object
    width: object
    if len(statement.ret_exprs) != 1:
        return None
    value = cast(_ValueSurface8616, statement.ret_exprs[0])
    try:
        instruction = _nonnegative_integer(value.tags["ins_addr"])
        block = _nonnegative_integer(value.tags["vex_block_addr"])
        width = _nonnegative_integer(value.bits)
    except (AttributeError, KeyError, TypeError):
        return None
    if instruction is None or block is None or width is None or width == 0:
        return None
    return ReturnValueOrigin8616(
        instruction, block, width,
        _nonnegative_integer(statement.tags.get("ins_addr")),
        _nonnegative_integer(statement.tags.get("vex_block_addr")),
    )


@cython.ccall
def return_value_origin_8616(statement: CReturn) -> ReturnValueOrigin8616 | None:
    """Read transported source identity without treating it as value-flow proof."""
    origin: object
    origin = statement.tags.get(_ORIGIN_TAG)
    return origin if isinstance(origin, ReturnValueOrigin8616) else None


def apply_codegen_return_origin_8616() -> None:
    """Install an idempotent x86-16 adapter at native return construction."""
    # The native untyped converter accepts backend-specific keyword arguments.
    original = cast(Callable[..., CReturn], CStructuredCodeGenerator._handle_Stmt_Return)
    if original.__name__ == "_return_with_value_origin_8616":
        return

    def _return_with_value_origin_8616(
        self: CStructuredCodeGenerator, statement: ailment.Stmt.Return, **kwargs: object,
    ) -> CReturn:
        """Keep native values and copy source metadata onto the owning return use."""
        origin: object
        result = original(self, statement, **kwargs)
        if self.project.arch.name != "86_16":
            return result
        origin = _ail_value_origin(statement)
        # Native conversion shares the AIL statement's dictionary. Never mutate
        # it, or place a per-use origin on a CVariable shared by other returns.
        result.tags = dict(result.tags)
        result.tags.pop(_ORIGIN_TAG, None)
        if origin is not None:
            result.tags[_ORIGIN_TAG] = origin
        return result

    CStructuredCodeGenerator._handle_Stmt_Return = _return_with_value_origin_8616
    original_extract = CStructuredCodeGenerator._handle_Expr_Extract

    def _handle_integer_extract_8616(
        self: CStructuredCodeGenerator, expr: ailment.Expr.Extract, **kwargs: object,
    ) -> object:
        """Lower little-endian integer slices without taking a temporary's address."""
        if self.project.arch.name == "86_16" and isinstance(expr.offset, ailment.Expr.Const):
            offset = expr.offset.value
            if type(offset) is int and offset > 0 and expr.bits in (8, 16):
                child = self._handle(expr.base)
                source = child.type
                if isinstance(source, SimTypeInt) and source.size in (16, 32) and offset * 8 + expr.bits <= source.size:
                    unsigned = self.default_simtype_from_bits(source.size, False).with_arch(self.project.arch)
                    target = self.default_simtype_from_bits(expr.bits, False).with_arch(self.project.arch)
                    shifted = CBinaryOp(
                        "Shr", CTypeCast(source, unsigned, child, codegen=self),
                        CConstant(offset * 8, unsigned, codegen=self), codegen=self,
                    )
                    return CTypeCast(unsigned, target, shifted, tags=expr.tags, codegen=self)
        return original_extract(self, expr, **kwargs)

    CStructuredCodeGenerator._handle_Expr_Extract = _handle_integer_extract_8616
    original_effect = CStructuredCodeGenerator._handle_Stmt_SideEffectStatement

    def _handle_gp_exit_effect_8616(
        self: CStructuredCodeGenerator, statement: ailment.Stmt.SideEffectStatement,
        is_expr: bool = False, **kwargs: object,
    ) -> object:
        """Lower a typed architectural exit consumer to a register write."""
        effect = statement.expr
        coordinate = statement.tags.get("inertia_gp_exit_coordinate")
        if (
            self.project.arch.name != "86_16" or not isinstance(effect, ailment.Expr.Call)
            or effect.target != "inertia_architectural_gp_exit"
        ):
            return original_effect(self, statement, is_expr=is_expr, **kwargs)
        from .gp_register_state import runtime_gp_state_assignment_8616

        if (
            is_expr or len(effect.args or ()) != 1
            or not isinstance(coordinate, (tuple, list)) or len(coordinate) != 2
        ):
            raise ValueError("invalid architectural GP exit operand")
        offset = _nonnegative_integer(coordinate[0])
        width = _nonnegative_integer(coordinate[1])
        if offset is None or not width:
            raise ValueError("invalid architectural GP exit coordinate")
        near = "inertia_word_near_return_cleanup" in statement.tags
        interrupt = "inertia_word_interrupt_return" in statement.tags
        cleanup = statement.tags.get(
            "inertia_word_interrupt_return" if interrupt else
            "inertia_word_near_return_cleanup" if near else "inertia_word_far_return_cleanup"
        )
        if cleanup is not None:
            from inertia.semantics.terminal_return_contract import (
                WordFarReturnLayout8616,
                WordInterruptReturnLayout8616,
                WordNearReturnLayout8616,
            )

            from .far_return_boundary_carriers import bind_word_far_return_effect_8616
            from .gp_register_state import runtime_gp_state_expr_8616
            from .segment_register_state import runtime_segment_state_cvar_8616

            site = statement.tags.get("ins_addr")
            if (
                (offset, width) != self.project.arch.registers["sp"]
                or type(cleanup) is not int or not 0 <= cleanup <= 0xFFFF or type(site) is not int
            ):
                raise ValueError("invalid word far return effect")
            ss = runtime_segment_state_cvar_8616(
                "ss", codegen=self, variable_type=SimTypeShort(False).with_arch(self.project.arch),
                function_addr=self._func.addr,
            )
            if ss is None:
                raise ValueError("word far return has no SS state")
            pre_sp = (
                runtime_gp_state_expr_8616("sp", codegen=self, function_addr=self._func.addr)
                if statement.tags.get("inertia_return_sp_is_incoming")
                else cast(CExpression, self._handle(effect.args[0]))
            )
            if pre_sp is None:
                raise ValueError("word return has no SP state")
            layout = (WordInterruptReturnLayout8616() if interrupt else
                      WordNearReturnLayout8616(cleanup) if near else WordFarReturnLayout8616(cleanup))
            if interrupt:
                self._inertia_force_codegen_regeneration_8616 = True
            return bind_word_far_return_effect_8616(self, self._func.addr, site, layout, ss, pre_sp)
        if (offset, width) == self.project.arch.registers["flags"]:
            from .packed_flags_state import packed_flags_exit_assignment_8616

            result = packed_flags_exit_assignment_8616(
                self, self._func.addr, cast(CExpression, self._handle(effect.args[0])),
            )
            from inertia.ir.status_flag_exit_projection import (
                bind_status_flag_phi_origins_8616,
                function_status_flag_exit_origins_8616,
            )

            site = statement.tags.get("ins_addr")
            rows = statement.tags.get("inertia_flags_phi_input_producers", ())
            incoming_edges = {} if rows else None
            carry_sources = dict(statement.tags.get("inertia_flags_phi_carry_sources", ()))
            native_carry = {} if carry_sources else None
            origins = function_status_flag_exit_origins_8616(
                self.project, self._func, incoming_edges=incoming_edges, native_carry=native_carry,
            )
            if origins is not None and site in origins:
                states = tuple(sorted(
                    tuple((-1 if origin.producer is None else origin.producer, int(origin.defined))
                          for origin in state.origins)
                    for state in origins[site]
                ))
                tags = {
                    **result.tags,
                    "ins_addr": site,
                    "inertia_status_flag_exit_origins": states,
                }
                if incoming_edges is not None:
                    # Protect the generated carrier even when the numeric SSA
                    # inputs do not yet prove every native status-bit producer.
                    tags["inertia_status_flag_exit_phi_candidates"] = rows
                    bindings = bind_status_flag_phi_origins_8616(
                        rows, incoming_edges, origins[site], site,
                        carry_sources=carry_sources, native_carry=native_carry,
                    )
                    if os.getenv("INERTIA_DEBUG_FLAGS_EXIT_BINDING") == "2":
                        print("[flags-phi-native-binding]", site, bindings, carry_sources)
                    if bindings:
                        tags["inertia_status_flag_exit_phi_inputs"] = bindings
                        tags["inertia_status_flag_exit_phi_carry_sources"] = tuple(sorted(carry_sources.items()))
                result.tags = tags
            return result
        arch = self.project.arch
        register = arch.translate_register_name(offset, size=width)
        if arch.registers.get(register) != (offset, width):
            raise ValueError(f"no exact architectural GP exit view: {(offset, width)}")
        result = runtime_gp_state_assignment_8616(
            register, cast(CExpression, self._handle(effect.args[0])),
            codegen=self, function_addr=self._func.addr, exit_only=True,
        )
        if result is None:
            raise ValueError(f"unlowered architectural GP exit operand: {register}")
        result.tags = {
            **result.tags,
            "ins_addr": statement.tags.get("ins_addr"),
            "inertia_gp_exit_coordinate": (offset, width),
        }
        return result

    CStructuredCodeGenerator._handle_Stmt_SideEffectStatement = _handle_gp_exit_effect_8616
