# cython: language_level=3, infer_types=True
"""Preserve explicit AIL arithmetic types at native C construction.

Layer: Types/Lowering.
Responsibility: consume proven scalar operation widths and signedness before
native C type inference can replace them with DOS int-sized operand types.
Consumes alias, widening, and typed facts at the native codegen boundary.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import cython

from angr.ailment.expression import BinaryOp, Const, Convert
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CExpression, CTypeCast
from angr.sim_type import SimTypeNum

from .semantic_cast import CSemanticCast8616
import operator

_DWORD_BITS = 32
_WORD_BITS = 16


def lower_native_word_extension_8616(expression: Convert, native: CExpression) -> CExpression | None:
    """Implement unsigned extension of a modulo-word arithmetic result."""
    if expression.is_signed and expression.from_bits == 8 and expression.to_bits == 16 and isinstance(native, CTypeCast):
        child = native.expr
        byte = CSemanticCast8616(None, SimTypeNum(8, True), child, codegen=native.codegen)
        return CSemanticCast8616(None, SimTypeNum(16, True), byte, codegen=native.codegen, tags=native.tags)
    operand = expression.operand
    if (
        expression.from_bits != _WORD_BITS or expression.to_bits != _DWORD_BITS or expression.is_signed
        or not isinstance(operand, BinaryOp) or operand.op not in {"Add", "Sub", "Mul"}
        or operand.floating_point or operand.vector_count is not None or operand.vector_size is not None
        or not isinstance(native, CTypeCast) or not isinstance(native.expr, CBinaryOp)
        or native.expr.op != operand.op
    ):
        return None
    arithmetic = native.expr
    wide = SimTypeNum(_DWORD_BITS, False)
    # Unsigned arithmetic also avoids signed-promotion overflow on hosts
    # whose int is wider than DOS int. Only the low word is then extended.
    wrapped = CBinaryOp(
        arithmetic.op,
        CSemanticCast8616(None, wide, arithmetic.lhs, codegen=native.codegen),
        CSemanticCast8616(None, wide, arithmetic.rhs, codegen=native.codegen),
        tags=arithmetic.tags, codegen=native.codegen,
    )
    word = CSemanticCast8616(None, SimTypeNum(_WORD_BITS, False), wrapped, codegen=native.codegen)
    return CSemanticCast8616(None, native.dst_type, word, codegen=native.codegen, tags=native.tags)


@cython.ccall
def lower_native_integer_operation_8616(expression: BinaryOp, native: CExpression) -> CExpression | None:
    """Keep word/dword shifts and dword division at their proven native widths.

    Shifts operate on unsigned bitvectors even when a sign-extended value feeds
    them. Division instead consumes the signedness explicitly supplied by AIL.
    Variable shifts are refused until their valid-count contract is available.
    """
    non_scalar = expression.floating_point or expression.vector_count is not None or expression.vector_size is not None
    if non_scalar or not isinstance(native, CBinaryOp):
        return None
    if (expression.bits in {8, _WORD_BITS}
            and expression.op in {"Add", "Sub", "Mul"}
            and operator.eq(native.op, expression.op)
            and all(operand.bits == expression.bits for operand in expression.operands)):
        # C promotes byte/word operands; consumers such as zero tests
        # must instead observe the modulo-width result of the AIL operation.
        wide = SimTypeNum(_DWORD_BITS, False)
        arithmetic = CBinaryOp(
            expression.op,
            CSemanticCast8616(None, wide, native.lhs, codegen=native.codegen),
            CSemanticCast8616(None, wide, native.rhs, codegen=native.codegen),
            codegen=native.codegen,
        )
        return CSemanticCast8616(
            None, SimTypeNum(expression.bits, expression.signed), arithmetic,
            codegen=native.codegen, tags=native.tags,
        )
    if operator.eq(expression.bits, _WORD_BITS):
        return _lower_native_word_shift_8616(expression, native)
    if operator.ne(expression.bits, _DWORD_BITS):
        return None
    left, right = expression.operands
    if operator.ne(left.bits, _DWORD_BITS):
        return None
    if expression.op == "Shl":
        if not isinstance(right, Const) or not isinstance(right.value, int) or not 0 <= right.value < _DWORD_BITS:
            return None
        signed = False
        rhs = native.rhs
    elif expression.op in {"Div", "Mod"} and operator.eq(right.bits, _DWORD_BITS):
        signed = expression.signed
        rhs = CSemanticCast8616(None, SimTypeNum(_DWORD_BITS, signed), native.rhs, codegen=native.codegen)
    else:
        return None
    lhs = CSemanticCast8616(None, SimTypeNum(_DWORD_BITS, signed), native.lhs, codegen=native.codegen)
    return CBinaryOp(expression.op, lhs, rhs, codegen=native.codegen, tags=native.tags)


@cython.ccall
def _lower_native_word_shift_8616(expression: BinaryOp, native: CBinaryOp) -> CExpression | None:
    """Widen byte-derived operands before DOS promotion, then restore the word.

    Unsigned word operands stay unsigned on a 16-bit C implementation. On a
    32-bit host their largest supported intermediate, 65535 << 15, remains
    within signed int32; the final conversion preserves native truncation.
    No memory reads, argument identities, or nonliteral counts are inferred.
    """
    left, right = expression.operands
    if expression.op != "Shl" or operator.ne(native.op, expression.op) or operator.ne(left.bits, _WORD_BITS):
        return None
    if not isinstance(right, Const) or not isinstance(right.value, int) or not 0 <= right.value < _WORD_BITS:
        return None
    type_ = SimTypeNum(_WORD_BITS, False)
    lhs = CSemanticCast8616(None, type_, native.lhs, codegen=native.codegen)
    shifted = CBinaryOp("Shl", lhs, native.rhs, codegen=native.codegen, tags=native.tags)
    return CSemanticCast8616(None, type_, shifted, codegen=native.codegen, tags=native.tags)
