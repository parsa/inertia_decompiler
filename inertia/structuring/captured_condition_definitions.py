"""Find the exact structured definitions feeding a straight-line guard."""

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CIfElse,
    CStatements,
    CVariable,
)


def captured_guard_definitions_8616(
    root: object, guard: object, uses: tuple[CVariable, ...],
) -> tuple[CAssignment, ...] | None:
    """Bind distinct SSA uses to preceding assignments in one linear prefix.

    Only a top-level first arm is supported. A preceding branch, label,
    indirect write, or assignment to the same rendered variable through a
    different SSA identity makes the prefix ineligible.
    """
    if not isinstance(root, CStatements) or not uses:
        return None
    variables = tuple(use.variable for use in uses)
    carriers = tuple(use.unified_variable for use in uses)
    if any(var is None for var in variables) or len({id(var) for var in variables}) != len(uses):
        return None

    definitions: dict[int, CAssignment] = {}
    pending = list(reversed(root.statements))
    while pending:
        stmt = pending.pop()
        if isinstance(stmt, CStatements):
            pending.extend(reversed(stmt.statements))
            continue
        if isinstance(stmt, CIfElse) and stmt.condition_and_nodes and stmt.condition_and_nodes[0][0] is guard:
            return tuple(definitions[i] for i in range(len(uses))) if len(definitions) == len(uses) else None
        if not isinstance(stmt, CAssignment) or not isinstance(stmt.lhs, CVariable):
            return None
        lhs = stmt.lhs
        for i, (variable, carrier) in enumerate(zip(variables, carriers, strict=True)):
            if lhs.variable is variable:
                if i != len(definitions):
                    return None
                if i in definitions or lhs.unified_variable is not carrier:
                    return None
                definitions[i] = stmt
            elif carrier is not None and (lhs.unified_variable is carrier or lhs.variable is carrier):
                return None
    return None


def captured_byte_compare_expression_8616(root, guard, fact):
    """Bind a byte equality guard to its uniquely executed captured load."""
    from angr.analyses.decompiler.structured_codegen.c import (
        CBinaryOp, CConstant, CIfBreak, CTypeCast,
    )
    from angr.sim_variable import SimRegisterVariable, SimTemporaryVariable
    from inertia.ir.core import IRValue, MemSpace
    from inertia.widening.segmented_load_identity import segmented_load_identity_8616

    mem, imm = fact.lhs, fact.rhs
    if (
        fact.op not in {"eq", "ne"} or fact.width_bits != 8
        or not isinstance(mem, IRValue) or mem.space not in {MemSpace.DS, MemSpace.ES, MemSpace.SS}
        or mem.index is not None or mem.size != 1 or not 0 <= mem.offset <= 0xffff
        or not isinstance(imm, IRValue) or imm.space is not MemSpace.CONST
        or not isinstance(imm.const, int) or not 0 <= imm.const <= 255
        or not isinstance(fact.producer_insn, int) or not isinstance(fact.block_addr, int)
    ):
        return None
    pending = [root]
    capture = None
    while pending:
        stmt = pending.pop()
        if isinstance(stmt, CStatements):
            pending.extend(reversed(stmt.statements))
            continue
        if stmt is guard and isinstance(stmt, (CIfElse, CIfBreak)):
            if capture is None:
                return None
            use = capture.lhs
            signed = use.type.signed
            if signed is None and imm.const >= 128:
                return None
            constant = imm.const - 256 if signed and imm.const >= 128 else imm.const
            return CBinaryOp(
                "CmpEQ" if fact.op == "eq" else "CmpNE",
                use, CConstant(constant, use.type, codegen=use.codegen),
                codegen=use.codegen,
            )
        if not isinstance(stmt, CAssignment) or not isinstance(stmt.lhs, CVariable):
            return None
        lhs = stmt.lhs
        if capture is not None and (
            lhs.variable is capture.lhs.variable
            or (capture.lhs.unified_variable is not None
                and lhs.unified_variable is capture.lhs.unified_variable)
        ):
            return None
        if stmt.tags.get("ins_addr") != fact.producer_insn or stmt.tags.get("vex_block_addr") != fact.block_addr:
            continue
        if (
            not isinstance(stmt.tags.get("vex_stmt_idx"), int) or lhs.type.size != 8
            or not isinstance(lhs.variable, (SimRegisterVariable, SimTemporaryVariable))
        ):
            continue
        value = stmt.rhs
        while isinstance(value, CTypeCast) and value.dst_type.size == 8:
            value = value.expr
        identity = segmented_load_identity_8616(value)
        if (
            identity is not None and identity.space is mem.space and identity.width == 1
            and identity.offset == mem.offset and identity.region == lhs.codegen.cfunc.addr
            and value.tags.get("inertia_source_instruction_addrs") == (fact.producer_insn,)
        ):
            if capture is not None:
                return None
            capture = stmt
    return None


def captured_byte_guard_8616(root, branch, guard, fact, *, body_is_taken: bool) -> bool:
    """Check an existing guard against the byte captured before its branch."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CITE, CUnaryOp

    expected = captured_byte_compare_expression_8616(root, branch, fact)
    if expected is None:
        return False
    inverted = not body_is_taken
    if isinstance(guard, CITE):
        if not all(isinstance(arm, CConstant) for arm in (guard.iftrue, guard.iffalse)):
            return False
        pair = guard.iftrue.value, guard.iffalse.value
        if pair not in {(0, 1), (1, 0)}:
            return False
        inverted ^= pair == (0, 1)
        guard = guard.cond
    want_eq = (expected.op == "CmpEQ") != inverted
    if isinstance(guard, CUnaryOp) and guard.op == "Not":
        if not want_eq or expected.rhs.value != 0:
            return False
        use = guard.operand
    elif (
        isinstance(guard, CBinaryOp) and guard.op == ("CmpEQ" if want_eq else "CmpNE")
        and isinstance(guard.rhs, CConstant) and guard.rhs.value == expected.rhs.value
    ):
        use = guard.lhs
    else:
        return False
    return (
        isinstance(use, CVariable) and use.variable is expected.lhs.variable
        and use.unified_variable is expected.lhs.unified_variable
        and use.type == expected.lhs.type
    )


def promoted_stack_test_8616(guard, fact, *, body_is_taken: bool) -> bool:
    """Match TEST's masked low byte to an existing exact BP slot view."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant
    from angr.sim_variable import SimStackVariable
    from inertia.ir.core import IRBinaryValue, IRValue, MemSpace

    operand = fact.lhs
    if (fact.op not in {"zero", "nonzero"} or fact.width_bits != 8 or fact.rhs is not None
        or not isinstance(operand, IRBinaryValue) or operand.op != "and" or operand.size != 1):
        return False
    slot, mask = operand.lhs, operand.rhs
    if (
        not isinstance(slot, IRValue) or slot.space is not MemSpace.SS or slot.name != "bp"
        or slot.index is not None or slot.size != 1
        or not isinstance(mask, IRValue) or mask.space is not MemSpace.CONST
        or not isinstance(mask.const, int) or not 0 <= mask.const <= 255
        or fact.producer_semantics != ("test_mem_imm8", ("bp", slot.offset & 0xffff, slot.offset), mask.const)
    ):
        return False
    if (
        not isinstance(guard, CBinaryOp)
        or guard.op != ("CmpEQ" if (fact.op == "zero") == body_is_taken else "CmpNE")
        or not isinstance(guard.rhs, CConstant) or guard.rhs.value != 0
        or not isinstance(guard.lhs, CBinaryOp) or guard.lhs.op != "And"
        or not isinstance(guard.lhs.rhs, CConstant) or guard.lhs.rhs.value != mask.const
    ):
        return False
    view = guard.lhs.lhs
    if not isinstance(view, CVariable):
        return False
    variable = view.variable
    if not isinstance(variable, SimStackVariable):
        return False
    owner = view.unified_variable
    return all(
        isinstance(v, SimStackVariable)
        and (v.base, v.offset, v.size, v.region) == ("bp", slot.offset, 1, variable.region)
        for v in (variable, owner if owner is not None else variable)
    )


def captured_word_compare_8616(root, guard, fact, *, body_is_taken: bool) -> bool:
    """Prove a direct word/immediate EQ or NE over two captured byte loads."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CITE, CTypeCast

    from inertia.ir.core import IRValue, MemSpace
    from inertia.widening.segmented_load_identity import segmented_load_identity_8616

    mem, imm = fact.lhs, fact.rhs
    if (
        fact.op not in {"eq", "ne"} or fact.width_bits != 16
        or not isinstance(mem, IRValue) or mem.space not in {MemSpace.DS, MemSpace.ES, MemSpace.SS}
        or not 0 <= mem.offset <= 0xffff or mem.size != 2 or mem.index is not None
        or not isinstance(imm, IRValue) or imm.space is not MemSpace.CONST
        or not isinstance(fact.producer_insn, int) or not isinstance(fact.block_addr, int)
    ):
        return False
    cmp = guard
    inverted = False
    if isinstance(cmp, CITE):
        if not all(isinstance(c, CConstant) for c in (cmp.iftrue, cmp.iffalse)):
            return False
        pair = (cmp.iftrue.value, cmp.iffalse.value)
        if pair not in {(0, 1), (1, 0)}:
            return False
        inverted = pair == (0, 1)
        cmp = cmp.cond
    expected_eq = (fact.op == "eq") == body_is_taken
    if (
        not isinstance(cmp, CBinaryOp) or cmp.op not in {"CmpEQ", "CmpNE"}
        or ((cmp.op == "CmpEQ") != inverted) != expected_eq
        or not isinstance(cmp.rhs, CConstant) or cmp.rhs.value != imm.const
    ):
        return False
    word = cmp.lhs
    if not isinstance(word, CBinaryOp) or word.op != "Or" or not isinstance(word.lhs, CVariable):
        return False
    hi = word.rhs
    if (
        not isinstance(hi, CBinaryOp) or hi.op != "Mul" or not isinstance(hi.lhs, CVariable)
        or not isinstance(hi.rhs, CConstant) or hi.rhs.value != 256
    ):
        return False
    uses = (word.lhs, hi.lhs)
    if any(use.type.size != 8 or use.type.signed is not False for use in uses):
        return False
    definitions = captured_guard_definitions_8616(root, guard, uses)
    if definitions is None:
        return False
    indices = []
    for lane, definition in enumerate(definitions):
        if definition.tags.get("ins_addr") != fact.producer_insn or definition.tags.get("vex_block_addr") != fact.block_addr:
            return False
        idx = definition.tags.get("vex_stmt_idx")
        if not isinstance(idx, int):
            return False
        indices.append(idx)
        value = definition.rhs
        while isinstance(value, CTypeCast):
            if value.dst_type.size != 8:
                return False
            value = value.expr
        identity = segmented_load_identity_8616(value)
        if (
            identity is None or identity.space is not mem.space or identity.width != 1
            or identity.offset != (mem.offset + lane) & 0xffff or identity.region != fact.block_addr
            or value.tags.get("inertia_source_instruction_addrs") != (fact.producer_insn,)
        ):
            return False
    return indices[0] < indices[1]
