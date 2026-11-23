from itertools import count
from types import SimpleNamespace
from unittest import TestCase

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CStatements, CTypeCast, CVariable
from angr.sim_type import SimTypeChar, SimTypeNum, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from capstone import CS_ARCH_X86, CS_MODE_16, Cs

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.stack_variable_coordinates import record_stack_variable_coordinate_projection_8616
from inertia.postprocess import decompiler_postprocess_jcc as jcc


class LegacyJccTestOperandOccurrenceTests(TestCase):
    def setUp(self):
        self.decoder = Cs(CS_ARCH_X86, CS_MODE_16)
        self.decoder.detail = True
        self.project = SimpleNamespace(arch=Arch86_16())
        self.codegen = SimpleNamespace(
            project=self.project,
            next_ident=lambda name: name,
            next_node_idx=count().__next__,
        )

    def decode(self, machine_hex, block_start, *, assignments, value_type=None):
        insns = tuple(self.decoder.disasm(bytes.fromhex(machine_hex), 0x100))
        block = insns[block_start:]
        test_insn = next(insn for insn in block if insn.mnemonic == "test")
        branch = block[-1]

        def lift_block(addr, *, opt_level):
            self.assertEqual((addr, opt_level), (block[0].address, 0))
            return SimpleNamespace(capstone=SimpleNamespace(insns=block))

        self.project.factory = SimpleNamespace(block=lift_block)
        bx, size = self.project.arch.registers["bx"]
        lhs = CVariable(SimRegisterVariable(bx, size, name="bx"), codegen=self.codegen)
        storage = SimStackVariable(8, 2, base="bp", name="arg_8", ident="arg_0")
        if value_type is None:
            value_type = SimTypeShort(False)
        stack_slot = CVariable(storage, variable_type=value_type.with_arch(self.project.arch), codegen=self.codegen)
        record_stack_variable_coordinate_projection_8616(
            self.codegen, variable=storage, cvar=stack_slot, bp_offset=8, entry_sp_offset=6, size=2
        )
        statements = [
            CAssignment(lhs, rhs, codegen=self.codegen, tags={"ins_addr": insns[index].address})
            for index, rhs in assignments(stack_slot)
        ]
        self.codegen.cfunc = CStatements(statements, addr=0x100, codegen=self.codegen)
        self.codegen._inertia_jcc_function_insns_8616 = insns
        collected = jcc._register_exprs_by_ins_addr_8616(self.codegen, self.project)
        self.assertIs(collected[(0x100, "bx", 2)], stack_slot)
        decoded = jcc._translate_cmp_jcc_guard_8616(self.project, self.codegen, block[0].address, branch.address)
        return decoded, collected.get((test_insn.address, "bx", 2))

    def test_straight_line_bp_load_reaches_test_without_test_assignment(self):
        decoded, test_assignment = self.decode("8b5e08 85db 7502", 0, assignments=lambda slot: [(0, slot)])
        self.assertIsNone(test_assignment)
        self.assertIsNotNone(decoded)
        value = decoded.lhs.expr if isinstance(decoded.lhs, CTypeCast) else decoded.lhs
        self.assertEqual(value.variable.offset, 8)
        self.assertEqual(value.type.size, 16)
        self.assertEqual(decoded.rhs.value, 0)
        self.assertEqual(decoded.op, "CmpNE")

    def assert_word_load_refuses_argument_type(self, value_type):
        decoded, test_assignment = self.decode(
            "8b5e08 85db 7502", 0, assignments=lambda slot: [(0, slot)], value_type=value_type
        )
        self.assertIsNone(test_assignment)
        self.assertIsNone(decoded)

    def test_padded_byte_argument_does_not_represent_loaded_word(self):
        self.assert_word_load_refuses_argument_type(SimTypeChar(False))

    def test_partial_byte_of_argument_does_not_represent_loaded_word(self):
        self.assert_word_load_refuses_argument_type(SimTypeNum(12, signed=False))

    def test_recurrent_load_does_not_reuse_preheader_bp_slot(self):
        decoded, test_assignment = self.decode(
            "8b5e08 83c350 8b1f 85db 7402", 2, assignments=lambda slot: [(0, slot)]
        )
        self.assertIsNone(test_assignment)
        self.assertIsNone(decoded)

    def test_assignment_tagged_at_test_is_not_an_operand_use(self):
        decoded, test_assignment = self.decode(
            "8b5e08 85db 7502", 1, assignments=lambda slot: [(0, slot), (1, slot)]
        )
        self.assertIsNotNone(test_assignment)
        self.assertIsNone(decoded)

    def test_non_ss_load_cannot_prove_bp_slot(self):
        decoded, _ = self.decode("3e8b5e08 85db 7502", 0, assignments=lambda slot: [(0, slot)])
        self.assertIsNone(decoded)

    def test_store_between_test_and_branch_keeps_captured_flags(self):
        decoded, _ = self.decode("8b5e08 85db 895608 7502", 0, assignments=lambda slot: [(0, slot)])
        self.assertIsNone(decoded)
