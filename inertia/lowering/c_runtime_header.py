# cython: language_level=3, infer_types=True
"""Render C runtime helper declarations required by lowered output.

Layer: Types/Lowering.
Responsibility: owns C runtime helper declarations for lowered output.
Consumes alias, widening, and typed facts by emitting only the helper surface
needed for already-materialized segmented memory and runtime abstractions.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Sequence

from inertia.frontend.x86_16.simos_86_16 import get_interrupt_handler_class
from inertia.lowering.analysis_helpers import (
    InterruptCall,
    interrupt_service_declarations,
    interrupt_service_spec,
)
from inertia.semantics.terminal_return_contract import WordInterruptReturnLayout8616

from .gp_word_runtime import GPRegisterRuntimeABI8616, coherent_gp_runtime_header_8616
from .near_pointer_value_runtime import NearPointerArgumentHelper8616, render_near_pointer_argument_runtime_8616

LOWERED_RUNTIME_HELPER_DECLARATIONS_8616: dict[str, str] = {
    "clock": "clock_t clock(void);",
    "rand": "int rand(void);",
    "srand": "void srand(unsigned int seed);",
    "time": "time_t time(time_t *out);",
    "strcpy": "char *strcpy(char *dst, const char *src);",
    "dos_int21_flags": "unsigned short dos_int21_flags(void);",
    "inertia_io_out8": "void inertia_io_out8(uint16_t port, uint8_t value);",
    "inertia_io_out16": "void inertia_io_out16(uint16_t port, uint16_t value);",
    "inertia_io_out32": "void inertia_io_out32(uint16_t port, uint32_t value);",
}

KNOWN_EXTERNAL_DECLARATIONS_8616: dict[str, str] = {
    "memset": "void * memset(void *dst, int value, unsigned short count);",
    "outtext": "void outtext(char *a0);",
    "sprintf": "int sprintf(char *buf, const char *fmt, ...);",
}

LOWERED_ZERO_ARG_RUNTIME_HELPER_DECLARATIONS_8616: dict[str, str] = {
    name: LOWERED_RUNTIME_HELPER_DECLARATIONS_8616[name]
    for name in iter(("clock", "rand"))
}

LOWERED_RUNTIME_MACROS_8616: frozenset[str] = frozenset(
    {
        "MEM_U8",
        "MEM_U16",
        "MEM_U32",
        "MK_FP",
        "NEAR_BYTE_ADD",
        NearPointerArgumentHelper8616.SINGLE_EVALUATION.value,
        "NEAR_OFFSET",
        "NEAR_PTR",
        "PTR_U16",
        "PTR_U32",
        "SEG_LINEAR",
        "SEG_PTR",
        "SEG_U8",
        "SEG_U16",
        "SEG_U32",
    }
)

# Exact external return ABIs override caller-use inference. An unused result
# proves only that the caller discards it; it does not change the callee ABI.
KNOWN_EXTERNAL_RETURN_TYPES_8616: dict[str, str] = {
    "getvideoconfig": "unsigned short",
    "memset": "void *",
    "outtext": "void",
    "intdos": "int",
    "intdosx": "int",
}

_MSC_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616: tuple[str, ...] = (
    "long aNldiv(long dividend, long divisor);",
)

_PORTABLE_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616: tuple[str, ...] = (
    "int32_t aNldiv(int32_t dividend, int32_t divisor);",
)

_TARGET_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616: dict[str, dict[str, str]] = {
    "msc-dos": {
        "aNldiv": _MSC_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616[0],
        "setbkcolor": "long setbkcolor(long color);",
    },
    "portable-flat": {
        "aNldiv": _PORTABLE_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616[0],
        "setbkcolor": "int32_t setbkcolor(int32_t color);",
    },
}

_RUNTIME_SEGMENT_STATE_DECLARATIONS_8616: tuple[str, ...] = (
    "extern uint16_t inertia_cs;",
    "extern uint16_t inertia_ds;",
    "extern uint16_t inertia_es;",
    "extern uint16_t inertia_ss;",
)


@cython.ccall
def runtime_helper_declaration_8616(name: object, target: object) -> object:
    """Return an exact external declaration owned by the selected C ABI."""
    declaration: object
    target_declarations: object
    normalized_target = str(target or "").strip().lower()
    target_declarations = _TARGET_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616.get(normalized_target, {})
    declaration = target_declarations.get(name)
    if declaration is not None:
        return declaration
    declaration = KNOWN_EXTERNAL_DECLARATIONS_8616.get(name)
    if declaration is not None:
        return declaration
    return LOWERED_RUNTIME_HELPER_DECLARATIONS_8616.get(name)


@cython.ccall
def interrupt_helper_declarations_8616(
    calls: Sequence[InterruptCall],
    api_style: object,
) -> object:
    """Lower typed interrupt calls to declarations for their emitted helpers."""
    call: object
    service_calls = [
        call
        for call in iter(calls)
        if call.vector == 0x21 or interrupt_service_spec(call) is not None
    ]
    declarations: list[str] = list(interrupt_service_declarations(service_calls, api_style))
    seen = set(declarations)
    for call in calls:
        handler = get_interrupt_handler_class(call.vector)
        return_type = "void" if handler.NO_RET else "unsigned short"
        if call.vector == 0x33 and call.ax == 0x0004:
            declaration = (
                f"{return_type} {handler.INT_NAME}(unsigned short ax, "
                "unsigned short cx, unsigned short dx);"
            )
        elif call.vector == 0x21:
            declaration = f"{return_type} {handler.INT_NAME}();"
        else:
            declaration = f"{return_type} {handler.INT_NAME}(void);"
        if declaration not in seen:
            seen.add(declaration)
            declarations.append(declaration)
    return declarations


@cython.ccall
def is_lowered_runtime_macro_8616(name: object) -> cython.bint:
    """Return whether lowering owns ``name`` as a C macro rather than a callable."""
    return name in LOWERED_RUNTIME_MACROS_8616


@cython.ccall
def render_pointer_storage_macros_8616(target: object) -> str:
    """Render target pointer-to-storage casts for headers and rebuild harnesses."""
    if target not in {"msc-dos", "portable-flat"}:
        raise ValueError(f"Unsupported pointer-storage target: {target!r}")
    intermediate_cast = "(uintptr_t)" if target == "portable-flat" else ""
    return (
        f"#define PTR_U16(ptr)       ((uint16_t){intermediate_cast}(ptr))\n"
        f"#define PTR_U32(ptr)       ((uint32_t){intermediate_cast}(ptr))\n"
    )


@cython.ccall
def render_near_pointer_arithmetic_macros_8616(target: object) -> object:
    """Render explicit guest-offset arithmetic, not native element arithmetic.

    Consumers must prove the source and result segment bindings and provide
    side-effect-free operands. Portable pointers must denote the supplied guest
    segment's memory view (or null); an unrelated native object aborts rather
    than contributing host address bits. Native DOS consumers additionally
    require the result segment to be the native near-data segment. This helper
    does not establish those bindings or infer a pointee type.
    """
    if target not in {"msc-dos", "portable-flat"}:
        raise ValueError(f"Unsupported near-pointer arithmetic target: {target!r}")
    if target == "msc-dos":
        offset = "#define NEAR_OFFSET(seg, ptr) ((uint16_t)(ptr))\n"
        pointer = "#define NEAR_PTR(seg, off) ((void near *)(uint16_t)(off))\n"
    else:
        offset = (
            "#define NEAR_OFFSET(seg, ptr) ((ptr) == 0 ? (uint16_t)0 : "
            "((uintptr_t)(ptr) - (uintptr_t)SEG_PTR((seg), 0) <= 0xffffUL ? "
            "(uint16_t)((uintptr_t)(ptr) - (uintptr_t)SEG_PTR((seg), 0)) : "
            "(abort(), (uint16_t)0)))\n"
        )
        pointer = (
            "#define NEAR_PTR(seg, off) ((uint16_t)(off) == 0 ? (void *)0 : "
            "(void *)SEG_PTR((seg), (uint16_t)(off)))\n"
        )
    return offset + pointer + (
        "#define NEAR_BYTE_ADD(src_seg, dst_seg, ptr, bytes) "
        "NEAR_PTR((dst_seg), (uint16_t)(NEAR_OFFSET((src_seg), (ptr)) + "
        "(uint16_t)(bytes)))\n"
    )


def _render_word_push_runtime_8616() -> str:
    """Render common physical stack writes after the segmented macros."""
    return (
        "#ifndef INERTIA_CALL_FRAME_WRITE\n"
        "#define INERTIA_CALL_FRAME_WRITE(ss, off, byte) (*(volatile uint8_t far *)SEG_PTR((ss), (off)) = (byte))\n"
        "#endif\n"
        "static uint16_t inertia_push_word(uint16_t ss, uint16_t sp, uint16_t value)\n"
        "{\n"
        "    sp = (uint16_t)(sp - 2u);\n"
        "    INERTIA_CALL_FRAME_WRITE(ss, sp, (uint8_t)value);\n"
        "    INERTIA_CALL_FRAME_WRITE(ss, (uint16_t)(sp + 1u), (uint8_t)(value >> 8));\n"
        "    return sp;\n"
        "}\n"
    )


@cython.ccall
def render_word_far_return_runtime_8616() -> str:
    """Render the word RETF runtime primitive after the segmented macros."""
    iret = WordInterruptReturnLayout8616
    return (
        "extern uint16_t inertia_ip;\n"
        "#ifndef INERTIA_RETF_BYTE\n"
        "#define INERTIA_RETF_BYTE(ss, off) (*(volatile uint8_t far *)SEG_PTR((ss), (off)))\n"
        "#endif\n"
        "static uint16_t inertia_stack_read_word(uint16_t ss, uint16_t sp)\n"
        "{\n"
        "    uint16_t value = INERTIA_RETF_BYTE(ss, sp);\n"
        "    value |= (uint16_t)((uint16_t)INERTIA_RETF_BYTE(ss, (uint16_t)(sp + 1u)) << 8);\n"
        "    return value;\n"
        "}\n"
        "static uint16_t inertia_call_far_word(uint16_t ss, uint16_t sp, uint16_t saved_ip, uint16_t target_cs, uint16_t target_ip)\n"
        "{\n"
        "    sp = inertia_push_word(ss, sp, inertia_cs);\n"
        "    sp = inertia_push_word(ss, sp, saved_ip);\n"
        "    inertia_cs = target_cs;\n"
        "    inertia_ip = target_ip;\n"
        "    return sp;\n"
        "}\n"
        "static uint16_t inertia_call_far_linear(uint16_t ss, uint16_t sp, uint32_t continuation, uint16_t target_cs, uint16_t target_ip)\n"
        "{\n"
        "    uint16_t saved_ip = (uint16_t)(continuation - ((uint32_t)inertia_cs << 4));\n"
        "    return inertia_call_far_word(ss, sp, saved_ip, target_cs, target_ip);\n"
        "}\n"
        "static uint16_t inertia_ret_word(uint16_t ss, uint16_t sp, uint16_t cleanup)\n"
        "{\n"
        "    uint16_t ip;\n"
        "    ip = inertia_stack_read_word(ss, sp);\n"
        "    inertia_ip = ip;\n"
        "    return (uint16_t)(sp + 2u + cleanup);\n"
        "}\n"
        "static uint16_t inertia_retf_word(uint16_t ss, uint16_t sp, uint16_t cleanup)\n"
        "{\n"
        "    uint16_t ip, cs;\n"
        "    ip = inertia_stack_read_word(ss, sp);\n"
        "    cs = inertia_stack_read_word(ss, (uint16_t)(sp + 2u));\n"
        "    inertia_ip = ip;\n"
        "    inertia_cs = cs;\n"
        "    return (uint16_t)(sp + 4u + cleanup);\n"
        "}\n"
        "extern uint16_t inertia_flags;\n"
        "static uint16_t inertia_iret_word(uint16_t ss, uint16_t sp)\n"
        "{\n"
        "    uint16_t ip, cs, flags;\n"
        "    ip = INERTIA_RETF_BYTE(ss, sp);\n"
        "    ip |= (uint16_t)((uint16_t)INERTIA_RETF_BYTE(ss, (uint16_t)(sp + 1u)) << 8);\n"
        f"    cs = INERTIA_RETF_BYTE(ss, (uint16_t)(sp + {iret.cs_displacement}u));\n"
        f"    cs |= (uint16_t)((uint16_t)INERTIA_RETF_BYTE(ss, (uint16_t)(sp + {iret.cs_displacement + 1}u)) << 8);\n"
        f"    flags = INERTIA_RETF_BYTE(ss, (uint16_t)(sp + {iret.flags_displacement}u));\n"
        f"    flags |= (uint16_t)((uint16_t)INERTIA_RETF_BYTE(ss, (uint16_t)(sp + {iret.flags_displacement + 1}u)) << 8);\n"
        "    inertia_ip = ip;\n"
        "    inertia_cs = cs;\n"
        f"    inertia_flags = (uint16_t)((flags & {iret.flags_writable_mask}u) | {iret.flags_fixed_mask}u);\n"
        f"    return (uint16_t)(sp + {iret.sp_displacement}u);\n"
        "}\n"
    )


@cython.ccall
def render_c_runtime_header_8616(
    target: object,
    *,
    gp_runtime_abi: GPRegisterRuntimeABI8616 = GPRegisterRuntimeABI8616.SCALAR,
    word_far_return: bool = False,
) -> object:
    """Return the C helper header for the requested generated-C target."""
    normalized = str(target or "").strip().lower()
    gp_header = (
        coherent_gp_runtime_header_8616()
        if gp_runtime_abi is GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS else ""
    )
    runtime_helper_declarations = "\n".join(LOWERED_RUNTIME_HELPER_DECLARATIONS_8616.values())
    runtime_segment_state_declarations = "\n".join(_RUNTIME_SEGMENT_STATE_DECLARATIONS_8616)
    far_return_runtime = render_word_far_return_runtime_8616() if word_far_return else ""
    if normalized == "msc-dos":
        compiler_helper_declarations = "\n".join(_MSC_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616)
        return gp_header + (
            "#include <DOS.H>\n"
            "\n"
            "typedef signed char    int8_t;\n"
            "typedef signed short   int16_t;\n"
            "typedef signed long    int32_t;\n"
            "typedef unsigned char  uint8_t;\n"
            "typedef unsigned short uint16_t;\n"
            "typedef unsigned long  uint32_t;\n"
            "typedef long clock_t;\n"
            "typedef long time_t;\n"
            "\n"
            f"{runtime_helper_declarations}\n"
            f"{compiler_helper_declarations}\n"
            f"{runtime_segment_state_declarations}\n"
            "\n"
            "#ifndef MK_FP\n"
            "#define MK_FP(seg, off) ((uint8_t far *)((((unsigned long)(unsigned short)(seg)) << 16) | (unsigned short)(off)))\n"
            "#endif\n"
            "\n"
            "#define SEG_PTR(seg, off)  MK_FP((seg), (off))\n"
            "#define SEG_U8(seg, off)   (*(uint8_t  far *)MK_FP((seg), (off)))\n"
            "#define SEG_U16(seg, off)  (*(uint16_t far *)MK_FP((seg), (off)))\n"
            "#define SEG_U32(seg, off)  (*(uint32_t far *)MK_FP((seg), (off)))\n"
            "#define MEM_U8(ptr)        (*(uint8_t  *)(ptr))\n"
            "#define MEM_U16(ptr)       (*(uint16_t *)(ptr))\n"
            "#define MEM_U32(ptr)       (*(uint32_t *)(ptr))\n"
            f"{render_pointer_storage_macros_8616(normalized)}"
            f"{render_near_pointer_arithmetic_macros_8616(normalized)}"
            f"{render_near_pointer_argument_runtime_8616(normalized)}"
            f"{_render_word_push_runtime_8616()}"
            f"{far_return_runtime}"
        )
    if normalized == "portable-flat":
        compiler_helper_declarations = "\n".join(_PORTABLE_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616)
        return gp_header + (
            "#include <stdbool.h>\n"
            "#include <stddef.h>\n"
            "#include <stdint.h>\n"
            "#include <stdlib.h>\n"
            "\n"
            "typedef long clock_t;\n"
            "typedef long time_t;\n"
            "\n"
            f"{runtime_helper_declarations}\n"
            f"{compiler_helper_declarations}\n"
            "\n"
            "extern uint8_t inertia_memory[];\n"
            f"{runtime_segment_state_declarations}\n"
            "\n"
            "#ifndef far\n"
            "#define far\n"
            "#endif\n"
            "\n"
            "#define SEG_LINEAR(seg, off) ((((uint32_t)(uintptr_t)(seg)) << 4) + ((uint16_t)(uintptr_t)(off)))\n"
            "#define MK_FP(seg, off)      (&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_PTR(seg, off)    ((char *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U8(seg, off)     (*(uint8_t  *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U16(seg, off)    (*(uint16_t *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U32(seg, off)    (*(uint32_t *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define MEM_U8(ptr)          (*(uint8_t  *)(ptr))\n"
            "#define MEM_U16(ptr)         (*(uint16_t *)(ptr))\n"
            "#define MEM_U32(ptr)         (*(uint32_t *)(ptr))\n"
            f"{render_pointer_storage_macros_8616(normalized)}"
            f"{render_near_pointer_arithmetic_macros_8616(normalized)}"
            f"{render_near_pointer_argument_runtime_8616(normalized)}"
            f"{_render_word_push_runtime_8616()}"
            f"{far_return_runtime}"
        )
    return gp_header


__all__ = [
    "KNOWN_EXTERNAL_DECLARATIONS_8616",
    "KNOWN_EXTERNAL_RETURN_TYPES_8616",
    "LOWERED_RUNTIME_HELPER_DECLARATIONS_8616",
    "LOWERED_RUNTIME_MACROS_8616",
    "LOWERED_ZERO_ARG_RUNTIME_HELPER_DECLARATIONS_8616",
    "interrupt_helper_declarations_8616",
    "is_lowered_runtime_macro_8616",
    "render_c_runtime_header_8616",
    "render_near_pointer_arithmetic_macros_8616",
    "render_pointer_storage_macros_8616",
    "runtime_helper_declaration_8616",
]
