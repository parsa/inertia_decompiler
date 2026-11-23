/* Scratch host ABI adapter. Includes the unmodified 1283C file; 29B99 is a separate TU. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "host_abi.h"
#include "../exact-gp-29b99/00029b99-sub_29b99.c"
static void sub_1283c(void) { abort(); }

inertia_gp_lane inertia_gp_eax, inertia_gp_ebx, inertia_gp_esp, inertia_gp_ebp;
uint16_t bx, inertia_ds, inertia_ss, inertia_flags, xffff;
uint16_t sub_29b99(uint16_t index, uint16_t owner);

static uint16_t linear_words[0x80000];
static uint16_t *pending;
static uint16_t pending_offset, cs, ip;
static unsigned witness_function;

static unsigned input_hex(void)
{
    unsigned value;
    if (scanf("%x", &value) != 1)
        abort();
    return value;
}

static uint16_t *word(uint16_t segment, uint16_t offset)
{
    assert(!(offset & 1));
    assert(segment == inertia_ds || segment == inertia_ss);
    unsigned linear = ((unsigned)segment << 4) + offset;
    assert(linear < 0x100000);
    return &linear_words[linear / 2];
}

static void flush_write(void)
{
    if (pending) {
        printf("DS W %04x:%04x 2 %04x\n", inertia_ds, pending_offset, *pending);
        pending = NULL;
    }
}

uint16_t *witness_word(uint16_t segment, uint16_t offset)
{
    assert(segment == inertia_ds);
    uint16_t *p = word(segment, offset);
    flush_write();
    if (witness_function == 0x1283c) {
        pending = p;
        pending_offset = offset;
    } else {
        printf("DS R %04x:%04x 2 %04x\n", segment, offset, *p);
    }
    return p;
}

uint16_t inertia_retf_word(uint16_t segment, uint16_t sp, uint16_t cleanup)
{
    flush_write();
    assert(segment == inertia_ss);
    ip = *word(segment, sp);
    printf("SS R %04x:%04x 2 %04x\n", segment, sp, ip);
    cs = *word(segment, sp + 2);
    printf("SS R %04x:%04x 2 %04x\n", segment, sp + 2, cs);
    return sp + 4 + cleanup;
}

int main(void)
{
    witness_function = input_hex();
    inertia_ds = input_hex(); inertia_ss = input_hex();
    inertia_eax = input_hex(); inertia_ebx = input_hex();
    inertia_ebp = input_hex(); inertia_esp = input_hex();
    inertia_flags = input_hex();
    const unsigned count = input_hex();
    for (unsigned i = 0; i < count; ++i) {
        const unsigned segment = input_hex(), offset = input_hex();
        *word(segment, offset) = input_hex();
    }
    if (witness_function == 0x1283c) {
        sub_1283c();
    } else {
        assert(witness_function == 0x29b99);
        uint16_t index = *word(inertia_ss, (uint16_t)inertia_esp + 4);
        uint16_t owner = *word(inertia_ss, (uint16_t)inertia_esp + 6);
        uint16_t result = sub_29b99(index, owner);
        assert(result == (uint16_t)inertia_eax);
    }
    printf("EXIT EAX=%08x EBX=%08x EBP=%08x ESP=%08x FLAGS=%04x CS:IP=%04x:%04x\n",
           inertia_eax, inertia_ebx, inertia_ebp, inertia_esp, inertia_flags, cs, ip);
    for (unsigned i = 0; i < count; ++i) {
        const unsigned segment = input_hex(), offset = input_hex();
        printf("FINAL %04x:%04x %04x\n", segment, offset, *word(segment, offset));
    }
}
