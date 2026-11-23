#include <stdint.h>

uint16_t *witness_word(uint16_t segment, uint16_t offset);
uint16_t inertia_retf_word(uint16_t segment, uint16_t sp, uint16_t cleanup);
#define SEG_U16(segment, offset) (*witness_word((segment), (offset)))
