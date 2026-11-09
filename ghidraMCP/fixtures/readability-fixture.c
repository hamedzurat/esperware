#include <stdint.h>

static uint32_t mix(uint32_t value, uint32_t salt) {
    value ^= salt + 0x9e3779b9u + (value << 6) + (value >> 2);
    value = (value ^ (value >> 16)) * 0x7feb352du;
    return value ^ (value >> 15);
}

uint32_t transform(uint32_t input, uint32_t key) {
    uint32_t state = mix(input, key);
    if ((state & 3u) == 0u) state += key;
    else state ^= input >> 3;
    return mix(state, input);
}

int main(int argc, char **argv) {
    uint32_t value = (uint32_t) argc;
    if (argv != 0) value = transform(value, (uint32_t) argv[0][0]);
    return (int) (value & 0x7fu);
}
