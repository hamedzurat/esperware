#include <stdint.h>

typedef struct {
    uint32_t value;
    uint32_t salt;
} ProbeState;

volatile ProbeState probe_state;

static uint32_t mix(uint32_t value, uint32_t salt) {
    value ^= salt + 0x9e3779b9u + (value << 6) + (value >> 2);
    value = (value ^ (value >> 16)) * 0x7feb352du;
    return value ^ (value >> 15);
}

uint32_t transform(uint32_t input, uint32_t key) {
    probe_state.value = input;
    probe_state.salt = key;
    uint32_t state = mix(probe_state.value, probe_state.salt);
    if ((state & 3u) == 0u) state += key;
    else state ^= input >> 3;
    probe_state.value = mix(state, input);
    return probe_state.value;
}

int main(int argc, char **argv) {
    uint32_t value = (uint32_t) argc;
    if (argv != 0) value = transform(value, (uint32_t) argv[0][0]);
    return (int) (value & 0x7fu);
}
