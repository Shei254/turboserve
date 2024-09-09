#include <stdint.h>
#include <stdlib.h>

extern "C" {
bool turboserve_h2_huffman_decode_for_fuzzing(const uint8_t *input,
                                        size_t input_len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return turboserve_h2_huffman_decode_for_fuzzing(data, size) == true;
}
}
