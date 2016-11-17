#include "DES.h"
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>


int main(int argc, char **argv) {
    uint64_t key, round_key, next_key, possible_keys[256];
    if(argc < 2) {
        printf("Please give a key as argument\n");
        return 1;
    }
    key = strtoull(argv[1], NULL, 16);
    printf("Input key: %016" PRIx64 "\n", key);
    round_key = key;
    key_schedule(&round_key, &next_key, 0);
    printf("Round key: %016" PRIx64 "\n", round_key);
    printf("Reversing round key...\n");
    reverse_key_schedule(round_key, 0, possible_keys);
    for(int i = 0; i < 256; i++) {
        printf("%016" PRIx64 "\n", possible_keys[i]);
        if((possible_keys[i] & 0x00000000fefefefefefe) == (key & 0x00000000fefefefefefe)) {
            printf("Key found at offset %d!\n", i);
            return 0;
        }
    }
    printf("Key not found :(\n");
    return 1;
}
