/* ===================================================================== */
/* This file is a little helper to compute DES key scheduling            */
/* from the first round key                                              */
/* Original authors: Charles Hubain <me@haxelion.eu>  2016               */
/*                   Philippe Teuwen <phil@teuwen.org> 2016              */
/*                                                                       */
/* Usage:                                                                */
/* des_keyschedule DES_key_in_hex                                        */
/* des_keyschedule Round_key_in_hex plaintext_in_hex ciphertext_in_hex   */
/*                                                                       */
/* Examples:                                                             */
/* des_keyschedule 11223344556677881122334455667788                      */
/* des_keyschedule 23D7F7B876B180306793B37432F5C4FC 1                    */
/* des_keyschedule 43EDA420DD033E7627347DC2CC6E0B4E 9                    */
/* des_keyschedule EAC68B6B37C5B51D10F1C8DFDC9FC391 10                   */
/*                                                                       */
/* Note that parity bits are always discarded                            */
/*                                                                       */
/* Based on the unlicensed DES code https://github.com/mimoo/DES         */
/* and released under the same licensing terms:                          */
/*                                                                       */
/* This is free and unencumbered software released into the public domain*/
/*                                                                       */
/* Anyone is free to copy, modify, publish, use, compile, sell, or       */
/* distribute this software, either in source code form or as a compiled */
/* binary, for any purpose, commercial or non-commercial, and by any     */
/* means.                                                                */
/*                                                                       */
/* In jurisdictions that recognize copyright laws, the author or authors */
/* of this software dedicate any and all copyright interest in the       */
/* software to the public domain. We make this dedication for the benefit*/
/* of the public at large and to the detriment of our heirs and          */
/* successors. We intend this dedication to be an overt act of           */
/* relinquishment in perpetuity of all present and future rights to this */
/* software under copyright law.                                         */
/*                                                                       */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,       */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF    */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.*/
/* IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR     */
/* OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, */
/* ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR */
/* OTHER DEALINGS IN THE SOFTWARE.                                       */
/*                                                                       */
/* For more information, please refer to <http://unlicense.org/>         */
/* ===================================================================== */

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
