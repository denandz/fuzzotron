/*
 * File:   generator.h
 * Author: DoI
 */

#ifndef GENERATOR_H
#define GENERATOR_H

#include <stdint.h>

// Flip a bit, re-used from AFL
#define FLIP_BIT(_ar, _b) do { \
    uint8_t* _arf = (uint8_t*)(_ar); \
    uint32_t _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
} while (0)

// linked list
typedef struct {
        unsigned long len;
        char * data;
        void * next; // pointer to the next testcase in the list
} testcase_t;

testcase_t * generator_blab(char * count, char * grammar, char * path, char * prefix);
testcase_t * generator_radamsa(char * count, char * testcase_dir, char * path, char * prefix);
testcase_t * generate_swbitflip(char * input, unsigned long in_len, unsigned long offset, unsigned long count);
testcase_t * load_testcases(char * path, char * prefix);
int save_testcases(testcase_t * cases, char * path);
void save_case(char * data, unsigned long len, uint32_t hash, char * directory);
int save_case_p(char * data, unsigned long len, char * prefix, char * directory);
void free_testcases(testcase_t * cases);

#endif