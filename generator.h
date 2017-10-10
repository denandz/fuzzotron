/*
 * File:   generator.h
 * Author: DoI
 */

 #include <stdint.h>

 // Flip a bit, re-used from AFL
 #define FLIP_BIT(_ar, _b) do { \
     uint8_t* _arf = (uint8_t*)(_ar); \
     uint32_t _bf = (_b); \
     _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
   } while (0)

// linked list
struct testcase {
        unsigned long len;
        char * data;
        struct testcase * next;
};

struct testcase * generator_blab(char * count, char * grammar, char * path, char * prefix);
struct testcase * generator_radamsa(char * count, char * testcase_dir, char * path, char * prefix);
struct testcase * generate_swbitflip(char * input, unsigned long in_len, unsigned long offset, unsigned long count);
struct testcase * load_testcases(char * path, char * prefix);
int save_testcases(struct testcase * cases, char * path);
void save_case(char * data, unsigned long len, uint32_t hash, char * directory);
int save_case_p(char * data, unsigned long len, char * prefix, char * directory);
void free_testcases(struct testcase * cases);
