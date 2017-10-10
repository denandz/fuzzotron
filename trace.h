/*
* Various bitmap tracing tools. Mostly liberated from afl-fuzz http://lcamtuf.coredump.cx/afl/
*/

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
#define HASH_CONST          0xa5b35705
#define NULL_HASH           2982225436 // when an empty bitmap is hashed

#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

uint32_t wait_for_bitmap(const void * trace_bits);
uint8_t * setup_shm(int shm_id);
uint8_t has_new_bits(uint8_t * virgin_map, uint8_t * trace_bits);
