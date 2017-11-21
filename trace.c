/*
* Various bitmap tracing tools. Mostly liberated from afl with minor tweaking.
* Thanks lcamtuf! http://lcamtuf.coredump.cx/afl/
*/

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/shm.h>

#include "hash.h"
#include "trace.h"
#include "util.h"


uint8_t * setup_shm(int shm_id){
    uint8_t * trace_bits;
    trace_bits = shmat(shm_id, NULL, 0);
    if (trace_bits == (uint8_t *)-1){
        fatal("[!] shmat() failed: %s\n", strerror(errno));
    }

    return trace_bits;
}

// will watch the bitmap and loop untill the bitmap stops changing
uint32_t wait_for_bitmap(const void* trace_bits){
    uint32_t checksum;
    uint32_t previous_checksum = 0;
    long null_count = 0, hash_count = 0;

    while(1){
        checksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

        if (checksum == NULL_HASH){
            // null ?
            null_count++;
            if(null_count > 200) // nada after 2 seconds
                return NULL_HASH;
            else{
                usleep(10000);
                continue;
            }
        }

        if(previous_checksum == checksum)
            break;

        previous_checksum = checksum;
        hash_count++;
        if(hash_count > 200) // still changing after 2 seconds
            return 0;

        usleep(50000);
    }
    //printf("bitmap stopped changing\n");
    return checksum;
}

/* Shamelessly liberated from AFL (http://lcamtuf.coredump.cx/afl/)

   Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

uint8_t has_new_bits(uint8_t * virgin_map, uint8_t * trace_bits) {

#ifdef __x86_64__

  uint64_t * current = (uint64_t *)trace_bits;
  uint64_t * virgin  = (uint64_t *)virgin_map;

  uint32_t  i = (MAP_SIZE >> 3);

#else

  uint32_t * current = (uint32_t *)trace_bits;
  uint32_t * virgin  = (uint32_t *)virgin_map;

  uint32_t i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

  uint8_t   ret = 0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        uint8_t * cur = (uint8_t *)current;
        uint8_t * vir = (uint8_t *)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef __x86_64__

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;

#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1;

#endif /* ^__x86_64__ */

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  return ret;
}
