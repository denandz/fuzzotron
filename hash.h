// Shamelessly liberated from AFL. Thanks lcamtuf!

/*
   american fuzzy lop - hashing function
   -------------------------------------

   The hash32() function is a variant of MurmurHash3, a good
   non-cryptosafe hashing function developed by Austin Appleby.

   For simplicity, this variant does *NOT* accept buffer lengths
   that are not divisible by 8 bytes. The 32-bit version is otherwise
   similar to the original; the 64-bit one is a custom hack with
   mostly-unproven properties.

   Austin's original code is public domain.

   Other code written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _HAVE_HASH_H
#define _HAVE_HASH_H

#ifdef __x86_64__

#define ROL64(_x, _r)  ((((uint64_t)(_x)) << (_r)) | (((uint64_t)(_x)) >> (64 - (_r))))

static inline uint32_t hash32(const void* key, uint32_t len, uint32_t seed) {

  const uint64_t* data = (uint64_t*)key;
  uint64_t h1 = seed ^ len;

  len >>= 3;

  while (len--) {

    uint64_t k1 = *data++;

    k1 *= 0x87c37b91114253d5ULL;
    k1  = ROL64(k1, 31);
    k1 *= 0x4cf5ad432745937fULL;

    h1 ^= k1;
    h1  = ROL64(h1, 27);
    h1  = h1 * 5 + 0x52dce729;

  }

  h1 ^= h1 >> 33;
  h1 *= 0xff51afd7ed558ccdULL;
  h1 ^= h1 >> 33;
  h1 *= 0xc4ceb9fe1a85ec53ULL;
  h1 ^= h1 >> 33;

  return h1;

}

#else

#define ROL32(_x, _r)  ((((uint32_t)(_x)) << (_r)) | (((uint32_t)(_x)) >> (32 - (_r))))

static inline uint32_t hash32(const void* key, uint32_t len, uint32_t seed) {

  const uint32_t* data  = (uint32_t*)key;
  uint32_t h1 = seed ^ len;

  len >>= 2;

  while (len--) {

    u32 k1 = *data++;

    k1 *= 0xcc9e2d51;
    k1  = ROL32(k1, 15);
    k1 *= 0x1b873593;

    h1 ^= k1;
    h1  = ROL32(h1, 13);
    h1  = h1 * 5 + 0xe6546b64;

  }

  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return h1;

}

#endif /* ^__x86_64__ */

#endif /* !_HAVE_HASH_H */
