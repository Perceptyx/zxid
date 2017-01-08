/* zxdata.h  -  Cache Hash and data structure definitions
 * Copyright (c) 2016 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing. See file COPYING.
 * Special grant: zxdata.h may be used with zxid open source project under
 * same licensing terms as zxid itself.
 * $Id$
 *
 * 6.4.2016,  created --Sampo
 *
 * The zxcached incorporates an in-memory database implemented using a
 * global hash which points to data items that may be either raw data or
 * in their own right data structures, such as local hashes. Basically
 * same hash (and array) definitions are applied to both, but there
 * are differences in locking and key allocation.
 *
 * The global hash itself is governed by a global lock. Adding keys
 * to the hash is only possible under the lock. Reading the keys
 * does not require any lock. This is a deliberate optimization
 * in favour of reads. However, each value is governed by its own lock,
 * so changing the values does not cause contention on the global lock.
 *
 * Th local hashes use the global hash as key store, i.e. each key
 * kets stored exactly once irrespective of how many times it is
 * used by the local hashes.
 */

#ifndef _zxdata_h
#define _zxdata_h

#include "zx.h"
#include "zxid.h"
#include "hiios.h"    /* for struct hi_lock */

/* Possible data type kinds for execution environment */

#define ZXVAL_NIL  0
#define ZXVAL_INT  1
#define ZXVAL_DBL  2
#define ZXVAL_STR  3
#define ZXVAL_BOOL 4    /* value stored in val.ue.i */
#define ZXVAL_ARY  5
#define ZXVAL_HASH 6
#define ZXVAL_KEYVAL 7  /* unhashed array of key value pairs (lazy hash when deserializing) */
#define ZXVAL_PACK 8

struct zx_val {
  long len;              /* length of string s, array a, or hash h */
  unsigned short spares; /* number of spare elements in the end of an array or string */
  unsigned char flags;   /* 0x01 the memory of str (or array or hash) should not be freed */
  unsigned char kind;    /* See ZXVAL_* constants */
  union {
    long long i; /* 64bit */
    long i32;
    float f;
    double d;
    char* s;
    struct zx_val** a;
    struct zx_bucket** h;
    struct zx_gbucket** gh;

    //struct zx_lstr ls;  /* string: length + char* */
    //struct zx_ary* ary;
    //struct zx_hash* hash;
  } ue;
};

//struct zx_ary {
//  int len;
//  struct zx_val val[];
//};

/* Normal hash bucket. If there is a hash collision, n (next) pointer chains the buckets. */

struct zx_bucket {
  struct zx_bucket* n;
  char* key;
  long len;
  unsigned char pad0;
  unsigned char pad1;
  unsigned char pad2;
  unsigned char pad3;
  struct zx_val val;
};

/* Global hash bucket. This adds fields needed for replication and memcached binary
 * protocol support. */

struct zx_gbucket {
  struct zx_bucket b;
  long long updatens;  /* 64bit last update timestamp (ns) for replication, see clock_gettime(2) */
  long long expiryns;  /* 64bit seconds since unix epoch */
  struct hi_lock mut;  /* data lock */
  unsigned char symkey[32]; /* AES256 (or other algo) symmetric encryption key */
};

/* Record type for global hash msgpack.org values with evaluation environment */

struct zx_pack {
  struct zx_val* val;  /* expanded data structure */
  char* raw;
  long len;
  unsigned char pad0;
  unsigned char pad1;
  unsigned char pad2;
  unsigned char pad3;
};

extern int zx_ghlen;   /* the global hash sparse length */
extern struct zx_gbucket** zx_gh;  /* the global hash */

struct zx_bucket* zx_get_by_len_key(int hlen, struct zx_bucket** h, int len, const char* key);
struct zx_gbucket* zx_global_get_by_len_key(int len, const char* key);
struct zx_bucket* zx_set_by_len_key(int hlen, struct zx_bucket** h, int len, const char* key, struct zx_val* val);
struct zx_gbucket* zx_global_set_by_len_key(int len, const char* key, struct zx_val* val);

struct zx_bucket* zx_free_bucket(struct zx_ctx* c, struct zx_bucket* b, int deep);
struct zx_val* zx_new_val(struct zx_ctx* c, int kind);
struct zx_val* zx_free_val(struct zx_ctx* c, struct zx_val* val, int deep);

int zx_val2msgpack(struct zx_val* val, int maxlen, unsigned char* buf, int maxrecurse, int flags);
struct zx_val* zx_msgpack2val2(struct zx_ctx* c, unsigned char** buf, unsigned char* lim, int flags);
struct zx_val* zx_msgpack2val(struct zx_ctx* c, int len, unsigned char* buf, int flags);

int zx_global_write(zxid_conf* cf, int ghkeylen, const char* ghkey, const unsigned char* symkey, struct zx_val* val);

const char* zx_val_to_str(struct zx_ctx* c, struct zx_val* val);

#endif /* _zxdata_h */
