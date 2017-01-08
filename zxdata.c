/* zxdata.c  -  Key Value data structure manipulations
 * Copyright (c) 2016 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing. See file COPYING.
 * Special grant: zxdata.c may be used with zxid open source project under
 * same licensing terms as zxid itself.
 * $Id$
 *
 * 3.4.2016, created --Sampo
 * 13.12.2016, review, comments --Sampo
 *
 * The locking strategy for the global hash keys is a bit unorthodox: the basic
 * idea is to have a global lock protecting writes and we use the relatively
 * often taken shuffler->todo_mut for this purpose. The idea is that
 * the writes are absolutely safe while reads will be up to date "soon
 * enough" (as soon as the thread runs through main loop of shuffler)
 * and are not burdened with locking overhead. We also use aligned
 * pointers for which reads and writes are atomic on ix86 and ix86_64 (AMD64)
 * architectures. This should ensure that there will not be corrupt pointers.
 *
 * Each global hash bucket is protected by its own lock which will
 * ensure safe reads and writes of the actual data.
 *
 * To further simplify matters, keys are never deleted from the global hash
 * and the global hash is never rehashed (its size is tuned at startup
 * using -nkeys option according to the available memory, key space slicing
 * and past operational experiences). If this memory is not enough, machine
 * will need to be upgraded, and process restarted with bigger -nkeys (vertical
 * scaling), or a horizontal scaling with more machines deployed in new slices
 * will need to be engaged.
 */

#include <string.h>
#include <malloc.h>
#include <pthread.h>

#include "platform.h"
#include "errmac.h"
#include "hiios.h"    /* for struct hi_lock */
#include "zx.h"
#include "zxdata.h"

extern struct hiios* shuff; /* global for accessing the shuffler and its todo_mut */

/* Called by:  zx_msgpack2val2 x24 */
struct zx_val* zx_new_val(struct zx_ctx* c, int kind)
{
  struct zx_val* val = ZX_ZALLOC(c, struct zx_val);
  val->kind = kind;
  return val;
}

/*() Free a val object
 *
 * c:: context object for memory allocation
 * val:: value to be freed
 * deep:: Flag indicating whether to chase rependent data structures and free them, too
 *     - 0 = shallow free
 *     - 1 = medium free: free one layer of string, array, and hash, but do not chase
 *     - 2 or more = deep free: chase the entire data structure and free all, but do not
 *       exceed recursion depth specified by deep. Suggested value 100 for normal use.
 * return:: Always returns 0, which can be used to nullify pointer at caller size.
 */

/* Called by:  zx_free_bucket, zx_free_val */
static void zx_free_val_dep(struct zx_ctx* c, struct zx_val* val, int deep)
{
  int i;
  struct zx_bucket* pb;
  struct zx_bucket* b;

  switch (val->kind) {
  case ZXVAL_NIL: /* 0 */
  case ZXVAL_INT: /* 1 */
  case ZXVAL_DBL: /* 2 */
  case ZXVAL_BOOL: /* 4 */
    break;
  case ZXVAL_STR: /* 3 */
    if (!(val->flags & 0x01) && val->ue.s)
      ZX_FREE(c, val->ue.s);
    break;
    
  case ZXVAL_ARY: /* 5 */
  case ZXVAL_KEYVAL: /* 7 */
    if (deep>1) {
      for (i = 0; i < val->len+val->spares; ++i)
	zx_free_val(c, val->ue.a+i, deep-1);
    }
    ZX_FREE(c, val->ue.a);
    break;
    
  case ZXVAL_HASH: /* 6 */
    if (deep>1) {	
      for (i = 0; i < val->len; ++i) {
	for (pb = val->ue.h[i], b = pb?pb->n:0; pb && b; pb = b, b = pb->n) {
	  zx_free_bucket(c, pb, deep-1);
	}
	if (pb)
	  zx_free_bucket(c, pb, deep-1);
      }
    }
    ZX_FREE(c, val->ue.h);
    break;
    
  case ZXVAL_PACK: /* 7 */
  default:
    ERR("unknown val->kind=0x%x", val->kind);
  }
}

/* Called by:  zx_free_val_dep, zx_msgpack2val2 */
struct zx_val* zx_free_val(struct zx_ctx* c, struct zx_val* val, int deep)
{
  if (deep)
    zx_free_val_dep(c, val, deep);
  ZX_FREE(c, val);
  return 0;
}

/*() Promote kind of val object to string
 * This is not proper deep serialization. It merely converts ints to strings.
 * This is often needed as hash keys have to be strings.
 *
 * c:: context object for memory allocation
 * val:: value to be freed
 */

/* Called by:  zx_msgpack2val2 */
const char* zx_val_to_str(struct zx_ctx* c, struct zx_val* val)
{
  int len;
  switch (val->kind) {
  case ZXVAL_NIL: /* 0 */
  case ZXVAL_INT: /* 1 */
  case ZXVAL_DBL: /* 2 */
  case ZXVAL_BOOL: /* 4 */
    val->kind = ZXVAL_STR;
    val->ue.s = zx_alloc_sprintf(c, &len, "%d", val->ue.i);
    val->len = len;
    break;
  case ZXVAL_ARY: /* 5 */
  case ZXVAL_KEYVAL: /* 7 */
    val->kind = ZXVAL_STR;
    val->ue.s = zx_alloc_sprintf(c, &len, "ary_%p", val->ue.a);
    val->len = len;
    break;
  case ZXVAL_HASH: /* 6 */
    val->kind = ZXVAL_STR;
    val->ue.s = zx_alloc_sprintf(c, &len, "hash_%p", val->ue.a);
    val->len = len;
    break;
  case ZXVAL_STR: /* 3 */
    break;
  case ZXVAL_PACK: /* 7 */
  default:
    ERR("unknown val->kind=0x%x", val->kind);
  }
  return val->ue.s;
}

/*(-) Find the place in sparse array.
 * The position may be empty (miss) or it may contain pointer to some bucket,
 * but this function does not check if the key of the bucket matches. */

/* Called by:  zx_get_by_len_key, zx_global_set_by_len_key, zx_set_by_len_key */
static struct zx_bucket** zx_bucket_slot_by_len_key(int hlen, struct zx_bucket** h, int len, const char* key)
{
  int raw_hash;
  BHASH(key, len, raw_hash);
  return h + raw_hash % hlen;
}

/* Called by:  zx_global_get_by_len_key */
struct zx_bucket* zx_get_by_len_key(int hlen, struct zx_bucket** h, int len, const char* key)
{
  struct zx_bucket** bktp = zx_bucket_slot_by_len_key(hlen, h, len, key);
  struct zx_bucket* bkt;
  for (bkt = *bktp; bkt; bkt = bkt->n) {
    if (len == bkt->len && !memcmp(key, bkt->key, len))
      return bkt;
  }
  return 0; /* miss */
}

/* Called by:  mcdb_got_get, zx_set_by_len_key */
struct zx_gbucket* zx_global_get_by_len_key(int len, const char* key)
{
  struct zx_bucket* bkt = zx_get_by_len_key(zx_ghlen, (struct zx_bucket**)zx_gh, len, key);
  return (struct zx_gbucket*)bkt;
}

/*() Create a new global hash bucket
 * Copy of the key string is always made.
 */

/* Called by:  zx_global_set_by_len_key x2 */
static struct zx_gbucket* zx_new_gbucket(int len, const char* key, struct zx_val* val)
{
  struct zx_gbucket* bkt = malloc(sizeof(struct zx_gbucket));
  memset(bkt, 0, sizeof(struct zx_gbucket));
  bkt->b.len = len;
  bkt->b.key = malloc(len);
  memcpy(bkt->b.key, key, len);
  memcpy(&bkt->b.val, val, sizeof(struct zx_val));
  LOCK_INIT(bkt->mut);
  return bkt;
}

/* Called by:  zx_free_val_dep x2 */
struct zx_bucket* zx_free_bucket(struct zx_ctx* c, struct zx_bucket* b, int deep)
{
  zx_free_val_dep(c, &b->val, deep);
  ZX_FREE(c, b);
  return 0;
}

/*() Insert into global hash.
 *
 * len:: Length of the key string
 * key:: Key string. Copy of the string is made (unless already in the hash).
 * val:: Value to be stored in the hash. The zx_val object is copied. No copy of
 *     the underlying string, array, or second order hash is made.
 * return:: The hash element that was referenced
 */

/* Called by:  mcdb_got_set, zx_set_by_len_key */
struct zx_gbucket* zx_global_set_by_len_key(int len, const char* key, struct zx_val* val)
{
  struct zx_bucket** bktp = zx_bucket_slot_by_len_key(zx_ghlen, (struct zx_bucket**)zx_gh, len, key);
  struct zx_gbucket*  bkt = (struct zx_gbucket*)*bktp;
  D("key(%.*s) bktp=%p bkt=%p", len, key, bktp, bkt);
  
  if (!bkt) {  /* miss: slot not yet occupied */
    bkt = zx_new_gbucket(len, key, val);
    LOCK(shuff->todo_mut, "global_set1");
    *bktp = &bkt->b;
    UNLOCK(shuff->todo_mut, "global_set1");
    return bkt;
  }
  
  for (bkt = (struct zx_gbucket*)*bktp; bkt; bkt = (struct zx_gbucket*)bkt->b.n) {
    if (len == bkt->b.len && !memcmp(key, bkt->b.key, len)) {  /* hit */
      LOCK(bkt->mut, "global_set2");
      memcpy(&bkt->b.val, val, sizeof(struct zx_val));
      UNLOCK(bkt->mut, "global_set2");
      return bkt;
    }
  }
  
  /* slot occupied, but miss for our key: insert the new bucket after
   * the first bucket (we want to leave the first in the slot
   * so we do not need to take lock protecting entire hash array). */
  bkt = zx_new_gbucket(len, key, val);
  LOCK(shuff->todo_mut, "global_set3");
  bkt->b.n = (*bktp)->n;
  (*bktp)->n = &bkt->b;
  UNLOCK(shuff->todo_mut, "global_set3");
  return bkt;
}

/*() Insert into normal hash.
 *
 * hlen:: Length of the hash array, usually sparese, more than the keys in the hash
 * h:: The hash table array from whihc linked list of zx_buckets hang
 * len:: Length of the key string
 * key:: Key string. Copy of the string is made (unless already in the hash).
 * val:: Value to be stored in the hash. The zx_val object is copied. No copy of
 *     the underlying string, array, or second order hash is made.
 * return:: The hash element that was referenced
 *
 * N.B. Current implementation of normal hashes still uses global hash for keeping
 * the keys (so every key is only stored once). Thus a normal hash insert can cause
 * a globabl hash insert, with consequent locking.
 */

/* Called by:  zx_msgpack2val2 */
struct zx_bucket* zx_set_by_len_key(int hlen, struct zx_bucket** h, int len, const char* key, struct zx_val* val)
{
  struct zx_bucket** bktp = zx_bucket_slot_by_len_key(hlen, h, len, key);
  struct zx_bucket*  bkt;
  struct zx_gbucket* kbkt;

  if (!*bktp) {  /* slot not yet occupied */
    *bktp = bkt = malloc(sizeof(struct zx_bucket));
    bkt->n = 0;
    goto keycopyval;
  }
  
  for (bkt = *bktp; bkt; bkt = bkt->n) {
    if (len == bkt->len && !memcmp(key, bkt->key, len))
      goto copyval;
  }
  /* slot occupied, but miss for our key: insert the new bucket after
   * the first bucket (we want to leave the first in the slot
   * so we do not need to take lock protecting entire hash array). */
  bkt = malloc(sizeof(struct zx_bucket));
  bkt->n = (*bktp)->n;
  (*bktp)->n = bkt;

keycopyval:
  // Put the key to the global hash
  if (!(kbkt = zx_global_get_by_len_key(len, key))) {
    struct zx_val val;
    memset(&val, 0, sizeof(val));  /* dummy value just as place holder for key string */
    kbkt = zx_global_set_by_len_key(len, key, &val);
  }
  bkt->key = kbkt->b.key;
copyval:
  memcpy(&bkt->val, val, sizeof(struct zx_val));
  return bkt;
}

/* EOF  --  zxdata.c */
