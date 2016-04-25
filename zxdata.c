/* zxdata.c  -  Key Value data structure manipulations
 * Copyright (c) 2016 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing. See file COPYING.
 * Special grant: zxbusd.c may be used with zxid open source project under
 * same licensing terms as zxid itself.
 * $Id$
 *
 * 3.4.2016, created --Sampo
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
 * using -nkeys option according to available memory, key space slicing
 * and part operational experiences).
 */

#include <string.h>
#include <malloc.h>
#include <pthread.h>

#include "platform.h"
#include "errmac.h"
#include "hiios.h"    /* for struct hi_lock */
#include "zxdata.h"

extern struct hiios* shuff; /* global for accessing the shuffler and its todo_mut */

struct zx_lstr* zx_new_lstr(int len, const char* s)
{
#if 0
  struct zx_lstr* ls = malloc(sizeof(struct zx_lstr)+len);
  ls->len = len;
  ls->s = ((char*)ls)+sizeof(struct zx_lstr);
#else
  struct zx_lstr* ls = malloc(sizeof(struct zx_lstr));
  ls->len = len;
  ls->s = malloc(sizeof(struct zx_lstr));
#endif
  memcpy(ls->s, s, len);
  return ls;
}

/* Find the place in sparse array.
 * The position may be empty (miss) or it may contain pointer to some bucket,
 * but this function fors not check if the key of the bucket matches. */

static struct zx_bucket** zx_bucket_slot_by_len_key(struct zx_hash* h, int len, const char* key)
{
  int raw_hash;
  BHASH(key, len, raw_hash);
  return h->bucket + raw_hash % h->len;
}

struct zx_bucket* zx_get_by_len_key(struct zx_hash* h, int len, const char* key)
{
  struct zx_bucket** bktp = zx_bucket_slot_by_len_key(h, len, key);
  struct zx_bucket* bkt;
  for (bkt = *bktp; bkt; bkt = bkt->n) {
    if (len == bkt->key->len && !memcmp(key, bkt->key->s, len))
      return bkt;
  }
  return 0; /* miss */
}

struct zx_gbucket* zx_global_get_by_len_key(int len, const char* key)
{
  struct zx_bucket* bkt = zx_get_by_len_key(zx_gh, len, key);
  return (struct zx_gbucket*)bkt;
}

static struct zx_gbucket* zx_new_gbucket(int len, const char* key, struct zx_val* val)
{
  struct zx_gbucket* bkt = malloc(sizeof(struct zx_gbucket));
  memset(bkt, 0, sizeof(struct zx_gbucket));
  bkt->b.key = zx_new_lstr(len, key);
  memcpy(&bkt->b.val, val, sizeof(struct zx_val));
  LOCK_INIT(bkt->mut);
  return bkt;
}

struct zx_gbucket* zx_global_set_by_len_key(int len, const char* key, struct zx_val* val)
{
  struct zx_bucket** bktp = zx_bucket_slot_by_len_key(zx_gh, len, key);
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
    if (len == bkt->b.key->len && !memcmp(key, bkt->b.key->s, len)) {  /* hit */
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

struct zx_bucket* zx_set_by_len_key(struct zx_hash* h, int len, const char* key, struct zx_val* val)
{
  struct zx_bucket** bktp = zx_bucket_slot_by_len_key(h, len, key);
  struct zx_bucket*  bkt;
  struct zx_gbucket* kbkt;

  if (!*bktp) {  /* slot not yet occupied */
    *bktp = bkt = malloc(sizeof(struct zx_bucket));
    bkt->n = 0;
    goto keycopyval;
  }
  
  for (bkt = *bktp; bkt; bkt = bkt->n) {
    if (len == bkt->key->len && !memcmp(key, bkt->key->s, len))
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
