/* zxmsgpack.c  -  Serialize and deserialize zx_val to msgpack
 * Copyright (c) 2016 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing. See file COPYING.
 * Special grant: zxbusd.c may be used with zxid open source project under
 * same licensing terms as zxid itself.
 * $Id$
 *
 * 27.4.2016, created --Sampo
 *
 * We aim to support MessagePack (msgpack) specification of 2013-04-21 21:52:33 -0700
 * as found in https://github.com/msgpack/msgpack/blob/master/spec.md
 */

#include <string.h>
#include <malloc.h>
#include <pthread.h>

#include "platform.h"
#include "errmac.h"
#include "zx.h"
#include "zxid.h"
#include "zxdata.h"

/*() Compute length of msgpack serialization of a value and optionally render the serializatio
 * val:: Value (can be root of a complex data structure)
 * maxlen:: Maxium amount that will be rendered to the buffer (i.e. the size of the buffer)
 * buf:: Buffer where msgpack output is rendered. If 0, only length computation is performed.
 * maxrecurse:: How deep recursion to data structure is allwed. Keeps us from getting
 *     in trouble with data structures that are cyclic (they never should be) or
 *     extremely deep. Reasonable value is perhaps 100.
 * flags:: Flags determining how the serialization is to be done
 * return:: The length of the serialization (how big the buffer needs to be)
 */

int zx_val2msgpack(struct zx_val* val, int maxlen, unsigned char* buf, int maxrecurse, int flags)
{
  int i,len,cnt;
  struct zx_bucket* b;
  
  if (!val)
    return 0;
  if (!maxrecurse)
    return 0;

  switch (val->kind) {
  case ZXVAL_NIL: /* 0 */
    if (buf && maxlen > 0)
      *buf = 0xc0;
    return 1;

  case ZXVAL_INT: /* 1 */
    if (IN_RANGE(val->ue.i, 0, 127)) {
      if (buf && maxlen > 0)
	*buf = val->ue.i;
      return 1;
    } 
    if (IN_RANGE(val->ue.i, -32, -1)) {
      if (buf && maxlen > 0)
	*buf = (unsigned char)(val->ue.i);
      return 1;
    } 
    if (IN_RANGE(val->ue.i, 0, 255)) {
      if (buf && maxlen > 1) {
	buf[0] = 0xcc;
	buf[1] = val->ue.i;
      }
      return 2;
    }
    if (IN_RANGE(val->ue.i, -128, -1)) {
      if (buf && maxlen > 1) {
	buf[0] = 0xd0;
	*buf = (unsigned char)val->ue.i;
      }
      return 2;
    }
    if (IN_RANGE(val->ue.i, 0, 65535)) {
      if (buf && maxlen > 2) {
	buf[0] = 0xcd;
	buf[1] = (val->ue.i >> 8) & 0xff;
	buf[2] = val->ue.i & 0xff;
      }
      return 3;
    }
    if (IN_RANGE(val->ue.i, -32768, -1)) {
      if (buf && maxlen > 2) {
	buf[0] = 0xd1;
	buf[1] = (val->ue.i >> 8) & 0xff;
	buf[2] = val->ue.i & 0xff;
      }
      return 3;
    }
    if (IN_RANGE(val->ue.i, 0, 2<<32-1)) {
      if (buf && maxlen > 4) {
	buf[0] = 0xce;
	buf[1] = (val->ue.i >> 24) & 0xff;
	buf[2] = (val->ue.i >> 16) & 0xff;
	buf[3] = (val->ue.i >> 8) & 0xff;
	buf[4] = val->ue.i & 0xff;
      }
      return 5;
    }
    if (IN_RANGE(val->ue.i, -(2<<31), -1)) {
      if (buf && maxlen > 4) {
	buf[0] = 0xd2;
	buf[1] = (val->ue.i >> 24) & 0xff;
	buf[2] = (val->ue.i >> 16) & 0xff;
	buf[3] = (val->ue.i >> 8) & 0xff;
	buf[4] = val->ue.i & 0xff;
      }
      return 5;
    }
    if (buf && maxlen > 8) {
      buf[0] = 0xd3;
      buf[1] = (val->ue.i >> 56) & 0xff;
      buf[2] = (val->ue.i >> 48) & 0xff;
      buf[3] = (val->ue.i >> 40) & 0xff;
      buf[4] = (val->ue.i >> 32) & 0xff;
      buf[5] = (val->ue.i >> 24) & 0xff;
      buf[6] = (val->ue.i >> 16) & 0xff;
      buf[7] = (val->ue.i >> 8) & 0xff;
      buf[8] = val->ue.i & 0xff;
    }
    return 9;

  case ZXVAL_DBL: /* 2 */
    if (buf && maxlen > 8) {
      buf[0] = 0xcb;
      /* N.B. Here we depend on ue.i overlaying ue.d in the union */
      buf[1] = (val->ue.i >> 56) & 0xff;
      buf[2] = (val->ue.i >> 48) & 0xff;
      buf[3] = (val->ue.i >> 40) & 0xff;
      buf[4] = (val->ue.i >> 32) & 0xff;
      buf[5] = (val->ue.i >> 24) & 0xff;
      buf[6] = (val->ue.i >> 16) & 0xff;
      buf[7] = (val->ue.i >> 8) & 0xff;
      buf[8] = val->ue.i & 0xff;
    }
    return 9;

  case ZXVAL_STR: /* 3 */
    if (val->len < 32) {
      if (buf && maxlen > val->len) {
	*buf = 0b10100000 | val->len;
	memcpy(buf+1, val->ue.s, val->len);
      }
      return 1+val->len;
    }
    if (val->len < 256) {
      if (buf && maxlen > val->len+1) {
	buf[0] = 0xd9;
	buf[1] = val->len;
	memcpy(buf+2, val->ue.s, val->len);
      }
      return 2+val->len;
    }
    if (val->len < 65536) {
      if (buf && maxlen > val->len+2) {
	buf[0] = 0xda;
	buf[1] = (val->len >> 8) & 0xff;
	buf[2] = val->len & 0xff;
	memcpy(buf+3, val->ue.s, val->len);
      }
      return 3+val->len;
    }
    if (buf && maxlen > val->len+1) {
      buf[0] = 0xda;
      buf[1] = (val->len >> 24) & 0xff;
      buf[2] = (val->len >> 16) & 0xff;
      buf[3] = (val->len >> 8) & 0xff;
      buf[4] = val->len & 0xff;
      memcpy(buf+5, val->ue.s, val->len);
    }
    return 5+val->len;

  case ZXVAL_BOOL: /* 4 */
    if (buf && maxlen > 0)
      *buf = val->ue.i ? 0xc3 : 0xc2;
    return 1;

  case ZXVAL_ARY: /* 5 */
    if (val->len < 16) {
      if (buf && maxlen > val->len)
	buf[0] = 0b10010000 | val->len;
      len = 1;
    } else if (val->len < 65536) {
      if (buf && maxlen > val->len) {
	buf[0] = 0xdc;
	buf[1] = (val->len >> 8) & 0xff;
	buf[2] = val->len & 0xff;
      }
      len = 3;
    } else {
      if (buf && maxlen > val->len) {
	buf[0] = 0xdc;
	buf[1] = (val->len >> 24) & 0xff;
	buf[2] = (val->len >> 16) & 0xff;
	buf[3] = (val->len >> 8) & 0xff;
	buf[4] = val->len & 0xff;
      }
      len = 5;
    }
  process_ary:
    for (i = 0; i < val->len; ++i)
      len += zx_val2msgpack(val->ue.a[i], maxlen-len, buf+len, maxrecurse-1, flags);
    return len;
    
  case ZXVAL_KEYVAL: /* 7 */
    if (val->len < 16) {
      if (buf && maxlen > val->len)
	buf[0] = 0b10000000 | val->len;
      len = 1;
    } else if (val->len < 65536) {
      if (buf && maxlen > val->len) {
	buf[0] = 0xde;
	buf[1] = (val->len >> 8) & 0xff;
	buf[2] = val->len & 0xff;
      }
      len = 3;
    } else {
      if (buf && maxlen > val->len) {
	buf[0] = 0xdf;
	buf[1] = (val->len >> 24) & 0xff;
	buf[2] = (val->len >> 16) & 0xff;
	buf[3] = (val->len >> 8) & 0xff;
	buf[4] = val->len & 0xff;
      }
      len = 5;
    }
    goto process_ary;
    
  case ZXVAL_HASH: /* 6 */
    /* Since our hashes are sparse and the val->len reflects the sparse size of the
     * hash table, we would have to count the elements first to choose optimal
     * size representation. OTOH, each hash bucket may actually have a chain
     * of keys that hashed to the same bucket, so the size may also be more than
     * indicated by the len field. In interest of run time, we choose size representation
     * pessimistically as 32bits (0xdf). In any case, we will have to
     * come back and update the actual length field once we know the count. */
    len = 5;
    for (cnt = i = 0; i < val->len; ++i)
      for (b = val->ue.h[i]; b; b = b->n, ++cnt)
	len += zx_val2msgpack(&val->ue.h[i]->val, maxlen-len, buf+len, maxrecurse-1, flags);
    if (buf && maxlen > 4) {
      buf[0] = 0xdf;
      buf[1] = (cnt >> 24) & 0xff;
      buf[2] = (cnt >> 16) & 0xff;
      buf[3] = (cnt >> 8) & 0xff;
      buf[4] = cnt & 0xff;
    }
    return len;
    
  case ZXVAL_PACK: /* 7 */
  default:
    ERR("unknown val->kind=0x%x", val->kind);
    return 0;
  }
}

/*() Deserialize msgpack
 *
 * val:: Value (can be root of a complex data structure)
 * buf:: Pointer to pointer to buffer where msgpack data resides. The *buf is
 *     incremented as data is consumed so the caller can know how much data
 *     was consumed. Caller can also try deserializing the remaing data by calling
 *     this function again.
 * lim:: Pointer to one past the end of the buffer.
 * flags:: Flags determining how the serialization is to be done. Following exist
 *     - 0x01 specifies that data, such as strings, can be referenced from buf without
 *       allocation and copying (there will still be other allocation, e.g. for
 *       the zx_val objects themselves).
 *     - 0x02 enables lazy hashing, i.e. mai is read in simply as an array and tagged ZXVAL_KEYVAL
 *     - 0x04 adds to arrays 16 elements of padding (so array expansion does not force realloc)
 * return:: zx_val object
 */

struct zx_val* zx_msgpack2val2(struct zx_ctx* c, unsigned char** buf, unsigned char* lim, int flags)
{
  int i,cnt;
  struct zx_val* key;
  struct zx_val* val;
  if (*buf >= lim)
    goto err;

  switch ((*buf)[0]) {
  case 0xc0: val = zx_new_val(c, ZXVAL_NIL); (*buf)++; return val;
  case 0xc2: val = zx_new_val(c, ZXVAL_BOOL); (*buf)++; return val; /* false */
  case 0xc3: val = zx_new_val(c, ZXVAL_BOOL); val->ue.i = 1; (*buf)++; return val; /* true */

  case 0xcc:  /* uint 8 */
    if (*buf+2 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_INT);
    val->ue.i = (*buf)[1];
    *buf += 2;
    return val;

  case 0xcd:  /* uint 16 */
    if (*buf+3 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_INT);
    val->ue.i = (*buf)[1] << 8 | (*buf)[2];
    *buf += 3;;
    return val;

  case 0xce:  /* uint 32 */
    if (*buf+5 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_INT);
    val->ue.i = (*buf)[1] << 24 | (*buf)[2] << 16 | (*buf)[3] << 8 | (*buf)[4];
    *buf += 5;;
    return val;

  case 0xcf:  /* uint 64 */
    if (*buf+9 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_INT);
    val->ue.i = (unsigned long long)(*buf)[1] << 56
      | (unsigned long long)(*buf)[2] << 48
      | (unsigned long long)(*buf)[3] << 40
      | (unsigned long long)(*buf)[4] << 32
      | (unsigned long long)(*buf)[5] << 24
      | (unsigned long long)(*buf)[6] << 16
      | (unsigned long long)(*buf)[7] << 8
      | (unsigned long long)(*buf)[8];
    *buf += 9;;
    return val;

  case 0xd0:  /* signed int 8 */
    if (*buf+2 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_INT);
    val->ue.i = (signed char)(*buf)[1];
    *buf +=2;
    return val;

  case 0xd1:  /* signed int 16 */
    if (*buf+3 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_INT);
    val->ue.i = (signed short)((*buf)[1] << 8 | (*buf)[2]);
    *buf += 3;;
    return val;

  case 0xd2:  /* signed int 32 */
    if (*buf+5 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_INT);
    val->ue.i = (signed long)((*buf)[1] << 24 | (*buf)[2] << 16 | (*buf)[3] << 8 | (*buf)[4]);
    *buf += 5;;
    return val;

  case 0xd3:  /* signed int 64 */
    if (*buf+9 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_INT);
    val->ue.i = (signed long long)(  (signed long long)(*buf)[1] << 56
				     | (signed long long)(*buf)[2] << 48
				     | (signed long long)(*buf)[3] << 40
				     | (signed long long)(*buf)[4] << 32
				     | (signed long long)(*buf)[5] << 24
				     | (signed long long)(*buf)[6] << 16
				     | (signed long long)(*buf)[7] << 8
				     | (signed long long)(*buf)[8]);
    *buf += 9;;
    return val;

  case 0xca:  /* float 32 */
    if (*buf+5 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_DBL);
    /* We rely here on ue.i32 field to access the ue.d field via union */
    val->ue.i32 = (unsigned long)(*buf)[1] << 24
      | (unsigned long)(*buf)[2] << 16
      | (unsigned long)(*buf)[3] << 8
      | (unsigned long)(*buf)[4];
    val->ue.d = val->ue.f; /* *** this may be dodgy */
    *buf += 5;;
    return val;

  case 0xcb:  /* double 64 */
    if (*buf+9 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_DBL);
    /* We rely here on ue.i field to access the ue.d field via union */
    val->ue.i = (unsigned long long)(*buf)[1] << 56
      | (unsigned long long)(*buf)[2] << 48
      | (unsigned long long)(*buf)[3] << 40
      | (unsigned long long)(*buf)[4] << 32
      | (unsigned long long)(*buf)[5] << 24
      | (unsigned long long)(*buf)[6] << 16
      | (unsigned long long)(*buf)[7] << 8
      | (unsigned long long)(*buf)[8];
    *buf += 9;;
    return val;

  case 0xdc:  /* ary 16 */
    if (*buf+3 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_ARY);
    val->len = (*buf)[1] << 8 | (*buf)[2];
    *buf += 3;
    goto process_ary;

  case 0xdd:  /* ary 32 */
    if (*buf+5 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_ARY);
    val->len = (*buf)[1] << 24 | (*buf)[2] << 16 | (*buf)[3] << 8 | (*buf)[4];
    *buf += 5;
    goto process_ary;

  case 0xde:  /* map 16 */
    if (*buf+3 > lim)
      goto err1;
    cnt = (*buf)[1] << 8 | (*buf)[2];
    *buf += 3;
    goto process_map;

  case 0xdf:  /* map 32 */
    if (*buf+5 > lim)
      goto err1;
    cnt = (*buf)[1] << 24 | (*buf)[2] << 16 | (*buf)[3] << 8 | (*buf)[4];
    *buf += 5;
    goto process_map;

  case 0xd9:  /* str 8 */
  case 0xc4:  /* bin 8 */
    if (*buf+2 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_STR);
    val->len = (*buf)[1];
    if (*buf+2+val->len > lim)
      goto err2;
    if (flags & 0x01) {
      val->ue.s = (char*)*buf+2;
      val->flags = 0x01;
    } else {
      val->ue.s = ZX_ALLOC(c, val->len);
      memcpy(val->ue.s, *buf+2, val->len);
    }
    *buf += 2+val->len;
    return val;
    
  case 0xda:  /* str 16 */
  case 0xc5:  /* bin 16 */
    if (*buf+3 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_STR);
    val->len = (*buf)[1] << 8 | (*buf)[2];
    if (*buf+3+val->len > lim)
      goto err2;
    if (flags & 0x01) {
      val->ue.s = (char*)*buf+3;
      val->flags = 0x01;
    } else {
      val->ue.s = ZX_ALLOC(c, val->len);
      memcpy(val->ue.s, *buf+3, val->len);
    }
    *buf += 3+val->len;
    return val;
    
  case 0xdb:  /* str 32 */
  case 0xc6:  /* bin 32 */
    if (*buf+5 > lim)
      goto err1;
    val = zx_new_val(c, ZXVAL_STR);
    val->len = (*buf)[1] << 24 | (*buf)[2] << 16 | (*buf)[3] << 8 | (*buf)[4];
    if (*buf+5+val->len > lim)
      goto err2;
    if (flags & 0x01) {
      val->ue.s = (char*)*buf+5;
      val->flags = 0x01;
    } else {
      val->ue.s = ZX_ALLOC(c, val->len);
      memcpy(val->ue.s, *buf+5, val->len);
    }
    *buf += 5+val->len;
    return val;
    
  default:
    switch ((*buf)[0] & 0b11100000) {
    case 0b10100000: /* str 5 */
      val = zx_new_val(c, ZXVAL_STR);
      val->len = (*buf)[0] & 0b00011111;
      if (*buf+1+val->len > lim)
	goto err2;
      if (flags & 0x01) {
	val->ue.s = (char*)*buf+1;
	val->flags = 0x01;
      } else {
	val->ue.s = ZX_ALLOC(c, val->len);
	memcpy(val->ue.s, *buf+1, val->len);
      }
      *buf += 1+val->len;
      return val;
    case 0b10000000: /* ary or map with 4 bit length */
      if ((*buf)[0] & 0b00010000) {  /* array */
	val = zx_new_val(c, ZXVAL_ARY);
	cnt = val->len = (*buf)[0] & 0b00001111;
	(*buf)++;
      process_ary:
	if (flags & 0x04) {
	  val->spares = 16;
	  val->ue.a = ZX_ALLOC(c, (cnt+16)*sizeof(struct zx_val*));
	} else
	  val->ue.a = ZX_ALLOC(c, cnt*sizeof(struct zx_val*));
	for (i = 0; i < cnt; ++i)
	  val->ue.a[i] = zx_msgpack2val2(c, buf, lim, flags);
	return val;
      } else {  /* map */
	cnt = (*buf)[0] & 0b00001111;
      process_map:
	if (flags & 0x02) {
	  val = zx_new_val(c, ZXVAL_KEYVAL);
	  cnt *= 2;
	  val->len = cnt;
	  goto process_ary;
	} else {
	  val = zx_new_val(c, ZXVAL_HASH);
	  if (flags & 0x04) {
	    val->len = cnt*4;  /* generous expansion space */
	  } else {
	    val->len = cnt+(cnt>>1); /* not much expansion */
	  }
	  val->ue.h = ZX_ALLOC(c, val->len*sizeof(struct zx_bucket*));
	  memset(val->ue.h, 0, val->len*sizeof(struct zx_bucket*));
	  for (i = 0; i < cnt; ++i) {
	    key = zx_msgpack2val2(c, buf, lim, flags);
	    zx_set_by_len_key(val->len, val->ue.h, key->len, key->ue.s,
			      zx_msgpack2val2(c, buf, lim, flags));
	    if (key->kind != ZXVAL_STR) {
	      D("Nonstring hash key seen %d=%lld", key->kind, key->ue.i);
	      zx_val_to_str(c, key);
	    }
	    zx_free_val(c, key, 100); /* hash made a copy of the key string */
	  }
	}
	return val;
      }
    case 0b11000000: ERR("Invalid or unsupported msgspec format(0x%x)", (*buf)[0]); return 0;
    case 0b11100000: /* negative int */
      val = zx_new_val(c, ZXVAL_INT);
      val->ue.i = (signed char)(*buf)[0];  /* cast to signed to make sure sign extension happens */
      (*buf)++;
      return val;
    default:
      val = zx_new_val(c, ZXVAL_INT);
      val->ue.i = (*buf)[0] & 0b01111111;  /* positive int */
      (*buf)++;
      return val;
    }
  }

 err2:
  ERR("next msgpack format(0x%x) len=%ld would extend beyond limit buf=%p lim=%p", **buf, val->len, *buf, lim);
  ZX_FREE(c, val);
  return 0;
 err1:
  ERR("next msgpack format(0x%x) would extend beyond limit buf=%p lim=%p", **buf, *buf, lim);
  return 0;
 err:
  ERR("next msgpack format would extend beyond limit buf=%p lim=%p", *buf, lim);
  return 0;
}

struct zx_val* zx_msgpack2val(struct zx_ctx* c, int len, unsigned char* buf, int flags)
{
  return zx_msgpack2val2(c, &buf, buf+len, flags);
}

/* EOF  --  zxmsgpack.c */
