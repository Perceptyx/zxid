/* zxdatastore.c  -  Key Value data structure persistence on filesystem
 * Copyright (c) 2016 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing. See file COPYING.
 * Special grant: zxbusd.c may be used with zxid open source project under
 * same licensing terms as zxid itself.
 * $Id$
 *
 * 23.4.2016, created --Sampo
 *
 * The data is generally stored as journal log, i.e. series of changes
 * applied. Replaying the journal recreates the state of the database.
 *
 * Each global hash key has its own journal in subdirectory /var/zxid/cache/db/<HASH>/...
 */

#include "platform.h"
#include "errmac.h"

#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "hiios.h"    /* for struct hi_lock */
#include "zx.h"
#include "zxid.h"
#include "zxidconf.h"
#include "zxidutil.h"
#include "zxdata.h"

extern char* zxcache_path;

/*                         1234567890123456789 */
#define MAGIC_PATTERN_19 "\ndeadbeef-SERVE3-h\n"

/*() Write to an append only file the value corresponding to global hash key
 *
 * Writing consists of first applying msgpack to serialize the value,
 * which can be a complex data structure, then compressing and
 * encrypting the result and finally writing a header and the result
 * to a file in append mode. Voluntary file locking, using
 * fcntl(F_SETLKW), is employed to prevent two simultaneous writes.
 *
 * cf:: configuration object
 * ghkeylen:: Length of globalhash key
 * ghkey:: Globalhash key
 * symkey:: Symmetric encryption key, typically from global hash bucket
 * val:: Value to be written, typically from global hash val field.
 * return:: 0 on failure, positive on success
 */

int zx_global_write(zxid_conf* cf, int ghkeylen, const char* ghkey, const unsigned char* symkey, struct zx_val* val)
{
  int len, zlen;
  char* pk;
  char* zpk;
  struct zx_str* ss;
  unsigned char hdr[32];
  struct timespec ts;
  long long ns;
  char path[ZXID_MAX_BUF];

  len = zx_val2msgpack(val, 0,0, 100,0x0);
  pk = ZX_ALLOC(cf->ctx, len);
  zx_val2msgpack(val, len, (unsigned char*)pk, 100, 0x0);
  zpk = zx_zlib_raw_deflate(cf->ctx, len, pk, &zlen);
  ZX_FREE(cf->ctx, pk);
  pk = ZX_ALLOC(cf->ctx, zlen+32);
  zx_rand(pk, 32); /* salt */
  memcpy(pk+32, zpk, zlen);
  ZX_FREE(cf->ctx, zpk);
  ss = zx_raw_cipher2(cf->ctx, AES256GCM, 1, 32, symkey, zlen+32, pk, 12, 0);
  ZX_FREE(cf->ctx, pk);

  memcpy(hdr, MAGIC_PATTERN_19, sizeof(MAGIC_PATTERN_19)-1);
  hdr[20] = 0; /* flags */
  hdr[20] = (ss->len >> 24) & 0xff;
  hdr[21] = (ss->len >> 16) & 0xff;
  hdr[22] = (ss->len >> 8) & 0xff;
  hdr[23] = ss->len & 0xff;

  clock_gettime(CLOCK_REALTIME, &ts);
  ns = ts.tv_sec * 1000000000 + ts.tv_nsec;
  hdr[24] = (ns >> 24) & 0xff;
  hdr[25] = (ns >> 16) & 0xff;
  hdr[26] = (ns >> 8) & 0xff;
  hdr[27] = (ns >> 8) & 0xff;
  hdr[28] = (ns >> 24) & 0xff;
  hdr[29] = (ns >> 16) & 0xff;
  hdr[30] = (ns >> 8) & 0xff;
  hdr[31] = ns & 0xff;
  
  // *** should we consider per user subdirectories?
  name_from_path(path, sizeof(path), "%s%.*s.zxd", zxcache_path, ghkeylen, ghkey);
  len = write2_or_append_lock_c_path(path, 32, (char*)hdr, ss->len, ss->s, "global_write", SEEK_END, O_APPEND);
  zx_str_free(cf->ctx, ss);
  return len;
}

/*() Read most up to date version of value of the key
 *
 * Reading consists scanning backwards the append only file
 * for latest full update. Scanning employs the magic pattern
 * to locate suitable candidate locations in the file.
 * The scanning is implemented "in-memory" using memory mapped file.
 *
 * NOT YET IMPLEMENTED: After the full update has been processed,
 * the rest of the file is read an partial updates are applied,
 * thus bringing the value completely up to date.
 *
 * During all these operations voluntary lock on file, using
 * fcntl(F_SETLKW), is held to prevent simultaneous write.
 *
 * cf:: configuration object
 * ghkeylen:: Length of globalhash key
 * ghkey:: Globalhash key
 * symkey:: Symmetric encryption key, typically from global hash bucket
 * val:: Value to be written, typically from global hash val field.
 * return:: 0 on failure, positive on success
 */

int zx_global_read_last(zxid_conf* cf, int ghkeylen, const char* ghkey, const unsigned char* symkey, struct zx_val* val)
{
  char path[ZXID_MAX_BUF];
  fdtype fd;
  unsigned char* map;
  unsigned char* p;
  int len;

  // *** should we consider per user subdirectories?
  name_from_path(path, sizeof(path), "%s%.*s.zxd", zxcache_path, ghkeylen, ghkey);
  fd = open(path, O_RD, 0666);
  if (fd == BADFD) goto badopen;
  if (FLOCKEX(fd)  == -1) {
    ERR("%s: Locking exclusively file `%s' failed: %d %s; euid=%d egid=%d. Check that the file system supports locking. %s", which, c_path, errno, STRERROR(errno), geteuid(), getegid(), WRITE_FAIL_MSG);
    close_file(fd, "read_last");
    return 0;
  }
  
  len = get_file_size(fd);
  map = mmap(0, len, PROT_READ, MAP_PRIVATE|MAP_NORESERVE, fd, 0);
  if (map == MAP_FAILED) {
    ERR("memory mapping `%s' failed: %d %s; euid=%d egid=%d.", path, errno, STRERROR(errno), geteuid(), getegid());
    close_file(fd, "read_last");
    return 0;
  }

  for (p = map+len-1; 1;) {
    p = rmemmem(p, MAGIC_PATTERN_19, sizeof(MAGIC_PATTERN_19)-1);
    if (!p) {
      ERR("No suitable update found %p", p);
      break;
    }
    // ***
  }

  if (munmap(map, len) < 0) {
    ERR("unmapping memory `%s' failed: %d %s; euid=%d egid=%d.", path, errno, STRERROR(errno), geteuid(), getegid());
    close_file(fd, "read_last");
    return 0;
  }  
  FUNLOCK(fd);
  if (close_file(fd, "read_last") < 0) {
    ERR("closing file(%s) failed: %d %s; euid=%d egid=%d. %s Could be NFS problem.", path, errno, STRERROR(errno), geteuid(), getegid());
    return 0;
  }
  return 1;
  
badopen:
  ERR("Opening file(%s) for writing failed: %d %s; euid=%d egid=%d", path, errno, STRERROR(errno), geteuid(), getegid());
  return 0;
}
/* EOF  --  zxdatastore.c */
