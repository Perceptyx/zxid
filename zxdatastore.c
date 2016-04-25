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

#include <string.h>
#include <malloc.h>
#include <pthread.h>

#include "platform.h"
#include "errmac.h"
#include "hiios.h"    /* for struct hi_lock */
#include "zxdata.h"

extern struct hiios* shuff; /* global for accessing the shuffler and its todo_mut */

/* EOF  --  zxdatastore.c */
