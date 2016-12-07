/* mcdb.c  -  memcached binary protocol (1.3) for HIIOS engine
 * Copyright (c) 2016 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing. See file COPYING.
 * Special grant: http.c may be used with zxid open source project under
 * same licensing terms as zxid itself.
 * $Id$
 *
 * 3.4.2016, created, based on stomp.c --Sampo
 */

#include "platform.h"
#include "errmac.h"
#include "akbox.h"
#include "hiios.h"
#include "hiproto.h"
#include "zxdata.h"
#include <zx/c/zxidvers.h>
#include <zx/zxidconf.h>
#include <zx/zxidutil.h>

#include <ctype.h>
#include <memory.h>
#include <stdlib.h>
#include <netinet/in.h> /* htons(3) and friends */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/* Alias some struct fields for headers that can not be seen together. */
#define receipt   host
#define rcpt_id   host
#define acpt_vers vers
#define tx_id     vers
#define session   login
#define subs_id   login
#define subsc     login
#define server    pw
#define ack       pw
#define msg_id    pw
#define heart_bt  dest
#define zx_rcpt_sig dest

extern int verbose;  /* defined in option parsing in zxceched.c */
extern zxid_conf* zx_cf;

#if 0
/* Called by: */
static struct hi_pdu* mcdb_encode_start(struct hi_thr* hit)
{
  struct hi_pdu* resp = hi_pdu_alloc(hit,0,"mcdb_enc_start");
  if (!resp) { hi_dump(hit->shf); NEVERNEVER("*** out of pdus in bad place %d", 0); }
  return resp;
}
#endif

const char* mcdb_zero_cas = "\0\0\0\0\0\0\0\0";  /* When no real cas is needed */

/*() Send success response to remote client.
 * Response has many optional parts depending on op or circumstances.
 *
 * extralen, extra:: If spc specifies an extra for the command, this must be supplied
 * cpkey:: If response is supposed to have key. If set, key will be copied from req
 * datatype:: Datatype field. Supply as 0 if not used
 * vallen, val:: Value field of response. Supply as 0,0 if not needed
 * cas:: 8byte string for cas value. Supply as  "\0\0\0\0\0\0\0\0" if not needed
 * return:: 0 for success in scheduling for write (real success is determined later) */

/* Called by:  mcdb_got_get, mcdb_got_set, mcdb_got_zxmsgpack */
int mcdb_ok(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req, int extralen, const char* extra, int cpkey, const char datatype, int vallen, const char* val, const char* cas)
{
  int len;
  char* p;
  struct hi_pdu* resp = hi_pdu_alloc(hit, io, "mcdb_ok");
  p = resp->ap;
  p[0] = MCDB_RESP_MAGIC;  /* 0x81 */
  p[1] = req->ad.mcdb.op;
  if (cpkey) {
    p[2] = (req->ad.mcdb.keylen >> 8) & 0xff;  /* network byte order (big endian) */
    p[3] = req->ad.mcdb.keylen & 0xff;
    len = req->ad.mcdb.keylen;
  } else {
    p[2] = p[3] = 0;  /* no key required */
    len = 0;
  }
  p[4] = extralen;
  p[5] = datatype;
  p[6] = p[7] = MCDB_STATUS_OK; /* 0x0000 */
  len += extralen + vallen;
  p[8] = (len >> 24) & 0xff;  /* network byte order (big endian) */
  p[9] = (len >> 16) & 0xff;
  p[10] = (len >> 8) & 0xff;
  p[11] = len & 0xff;
  memcpy(p+12, req->ad.mcdb.opaque, 4);
  memcpy(p+16, cas, 8);
  if (extralen)
    memcpy(p+24, extra, extralen);
  resp->ap += 24+extralen;
  
  D("ok req=%p resp=%p vallen=%d cpkey=%d", req, resp, vallen, cpkey);
  if (vallen) {
    if (cpkey) {
      hi_send3(hit, io, 0, req, resp, 24+extralen, p, req->ad.mcdb.keylen, req->ad.mcdb.key, vallen, (void*)val);
    } else {
      hi_send2(hit, io, 0, req, resp, 24+extralen, p, vallen, (void*)val);
    }
  } else {
    if (cpkey) {
      hi_send2(hit, io, 0, req, resp, 24+extralen, p, req->ad.mcdb.keylen, req->ad.mcdb.key);
    } else {
      hi_send1(hit, io, 0, req, resp, 24+extralen, p);
    }
  }
  return 0;
}

/*() Send error to remote client. */

/* Called by:  mcdb_cmd_ni, mcdb_decode x3, mcdb_frame_err, mcdb_got_get x2, mcdb_got_login x2, mcdb_got_set */
int mcdb_err(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req, int status, const char* emsg)
{
  int len;
  char* p;
  struct hi_pdu* resp = hi_pdu_alloc(hit, io, "mcdb_err");
  p = resp->ap;
  p[0] = MCDB_RESP_MAGIC;  /* 0x81 */
  p[1] = req->ad.mcdb.op;
#if 1
  p[2] = p[3] = 0;  /* no key in error message */
#else
  p[2] = (req->ad.mcdb.keylen >> 8) & 0xff;  /* network byte order (big endian) */
  p[3] = req->ad.mcdb.keylen & 0xff;
#endif
  p[4] = 0;  /* no extra for error messages  -- req->ad.mcdb.extralen; */
  p[5] = 0;  /* data type for error messages -- req->ad.mcdb.datatype; */
  p[6] = (status >> 8) & 0xff;  /* network byte order (big endian) */
  p[7] = status & 0xff;
  len = strlen(emsg);
  if (len > 65535)
    len = 65535;
  p[8] = p[9] = 0;  /* network byte order (big endian) */
  p[10] = (len >> 8) & 0xff;
  p[11] = len & 0xff;
  memcpy(p+12, req->ad.mcdb.opaque, 4);  //memset(p+12, 0, 4);
#if 1
  memset(p+16, 0, 8);
#else
  memcpy(p+16, req->ad.mcdb.cas, 8);
#endif
  memcpy(p+24, emsg, len);
  resp->ap += 24+len;

  ERR("%s (%d)", emsg, status);
  hi_send1(hit, io, 0, req, resp, 24+len, p);
  return HI_CONN_CLOSE;
}

/*() Send an error early on in decode process */

/* Called by:  mcdb_decode x2 */
static int mcdb_frame_err(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req, const char* emsg)
{
  D("emsg(%s)", emsg);
  /* At this early stage the req is still a io->cur_pdu. We need to
   * promote it to a real request so that the free logic will work right. */
  hi_add_to_reqs(hit, io, req, MCDB_MIN_PDU_SIZE);
  return mcdb_err(hit,io,req,MCDB_STATUS_INVALID_ARGS,emsg);
}

/*() Send not implemented error to remote client. */

/* Called by:  mcdb_decode */
static int mcdb_cmd_ni(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req, const char cmd)
{
  return mcdb_err(hit,io,req,MCDB_STATUS_UNKNOWN_COMMAND,"command not implemented or unknown");
}

#if 0
/*() Got ERROR from remote client. */

/* Called by: */
static int mcdb_got_err(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req)
{
  /*struct hi_pdu* resp = mcdb_encode_start(hit);*/
  /*hi_sendv(hit, io, 0, req, resp, len, resp->m, size, req->m + len);*/
  ERR("remote sent error(%.*s)", (int)(req->ap-req->m), req->m);
  return HI_CONN_CLOSE;
}

/*() Send a receipt to client. */

/* Called by:  mcdb_got_send */
void mcdb_send_receipt(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req)
{
  int len;
  char* rcpt;
  char sigbuf[1024];
  if ((rcpt = req->ad.mcdb.receipt)) {
    len = (char*)memchr(rcpt, '\n', req->ap - rcpt) - rcpt;
  } else {
    len = 1;
    rcpt = "-";
  }
  DD("rcpt(%.*s) len=%d", len, rcpt, len);

  zxbus_mint_receipt(zx_cf, sizeof(sigbuf), sigbuf,
		     len, rcpt,
		     -2, req->ad.mcdb.dest,
		     -1, io->ent->eid,   /* entity to which we issue receipt */
		     req->ad.mcdb.len, req->ad.mcdb.body);
  hi_sendf(hit, io, 0, req, "RECEIPT\nreceipt-id:%.*s\nzx-rcpt-sig:%s\n\n%c", len, rcpt, sigbuf,0);
}

/* MCDB Received Command Handling */

/* Called by: */
static int mcdb_got_login(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req)
{
  if (!req->ad.mcdb.login)
    return mcdb_err(hit, io, req, "login fail", "No login header supplied (client error). zxbusd(8) requires login header whose value is the EntityID of the connecting client.");
  
  if (zxbus_login_ent(hit, io, req)) {
    hi_sendf(hit, io, 0, req, "CONNECTED\nversion:1.1\nserver:zxbusd-1.x\n\n%c", 0);
    return 0;
  } else
    return mcdb_err(hit, io, req, "login fail", "login failed either due to nonexistent entity id or bad credential");
}

/*() Main function for receiving memcached binary protocol requests
 * This function will first store the line in a persistent way (RAID1
 * arrangement needs to be implemented at the OS level), and then,
 * perhaps, attempt to deliver the message to all subscribers. Indeed,
 * delivery should be attempted first and if successful, the persistence
 * is not necessary. If delivery is unsuccessful, the delivery needs
 * to be retried, i.e. this is a store-and-forward system. However,
 * the delivery first approach needs extensive IO engine
 * operations and it thus may be easier to just store the message
 * first and then have a separate process attempt the sending. This
 * latter is the approach adopted here. */

/* Called by: */
static void mcdb_got_send(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req)
{
  // ***
  if (zxbus_persist(hit, io, req)) {
    mcdb_send_receipt(hit, io, req);
  } else {
    ERR("Persist Problem. Disk full? %d", 0);
    //hi_sendf(hit, io, 0, req, "ERROR\nmessage:persist failure\nreceipt-id:%.*s\n\nUnable to persist message. Can not guarantee reliable delivery, therefore rejecting.%c", len, rcpt, 0);
  }
}

/*() Find a request that matches response. Looks in
 * the io->pending list for message ID match. When found,
 * the req is dequeued from pending. */

/* Called by:  mcdb_got_ack, mcdb_got_nack */
static struct hi_pdu* mcdb_find_pending_req_for_resp(struct hi_io* io, struct hi_pdu* resp)
{
  struct hi_pdu* prev;
  struct hi_pdu* req;
  int midlen=resp->ad.mcdb.msg_id?(strchr(resp->ad.mcdb.msg_id,'\n')- resp->ad.mcdb.msg_id):0;
  
  LOCK(io->qel.mut, "ack");
  for (prev = 0, req = io->pending; req; prev = req, req = req->n) {
    if (!memcmp(resp->ad.mcdb.msg_id, req->ad.mcdb.msg_id, midlen+1)) {
      if (prev)
	prev->n = req->n;
      else
	io->pending = req->n;
      resp->req = req;
      resp->parent = req->parent;
      break;
    }
  }
  UNLOCK(io->qel.mut, "ack");
  return req;
}

/*() Process NACK response from client to MESSAGE request sent by server.
 * This is essentially nice way for the client to communicate to us it has
 * difficulty in persisting the message. It could also just hang up and the
 * net effect would be the same. However, receiving the NACK allows us to
 * close the delivery batch sooner so we can free the memory in the
 * hopeless cases quicker. (*** there should also be a handler for
 * close-connection lost that would do similar cleanup) */

/* Called by: */
static void mcdb_got_nack(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* resp)
{
  int sublen, midlen, siglen;
  struct hi_pdu* parent;

  sublen = resp->ad.mcdb.subsc ? (strchr(resp->ad.mcdb.subsc, '\n') - resp->ad.mcdb.subsc) : 0;
  midlen = resp->ad.mcdb.msg_id ?(strchr(resp->ad.mcdb.msg_id, '\n')- resp->ad.mcdb.msg_id) : 0;
  siglen = resp->ad.mcdb.zx_rcpt_sig ? (strchr(resp->ad.mcdb.zx_rcpt_sig, '\n') - resp->ad.mcdb.zx_rcpt_sig) : 0;

  D("NACK subsc(%.*s) msg_id(%.*s) zx_rcpt_sig(%.*s)", sublen, sublen?resp->ad.mcdb.subsc:"", midlen, midlen?resp->ad.mcdb.msg_id:"", siglen, siglen?resp->ad.mcdb.zx_rcpt_sig:"");
  
  ASSERTOPP(resp->req, ==, 0);
  if (!mcdb_find_pending_req_for_resp(io, resp)) {
    ERR("Unsolicited NACK subsc(%.*s) msg_id(%.*s)", sublen, sublen?resp->ad.mcdb.subsc:"", midlen, midlen?resp->ad.mcdb.msg_id:"");
    return;
  }
  parent = resp->parent;
  ASSERT(parent);
  
  /* *** add validation of zx_rcpt_sig. Lookup the cert using metadata for the EID. */
  /* Remember NACK somewhere? */
  hi_free_resp(hit, resp, "nack ");
  
  ++(parent->ad.delivb.nacks);
  if (--(parent->ad.delivb.acks) <= 0) {
    ASSERTOPI(parent->ad.delivb.acks, ==, 0);
    close_file(parent->ad.delivb.ack_fd, "got_nack");
    D("nack: freeing parent(%p)", parent);
    hi_free_req(hit, parent, "nack ");
  }
}

/*() Process ACK response from client to MESSAGE request sent by server. */

/* Called by: */
static void mcdb_got_ack(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* resp)
{
  int sublen, midlen, siglen, ver;
  struct hi_pdu* parent;
  char* eid;
  char buf[1024];
  
  /* First, it was wrong for hi_add_to_reqs() to be called for an ACK as acks are
   * really responses to MESSAGEs. Thus undo that action here. */
  
  hi_del_from_reqs(io, resp);
  
  sublen = resp->ad.mcdb.subsc ? (strchr(resp->ad.mcdb.subsc, '\n') - resp->ad.mcdb.subsc) : 0;
  midlen = resp->ad.mcdb.msg_id ?(strchr(resp->ad.mcdb.msg_id, '\n')- resp->ad.mcdb.msg_id) : 0;
  siglen = resp->ad.mcdb.zx_rcpt_sig ? (strchr(resp->ad.mcdb.zx_rcpt_sig, '\n') - resp->ad.mcdb.zx_rcpt_sig) : 0;

  DD("ACK subsc(%.*s) msg_id(%.*s) zx_rcpt_sig(%.*s)", sublen, sublen?resp->ad.mcdb.subsc:"", midlen, midlen?resp->ad.mcdb.msg_id:"", siglen, siglen?resp->ad.mcdb.zx_rcpt_sig:"");

  if (!mcdb_find_pending_req_for_resp(io, resp)) {
    ERR("Unsolicited ACK subsc(%.*s) msg_id(%.*s)", sublen, sublen?resp->ad.mcdb.subsc:"", midlen, midlen?resp->ad.mcdb.msg_id:"");
    return;
  }
  parent = resp->parent;
  ASSERT(parent);
  
  if (errmac_debug>1)
    D("ACK par_%p->len=%d rq_%p->len=%d\nparent->body(%.*s)\n   req->body(%.*s)", parent, parent->ad.delivb.len, resp->req, resp->req->ad.mcdb.len, parent->ad.delivb.len, parent->ad.delivb.body, resp->req->ad.mcdb.len, resp->req->ad.mcdb.body);
  else
    D("ACK par_%p->len=%d rq_%p->len=%d", parent, parent->ad.delivb.len, resp->req, resp->req->ad.mcdb.len);

  eid = zxid_my_ent_id_cstr(zx_cf);
  ver = zxbus_verify_receipt(zx_cf, io->ent->eid,
			     siglen, siglen?resp->ad.mcdb.zx_rcpt_sig:"",
			     -2, resp->req->ad.mcdb.msg_id,
			     -2, resp->req->ad.mcdb.dest,
			     -1, eid,  /* our eid, the receipt was issued to us */
			     resp->req->ad.mcdb.len, resp->req->ad.mcdb.body);
  ZX_FREE(zx_cf->ctx, eid);
  if (ver != ZXSIG_OK) {
    ERR("ACK signature validation failed: %d", ver);
    hi_free_resp(hit, resp, "ack ");
    return;
  }
  
  /* Record the receipt in /var/zxid/bus/ch/DEST/.ack/SHA1.ack for our audit trail, and to
   * indicate that we need not attempt delivery again to this entity. */
  write_all_fd_fmt(parent->ad.delivb.ack_fd, "ACK", sizeof(buf), buf, "AB1 %s ACK %.*s\n",
		   io->ent->eid, siglen, siglen?resp->ad.mcdb.zx_rcpt_sig:"");
  
  hi_free_resp(hit, resp, "ack ");
  
  if (--(parent->ad.delivb.acks) <= 0) {
    ASSERTOPI(parent->ad.delivb.acks, ==, 0);
    close_file(parent->ad.delivb.ack_fd, "got_ack");
    if (!parent->ad.delivb.nacks) {
      D("Delivered to all: mv msg to .del par_%p", parent);
      zxbus_retire(hit, parent);
    }
    hi_free_req(hit, parent, "parent ");
  }
}
#endif

/*() Cache get operation */

/* Called by:  mcdb_decode x2 */
static void mcdb_got_get(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req, int cpkey)
{
  struct zx_gbucket* bkt;
  if (req->ad.mcdb.extraslen || req->ad.mcdb.vallen) {
    mcdb_err(hit, io, req, MCDB_STATUS_INVALID_ARGS, "must not have extras or value");
    return;
  }
  /* lookup the value from hash */
  if (bkt = zx_global_get_by_len_key(req->ad.mcdb.keylen, req->ad.mcdb.key)) {
    D("get(%.*s) bkt=%p val(%.*s) cpkey=%d", req->ad.mcdb.keylen, req->ad.mcdb.key, bkt, (int)bkt->b.val.len, bkt->b.val.ue.s, cpkey);
    mcdb_ok(hit, io, req, 4, "\0\0\0\0", cpkey, 0,
	    bkt->b.val.len, bkt->b.val.ue.s, mcdb_zero_cas);
  } else {
    mcdb_err(hit, io, req, MCDB_STATUS_KEY_NOT_FOUND, "miss");
  }
}

/*() Cache set operation (also add, replace) */

/* Called by:  mcdb_decode x2 */
static void mcdb_got_set(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req, int quiet)
{
  struct zx_gbucket* gb;
  struct zx_val val;
  unsigned char* p;
  int expires;
  if (req->ad.mcdb.extraslen != 8) {
    mcdb_err(hit, io, req, MCDB_STATUS_INVALID_ARGS, "must have extras, key, and value");
    return;
  }
  p = req->ad.mcdb.extras;
  expires = p[4] << 24 | p[5] << 16 | p[6] << 8 | p[7];

  /* store the value in global hash */
  memset(&val, 0, sizeof(val));
  val.kind = ZXVAL_STR;
  val.len = req->ad.mcdb.vallen;
  val.ue.s = malloc(req->ad.mcdb.vallen);
  memcpy(val.ue.s, req->ad.mcdb.val, val.len);
  gb = zx_global_set_by_len_key(req->ad.mcdb.keylen, req->ad.mcdb.key, &val);
  zx_global_write(zx_cf, req->ad.mcdb.keylen, req->ad.mcdb.key, gb->symkey, &val);
  // *** propagate value to replicas
  if (quiet) {
    hi_free_req_fe(hit, req);
  } else {
    mcdb_ok(hit, io, req, 0, 0, 0, 0, 0, 0, mcdb_zero_cas);
  }
}

/*() Nonstandard MCDB command for ZX specific msgpack formatted envelopes
 * Based on different body content, diffrent magic can be invoked:
 * dump - dump data structures to stdout with hi_dump() */

/* Called by:  mcdb_decode */
static void mcdb_got_zxmsgpack(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req)
{
  mcdb_ok(hit, io, req, 0, 0, 0, 0, 0, 0, mcdb_zero_cas);
}

/*() MCDB decoder and dispatch.
 * Memcached Binary protocol always starts by fixed 24 byte header.
 * Return:: 0 for no error (including need more and PDU complete and processed),
 * 1 to force closing connection, 2=need more. */

/* Called by:  hi_read */
int mcdb_decode(struct hi_thr* hit, struct hi_io* io)
{
  struct hi_pdu* req = io->cur_pdu;
  char* lim;
  unsigned char* p = (unsigned char*)req->m;
  
  D("decode req(%p)->need=%d have=%d", req, req->need, (int)(req->ap - req->m));
  HI_SANITY(hit->shf, hit);
  
  if ((unsigned char*)req->ap - p < MCDB_MIN_PDU_SIZE) {   /* too little, need more */
    req->need = MCDB_MIN_PDU_SIZE;
    D("need=%d have=%d", req->need, (int)(req->ap - req->m));
    return  HI_NEED_MORE;
  }
  
  /* Extract header fields */

  req->ad.mcdb.magic  = p[0];
  if (req->ad.mcdb.magic != MCDB_REQ_MAGIC) {
    return mcdb_frame_err(hit, io, req, "Request Magic 0x80 expected.");
  }
  req->ad.mcdb.op     = p[1];
  req->ad.mcdb.keylen = p[2] << 8 | p[3];  /* Network byte order (bigendian) */
  req->ad.mcdb.extraslen = p[4];
  req->ad.mcdb.datatype  = p[5];
  req->ad.mcdb.status = p[6] << 8 | p[7];  /* Network byte order (bigendian) */
  req->ad.mcdb.len    = p[8] << 24 | p[9] << 16 | p[10] << 8 | p[11];  /* Network byte order */
  memcpy(req->ad.mcdb.opaque, p+12, 4);
  memcpy(req->ad.mcdb.cas,    p+16, 8);
  p += 24;
  lim = (char*)p+req->ad.mcdb.len;
  if (lim > req->ap) {
    req->need = lim - req->ap;
    D("need=%d have=%d", req->need, (int)(req->ap - req->m));
    return HI_NEED_MORE;
  }

  req->need = lim-req->m; /* final PDU length */
  req->ad.mcdb.extras = p;
  p += req->ad.mcdb.extraslen;
  if ((char*)p > lim) goto ooberr;
  req->ad.mcdb.key = (char*)p;
  p += req->ad.mcdb.keylen;
  if ((char*)p > lim) goto ooberr;
  req->ad.mcdb.val = (char*)p;
  req->ad.mcdb.vallen = lim-(char*)p;
  ASSERT(lim-(char*)p >= 0);
  
  HI_SANITY(hit->shf, hit);
  hi_add_to_reqs(hit, io, req, MCDB_MIN_PDU_SIZE);
  HI_SANITY(hit->shf, hit);

  /* Operation dispatch */

  switch (req->ad.mcdb.op) {
  case MCDB_GETQ: // 0x09
  case MCDB_GET:   mcdb_got_get(hit,io,req,0); break; //  0x00
  case MCDB_GETKQ: // 0x0D
  case MCDB_GETK:  mcdb_got_get(hit,io,req,1); break; //  0x0C
  case MCDB_ADD: //  0x02
  case MCDB_REPLACE: // 0x03
  case MCDB_SET:   mcdb_got_set(hit,io,req,0); break; //  0x01
  case MCDB_ADDQ: // 0x12
  case MCDB_REPLACEQ: // 0x13
  case MCDB_SETQ:  mcdb_got_set(hit,io,req,1); break; //  0x11
  case MCDB_ZXMSGPACK: mcdb_got_zxmsgpack(hit,io,req); break; // 0x21
  case MCDB_QUIT:  return mcdb_err(hit, io, req, MCDB_STATUS_OK, "bye"); // 0x07
  case MCDB_QUITQ: return HI_CONN_CLOSE; // 0x17
  case MCDB_NOP:   mcdb_err(hit, io, req, MCDB_STATUS_OK, ""); break; //  0x0A
  case MCDB_VERS:  mcdb_err(hit, io, req, MCDB_STATUS_OK, ZXID_REL); break; // 0x0B
  case MCDB_DEL: //  0x04
  case MCDB_INC: //  0x05
  case MCDB_DEC: //  0x06
  case MCDB_FLUSH: // 0x08
  case MCDB_APPEND: // 0x0E
  case MCDB_PREPEND: // 0x0F
  case MCDB_STAT: // 0x10
  case MCDB_DELQ: // 0x14
  case MCDB_INCQ: // 0x15
  case MCDB_DECQ: // 0x16
  case MCDB_FLUSHQ: // 0x18
  case MCDB_APPENDQ: // 0x19
  case MCDB_PREPENDQ: // 0x1A
  default:
    D("Unknown op 0x%02x ignored.", req->ad.mcdb.op);
    mcdb_cmd_ni(hit,io,req,req->ad.mcdb.op);
  }
  return 0;

ooberr:
  return mcdb_frame_err(hit, io, req, "Length field out of bounds.");
}

/* EOF  --  mcdb.c */
