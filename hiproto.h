/* hiproto.h  -  Protocol constants for hiios
 * Copyright (c) 2006,2012,2016 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing. See file COPYING.
 * Special grant: hiios.c may be used with zxid open source project under
 * same licensing terms as zxid itself.
 * $Id$
 *
 * 15.4.2006, created over Easter holiday --Sampo
 * 16.8.2012, modified license grant to allow use with ZXID.org --Sampo
 * 17.8.2012, added STOMP 1.1 definitions  --Sampo
 * 3.4.2016,  added memcached binary protocol definitions --Sampo
 *
 * See also: https://cloud.github.com/downloads/dustin/memcached/protocol-binary.txt
 */

#ifndef _hiproto_h
#define _hiproto_h

struct hi_thr;
struct hi_io;
struct hi_pdu;
struct hiios;

#include <pthread.h>

#define HIPROTO_POLL_OFF 0  /* no protocol specified, or in poll_tok inhibit poll */
#define HIPROTO_POLL_ON  1  /* a special value for poll_tok to trigger poll */
#define HIPROTO_SIS  2
#define HIPROTO_DTS  3
#define HIPROTO_SMTP 4
#define HIPROTO_HTTP 5
#define HIPROTO_TEST_PING 6
#define HIPROTO_STOMP 7
#define HIPROTO_STOMPS 8
#define HIPROTO_MCDB   9    /* memcached binary protocol */
#define HIPROTO_MCDBS 10

#ifdef ENA_S5066
/* Application SAP IDs. See Annex F. */

#define SAP_ID_SUBNET_MGMT 0
#define SAP_ID_ACKD_MSG    1
#define SAP_ID_UNACKD_MSG  2
#define SAP_ID_HMTP        3
#define SAP_ID_HFPOP       4
#define SAP_ID_OP_OW       5
#define SAP_ID_STREAM      6
#define SAP_ID_DATAGRAM    7
#define SAP_ID_PPP         8
#define SAP_ID_IP          9
/* 10,11 reserved for future assignment */
/* 12,13,14,15 local uses, ad-hoc */
#define SAP_ID_WALKIE_TALKIE 12   /* Half Duplex Digital Voice and chat */
#define SAP_ID_RFID          13   /* RFID tracking application */

/* Clients talking SIS are required to split long application data to several PDUs */
#define SIS_MIN_PDU_SIZE 5     /* preamble, version and length field */
#define SIS_UNIHDR_SIZE 12
#define SIS_MTU 2048           /* Reliable service MTU for u_pdu, see p. A-7 */
#define SIS_BCAST_MTU 4096     /* Maximum size of broadcast MTU for u_pdu, see p. A-7 */
#define SIS_MAX_PDU_SIZE (SIS_MIN_PDU_SIZE + SIS_UNIHDR_SIZE + SIS_BCAST_MTU)

#define DTS_SEG_SIZE 800  /* arbitrarily tunable below 1k (10 bits, see C.3.2.10, p. C-14) */

/* N.B. In practise segment size is limited by 8 bit EOT (End Of Transmission) field
 * that has range of 127.5 seconds. Given slow data rate, a PDU can take long time
 * to transmit. For example: 127 seconds is 1190 bytes @ 75bps or 38KB @ 2400bps.
 * See C.3.2.3, p. C-9 for discussion. */

/* D_PDU type constants */

#define DTS_DATA_ONLY  0
#define DTS_ACK_ONLY   1
#define DTS_DATA_ACK   2
#define DTS_RESET      3
#define DTS_EDATA_ONLY 4
#define DTS_EACK_ONLY  5
#define DTS_MGMT       6
#define DTS_NONARQ     7
#define DTS_ENONARQ    8
/* 9-14 reserved */
#define DTS_WARNING   15

#define SIS_UNIDATA_IND_MIN_HDR 22  /* min == no error and no non-rx'd blocks */

/* S_PDU type constants (these are distinct from primitives) */

#define S_PDU_DATA               0
#define S_PDU_OK                 1
#define S_PDU_FAIL               2
#define S_PDU_HARD_LINK_REQ      3
#define S_PDU_HARD_LINK_OK       4
#define S_PDU_HARD_LINK_REJ      5
#define S_PDU_HARD_LINK_TERM     6
#define S_PDU_HARD_LINK_TERM_OK  7

/* C_PDU type constants (already shifted for use in C_PCI */

#define C_PDU_DATA           0x00
#define C_PDU_LINK_REQ       0x10
#define C_PDU_LINK_OK        0x20
#define C_PDU_LINK_REJ       0x30
#define C_PDU_LINK_BREAK     0x40
#define C_PDU_LINK_BREAK_OK  0x50

int sis_decode(struct hi_thr* hit, struct hi_io* io);
int dts_decode(struct hi_thr* hit, struct hi_io* io);
void dts_send_uni(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req, int len, char* d);
void sis_send_bind(struct hi_thr* hit, struct hi_io* io, int sap, int rank, int svc_type);
struct hi_pdu* sis_encode_start(struct hi_thr* hit, int op, int len);

struct sis_sap {
  struct hi_io* io;
  char rank;
  char tx_mode;
  char flags;
  char n_re_tx;
};

#define SIS_MAX_SAP_ID 16
extern struct sis_sap saptab[SIS_MAX_SAP_ID];
extern pthread_mutex_t saptab_mut;

struct dts_conn {
  char remote_station_addr[4];
  int c_pdu_id;
  int rx_lwe;
  int rx_uwe;
  char acks[32];  /* Bitmap of acks, kept on receiving end */
  /* *** Do we need "memory ACK" array for misreceived PDUs? */
  struct hi_pdu* nonarq_pdus[4096];  /* The c_pdu_id is 12 bits */
  
  int tx_lwe;
  int tx_uwe;
  struct hi_pdu* tx_pdus[256];  /* Hold PDUs so we can re_tx them if they are not ack'd */
};
#endif

struct u_pdu {
  short len;
  char* data;
};

struct c_pdu_buf {
  int size;
#ifdef ENA_S5066
  char map[SIS_MAX_PDU_SIZE/8];  /* bitmap of bytes received so we know if we have received all */
  char m[SIS_MAX_PDU_SIZE];
#endif
};

void test_ping(struct hi_thr* hit, struct hi_io* io);
int http_decode(struct hi_thr* hit, struct hi_io* io);

/* SMTP support */

#define SMTP_MIN_PDU_SIZE 5     /* preamble and length field */
#define SMTP_MAX_PDU_SIZE 4096

/* States of SMTP parsing for client */
#define SMTP_INIT 0  /* wait for 220 greet\n (server: send 220 greet) */
#define SMTP_EHLO 1  /* 220 greet seen, issue EHLO<sp>s\n */
#define SMTP_RDY  2  /* wait for 250 from EHLO */
#define SMTP_MAIL 3  /*  send piped SMTP payload, MAIL FROM:<a>\n */
#define SMTP_RCPT 4  /*  RCPT TO:<a>\n or DATA\n */
#define SMTP_DATA 5  /*  Data entry stage (354) */
#define SMTP_SEND 6  /* wait for 354, send the message and \r\n.\r\n */
#define SMTP_SENT 7  /* Mail sent (250 after 354) */
#define SMTP_QUIT 8  /* wait for 221 goodbye */

/* States of SMTP parsing for server */
#define SMTP_START  11  /* expect EHLO, send 250 */
#define SMTP_MAIN   12  /* expect MAIL FROM, process RCPT TOs, DATA, and \r\n.\r\n */
#define SMTP_TO     13
#define SMTP_MORE0  14  /* Long mail. Keep sending body as SIS primitives. Noting seen. */
#define SMTP_MORE1  15  /* Assume "\r\n" has been seen and ".\r\n" needs to be seen. */
#define SMTP_MORE2  16  /* Assume "\r\n." has been seen and "\r\n" needs to be seen. */
#define SMTP_WAIT   17  /* expect 354 */
#define SMTP_STATUS 18  /* expect staus of message: 250 = sent, others error */
#define SMTP_END    19  /* expect QUIT and send 221 bye. If get MAIL FROM move to SMTP_MAIN. */

#define SMTP_GREET_DOMAIN "zxid.org"  /* *** config domain */
#define SMTP_EHLO_CLI "Beautiful"

int smtp_decode_req(struct hi_thr* hit, struct hi_io* io);
int smtp_decode_resp(struct hi_thr* hit, struct hi_io* io);

/* HTTP/1.0 Support */

#define HTTP_MIN_PDU_SIZE ((int)sizeof("GET / HTTP/1.0\n\n")-1)

/* STOMP 1.1 Support */

#define STOMP_MIN_PDU_SIZE (sizeof("ACK\n\n\0")-1)

/* States of STOMP parsing for client */
#define STOMP_INIT 0  /* Issue STOMP */
#define STOMP_CONN 1  /* wait for CONNECTED  (server: send CONNECTED) */
#define STOMP_RDY  2  /*  wait for any message */
#define STOMP_SEND 3  /*  SEND message */
#define STOMP_RCPT 4  /*  wait for RECEIPT */
#define STOMP_ACK  5  /*  ACK */
#define STOMP_SUB  6  /*  SUBSCRIBE */
#define STOMP_UNSB 7  /*  UNSUBSCRIBE */
#define STOMP_DISC 8  /* DISCONNECT */
#define STOMP_QUIT 9  /* wait for RECEIPT in response to DISCONNECT */

/* States of STOMP parsing for server */
#define STOMP_START  20  /* expect STOMP (or CONNECT), send CONNECTED */
#define STOMP_MAIN   21  /* expect any command, e.g. SEND or SUBSCRIBE */
#define STOMP_MSG    22  /* Wait for ACK from MESSAGE */
#define STOMP_END    23  /* RECEPIT in response to DISCONNECT sent, linger before close */

int stomp_parse_pdu(struct hi_pdu* pdu);
void stomp_parse_header(struct hi_pdu* req, char* hdr, char* val);
int stomp_decode(struct hi_thr* hit, struct hi_io* io);
void stomp_msg_deliver(struct hi_thr* hit, struct hi_pdu* db_pdu);
int stomp_err(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req, const char* ecode, const char* emsg);
void stomp_send_receipt(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req);

/* memcached binary protocol support (1.3, 24byte header) */

#define MCDB_MIN_PDU_SIZE 24  /* fixed header of the binary protocol */

#define MCDB_REQ_MAGIC  0x80
#define MCDB_RESP_MAGIC 0x81

#define MCDB_GET  0x00
#define MCDB_SET  0x01
#define MCDB_ADD  0x02
#define MCDB_REPLACE 0x03
#define MCDB_DEL  0x04
#define MCDB_INC  0x05
#define MCDB_DEC  0x06
#define MCDB_QUIT 0x07
#define MCDB_FLUSH 0x08
#define MCDB_GETQ 0x09
#define MCDB_NOP  0x0A
#define MCDB_VERS 0x0B
#define MCDB_GETK 0x0C
#define MCDB_GETKQ 0x0D
#define MCDB_APPEND 0x0E
#define MCDB_PREPEND 0x0F
#define MCDB_STAT 0x10
#define MCDB_SETQ 0x11
#define MCDB_ADDQ 0x12
#define MCDB_REPLACEQ 0x13
#define MCDB_DELQ 0x14
#define MCDB_INCQ 0x15
#define MCDB_DECQ 0x16
#define MCDB_QUITQ 0x17
#define MCDB_FLUSHQ 0x18
#define MCDB_APPENDQ 0x19
#define MCDB_PREPENDQ 0x1A
#define MCDB_ZXMSGPACK 0x21  /* ZX specific: msgpack formatted envelope */

#define MCDB_STATUS_OK 0x0000
#define MCDB_STATUS_KEY_NOT_FOUND   0x0001
#define MCDB_STATUS_KEY_EXISTS      0x0002
#define MCDB_STATUS_VALUE_TOO_LARGE 0x0003
#define MCDB_STATUS_INVALID_ARGS    0x0004
#define MCDB_STATUS_ITEM_NOT_STORED 0x0005
#define MCDB_STATUS_UNKNOWN_COMMAND 0x0081
#define MCDB_STATUS_OUT_OF_MEMORY   0x0082

int mcdb_decode(struct hi_thr* hit, struct hi_io* io);

struct hi_ch* zxbus_find_ch(struct hiios* shf, int len, const char* dest);
struct hi_ent* zxbus_load_ent(struct hiios* shf, int len, const char* eid);
int zxbus_login_ent(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req);
int zxbus_retire(struct hi_thr* hit, struct hi_pdu* db_pdu);
int zxbus_persist(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req);
int zxbus_subscribe(struct hi_thr* hit, struct hi_io* io, struct hi_pdu* req);
int zxbus_load_subs(struct hiios* shf);
void zxbus_sched_pending_delivery(struct hi_thr* hit, const char* dest);

#endif /* _hiproto_h */
