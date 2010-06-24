/* c/zx-mm7-data.h - WARNING: This header was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Datastructure design, topography, and layout
 * Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for
 * terms and conditions of use. Element and attributes names as well
 * as some topography are derived from schema descriptions that were used as
 * input and may be subject to their own copright. */

#ifndef _c_zx_mm7_data_h
#define _c_zx_mm7_data_h

#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"

#ifndef ZX_ELEM_EXT
#define ZX_ELEM_EXT  /* This extension point should be defined by who includes this file. */
#endif

/* -------------------------- mm7_AdditionalInformation -------------------------- */
/* refby( zx_mm7_ReplaceReq_s zx_mm7_extendedReplaceReq_s zx_mm7_SubmitReq_s zx_mm7_DeliverReq_s ) */
#ifndef zx_mm7_AdditionalInformation_EXT
#define zx_mm7_AdditionalInformation_EXT
#endif

struct zx_mm7_AdditionalInformation_s* zx_DEC_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_AdditionalInformation_s* zx_NEW_mm7_AdditionalInformation(struct zx_ctx* c);
void zx_FREE_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_mm7_AdditionalInformation_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_AdditionalInformation_s* zx_DEEP_CLONE_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_mm7_AdditionalInformation_s* x, int dup_strs);
void zx_DUP_STRS_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_mm7_AdditionalInformation_s* x);
int zx_WALK_SO_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_mm7_AdditionalInformation_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_mm7_AdditionalInformation_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_mm7_AdditionalInformation_s* x);
int zx_LEN_WO_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_mm7_AdditionalInformation_s* x);
char* zx_ENC_SO_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_mm7_AdditionalInformation_s* x, char* p);
char* zx_ENC_WO_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_mm7_AdditionalInformation_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_mm7_AdditionalInformation_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_AdditionalInformation(struct zx_ctx* c, struct zx_mm7_AdditionalInformation_s* x);

struct zx_mm7_AdditionalInformation_s {
  ZX_ELEM_EXT
  zx_mm7_AdditionalInformation_EXT
  struct zx_str* href;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_mm7_AdditionalInformation_GET_href(struct zx_mm7_AdditionalInformation_s* x);





void zx_mm7_AdditionalInformation_PUT_href(struct zx_mm7_AdditionalInformation_s* x, struct zx_str* y);





#endif
/* -------------------------- mm7_Bcc -------------------------- */
/* refby( zx_mm7_Recipients_s ) */
#ifndef zx_mm7_Bcc_EXT
#define zx_mm7_Bcc_EXT
#endif

struct zx_mm7_Bcc_s* zx_DEC_mm7_Bcc(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Bcc_s* zx_NEW_mm7_Bcc(struct zx_ctx* c);
void zx_FREE_mm7_Bcc(struct zx_ctx* c, struct zx_mm7_Bcc_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Bcc_s* zx_DEEP_CLONE_mm7_Bcc(struct zx_ctx* c, struct zx_mm7_Bcc_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Bcc(struct zx_ctx* c, struct zx_mm7_Bcc_s* x);
int zx_WALK_SO_mm7_Bcc(struct zx_ctx* c, struct zx_mm7_Bcc_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Bcc(struct zx_ctx* c, struct zx_mm7_Bcc_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Bcc(struct zx_ctx* c, struct zx_mm7_Bcc_s* x);
int zx_LEN_WO_mm7_Bcc(struct zx_ctx* c, struct zx_mm7_Bcc_s* x);
char* zx_ENC_SO_mm7_Bcc(struct zx_ctx* c, struct zx_mm7_Bcc_s* x, char* p);
char* zx_ENC_WO_mm7_Bcc(struct zx_ctx* c, struct zx_mm7_Bcc_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Bcc(struct zx_ctx* c, struct zx_mm7_Bcc_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Bcc(struct zx_ctx* c, struct zx_mm7_Bcc_s* x);

struct zx_mm7_Bcc_s {
  ZX_ELEM_EXT
  zx_mm7_Bcc_EXT
  struct zx_mm7_RFC2822Address_s* RFC2822Address;	/* {0,1} nada */
  struct zx_mm7_Number_s* Number;	/* {0,1} nada */
  struct zx_mm7_ShortCode_s* ShortCode;	/* {0,1} nada */
  struct zx_mm7_Extension_s* Extension;	/* {0,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_RFC2822Address_s* zx_mm7_Bcc_GET_RFC2822Address(struct zx_mm7_Bcc_s* x, int n);
struct zx_mm7_Number_s* zx_mm7_Bcc_GET_Number(struct zx_mm7_Bcc_s* x, int n);
struct zx_mm7_ShortCode_s* zx_mm7_Bcc_GET_ShortCode(struct zx_mm7_Bcc_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_Bcc_GET_Extension(struct zx_mm7_Bcc_s* x, int n);

int zx_mm7_Bcc_NUM_RFC2822Address(struct zx_mm7_Bcc_s* x);
int zx_mm7_Bcc_NUM_Number(struct zx_mm7_Bcc_s* x);
int zx_mm7_Bcc_NUM_ShortCode(struct zx_mm7_Bcc_s* x);
int zx_mm7_Bcc_NUM_Extension(struct zx_mm7_Bcc_s* x);

struct zx_mm7_RFC2822Address_s* zx_mm7_Bcc_POP_RFC2822Address(struct zx_mm7_Bcc_s* x);
struct zx_mm7_Number_s* zx_mm7_Bcc_POP_Number(struct zx_mm7_Bcc_s* x);
struct zx_mm7_ShortCode_s* zx_mm7_Bcc_POP_ShortCode(struct zx_mm7_Bcc_s* x);
struct zx_mm7_Extension_s* zx_mm7_Bcc_POP_Extension(struct zx_mm7_Bcc_s* x);

void zx_mm7_Bcc_PUSH_RFC2822Address(struct zx_mm7_Bcc_s* x, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_Bcc_PUSH_Number(struct zx_mm7_Bcc_s* x, struct zx_mm7_Number_s* y);
void zx_mm7_Bcc_PUSH_ShortCode(struct zx_mm7_Bcc_s* x, struct zx_mm7_ShortCode_s* y);
void zx_mm7_Bcc_PUSH_Extension(struct zx_mm7_Bcc_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_Bcc_PUT_RFC2822Address(struct zx_mm7_Bcc_s* x, int n, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_Bcc_PUT_Number(struct zx_mm7_Bcc_s* x, int n, struct zx_mm7_Number_s* y);
void zx_mm7_Bcc_PUT_ShortCode(struct zx_mm7_Bcc_s* x, int n, struct zx_mm7_ShortCode_s* y);
void zx_mm7_Bcc_PUT_Extension(struct zx_mm7_Bcc_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_Bcc_ADD_RFC2822Address(struct zx_mm7_Bcc_s* x, int n, struct zx_mm7_RFC2822Address_s* z);
void zx_mm7_Bcc_ADD_Number(struct zx_mm7_Bcc_s* x, int n, struct zx_mm7_Number_s* z);
void zx_mm7_Bcc_ADD_ShortCode(struct zx_mm7_Bcc_s* x, int n, struct zx_mm7_ShortCode_s* z);
void zx_mm7_Bcc_ADD_Extension(struct zx_mm7_Bcc_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_Bcc_DEL_RFC2822Address(struct zx_mm7_Bcc_s* x, int n);
void zx_mm7_Bcc_DEL_Number(struct zx_mm7_Bcc_s* x, int n);
void zx_mm7_Bcc_DEL_ShortCode(struct zx_mm7_Bcc_s* x, int n);
void zx_mm7_Bcc_DEL_Extension(struct zx_mm7_Bcc_s* x, int n);

void zx_mm7_Bcc_REV_RFC2822Address(struct zx_mm7_Bcc_s* x);
void zx_mm7_Bcc_REV_Number(struct zx_mm7_Bcc_s* x);
void zx_mm7_Bcc_REV_ShortCode(struct zx_mm7_Bcc_s* x);
void zx_mm7_Bcc_REV_Extension(struct zx_mm7_Bcc_s* x);

#endif
/* -------------------------- mm7_CancelReq -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_CancelReq_EXT
#define zx_mm7_CancelReq_EXT
#endif

struct zx_mm7_CancelReq_s* zx_DEC_mm7_CancelReq(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_CancelReq_s* zx_NEW_mm7_CancelReq(struct zx_ctx* c);
void zx_FREE_mm7_CancelReq(struct zx_ctx* c, struct zx_mm7_CancelReq_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_CancelReq_s* zx_DEEP_CLONE_mm7_CancelReq(struct zx_ctx* c, struct zx_mm7_CancelReq_s* x, int dup_strs);
void zx_DUP_STRS_mm7_CancelReq(struct zx_ctx* c, struct zx_mm7_CancelReq_s* x);
int zx_WALK_SO_mm7_CancelReq(struct zx_ctx* c, struct zx_mm7_CancelReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_CancelReq(struct zx_ctx* c, struct zx_mm7_CancelReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_CancelReq(struct zx_ctx* c, struct zx_mm7_CancelReq_s* x);
int zx_LEN_WO_mm7_CancelReq(struct zx_ctx* c, struct zx_mm7_CancelReq_s* x);
char* zx_ENC_SO_mm7_CancelReq(struct zx_ctx* c, struct zx_mm7_CancelReq_s* x, char* p);
char* zx_ENC_WO_mm7_CancelReq(struct zx_ctx* c, struct zx_mm7_CancelReq_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_CancelReq(struct zx_ctx* c, struct zx_mm7_CancelReq_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_CancelReq(struct zx_ctx* c, struct zx_mm7_CancelReq_s* x);

struct zx_mm7_CancelReq_s {
  ZX_ELEM_EXT
  zx_mm7_CancelReq_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_SenderIdentification_s* SenderIdentification;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
  struct zx_elem_s* MessageID;	/* {1,1} xs:string */
  struct zx_mm7_Recipients_s* Recipients;	/* {0,1}  */
  struct zx_elem_s* ApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* ReplyApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* AuxApplicInfo;	/* {0,1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_CancelReq_GET_MM7Version(struct zx_mm7_CancelReq_s* x, int n);
struct zx_mm7_SenderIdentification_s* zx_mm7_CancelReq_GET_SenderIdentification(struct zx_mm7_CancelReq_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_CancelReq_GET_Extension(struct zx_mm7_CancelReq_s* x, int n);
struct zx_elem_s* zx_mm7_CancelReq_GET_MessageID(struct zx_mm7_CancelReq_s* x, int n);
struct zx_mm7_Recipients_s* zx_mm7_CancelReq_GET_Recipients(struct zx_mm7_CancelReq_s* x, int n);
struct zx_elem_s* zx_mm7_CancelReq_GET_ApplicID(struct zx_mm7_CancelReq_s* x, int n);
struct zx_elem_s* zx_mm7_CancelReq_GET_ReplyApplicID(struct zx_mm7_CancelReq_s* x, int n);
struct zx_elem_s* zx_mm7_CancelReq_GET_AuxApplicInfo(struct zx_mm7_CancelReq_s* x, int n);

int zx_mm7_CancelReq_NUM_MM7Version(struct zx_mm7_CancelReq_s* x);
int zx_mm7_CancelReq_NUM_SenderIdentification(struct zx_mm7_CancelReq_s* x);
int zx_mm7_CancelReq_NUM_Extension(struct zx_mm7_CancelReq_s* x);
int zx_mm7_CancelReq_NUM_MessageID(struct zx_mm7_CancelReq_s* x);
int zx_mm7_CancelReq_NUM_Recipients(struct zx_mm7_CancelReq_s* x);
int zx_mm7_CancelReq_NUM_ApplicID(struct zx_mm7_CancelReq_s* x);
int zx_mm7_CancelReq_NUM_ReplyApplicID(struct zx_mm7_CancelReq_s* x);
int zx_mm7_CancelReq_NUM_AuxApplicInfo(struct zx_mm7_CancelReq_s* x);

struct zx_elem_s* zx_mm7_CancelReq_POP_MM7Version(struct zx_mm7_CancelReq_s* x);
struct zx_mm7_SenderIdentification_s* zx_mm7_CancelReq_POP_SenderIdentification(struct zx_mm7_CancelReq_s* x);
struct zx_mm7_Extension_s* zx_mm7_CancelReq_POP_Extension(struct zx_mm7_CancelReq_s* x);
struct zx_elem_s* zx_mm7_CancelReq_POP_MessageID(struct zx_mm7_CancelReq_s* x);
struct zx_mm7_Recipients_s* zx_mm7_CancelReq_POP_Recipients(struct zx_mm7_CancelReq_s* x);
struct zx_elem_s* zx_mm7_CancelReq_POP_ApplicID(struct zx_mm7_CancelReq_s* x);
struct zx_elem_s* zx_mm7_CancelReq_POP_ReplyApplicID(struct zx_mm7_CancelReq_s* x);
struct zx_elem_s* zx_mm7_CancelReq_POP_AuxApplicInfo(struct zx_mm7_CancelReq_s* x);

void zx_mm7_CancelReq_PUSH_MM7Version(struct zx_mm7_CancelReq_s* x, struct zx_elem_s* y);
void zx_mm7_CancelReq_PUSH_SenderIdentification(struct zx_mm7_CancelReq_s* x, struct zx_mm7_SenderIdentification_s* y);
void zx_mm7_CancelReq_PUSH_Extension(struct zx_mm7_CancelReq_s* x, struct zx_mm7_Extension_s* y);
void zx_mm7_CancelReq_PUSH_MessageID(struct zx_mm7_CancelReq_s* x, struct zx_elem_s* y);
void zx_mm7_CancelReq_PUSH_Recipients(struct zx_mm7_CancelReq_s* x, struct zx_mm7_Recipients_s* y);
void zx_mm7_CancelReq_PUSH_ApplicID(struct zx_mm7_CancelReq_s* x, struct zx_elem_s* y);
void zx_mm7_CancelReq_PUSH_ReplyApplicID(struct zx_mm7_CancelReq_s* x, struct zx_elem_s* y);
void zx_mm7_CancelReq_PUSH_AuxApplicInfo(struct zx_mm7_CancelReq_s* x, struct zx_elem_s* y);


void zx_mm7_CancelReq_PUT_MM7Version(struct zx_mm7_CancelReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_CancelReq_PUT_SenderIdentification(struct zx_mm7_CancelReq_s* x, int n, struct zx_mm7_SenderIdentification_s* y);
void zx_mm7_CancelReq_PUT_Extension(struct zx_mm7_CancelReq_s* x, int n, struct zx_mm7_Extension_s* y);
void zx_mm7_CancelReq_PUT_MessageID(struct zx_mm7_CancelReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_CancelReq_PUT_Recipients(struct zx_mm7_CancelReq_s* x, int n, struct zx_mm7_Recipients_s* y);
void zx_mm7_CancelReq_PUT_ApplicID(struct zx_mm7_CancelReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_CancelReq_PUT_ReplyApplicID(struct zx_mm7_CancelReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_CancelReq_PUT_AuxApplicInfo(struct zx_mm7_CancelReq_s* x, int n, struct zx_elem_s* y);

void zx_mm7_CancelReq_ADD_MM7Version(struct zx_mm7_CancelReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_CancelReq_ADD_SenderIdentification(struct zx_mm7_CancelReq_s* x, int n, struct zx_mm7_SenderIdentification_s* z);
void zx_mm7_CancelReq_ADD_Extension(struct zx_mm7_CancelReq_s* x, int n, struct zx_mm7_Extension_s* z);
void zx_mm7_CancelReq_ADD_MessageID(struct zx_mm7_CancelReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_CancelReq_ADD_Recipients(struct zx_mm7_CancelReq_s* x, int n, struct zx_mm7_Recipients_s* z);
void zx_mm7_CancelReq_ADD_ApplicID(struct zx_mm7_CancelReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_CancelReq_ADD_ReplyApplicID(struct zx_mm7_CancelReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_CancelReq_ADD_AuxApplicInfo(struct zx_mm7_CancelReq_s* x, int n, struct zx_elem_s* z);

void zx_mm7_CancelReq_DEL_MM7Version(struct zx_mm7_CancelReq_s* x, int n);
void zx_mm7_CancelReq_DEL_SenderIdentification(struct zx_mm7_CancelReq_s* x, int n);
void zx_mm7_CancelReq_DEL_Extension(struct zx_mm7_CancelReq_s* x, int n);
void zx_mm7_CancelReq_DEL_MessageID(struct zx_mm7_CancelReq_s* x, int n);
void zx_mm7_CancelReq_DEL_Recipients(struct zx_mm7_CancelReq_s* x, int n);
void zx_mm7_CancelReq_DEL_ApplicID(struct zx_mm7_CancelReq_s* x, int n);
void zx_mm7_CancelReq_DEL_ReplyApplicID(struct zx_mm7_CancelReq_s* x, int n);
void zx_mm7_CancelReq_DEL_AuxApplicInfo(struct zx_mm7_CancelReq_s* x, int n);

void zx_mm7_CancelReq_REV_MM7Version(struct zx_mm7_CancelReq_s* x);
void zx_mm7_CancelReq_REV_SenderIdentification(struct zx_mm7_CancelReq_s* x);
void zx_mm7_CancelReq_REV_Extension(struct zx_mm7_CancelReq_s* x);
void zx_mm7_CancelReq_REV_MessageID(struct zx_mm7_CancelReq_s* x);
void zx_mm7_CancelReq_REV_Recipients(struct zx_mm7_CancelReq_s* x);
void zx_mm7_CancelReq_REV_ApplicID(struct zx_mm7_CancelReq_s* x);
void zx_mm7_CancelReq_REV_ReplyApplicID(struct zx_mm7_CancelReq_s* x);
void zx_mm7_CancelReq_REV_AuxApplicInfo(struct zx_mm7_CancelReq_s* x);

#endif
/* -------------------------- mm7_CancelRsp -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_CancelRsp_EXT
#define zx_mm7_CancelRsp_EXT
#endif

struct zx_mm7_CancelRsp_s* zx_DEC_mm7_CancelRsp(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_CancelRsp_s* zx_NEW_mm7_CancelRsp(struct zx_ctx* c);
void zx_FREE_mm7_CancelRsp(struct zx_ctx* c, struct zx_mm7_CancelRsp_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_CancelRsp_s* zx_DEEP_CLONE_mm7_CancelRsp(struct zx_ctx* c, struct zx_mm7_CancelRsp_s* x, int dup_strs);
void zx_DUP_STRS_mm7_CancelRsp(struct zx_ctx* c, struct zx_mm7_CancelRsp_s* x);
int zx_WALK_SO_mm7_CancelRsp(struct zx_ctx* c, struct zx_mm7_CancelRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_CancelRsp(struct zx_ctx* c, struct zx_mm7_CancelRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_CancelRsp(struct zx_ctx* c, struct zx_mm7_CancelRsp_s* x);
int zx_LEN_WO_mm7_CancelRsp(struct zx_ctx* c, struct zx_mm7_CancelRsp_s* x);
char* zx_ENC_SO_mm7_CancelRsp(struct zx_ctx* c, struct zx_mm7_CancelRsp_s* x, char* p);
char* zx_ENC_WO_mm7_CancelRsp(struct zx_ctx* c, struct zx_mm7_CancelRsp_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_CancelRsp(struct zx_ctx* c, struct zx_mm7_CancelRsp_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_CancelRsp(struct zx_ctx* c, struct zx_mm7_CancelRsp_s* x);

struct zx_mm7_CancelRsp_s {
  ZX_ELEM_EXT
  zx_mm7_CancelRsp_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_Status_s* Status;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_CancelRsp_GET_MM7Version(struct zx_mm7_CancelRsp_s* x, int n);
struct zx_mm7_Status_s* zx_mm7_CancelRsp_GET_Status(struct zx_mm7_CancelRsp_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_CancelRsp_GET_Extension(struct zx_mm7_CancelRsp_s* x, int n);

int zx_mm7_CancelRsp_NUM_MM7Version(struct zx_mm7_CancelRsp_s* x);
int zx_mm7_CancelRsp_NUM_Status(struct zx_mm7_CancelRsp_s* x);
int zx_mm7_CancelRsp_NUM_Extension(struct zx_mm7_CancelRsp_s* x);

struct zx_elem_s* zx_mm7_CancelRsp_POP_MM7Version(struct zx_mm7_CancelRsp_s* x);
struct zx_mm7_Status_s* zx_mm7_CancelRsp_POP_Status(struct zx_mm7_CancelRsp_s* x);
struct zx_mm7_Extension_s* zx_mm7_CancelRsp_POP_Extension(struct zx_mm7_CancelRsp_s* x);

void zx_mm7_CancelRsp_PUSH_MM7Version(struct zx_mm7_CancelRsp_s* x, struct zx_elem_s* y);
void zx_mm7_CancelRsp_PUSH_Status(struct zx_mm7_CancelRsp_s* x, struct zx_mm7_Status_s* y);
void zx_mm7_CancelRsp_PUSH_Extension(struct zx_mm7_CancelRsp_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_CancelRsp_PUT_MM7Version(struct zx_mm7_CancelRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_CancelRsp_PUT_Status(struct zx_mm7_CancelRsp_s* x, int n, struct zx_mm7_Status_s* y);
void zx_mm7_CancelRsp_PUT_Extension(struct zx_mm7_CancelRsp_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_CancelRsp_ADD_MM7Version(struct zx_mm7_CancelRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_CancelRsp_ADD_Status(struct zx_mm7_CancelRsp_s* x, int n, struct zx_mm7_Status_s* z);
void zx_mm7_CancelRsp_ADD_Extension(struct zx_mm7_CancelRsp_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_CancelRsp_DEL_MM7Version(struct zx_mm7_CancelRsp_s* x, int n);
void zx_mm7_CancelRsp_DEL_Status(struct zx_mm7_CancelRsp_s* x, int n);
void zx_mm7_CancelRsp_DEL_Extension(struct zx_mm7_CancelRsp_s* x, int n);

void zx_mm7_CancelRsp_REV_MM7Version(struct zx_mm7_CancelRsp_s* x);
void zx_mm7_CancelRsp_REV_Status(struct zx_mm7_CancelRsp_s* x);
void zx_mm7_CancelRsp_REV_Extension(struct zx_mm7_CancelRsp_s* x);

#endif
/* -------------------------- mm7_Cc -------------------------- */
/* refby( zx_mm7_Recipients_s ) */
#ifndef zx_mm7_Cc_EXT
#define zx_mm7_Cc_EXT
#endif

struct zx_mm7_Cc_s* zx_DEC_mm7_Cc(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Cc_s* zx_NEW_mm7_Cc(struct zx_ctx* c);
void zx_FREE_mm7_Cc(struct zx_ctx* c, struct zx_mm7_Cc_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Cc_s* zx_DEEP_CLONE_mm7_Cc(struct zx_ctx* c, struct zx_mm7_Cc_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Cc(struct zx_ctx* c, struct zx_mm7_Cc_s* x);
int zx_WALK_SO_mm7_Cc(struct zx_ctx* c, struct zx_mm7_Cc_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Cc(struct zx_ctx* c, struct zx_mm7_Cc_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Cc(struct zx_ctx* c, struct zx_mm7_Cc_s* x);
int zx_LEN_WO_mm7_Cc(struct zx_ctx* c, struct zx_mm7_Cc_s* x);
char* zx_ENC_SO_mm7_Cc(struct zx_ctx* c, struct zx_mm7_Cc_s* x, char* p);
char* zx_ENC_WO_mm7_Cc(struct zx_ctx* c, struct zx_mm7_Cc_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Cc(struct zx_ctx* c, struct zx_mm7_Cc_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Cc(struct zx_ctx* c, struct zx_mm7_Cc_s* x);

struct zx_mm7_Cc_s {
  ZX_ELEM_EXT
  zx_mm7_Cc_EXT
  struct zx_mm7_RFC2822Address_s* RFC2822Address;	/* {0,1} nada */
  struct zx_mm7_Number_s* Number;	/* {0,1} nada */
  struct zx_mm7_ShortCode_s* ShortCode;	/* {0,1} nada */
  struct zx_mm7_Extension_s* Extension;	/* {0,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_RFC2822Address_s* zx_mm7_Cc_GET_RFC2822Address(struct zx_mm7_Cc_s* x, int n);
struct zx_mm7_Number_s* zx_mm7_Cc_GET_Number(struct zx_mm7_Cc_s* x, int n);
struct zx_mm7_ShortCode_s* zx_mm7_Cc_GET_ShortCode(struct zx_mm7_Cc_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_Cc_GET_Extension(struct zx_mm7_Cc_s* x, int n);

int zx_mm7_Cc_NUM_RFC2822Address(struct zx_mm7_Cc_s* x);
int zx_mm7_Cc_NUM_Number(struct zx_mm7_Cc_s* x);
int zx_mm7_Cc_NUM_ShortCode(struct zx_mm7_Cc_s* x);
int zx_mm7_Cc_NUM_Extension(struct zx_mm7_Cc_s* x);

struct zx_mm7_RFC2822Address_s* zx_mm7_Cc_POP_RFC2822Address(struct zx_mm7_Cc_s* x);
struct zx_mm7_Number_s* zx_mm7_Cc_POP_Number(struct zx_mm7_Cc_s* x);
struct zx_mm7_ShortCode_s* zx_mm7_Cc_POP_ShortCode(struct zx_mm7_Cc_s* x);
struct zx_mm7_Extension_s* zx_mm7_Cc_POP_Extension(struct zx_mm7_Cc_s* x);

void zx_mm7_Cc_PUSH_RFC2822Address(struct zx_mm7_Cc_s* x, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_Cc_PUSH_Number(struct zx_mm7_Cc_s* x, struct zx_mm7_Number_s* y);
void zx_mm7_Cc_PUSH_ShortCode(struct zx_mm7_Cc_s* x, struct zx_mm7_ShortCode_s* y);
void zx_mm7_Cc_PUSH_Extension(struct zx_mm7_Cc_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_Cc_PUT_RFC2822Address(struct zx_mm7_Cc_s* x, int n, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_Cc_PUT_Number(struct zx_mm7_Cc_s* x, int n, struct zx_mm7_Number_s* y);
void zx_mm7_Cc_PUT_ShortCode(struct zx_mm7_Cc_s* x, int n, struct zx_mm7_ShortCode_s* y);
void zx_mm7_Cc_PUT_Extension(struct zx_mm7_Cc_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_Cc_ADD_RFC2822Address(struct zx_mm7_Cc_s* x, int n, struct zx_mm7_RFC2822Address_s* z);
void zx_mm7_Cc_ADD_Number(struct zx_mm7_Cc_s* x, int n, struct zx_mm7_Number_s* z);
void zx_mm7_Cc_ADD_ShortCode(struct zx_mm7_Cc_s* x, int n, struct zx_mm7_ShortCode_s* z);
void zx_mm7_Cc_ADD_Extension(struct zx_mm7_Cc_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_Cc_DEL_RFC2822Address(struct zx_mm7_Cc_s* x, int n);
void zx_mm7_Cc_DEL_Number(struct zx_mm7_Cc_s* x, int n);
void zx_mm7_Cc_DEL_ShortCode(struct zx_mm7_Cc_s* x, int n);
void zx_mm7_Cc_DEL_Extension(struct zx_mm7_Cc_s* x, int n);

void zx_mm7_Cc_REV_RFC2822Address(struct zx_mm7_Cc_s* x);
void zx_mm7_Cc_REV_Number(struct zx_mm7_Cc_s* x);
void zx_mm7_Cc_REV_ShortCode(struct zx_mm7_Cc_s* x);
void zx_mm7_Cc_REV_Extension(struct zx_mm7_Cc_s* x);

#endif
/* -------------------------- mm7_Content -------------------------- */
/* refby( zx_mm7_ReplaceReq_s zx_mm7_extendedReplaceReq_s zx_mm7_SubmitReq_s zx_mm7_DeliverReq_s ) */
#ifndef zx_mm7_Content_EXT
#define zx_mm7_Content_EXT
#endif

struct zx_mm7_Content_s* zx_DEC_mm7_Content(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Content_s* zx_NEW_mm7_Content(struct zx_ctx* c);
void zx_FREE_mm7_Content(struct zx_ctx* c, struct zx_mm7_Content_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Content_s* zx_DEEP_CLONE_mm7_Content(struct zx_ctx* c, struct zx_mm7_Content_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Content(struct zx_ctx* c, struct zx_mm7_Content_s* x);
int zx_WALK_SO_mm7_Content(struct zx_ctx* c, struct zx_mm7_Content_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Content(struct zx_ctx* c, struct zx_mm7_Content_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Content(struct zx_ctx* c, struct zx_mm7_Content_s* x);
int zx_LEN_WO_mm7_Content(struct zx_ctx* c, struct zx_mm7_Content_s* x);
char* zx_ENC_SO_mm7_Content(struct zx_ctx* c, struct zx_mm7_Content_s* x, char* p);
char* zx_ENC_WO_mm7_Content(struct zx_ctx* c, struct zx_mm7_Content_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Content(struct zx_ctx* c, struct zx_mm7_Content_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Content(struct zx_ctx* c, struct zx_mm7_Content_s* x);

struct zx_mm7_Content_s {
  ZX_ELEM_EXT
  zx_mm7_Content_EXT
  struct zx_str* allowAdaptations;	/* {0,1} attribute xs:boolean */
  struct zx_str* href;	/* {1,1} attribute xs:anyURI */
  struct zx_str* type;	/* {1,1} attribute hrxml:ExtendedAssociationTypeType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_mm7_Content_GET_allowAdaptations(struct zx_mm7_Content_s* x);
struct zx_str* zx_mm7_Content_GET_href(struct zx_mm7_Content_s* x);
struct zx_str* zx_mm7_Content_GET_type(struct zx_mm7_Content_s* x);





void zx_mm7_Content_PUT_allowAdaptations(struct zx_mm7_Content_s* x, struct zx_str* y);
void zx_mm7_Content_PUT_href(struct zx_mm7_Content_s* x, struct zx_str* y);
void zx_mm7_Content_PUT_type(struct zx_mm7_Content_s* x, struct zx_str* y);





#endif
/* -------------------------- mm7_DateTime -------------------------- */
/* refby( zx_mm7_Previouslysentdateandtime_s ) */
#ifndef zx_mm7_DateTime_EXT
#define zx_mm7_DateTime_EXT
#endif

struct zx_mm7_DateTime_s* zx_DEC_mm7_DateTime(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_DateTime_s* zx_NEW_mm7_DateTime(struct zx_ctx* c);
void zx_FREE_mm7_DateTime(struct zx_ctx* c, struct zx_mm7_DateTime_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_DateTime_s* zx_DEEP_CLONE_mm7_DateTime(struct zx_ctx* c, struct zx_mm7_DateTime_s* x, int dup_strs);
void zx_DUP_STRS_mm7_DateTime(struct zx_ctx* c, struct zx_mm7_DateTime_s* x);
int zx_WALK_SO_mm7_DateTime(struct zx_ctx* c, struct zx_mm7_DateTime_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_DateTime(struct zx_ctx* c, struct zx_mm7_DateTime_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_DateTime(struct zx_ctx* c, struct zx_mm7_DateTime_s* x);
int zx_LEN_WO_mm7_DateTime(struct zx_ctx* c, struct zx_mm7_DateTime_s* x);
char* zx_ENC_SO_mm7_DateTime(struct zx_ctx* c, struct zx_mm7_DateTime_s* x, char* p);
char* zx_ENC_WO_mm7_DateTime(struct zx_ctx* c, struct zx_mm7_DateTime_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_DateTime(struct zx_ctx* c, struct zx_mm7_DateTime_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_DateTime(struct zx_ctx* c, struct zx_mm7_DateTime_s* x);

struct zx_mm7_DateTime_s {
  ZX_ELEM_EXT
  zx_mm7_DateTime_EXT
  struct zx_str* sequence;	/* {0,1} attribute xs:positiveInteger */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_mm7_DateTime_GET_sequence(struct zx_mm7_DateTime_s* x);





void zx_mm7_DateTime_PUT_sequence(struct zx_mm7_DateTime_s* x, struct zx_str* y);





#endif
/* -------------------------- mm7_DeliverReq -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_DeliverReq_EXT
#define zx_mm7_DeliverReq_EXT
#endif

struct zx_mm7_DeliverReq_s* zx_DEC_mm7_DeliverReq(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_DeliverReq_s* zx_NEW_mm7_DeliverReq(struct zx_ctx* c);
void zx_FREE_mm7_DeliverReq(struct zx_ctx* c, struct zx_mm7_DeliverReq_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_DeliverReq_s* zx_DEEP_CLONE_mm7_DeliverReq(struct zx_ctx* c, struct zx_mm7_DeliverReq_s* x, int dup_strs);
void zx_DUP_STRS_mm7_DeliverReq(struct zx_ctx* c, struct zx_mm7_DeliverReq_s* x);
int zx_WALK_SO_mm7_DeliverReq(struct zx_ctx* c, struct zx_mm7_DeliverReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_DeliverReq(struct zx_ctx* c, struct zx_mm7_DeliverReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_DeliverReq(struct zx_ctx* c, struct zx_mm7_DeliverReq_s* x);
int zx_LEN_WO_mm7_DeliverReq(struct zx_ctx* c, struct zx_mm7_DeliverReq_s* x);
char* zx_ENC_SO_mm7_DeliverReq(struct zx_ctx* c, struct zx_mm7_DeliverReq_s* x, char* p);
char* zx_ENC_WO_mm7_DeliverReq(struct zx_ctx* c, struct zx_mm7_DeliverReq_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_DeliverReq(struct zx_ctx* c, struct zx_mm7_DeliverReq_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_DeliverReq(struct zx_ctx* c, struct zx_mm7_DeliverReq_s* x);

struct zx_mm7_DeliverReq_s {
  ZX_ELEM_EXT
  zx_mm7_DeliverReq_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_elem_s* MMSRelayServerID;	/* {0,1} xs:string */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
  struct zx_elem_s* VASPID;	/* {0,1} xs:string */
  struct zx_elem_s* VASID;	/* {0,1} xs:string */
  struct zx_elem_s* LinkedID;	/* {0,1} xs:string */
  struct zx_mm7_Sender_s* Sender;	/* {1,1}  */
  struct zx_mm7_Recipients_s* Recipients;	/* {0,1}  */
  struct zx_mm7_Previouslysentby_s* Previouslysentby;	/* {0,1}  */
  struct zx_mm7_Previouslysentdateandtime_s* Previouslysentdateandtime;	/* {0,1}  */
  struct zx_elem_s* SenderSPI;	/* {0,1} xs:string */
  struct zx_elem_s* RecipientSPI;	/* {0,1} xs:string */
  struct zx_elem_s* TimeStamp;	/* {0,1} xs:dateTime */
  struct zx_elem_s* ReplyChargingID;	/* {0,1} xs:string */
  struct zx_elem_s* Priority;	/* {0,1} Normal */
  struct zx_elem_s* Subject;	/* {0,1} xs:string */
  struct zx_elem_s* ApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* ReplyApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* AuxApplicInfo;	/* {0,1} xs:string */
  struct zx_mm7_UACapabilities_s* UACapabilities;	/* {0,1}  */
  struct zx_mm7_Content_s* Content;	/* {0,-1}  */
  struct zx_mm7_AdditionalInformation_s* AdditionalInformation;	/* {0,-1}  */
  struct zx_mm7_MessageExtraData_s* MessageExtraData;	/* {0,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_DeliverReq_GET_MM7Version(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_MMSRelayServerID(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_DeliverReq_GET_Extension(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_VASPID(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_VASID(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_LinkedID(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_mm7_Sender_s* zx_mm7_DeliverReq_GET_Sender(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_mm7_Recipients_s* zx_mm7_DeliverReq_GET_Recipients(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_mm7_Previouslysentby_s* zx_mm7_DeliverReq_GET_Previouslysentby(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_mm7_Previouslysentdateandtime_s* zx_mm7_DeliverReq_GET_Previouslysentdateandtime(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_SenderSPI(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_RecipientSPI(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_TimeStamp(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_ReplyChargingID(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_Priority(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_Subject(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_ApplicID(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_ReplyApplicID(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliverReq_GET_AuxApplicInfo(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_mm7_UACapabilities_s* zx_mm7_DeliverReq_GET_UACapabilities(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_mm7_Content_s* zx_mm7_DeliverReq_GET_Content(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_mm7_AdditionalInformation_s* zx_mm7_DeliverReq_GET_AdditionalInformation(struct zx_mm7_DeliverReq_s* x, int n);
struct zx_mm7_MessageExtraData_s* zx_mm7_DeliverReq_GET_MessageExtraData(struct zx_mm7_DeliverReq_s* x, int n);

int zx_mm7_DeliverReq_NUM_MM7Version(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_MMSRelayServerID(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_Extension(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_VASPID(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_VASID(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_LinkedID(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_Sender(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_Recipients(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_Previouslysentby(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_Previouslysentdateandtime(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_SenderSPI(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_RecipientSPI(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_TimeStamp(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_ReplyChargingID(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_Priority(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_Subject(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_ApplicID(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_ReplyApplicID(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_AuxApplicInfo(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_UACapabilities(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_Content(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_AdditionalInformation(struct zx_mm7_DeliverReq_s* x);
int zx_mm7_DeliverReq_NUM_MessageExtraData(struct zx_mm7_DeliverReq_s* x);

struct zx_elem_s* zx_mm7_DeliverReq_POP_MM7Version(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_MMSRelayServerID(struct zx_mm7_DeliverReq_s* x);
struct zx_mm7_Extension_s* zx_mm7_DeliverReq_POP_Extension(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_VASPID(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_VASID(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_LinkedID(struct zx_mm7_DeliverReq_s* x);
struct zx_mm7_Sender_s* zx_mm7_DeliverReq_POP_Sender(struct zx_mm7_DeliverReq_s* x);
struct zx_mm7_Recipients_s* zx_mm7_DeliverReq_POP_Recipients(struct zx_mm7_DeliverReq_s* x);
struct zx_mm7_Previouslysentby_s* zx_mm7_DeliverReq_POP_Previouslysentby(struct zx_mm7_DeliverReq_s* x);
struct zx_mm7_Previouslysentdateandtime_s* zx_mm7_DeliverReq_POP_Previouslysentdateandtime(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_SenderSPI(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_RecipientSPI(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_TimeStamp(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_ReplyChargingID(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_Priority(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_Subject(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_ApplicID(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_ReplyApplicID(struct zx_mm7_DeliverReq_s* x);
struct zx_elem_s* zx_mm7_DeliverReq_POP_AuxApplicInfo(struct zx_mm7_DeliverReq_s* x);
struct zx_mm7_UACapabilities_s* zx_mm7_DeliverReq_POP_UACapabilities(struct zx_mm7_DeliverReq_s* x);
struct zx_mm7_Content_s* zx_mm7_DeliverReq_POP_Content(struct zx_mm7_DeliverReq_s* x);
struct zx_mm7_AdditionalInformation_s* zx_mm7_DeliverReq_POP_AdditionalInformation(struct zx_mm7_DeliverReq_s* x);
struct zx_mm7_MessageExtraData_s* zx_mm7_DeliverReq_POP_MessageExtraData(struct zx_mm7_DeliverReq_s* x);

void zx_mm7_DeliverReq_PUSH_MM7Version(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_MMSRelayServerID(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_Extension(struct zx_mm7_DeliverReq_s* x, struct zx_mm7_Extension_s* y);
void zx_mm7_DeliverReq_PUSH_VASPID(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_VASID(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_LinkedID(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_Sender(struct zx_mm7_DeliverReq_s* x, struct zx_mm7_Sender_s* y);
void zx_mm7_DeliverReq_PUSH_Recipients(struct zx_mm7_DeliverReq_s* x, struct zx_mm7_Recipients_s* y);
void zx_mm7_DeliverReq_PUSH_Previouslysentby(struct zx_mm7_DeliverReq_s* x, struct zx_mm7_Previouslysentby_s* y);
void zx_mm7_DeliverReq_PUSH_Previouslysentdateandtime(struct zx_mm7_DeliverReq_s* x, struct zx_mm7_Previouslysentdateandtime_s* y);
void zx_mm7_DeliverReq_PUSH_SenderSPI(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_RecipientSPI(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_TimeStamp(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_ReplyChargingID(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_Priority(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_Subject(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_ApplicID(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_ReplyApplicID(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_AuxApplicInfo(struct zx_mm7_DeliverReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUSH_UACapabilities(struct zx_mm7_DeliverReq_s* x, struct zx_mm7_UACapabilities_s* y);
void zx_mm7_DeliverReq_PUSH_Content(struct zx_mm7_DeliverReq_s* x, struct zx_mm7_Content_s* y);
void zx_mm7_DeliverReq_PUSH_AdditionalInformation(struct zx_mm7_DeliverReq_s* x, struct zx_mm7_AdditionalInformation_s* y);
void zx_mm7_DeliverReq_PUSH_MessageExtraData(struct zx_mm7_DeliverReq_s* x, struct zx_mm7_MessageExtraData_s* y);


void zx_mm7_DeliverReq_PUT_MM7Version(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_MMSRelayServerID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_Extension(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Extension_s* y);
void zx_mm7_DeliverReq_PUT_VASPID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_VASID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_LinkedID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_Sender(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Sender_s* y);
void zx_mm7_DeliverReq_PUT_Recipients(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Recipients_s* y);
void zx_mm7_DeliverReq_PUT_Previouslysentby(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Previouslysentby_s* y);
void zx_mm7_DeliverReq_PUT_Previouslysentdateandtime(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Previouslysentdateandtime_s* y);
void zx_mm7_DeliverReq_PUT_SenderSPI(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_RecipientSPI(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_TimeStamp(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_ReplyChargingID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_Priority(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_Subject(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_ApplicID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_ReplyApplicID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_AuxApplicInfo(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverReq_PUT_UACapabilities(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_UACapabilities_s* y);
void zx_mm7_DeliverReq_PUT_Content(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Content_s* y);
void zx_mm7_DeliverReq_PUT_AdditionalInformation(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_AdditionalInformation_s* y);
void zx_mm7_DeliverReq_PUT_MessageExtraData(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_MessageExtraData_s* y);

void zx_mm7_DeliverReq_ADD_MM7Version(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_MMSRelayServerID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_Extension(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Extension_s* z);
void zx_mm7_DeliverReq_ADD_VASPID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_VASID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_LinkedID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_Sender(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Sender_s* z);
void zx_mm7_DeliverReq_ADD_Recipients(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Recipients_s* z);
void zx_mm7_DeliverReq_ADD_Previouslysentby(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Previouslysentby_s* z);
void zx_mm7_DeliverReq_ADD_Previouslysentdateandtime(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Previouslysentdateandtime_s* z);
void zx_mm7_DeliverReq_ADD_SenderSPI(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_RecipientSPI(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_TimeStamp(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_ReplyChargingID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_Priority(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_Subject(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_ApplicID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_ReplyApplicID(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_AuxApplicInfo(struct zx_mm7_DeliverReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverReq_ADD_UACapabilities(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_UACapabilities_s* z);
void zx_mm7_DeliverReq_ADD_Content(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_Content_s* z);
void zx_mm7_DeliverReq_ADD_AdditionalInformation(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_AdditionalInformation_s* z);
void zx_mm7_DeliverReq_ADD_MessageExtraData(struct zx_mm7_DeliverReq_s* x, int n, struct zx_mm7_MessageExtraData_s* z);

void zx_mm7_DeliverReq_DEL_MM7Version(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_MMSRelayServerID(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_Extension(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_VASPID(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_VASID(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_LinkedID(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_Sender(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_Recipients(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_Previouslysentby(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_Previouslysentdateandtime(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_SenderSPI(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_RecipientSPI(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_TimeStamp(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_ReplyChargingID(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_Priority(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_Subject(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_ApplicID(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_ReplyApplicID(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_AuxApplicInfo(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_UACapabilities(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_Content(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_AdditionalInformation(struct zx_mm7_DeliverReq_s* x, int n);
void zx_mm7_DeliverReq_DEL_MessageExtraData(struct zx_mm7_DeliverReq_s* x, int n);

void zx_mm7_DeliverReq_REV_MM7Version(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_MMSRelayServerID(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_Extension(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_VASPID(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_VASID(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_LinkedID(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_Sender(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_Recipients(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_Previouslysentby(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_Previouslysentdateandtime(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_SenderSPI(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_RecipientSPI(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_TimeStamp(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_ReplyChargingID(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_Priority(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_Subject(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_ApplicID(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_ReplyApplicID(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_AuxApplicInfo(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_UACapabilities(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_Content(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_AdditionalInformation(struct zx_mm7_DeliverReq_s* x);
void zx_mm7_DeliverReq_REV_MessageExtraData(struct zx_mm7_DeliverReq_s* x);

#endif
/* -------------------------- mm7_DeliverRsp -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_DeliverRsp_EXT
#define zx_mm7_DeliverRsp_EXT
#endif

struct zx_mm7_DeliverRsp_s* zx_DEC_mm7_DeliverRsp(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_DeliverRsp_s* zx_NEW_mm7_DeliverRsp(struct zx_ctx* c);
void zx_FREE_mm7_DeliverRsp(struct zx_ctx* c, struct zx_mm7_DeliverRsp_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_DeliverRsp_s* zx_DEEP_CLONE_mm7_DeliverRsp(struct zx_ctx* c, struct zx_mm7_DeliverRsp_s* x, int dup_strs);
void zx_DUP_STRS_mm7_DeliverRsp(struct zx_ctx* c, struct zx_mm7_DeliverRsp_s* x);
int zx_WALK_SO_mm7_DeliverRsp(struct zx_ctx* c, struct zx_mm7_DeliverRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_DeliverRsp(struct zx_ctx* c, struct zx_mm7_DeliverRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_DeliverRsp(struct zx_ctx* c, struct zx_mm7_DeliverRsp_s* x);
int zx_LEN_WO_mm7_DeliverRsp(struct zx_ctx* c, struct zx_mm7_DeliverRsp_s* x);
char* zx_ENC_SO_mm7_DeliverRsp(struct zx_ctx* c, struct zx_mm7_DeliverRsp_s* x, char* p);
char* zx_ENC_WO_mm7_DeliverRsp(struct zx_ctx* c, struct zx_mm7_DeliverRsp_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_DeliverRsp(struct zx_ctx* c, struct zx_mm7_DeliverRsp_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_DeliverRsp(struct zx_ctx* c, struct zx_mm7_DeliverRsp_s* x);

struct zx_mm7_DeliverRsp_s {
  ZX_ELEM_EXT
  zx_mm7_DeliverRsp_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_Status_s* Status;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
  struct zx_mm7_ServiceCode_s* ServiceCode;	/* {0,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_DeliverRsp_GET_MM7Version(struct zx_mm7_DeliverRsp_s* x, int n);
struct zx_mm7_Status_s* zx_mm7_DeliverRsp_GET_Status(struct zx_mm7_DeliverRsp_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_DeliverRsp_GET_Extension(struct zx_mm7_DeliverRsp_s* x, int n);
struct zx_mm7_ServiceCode_s* zx_mm7_DeliverRsp_GET_ServiceCode(struct zx_mm7_DeliverRsp_s* x, int n);

int zx_mm7_DeliverRsp_NUM_MM7Version(struct zx_mm7_DeliverRsp_s* x);
int zx_mm7_DeliverRsp_NUM_Status(struct zx_mm7_DeliverRsp_s* x);
int zx_mm7_DeliverRsp_NUM_Extension(struct zx_mm7_DeliverRsp_s* x);
int zx_mm7_DeliverRsp_NUM_ServiceCode(struct zx_mm7_DeliverRsp_s* x);

struct zx_elem_s* zx_mm7_DeliverRsp_POP_MM7Version(struct zx_mm7_DeliverRsp_s* x);
struct zx_mm7_Status_s* zx_mm7_DeliverRsp_POP_Status(struct zx_mm7_DeliverRsp_s* x);
struct zx_mm7_Extension_s* zx_mm7_DeliverRsp_POP_Extension(struct zx_mm7_DeliverRsp_s* x);
struct zx_mm7_ServiceCode_s* zx_mm7_DeliverRsp_POP_ServiceCode(struct zx_mm7_DeliverRsp_s* x);

void zx_mm7_DeliverRsp_PUSH_MM7Version(struct zx_mm7_DeliverRsp_s* x, struct zx_elem_s* y);
void zx_mm7_DeliverRsp_PUSH_Status(struct zx_mm7_DeliverRsp_s* x, struct zx_mm7_Status_s* y);
void zx_mm7_DeliverRsp_PUSH_Extension(struct zx_mm7_DeliverRsp_s* x, struct zx_mm7_Extension_s* y);
void zx_mm7_DeliverRsp_PUSH_ServiceCode(struct zx_mm7_DeliverRsp_s* x, struct zx_mm7_ServiceCode_s* y);


void zx_mm7_DeliverRsp_PUT_MM7Version(struct zx_mm7_DeliverRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliverRsp_PUT_Status(struct zx_mm7_DeliverRsp_s* x, int n, struct zx_mm7_Status_s* y);
void zx_mm7_DeliverRsp_PUT_Extension(struct zx_mm7_DeliverRsp_s* x, int n, struct zx_mm7_Extension_s* y);
void zx_mm7_DeliverRsp_PUT_ServiceCode(struct zx_mm7_DeliverRsp_s* x, int n, struct zx_mm7_ServiceCode_s* y);

void zx_mm7_DeliverRsp_ADD_MM7Version(struct zx_mm7_DeliverRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliverRsp_ADD_Status(struct zx_mm7_DeliverRsp_s* x, int n, struct zx_mm7_Status_s* z);
void zx_mm7_DeliverRsp_ADD_Extension(struct zx_mm7_DeliverRsp_s* x, int n, struct zx_mm7_Extension_s* z);
void zx_mm7_DeliverRsp_ADD_ServiceCode(struct zx_mm7_DeliverRsp_s* x, int n, struct zx_mm7_ServiceCode_s* z);

void zx_mm7_DeliverRsp_DEL_MM7Version(struct zx_mm7_DeliverRsp_s* x, int n);
void zx_mm7_DeliverRsp_DEL_Status(struct zx_mm7_DeliverRsp_s* x, int n);
void zx_mm7_DeliverRsp_DEL_Extension(struct zx_mm7_DeliverRsp_s* x, int n);
void zx_mm7_DeliverRsp_DEL_ServiceCode(struct zx_mm7_DeliverRsp_s* x, int n);

void zx_mm7_DeliverRsp_REV_MM7Version(struct zx_mm7_DeliverRsp_s* x);
void zx_mm7_DeliverRsp_REV_Status(struct zx_mm7_DeliverRsp_s* x);
void zx_mm7_DeliverRsp_REV_Extension(struct zx_mm7_DeliverRsp_s* x);
void zx_mm7_DeliverRsp_REV_ServiceCode(struct zx_mm7_DeliverRsp_s* x);

#endif
/* -------------------------- mm7_DeliveryCondition -------------------------- */
/* refby( zx_mm7_SubmitReq_s ) */
#ifndef zx_mm7_DeliveryCondition_EXT
#define zx_mm7_DeliveryCondition_EXT
#endif

struct zx_mm7_DeliveryCondition_s* zx_DEC_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_DeliveryCondition_s* zx_NEW_mm7_DeliveryCondition(struct zx_ctx* c);
void zx_FREE_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_mm7_DeliveryCondition_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_DeliveryCondition_s* zx_DEEP_CLONE_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_mm7_DeliveryCondition_s* x, int dup_strs);
void zx_DUP_STRS_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_mm7_DeliveryCondition_s* x);
int zx_WALK_SO_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_mm7_DeliveryCondition_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_mm7_DeliveryCondition_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_mm7_DeliveryCondition_s* x);
int zx_LEN_WO_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_mm7_DeliveryCondition_s* x);
char* zx_ENC_SO_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_mm7_DeliveryCondition_s* x, char* p);
char* zx_ENC_WO_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_mm7_DeliveryCondition_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_mm7_DeliveryCondition_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_DeliveryCondition(struct zx_ctx* c, struct zx_mm7_DeliveryCondition_s* x);

struct zx_mm7_DeliveryCondition_s {
  ZX_ELEM_EXT
  zx_mm7_DeliveryCondition_EXT
  struct zx_elem_s* DC;	/* {0,-1} xs:positiveInteger */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_DeliveryCondition_GET_DC(struct zx_mm7_DeliveryCondition_s* x, int n);

int zx_mm7_DeliveryCondition_NUM_DC(struct zx_mm7_DeliveryCondition_s* x);

struct zx_elem_s* zx_mm7_DeliveryCondition_POP_DC(struct zx_mm7_DeliveryCondition_s* x);

void zx_mm7_DeliveryCondition_PUSH_DC(struct zx_mm7_DeliveryCondition_s* x, struct zx_elem_s* y);


void zx_mm7_DeliveryCondition_PUT_DC(struct zx_mm7_DeliveryCondition_s* x, int n, struct zx_elem_s* y);

void zx_mm7_DeliveryCondition_ADD_DC(struct zx_mm7_DeliveryCondition_s* x, int n, struct zx_elem_s* z);

void zx_mm7_DeliveryCondition_DEL_DC(struct zx_mm7_DeliveryCondition_s* x, int n);

void zx_mm7_DeliveryCondition_REV_DC(struct zx_mm7_DeliveryCondition_s* x);

#endif
/* -------------------------- mm7_DeliveryReportReq -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_DeliveryReportReq_EXT
#define zx_mm7_DeliveryReportReq_EXT
#endif

struct zx_mm7_DeliveryReportReq_s* zx_DEC_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_DeliveryReportReq_s* zx_NEW_mm7_DeliveryReportReq(struct zx_ctx* c);
void zx_FREE_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_mm7_DeliveryReportReq_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_DeliveryReportReq_s* zx_DEEP_CLONE_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_mm7_DeliveryReportReq_s* x, int dup_strs);
void zx_DUP_STRS_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_mm7_DeliveryReportReq_s* x);
int zx_WALK_SO_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_mm7_DeliveryReportReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_mm7_DeliveryReportReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_mm7_DeliveryReportReq_s* x);
int zx_LEN_WO_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_mm7_DeliveryReportReq_s* x);
char* zx_ENC_SO_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_mm7_DeliveryReportReq_s* x, char* p);
char* zx_ENC_WO_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_mm7_DeliveryReportReq_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_mm7_DeliveryReportReq_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_DeliveryReportReq(struct zx_ctx* c, struct zx_mm7_DeliveryReportReq_s* x);

struct zx_mm7_DeliveryReportReq_s {
  ZX_ELEM_EXT
  zx_mm7_DeliveryReportReq_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_elem_s* MMSRelayServerID;	/* {0,1} xs:string */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
  struct zx_elem_s* MessageID;	/* {1,1} xs:string */
  struct zx_mm7_Recipient_s* Recipient;	/* {1,1}  */
  struct zx_mm7_Sender_s* Sender;	/* {1,1}  */
  struct zx_elem_s* Date;	/* {1,1} xs:dateTime */
  struct zx_elem_s* MMStatus;	/* {1,1} Indeterminate */
  struct zx_elem_s* MMStatusExtension;	/* {0,1} RejectionByMMSRecipient */
  struct zx_elem_s* StatusText;	/* {0,1} xs:string */
  struct zx_elem_s* ApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* ReplyApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* AuxApplicInfo;	/* {0,1} xs:string */
  struct zx_mm7_UACapabilities_s* UACapabilities;	/* {0,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_DeliveryReportReq_GET_MM7Version(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliveryReportReq_GET_MMSRelayServerID(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_DeliveryReportReq_GET_Extension(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliveryReportReq_GET_MessageID(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_mm7_Recipient_s* zx_mm7_DeliveryReportReq_GET_Recipient(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_mm7_Sender_s* zx_mm7_DeliveryReportReq_GET_Sender(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliveryReportReq_GET_Date(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliveryReportReq_GET_MMStatus(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliveryReportReq_GET_MMStatusExtension(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliveryReportReq_GET_StatusText(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliveryReportReq_GET_ApplicID(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliveryReportReq_GET_ReplyApplicID(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_elem_s* zx_mm7_DeliveryReportReq_GET_AuxApplicInfo(struct zx_mm7_DeliveryReportReq_s* x, int n);
struct zx_mm7_UACapabilities_s* zx_mm7_DeliveryReportReq_GET_UACapabilities(struct zx_mm7_DeliveryReportReq_s* x, int n);

int zx_mm7_DeliveryReportReq_NUM_MM7Version(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_MMSRelayServerID(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_Extension(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_MessageID(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_Recipient(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_Sender(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_Date(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_MMStatus(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_MMStatusExtension(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_StatusText(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_ApplicID(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_ReplyApplicID(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_AuxApplicInfo(struct zx_mm7_DeliveryReportReq_s* x);
int zx_mm7_DeliveryReportReq_NUM_UACapabilities(struct zx_mm7_DeliveryReportReq_s* x);

struct zx_elem_s* zx_mm7_DeliveryReportReq_POP_MM7Version(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_elem_s* zx_mm7_DeliveryReportReq_POP_MMSRelayServerID(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_mm7_Extension_s* zx_mm7_DeliveryReportReq_POP_Extension(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_elem_s* zx_mm7_DeliveryReportReq_POP_MessageID(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_mm7_Recipient_s* zx_mm7_DeliveryReportReq_POP_Recipient(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_mm7_Sender_s* zx_mm7_DeliveryReportReq_POP_Sender(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_elem_s* zx_mm7_DeliveryReportReq_POP_Date(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_elem_s* zx_mm7_DeliveryReportReq_POP_MMStatus(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_elem_s* zx_mm7_DeliveryReportReq_POP_MMStatusExtension(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_elem_s* zx_mm7_DeliveryReportReq_POP_StatusText(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_elem_s* zx_mm7_DeliveryReportReq_POP_ApplicID(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_elem_s* zx_mm7_DeliveryReportReq_POP_ReplyApplicID(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_elem_s* zx_mm7_DeliveryReportReq_POP_AuxApplicInfo(struct zx_mm7_DeliveryReportReq_s* x);
struct zx_mm7_UACapabilities_s* zx_mm7_DeliveryReportReq_POP_UACapabilities(struct zx_mm7_DeliveryReportReq_s* x);

void zx_mm7_DeliveryReportReq_PUSH_MM7Version(struct zx_mm7_DeliveryReportReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUSH_MMSRelayServerID(struct zx_mm7_DeliveryReportReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUSH_Extension(struct zx_mm7_DeliveryReportReq_s* x, struct zx_mm7_Extension_s* y);
void zx_mm7_DeliveryReportReq_PUSH_MessageID(struct zx_mm7_DeliveryReportReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUSH_Recipient(struct zx_mm7_DeliveryReportReq_s* x, struct zx_mm7_Recipient_s* y);
void zx_mm7_DeliveryReportReq_PUSH_Sender(struct zx_mm7_DeliveryReportReq_s* x, struct zx_mm7_Sender_s* y);
void zx_mm7_DeliveryReportReq_PUSH_Date(struct zx_mm7_DeliveryReportReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUSH_MMStatus(struct zx_mm7_DeliveryReportReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUSH_MMStatusExtension(struct zx_mm7_DeliveryReportReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUSH_StatusText(struct zx_mm7_DeliveryReportReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUSH_ApplicID(struct zx_mm7_DeliveryReportReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUSH_ReplyApplicID(struct zx_mm7_DeliveryReportReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUSH_AuxApplicInfo(struct zx_mm7_DeliveryReportReq_s* x, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUSH_UACapabilities(struct zx_mm7_DeliveryReportReq_s* x, struct zx_mm7_UACapabilities_s* y);


void zx_mm7_DeliveryReportReq_PUT_MM7Version(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUT_MMSRelayServerID(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUT_Extension(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_mm7_Extension_s* y);
void zx_mm7_DeliveryReportReq_PUT_MessageID(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUT_Recipient(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_mm7_Recipient_s* y);
void zx_mm7_DeliveryReportReq_PUT_Sender(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_mm7_Sender_s* y);
void zx_mm7_DeliveryReportReq_PUT_Date(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUT_MMStatus(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUT_MMStatusExtension(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUT_StatusText(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUT_ApplicID(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUT_ReplyApplicID(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUT_AuxApplicInfo(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliveryReportReq_PUT_UACapabilities(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_mm7_UACapabilities_s* y);

void zx_mm7_DeliveryReportReq_ADD_MM7Version(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliveryReportReq_ADD_MMSRelayServerID(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliveryReportReq_ADD_Extension(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_mm7_Extension_s* z);
void zx_mm7_DeliveryReportReq_ADD_MessageID(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliveryReportReq_ADD_Recipient(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_mm7_Recipient_s* z);
void zx_mm7_DeliveryReportReq_ADD_Sender(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_mm7_Sender_s* z);
void zx_mm7_DeliveryReportReq_ADD_Date(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliveryReportReq_ADD_MMStatus(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliveryReportReq_ADD_MMStatusExtension(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliveryReportReq_ADD_StatusText(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliveryReportReq_ADD_ApplicID(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliveryReportReq_ADD_ReplyApplicID(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliveryReportReq_ADD_AuxApplicInfo(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliveryReportReq_ADD_UACapabilities(struct zx_mm7_DeliveryReportReq_s* x, int n, struct zx_mm7_UACapabilities_s* z);

void zx_mm7_DeliveryReportReq_DEL_MM7Version(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_MMSRelayServerID(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_Extension(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_MessageID(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_Recipient(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_Sender(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_Date(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_MMStatus(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_MMStatusExtension(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_StatusText(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_ApplicID(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_ReplyApplicID(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_AuxApplicInfo(struct zx_mm7_DeliveryReportReq_s* x, int n);
void zx_mm7_DeliveryReportReq_DEL_UACapabilities(struct zx_mm7_DeliveryReportReq_s* x, int n);

void zx_mm7_DeliveryReportReq_REV_MM7Version(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_MMSRelayServerID(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_Extension(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_MessageID(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_Recipient(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_Sender(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_Date(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_MMStatus(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_MMStatusExtension(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_StatusText(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_ApplicID(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_ReplyApplicID(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_AuxApplicInfo(struct zx_mm7_DeliveryReportReq_s* x);
void zx_mm7_DeliveryReportReq_REV_UACapabilities(struct zx_mm7_DeliveryReportReq_s* x);

#endif
/* -------------------------- mm7_DeliveryReportRsp -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_DeliveryReportRsp_EXT
#define zx_mm7_DeliveryReportRsp_EXT
#endif

struct zx_mm7_DeliveryReportRsp_s* zx_DEC_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_DeliveryReportRsp_s* zx_NEW_mm7_DeliveryReportRsp(struct zx_ctx* c);
void zx_FREE_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_mm7_DeliveryReportRsp_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_DeliveryReportRsp_s* zx_DEEP_CLONE_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_mm7_DeliveryReportRsp_s* x, int dup_strs);
void zx_DUP_STRS_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_mm7_DeliveryReportRsp_s* x);
int zx_WALK_SO_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_mm7_DeliveryReportRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_mm7_DeliveryReportRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_mm7_DeliveryReportRsp_s* x);
int zx_LEN_WO_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_mm7_DeliveryReportRsp_s* x);
char* zx_ENC_SO_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_mm7_DeliveryReportRsp_s* x, char* p);
char* zx_ENC_WO_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_mm7_DeliveryReportRsp_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_mm7_DeliveryReportRsp_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_DeliveryReportRsp(struct zx_ctx* c, struct zx_mm7_DeliveryReportRsp_s* x);

struct zx_mm7_DeliveryReportRsp_s {
  ZX_ELEM_EXT
  zx_mm7_DeliveryReportRsp_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_Status_s* Status;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_DeliveryReportRsp_GET_MM7Version(struct zx_mm7_DeliveryReportRsp_s* x, int n);
struct zx_mm7_Status_s* zx_mm7_DeliveryReportRsp_GET_Status(struct zx_mm7_DeliveryReportRsp_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_DeliveryReportRsp_GET_Extension(struct zx_mm7_DeliveryReportRsp_s* x, int n);

int zx_mm7_DeliveryReportRsp_NUM_MM7Version(struct zx_mm7_DeliveryReportRsp_s* x);
int zx_mm7_DeliveryReportRsp_NUM_Status(struct zx_mm7_DeliveryReportRsp_s* x);
int zx_mm7_DeliveryReportRsp_NUM_Extension(struct zx_mm7_DeliveryReportRsp_s* x);

struct zx_elem_s* zx_mm7_DeliveryReportRsp_POP_MM7Version(struct zx_mm7_DeliveryReportRsp_s* x);
struct zx_mm7_Status_s* zx_mm7_DeliveryReportRsp_POP_Status(struct zx_mm7_DeliveryReportRsp_s* x);
struct zx_mm7_Extension_s* zx_mm7_DeliveryReportRsp_POP_Extension(struct zx_mm7_DeliveryReportRsp_s* x);

void zx_mm7_DeliveryReportRsp_PUSH_MM7Version(struct zx_mm7_DeliveryReportRsp_s* x, struct zx_elem_s* y);
void zx_mm7_DeliveryReportRsp_PUSH_Status(struct zx_mm7_DeliveryReportRsp_s* x, struct zx_mm7_Status_s* y);
void zx_mm7_DeliveryReportRsp_PUSH_Extension(struct zx_mm7_DeliveryReportRsp_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_DeliveryReportRsp_PUT_MM7Version(struct zx_mm7_DeliveryReportRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_DeliveryReportRsp_PUT_Status(struct zx_mm7_DeliveryReportRsp_s* x, int n, struct zx_mm7_Status_s* y);
void zx_mm7_DeliveryReportRsp_PUT_Extension(struct zx_mm7_DeliveryReportRsp_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_DeliveryReportRsp_ADD_MM7Version(struct zx_mm7_DeliveryReportRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_DeliveryReportRsp_ADD_Status(struct zx_mm7_DeliveryReportRsp_s* x, int n, struct zx_mm7_Status_s* z);
void zx_mm7_DeliveryReportRsp_ADD_Extension(struct zx_mm7_DeliveryReportRsp_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_DeliveryReportRsp_DEL_MM7Version(struct zx_mm7_DeliveryReportRsp_s* x, int n);
void zx_mm7_DeliveryReportRsp_DEL_Status(struct zx_mm7_DeliveryReportRsp_s* x, int n);
void zx_mm7_DeliveryReportRsp_DEL_Extension(struct zx_mm7_DeliveryReportRsp_s* x, int n);

void zx_mm7_DeliveryReportRsp_REV_MM7Version(struct zx_mm7_DeliveryReportRsp_s* x);
void zx_mm7_DeliveryReportRsp_REV_Status(struct zx_mm7_DeliveryReportRsp_s* x);
void zx_mm7_DeliveryReportRsp_REV_Extension(struct zx_mm7_DeliveryReportRsp_s* x);

#endif
/* -------------------------- mm7_Details -------------------------- */
/* refby( zx_mm7_Status_s zx_mm7_QueryStatusRsp_s ) */
#ifndef zx_mm7_Details_EXT
#define zx_mm7_Details_EXT
#endif

struct zx_mm7_Details_s* zx_DEC_mm7_Details(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Details_s* zx_NEW_mm7_Details(struct zx_ctx* c);
void zx_FREE_mm7_Details(struct zx_ctx* c, struct zx_mm7_Details_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Details_s* zx_DEEP_CLONE_mm7_Details(struct zx_ctx* c, struct zx_mm7_Details_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Details(struct zx_ctx* c, struct zx_mm7_Details_s* x);
int zx_WALK_SO_mm7_Details(struct zx_ctx* c, struct zx_mm7_Details_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Details(struct zx_ctx* c, struct zx_mm7_Details_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Details(struct zx_ctx* c, struct zx_mm7_Details_s* x);
int zx_LEN_WO_mm7_Details(struct zx_ctx* c, struct zx_mm7_Details_s* x);
char* zx_ENC_SO_mm7_Details(struct zx_ctx* c, struct zx_mm7_Details_s* x, char* p);
char* zx_ENC_WO_mm7_Details(struct zx_ctx* c, struct zx_mm7_Details_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Details(struct zx_ctx* c, struct zx_mm7_Details_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Details(struct zx_ctx* c, struct zx_mm7_Details_s* x);

struct zx_mm7_Details_s {
  ZX_ELEM_EXT
  zx_mm7_Details_EXT
};

#ifdef ZX_ENA_GETPUT










#endif
/* -------------------------- mm7_Extension -------------------------- */
/* refby( zx_mm7_Cc_s zx_mm7_ReplaceReq_s zx_mm7_CancelReq_s zx_mm7_SenderAddress_s zx_mm7_SubmitReq_s zx_mm7_Bcc_s zx_mm7_ThirdPartyPayer_s zx_mm7_ReadReplyReq_s zx_mm7_Sender_s zx_mm7_RSErrorRsp_s zx_mm7_DeliveryReportReq_s zx_mm7_ReplaceRsp_s zx_mm7_UserAgent_s zx_mm7_Recipient_s zx_mm7_To_s zx_mm7_DeliverRsp_s zx_mm7_DeliveryReportRsp_s zx_mm7_ReadReplyRsp_s zx_mm7_CancelRsp_s zx_mm7_VASPErrorRsp_s zx_mm7_DeliverReq_s zx_mm7_extendedCancelReq_s zx_mm7_SubmitRsp_s ) */
#ifndef zx_mm7_Extension_EXT
#define zx_mm7_Extension_EXT
#endif

struct zx_mm7_Extension_s* zx_DEC_mm7_Extension(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Extension_s* zx_NEW_mm7_Extension(struct zx_ctx* c);
void zx_FREE_mm7_Extension(struct zx_ctx* c, struct zx_mm7_Extension_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Extension_s* zx_DEEP_CLONE_mm7_Extension(struct zx_ctx* c, struct zx_mm7_Extension_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Extension(struct zx_ctx* c, struct zx_mm7_Extension_s* x);
int zx_WALK_SO_mm7_Extension(struct zx_ctx* c, struct zx_mm7_Extension_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Extension(struct zx_ctx* c, struct zx_mm7_Extension_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Extension(struct zx_ctx* c, struct zx_mm7_Extension_s* x);
int zx_LEN_WO_mm7_Extension(struct zx_ctx* c, struct zx_mm7_Extension_s* x);
char* zx_ENC_SO_mm7_Extension(struct zx_ctx* c, struct zx_mm7_Extension_s* x, char* p);
char* zx_ENC_WO_mm7_Extension(struct zx_ctx* c, struct zx_mm7_Extension_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Extension(struct zx_ctx* c, struct zx_mm7_Extension_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Extension(struct zx_ctx* c, struct zx_mm7_Extension_s* x);

struct zx_mm7_Extension_s {
  ZX_ELEM_EXT
  zx_mm7_Extension_EXT
  struct zx_mm7_IdentityAddressingToken_s* IdentityAddressingToken;	/* {0,1}  */
  struct zx_mm7_MessageExtraData_s* MessageExtraData;	/* {0,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_IdentityAddressingToken_s* zx_mm7_Extension_GET_IdentityAddressingToken(struct zx_mm7_Extension_s* x, int n);
struct zx_mm7_MessageExtraData_s* zx_mm7_Extension_GET_MessageExtraData(struct zx_mm7_Extension_s* x, int n);

int zx_mm7_Extension_NUM_IdentityAddressingToken(struct zx_mm7_Extension_s* x);
int zx_mm7_Extension_NUM_MessageExtraData(struct zx_mm7_Extension_s* x);

struct zx_mm7_IdentityAddressingToken_s* zx_mm7_Extension_POP_IdentityAddressingToken(struct zx_mm7_Extension_s* x);
struct zx_mm7_MessageExtraData_s* zx_mm7_Extension_POP_MessageExtraData(struct zx_mm7_Extension_s* x);

void zx_mm7_Extension_PUSH_IdentityAddressingToken(struct zx_mm7_Extension_s* x, struct zx_mm7_IdentityAddressingToken_s* y);
void zx_mm7_Extension_PUSH_MessageExtraData(struct zx_mm7_Extension_s* x, struct zx_mm7_MessageExtraData_s* y);


void zx_mm7_Extension_PUT_IdentityAddressingToken(struct zx_mm7_Extension_s* x, int n, struct zx_mm7_IdentityAddressingToken_s* y);
void zx_mm7_Extension_PUT_MessageExtraData(struct zx_mm7_Extension_s* x, int n, struct zx_mm7_MessageExtraData_s* y);

void zx_mm7_Extension_ADD_IdentityAddressingToken(struct zx_mm7_Extension_s* x, int n, struct zx_mm7_IdentityAddressingToken_s* z);
void zx_mm7_Extension_ADD_MessageExtraData(struct zx_mm7_Extension_s* x, int n, struct zx_mm7_MessageExtraData_s* z);

void zx_mm7_Extension_DEL_IdentityAddressingToken(struct zx_mm7_Extension_s* x, int n);
void zx_mm7_Extension_DEL_MessageExtraData(struct zx_mm7_Extension_s* x, int n);

void zx_mm7_Extension_REV_IdentityAddressingToken(struct zx_mm7_Extension_s* x);
void zx_mm7_Extension_REV_MessageExtraData(struct zx_mm7_Extension_s* x);

#endif
/* -------------------------- mm7_IdentityAddressingToken -------------------------- */
/* refby( zx_mm7_Extension_s ) */
#ifndef zx_mm7_IdentityAddressingToken_EXT
#define zx_mm7_IdentityAddressingToken_EXT
#endif

struct zx_mm7_IdentityAddressingToken_s* zx_DEC_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_IdentityAddressingToken_s* zx_NEW_mm7_IdentityAddressingToken(struct zx_ctx* c);
void zx_FREE_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_mm7_IdentityAddressingToken_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_IdentityAddressingToken_s* zx_DEEP_CLONE_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_mm7_IdentityAddressingToken_s* x, int dup_strs);
void zx_DUP_STRS_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_mm7_IdentityAddressingToken_s* x);
int zx_WALK_SO_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_mm7_IdentityAddressingToken_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_mm7_IdentityAddressingToken_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_mm7_IdentityAddressingToken_s* x);
int zx_LEN_WO_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_mm7_IdentityAddressingToken_s* x);
char* zx_ENC_SO_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_mm7_IdentityAddressingToken_s* x, char* p);
char* zx_ENC_WO_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_mm7_IdentityAddressingToken_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_mm7_IdentityAddressingToken_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_IdentityAddressingToken(struct zx_ctx* c, struct zx_mm7_IdentityAddressingToken_s* x);

struct zx_mm7_IdentityAddressingToken_s {
  ZX_ELEM_EXT
  zx_mm7_IdentityAddressingToken_EXT
  struct zx_elem_s* CredentialRef;	/* {1,1} xs:IDREF */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_IdentityAddressingToken_GET_CredentialRef(struct zx_mm7_IdentityAddressingToken_s* x, int n);

int zx_mm7_IdentityAddressingToken_NUM_CredentialRef(struct zx_mm7_IdentityAddressingToken_s* x);

struct zx_elem_s* zx_mm7_IdentityAddressingToken_POP_CredentialRef(struct zx_mm7_IdentityAddressingToken_s* x);

void zx_mm7_IdentityAddressingToken_PUSH_CredentialRef(struct zx_mm7_IdentityAddressingToken_s* x, struct zx_elem_s* y);


void zx_mm7_IdentityAddressingToken_PUT_CredentialRef(struct zx_mm7_IdentityAddressingToken_s* x, int n, struct zx_elem_s* y);

void zx_mm7_IdentityAddressingToken_ADD_CredentialRef(struct zx_mm7_IdentityAddressingToken_s* x, int n, struct zx_elem_s* z);

void zx_mm7_IdentityAddressingToken_DEL_CredentialRef(struct zx_mm7_IdentityAddressingToken_s* x, int n);

void zx_mm7_IdentityAddressingToken_REV_CredentialRef(struct zx_mm7_IdentityAddressingToken_s* x);

#endif
/* -------------------------- mm7_MessageExtraData -------------------------- */
/* refby( zx_mm7_ReplaceReq_s zx_mm7_extendedReplaceReq_s zx_mm7_SubmitReq_s zx_mm7_Extension_s zx_mm7_DeliverReq_s ) */
#ifndef zx_mm7_MessageExtraData_EXT
#define zx_mm7_MessageExtraData_EXT
#endif

struct zx_mm7_MessageExtraData_s* zx_DEC_mm7_MessageExtraData(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_MessageExtraData_s* zx_NEW_mm7_MessageExtraData(struct zx_ctx* c);
void zx_FREE_mm7_MessageExtraData(struct zx_ctx* c, struct zx_mm7_MessageExtraData_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_MessageExtraData_s* zx_DEEP_CLONE_mm7_MessageExtraData(struct zx_ctx* c, struct zx_mm7_MessageExtraData_s* x, int dup_strs);
void zx_DUP_STRS_mm7_MessageExtraData(struct zx_ctx* c, struct zx_mm7_MessageExtraData_s* x);
int zx_WALK_SO_mm7_MessageExtraData(struct zx_ctx* c, struct zx_mm7_MessageExtraData_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_MessageExtraData(struct zx_ctx* c, struct zx_mm7_MessageExtraData_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_MessageExtraData(struct zx_ctx* c, struct zx_mm7_MessageExtraData_s* x);
int zx_LEN_WO_mm7_MessageExtraData(struct zx_ctx* c, struct zx_mm7_MessageExtraData_s* x);
char* zx_ENC_SO_mm7_MessageExtraData(struct zx_ctx* c, struct zx_mm7_MessageExtraData_s* x, char* p);
char* zx_ENC_WO_mm7_MessageExtraData(struct zx_ctx* c, struct zx_mm7_MessageExtraData_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_MessageExtraData(struct zx_ctx* c, struct zx_mm7_MessageExtraData_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_MessageExtraData(struct zx_ctx* c, struct zx_mm7_MessageExtraData_s* x);

struct zx_mm7_MessageExtraData_s {
  ZX_ELEM_EXT
  zx_mm7_MessageExtraData_EXT
  struct zx_mm7_element_s* element;	/* {1,-1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_element_s* zx_mm7_MessageExtraData_GET_element(struct zx_mm7_MessageExtraData_s* x, int n);

int zx_mm7_MessageExtraData_NUM_element(struct zx_mm7_MessageExtraData_s* x);

struct zx_mm7_element_s* zx_mm7_MessageExtraData_POP_element(struct zx_mm7_MessageExtraData_s* x);

void zx_mm7_MessageExtraData_PUSH_element(struct zx_mm7_MessageExtraData_s* x, struct zx_mm7_element_s* y);


void zx_mm7_MessageExtraData_PUT_element(struct zx_mm7_MessageExtraData_s* x, int n, struct zx_mm7_element_s* y);

void zx_mm7_MessageExtraData_ADD_element(struct zx_mm7_MessageExtraData_s* x, int n, struct zx_mm7_element_s* z);

void zx_mm7_MessageExtraData_DEL_element(struct zx_mm7_MessageExtraData_s* x, int n);

void zx_mm7_MessageExtraData_REV_element(struct zx_mm7_MessageExtraData_s* x);

#endif
/* -------------------------- mm7_Number -------------------------- */
/* refby( zx_mm7_Cc_s zx_mm7_SenderAddress_s zx_mm7_Bcc_s zx_mm7_ThirdPartyPayer_s zx_mm7_Sender_s zx_mm7_UserAgent_s zx_mm7_Recipient_s zx_mm7_To_s ) */
#ifndef zx_mm7_Number_EXT
#define zx_mm7_Number_EXT
#endif

struct zx_mm7_Number_s* zx_DEC_mm7_Number(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Number_s* zx_NEW_mm7_Number(struct zx_ctx* c);
void zx_FREE_mm7_Number(struct zx_ctx* c, struct zx_mm7_Number_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Number_s* zx_DEEP_CLONE_mm7_Number(struct zx_ctx* c, struct zx_mm7_Number_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Number(struct zx_ctx* c, struct zx_mm7_Number_s* x);
int zx_WALK_SO_mm7_Number(struct zx_ctx* c, struct zx_mm7_Number_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Number(struct zx_ctx* c, struct zx_mm7_Number_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Number(struct zx_ctx* c, struct zx_mm7_Number_s* x);
int zx_LEN_WO_mm7_Number(struct zx_ctx* c, struct zx_mm7_Number_s* x);
char* zx_ENC_SO_mm7_Number(struct zx_ctx* c, struct zx_mm7_Number_s* x, char* p);
char* zx_ENC_WO_mm7_Number(struct zx_ctx* c, struct zx_mm7_Number_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Number(struct zx_ctx* c, struct zx_mm7_Number_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Number(struct zx_ctx* c, struct zx_mm7_Number_s* x);

struct zx_mm7_Number_s {
  ZX_ELEM_EXT
  zx_mm7_Number_EXT
  struct zx_str* addressCoding;	/* {0,1} attribute mm7:addressCodingType */
  struct zx_str* displayOnly;	/* {0,1} attribute xs:boolean */
  struct zx_str* id;	/* {0,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_mm7_Number_GET_addressCoding(struct zx_mm7_Number_s* x);
struct zx_str* zx_mm7_Number_GET_displayOnly(struct zx_mm7_Number_s* x);
struct zx_str* zx_mm7_Number_GET_id(struct zx_mm7_Number_s* x);





void zx_mm7_Number_PUT_addressCoding(struct zx_mm7_Number_s* x, struct zx_str* y);
void zx_mm7_Number_PUT_displayOnly(struct zx_mm7_Number_s* x, struct zx_str* y);
void zx_mm7_Number_PUT_id(struct zx_mm7_Number_s* x, struct zx_str* y);





#endif
/* -------------------------- mm7_PreferredChannels -------------------------- */
/* refby( zx_mm7_SubmitReq_s ) */
#ifndef zx_mm7_PreferredChannels_EXT
#define zx_mm7_PreferredChannels_EXT
#endif

struct zx_mm7_PreferredChannels_s* zx_DEC_mm7_PreferredChannels(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_PreferredChannels_s* zx_NEW_mm7_PreferredChannels(struct zx_ctx* c);
void zx_FREE_mm7_PreferredChannels(struct zx_ctx* c, struct zx_mm7_PreferredChannels_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_PreferredChannels_s* zx_DEEP_CLONE_mm7_PreferredChannels(struct zx_ctx* c, struct zx_mm7_PreferredChannels_s* x, int dup_strs);
void zx_DUP_STRS_mm7_PreferredChannels(struct zx_ctx* c, struct zx_mm7_PreferredChannels_s* x);
int zx_WALK_SO_mm7_PreferredChannels(struct zx_ctx* c, struct zx_mm7_PreferredChannels_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_PreferredChannels(struct zx_ctx* c, struct zx_mm7_PreferredChannels_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_PreferredChannels(struct zx_ctx* c, struct zx_mm7_PreferredChannels_s* x);
int zx_LEN_WO_mm7_PreferredChannels(struct zx_ctx* c, struct zx_mm7_PreferredChannels_s* x);
char* zx_ENC_SO_mm7_PreferredChannels(struct zx_ctx* c, struct zx_mm7_PreferredChannels_s* x, char* p);
char* zx_ENC_WO_mm7_PreferredChannels(struct zx_ctx* c, struct zx_mm7_PreferredChannels_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_PreferredChannels(struct zx_ctx* c, struct zx_mm7_PreferredChannels_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_PreferredChannels(struct zx_ctx* c, struct zx_mm7_PreferredChannels_s* x);

struct zx_mm7_PreferredChannels_s {
  ZX_ELEM_EXT
  zx_mm7_PreferredChannels_EXT
  struct zx_elem_s* DeliverUsing;	/* {1,-1} SMS */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_PreferredChannels_GET_DeliverUsing(struct zx_mm7_PreferredChannels_s* x, int n);

int zx_mm7_PreferredChannels_NUM_DeliverUsing(struct zx_mm7_PreferredChannels_s* x);

struct zx_elem_s* zx_mm7_PreferredChannels_POP_DeliverUsing(struct zx_mm7_PreferredChannels_s* x);

void zx_mm7_PreferredChannels_PUSH_DeliverUsing(struct zx_mm7_PreferredChannels_s* x, struct zx_elem_s* y);


void zx_mm7_PreferredChannels_PUT_DeliverUsing(struct zx_mm7_PreferredChannels_s* x, int n, struct zx_elem_s* y);

void zx_mm7_PreferredChannels_ADD_DeliverUsing(struct zx_mm7_PreferredChannels_s* x, int n, struct zx_elem_s* z);

void zx_mm7_PreferredChannels_DEL_DeliverUsing(struct zx_mm7_PreferredChannels_s* x, int n);

void zx_mm7_PreferredChannels_REV_DeliverUsing(struct zx_mm7_PreferredChannels_s* x);

#endif
/* -------------------------- mm7_Previouslysentby -------------------------- */
/* refby( zx_mm7_DeliverReq_s ) */
#ifndef zx_mm7_Previouslysentby_EXT
#define zx_mm7_Previouslysentby_EXT
#endif

struct zx_mm7_Previouslysentby_s* zx_DEC_mm7_Previouslysentby(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Previouslysentby_s* zx_NEW_mm7_Previouslysentby(struct zx_ctx* c);
void zx_FREE_mm7_Previouslysentby(struct zx_ctx* c, struct zx_mm7_Previouslysentby_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Previouslysentby_s* zx_DEEP_CLONE_mm7_Previouslysentby(struct zx_ctx* c, struct zx_mm7_Previouslysentby_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Previouslysentby(struct zx_ctx* c, struct zx_mm7_Previouslysentby_s* x);
int zx_WALK_SO_mm7_Previouslysentby(struct zx_ctx* c, struct zx_mm7_Previouslysentby_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Previouslysentby(struct zx_ctx* c, struct zx_mm7_Previouslysentby_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Previouslysentby(struct zx_ctx* c, struct zx_mm7_Previouslysentby_s* x);
int zx_LEN_WO_mm7_Previouslysentby(struct zx_ctx* c, struct zx_mm7_Previouslysentby_s* x);
char* zx_ENC_SO_mm7_Previouslysentby(struct zx_ctx* c, struct zx_mm7_Previouslysentby_s* x, char* p);
char* zx_ENC_WO_mm7_Previouslysentby(struct zx_ctx* c, struct zx_mm7_Previouslysentby_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Previouslysentby(struct zx_ctx* c, struct zx_mm7_Previouslysentby_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Previouslysentby(struct zx_ctx* c, struct zx_mm7_Previouslysentby_s* x);

struct zx_mm7_Previouslysentby_s {
  ZX_ELEM_EXT
  zx_mm7_Previouslysentby_EXT
  struct zx_mm7_UserAgent_s* UserAgent;	/* {0,-1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_UserAgent_s* zx_mm7_Previouslysentby_GET_UserAgent(struct zx_mm7_Previouslysentby_s* x, int n);

int zx_mm7_Previouslysentby_NUM_UserAgent(struct zx_mm7_Previouslysentby_s* x);

struct zx_mm7_UserAgent_s* zx_mm7_Previouslysentby_POP_UserAgent(struct zx_mm7_Previouslysentby_s* x);

void zx_mm7_Previouslysentby_PUSH_UserAgent(struct zx_mm7_Previouslysentby_s* x, struct zx_mm7_UserAgent_s* y);


void zx_mm7_Previouslysentby_PUT_UserAgent(struct zx_mm7_Previouslysentby_s* x, int n, struct zx_mm7_UserAgent_s* y);

void zx_mm7_Previouslysentby_ADD_UserAgent(struct zx_mm7_Previouslysentby_s* x, int n, struct zx_mm7_UserAgent_s* z);

void zx_mm7_Previouslysentby_DEL_UserAgent(struct zx_mm7_Previouslysentby_s* x, int n);

void zx_mm7_Previouslysentby_REV_UserAgent(struct zx_mm7_Previouslysentby_s* x);

#endif
/* -------------------------- mm7_Previouslysentdateandtime -------------------------- */
/* refby( zx_mm7_DeliverReq_s ) */
#ifndef zx_mm7_Previouslysentdateandtime_EXT
#define zx_mm7_Previouslysentdateandtime_EXT
#endif

struct zx_mm7_Previouslysentdateandtime_s* zx_DEC_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Previouslysentdateandtime_s* zx_NEW_mm7_Previouslysentdateandtime(struct zx_ctx* c);
void zx_FREE_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_mm7_Previouslysentdateandtime_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Previouslysentdateandtime_s* zx_DEEP_CLONE_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_mm7_Previouslysentdateandtime_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_mm7_Previouslysentdateandtime_s* x);
int zx_WALK_SO_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_mm7_Previouslysentdateandtime_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_mm7_Previouslysentdateandtime_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_mm7_Previouslysentdateandtime_s* x);
int zx_LEN_WO_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_mm7_Previouslysentdateandtime_s* x);
char* zx_ENC_SO_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_mm7_Previouslysentdateandtime_s* x, char* p);
char* zx_ENC_WO_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_mm7_Previouslysentdateandtime_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_mm7_Previouslysentdateandtime_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Previouslysentdateandtime(struct zx_ctx* c, struct zx_mm7_Previouslysentdateandtime_s* x);

struct zx_mm7_Previouslysentdateandtime_s {
  ZX_ELEM_EXT
  zx_mm7_Previouslysentdateandtime_EXT
  struct zx_mm7_DateTime_s* DateTime;	/* {0,-1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_DateTime_s* zx_mm7_Previouslysentdateandtime_GET_DateTime(struct zx_mm7_Previouslysentdateandtime_s* x, int n);

int zx_mm7_Previouslysentdateandtime_NUM_DateTime(struct zx_mm7_Previouslysentdateandtime_s* x);

struct zx_mm7_DateTime_s* zx_mm7_Previouslysentdateandtime_POP_DateTime(struct zx_mm7_Previouslysentdateandtime_s* x);

void zx_mm7_Previouslysentdateandtime_PUSH_DateTime(struct zx_mm7_Previouslysentdateandtime_s* x, struct zx_mm7_DateTime_s* y);


void zx_mm7_Previouslysentdateandtime_PUT_DateTime(struct zx_mm7_Previouslysentdateandtime_s* x, int n, struct zx_mm7_DateTime_s* y);

void zx_mm7_Previouslysentdateandtime_ADD_DateTime(struct zx_mm7_Previouslysentdateandtime_s* x, int n, struct zx_mm7_DateTime_s* z);

void zx_mm7_Previouslysentdateandtime_DEL_DateTime(struct zx_mm7_Previouslysentdateandtime_s* x, int n);

void zx_mm7_Previouslysentdateandtime_REV_DateTime(struct zx_mm7_Previouslysentdateandtime_s* x);

#endif
/* -------------------------- mm7_QueryStatusReq -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_QueryStatusReq_EXT
#define zx_mm7_QueryStatusReq_EXT
#endif

struct zx_mm7_QueryStatusReq_s* zx_DEC_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_QueryStatusReq_s* zx_NEW_mm7_QueryStatusReq(struct zx_ctx* c);
void zx_FREE_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_mm7_QueryStatusReq_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_QueryStatusReq_s* zx_DEEP_CLONE_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_mm7_QueryStatusReq_s* x, int dup_strs);
void zx_DUP_STRS_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_mm7_QueryStatusReq_s* x);
int zx_WALK_SO_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_mm7_QueryStatusReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_mm7_QueryStatusReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_mm7_QueryStatusReq_s* x);
int zx_LEN_WO_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_mm7_QueryStatusReq_s* x);
char* zx_ENC_SO_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_mm7_QueryStatusReq_s* x, char* p);
char* zx_ENC_WO_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_mm7_QueryStatusReq_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_mm7_QueryStatusReq_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_QueryStatusReq(struct zx_ctx* c, struct zx_mm7_QueryStatusReq_s* x);

struct zx_mm7_QueryStatusReq_s {
  ZX_ELEM_EXT
  zx_mm7_QueryStatusReq_EXT
  struct zx_mm7_TransactionID_s* TransactionID;	/* {1,1} nada */
  struct zx_elem_s* MessageType;	/* {1,1} xs:string */
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_elem_s* VASPID;	/* {0,1} xs:string */
  struct zx_elem_s* VASID;	/* {0,1} xs:string */
  struct zx_elem_s* MessageID;	/* {1,1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_TransactionID_s* zx_mm7_QueryStatusReq_GET_TransactionID(struct zx_mm7_QueryStatusReq_s* x, int n);
struct zx_elem_s* zx_mm7_QueryStatusReq_GET_MessageType(struct zx_mm7_QueryStatusReq_s* x, int n);
struct zx_elem_s* zx_mm7_QueryStatusReq_GET_MM7Version(struct zx_mm7_QueryStatusReq_s* x, int n);
struct zx_elem_s* zx_mm7_QueryStatusReq_GET_VASPID(struct zx_mm7_QueryStatusReq_s* x, int n);
struct zx_elem_s* zx_mm7_QueryStatusReq_GET_VASID(struct zx_mm7_QueryStatusReq_s* x, int n);
struct zx_elem_s* zx_mm7_QueryStatusReq_GET_MessageID(struct zx_mm7_QueryStatusReq_s* x, int n);

int zx_mm7_QueryStatusReq_NUM_TransactionID(struct zx_mm7_QueryStatusReq_s* x);
int zx_mm7_QueryStatusReq_NUM_MessageType(struct zx_mm7_QueryStatusReq_s* x);
int zx_mm7_QueryStatusReq_NUM_MM7Version(struct zx_mm7_QueryStatusReq_s* x);
int zx_mm7_QueryStatusReq_NUM_VASPID(struct zx_mm7_QueryStatusReq_s* x);
int zx_mm7_QueryStatusReq_NUM_VASID(struct zx_mm7_QueryStatusReq_s* x);
int zx_mm7_QueryStatusReq_NUM_MessageID(struct zx_mm7_QueryStatusReq_s* x);

struct zx_mm7_TransactionID_s* zx_mm7_QueryStatusReq_POP_TransactionID(struct zx_mm7_QueryStatusReq_s* x);
struct zx_elem_s* zx_mm7_QueryStatusReq_POP_MessageType(struct zx_mm7_QueryStatusReq_s* x);
struct zx_elem_s* zx_mm7_QueryStatusReq_POP_MM7Version(struct zx_mm7_QueryStatusReq_s* x);
struct zx_elem_s* zx_mm7_QueryStatusReq_POP_VASPID(struct zx_mm7_QueryStatusReq_s* x);
struct zx_elem_s* zx_mm7_QueryStatusReq_POP_VASID(struct zx_mm7_QueryStatusReq_s* x);
struct zx_elem_s* zx_mm7_QueryStatusReq_POP_MessageID(struct zx_mm7_QueryStatusReq_s* x);

void zx_mm7_QueryStatusReq_PUSH_TransactionID(struct zx_mm7_QueryStatusReq_s* x, struct zx_mm7_TransactionID_s* y);
void zx_mm7_QueryStatusReq_PUSH_MessageType(struct zx_mm7_QueryStatusReq_s* x, struct zx_elem_s* y);
void zx_mm7_QueryStatusReq_PUSH_MM7Version(struct zx_mm7_QueryStatusReq_s* x, struct zx_elem_s* y);
void zx_mm7_QueryStatusReq_PUSH_VASPID(struct zx_mm7_QueryStatusReq_s* x, struct zx_elem_s* y);
void zx_mm7_QueryStatusReq_PUSH_VASID(struct zx_mm7_QueryStatusReq_s* x, struct zx_elem_s* y);
void zx_mm7_QueryStatusReq_PUSH_MessageID(struct zx_mm7_QueryStatusReq_s* x, struct zx_elem_s* y);


void zx_mm7_QueryStatusReq_PUT_TransactionID(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_mm7_TransactionID_s* y);
void zx_mm7_QueryStatusReq_PUT_MessageType(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_QueryStatusReq_PUT_MM7Version(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_QueryStatusReq_PUT_VASPID(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_QueryStatusReq_PUT_VASID(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_QueryStatusReq_PUT_MessageID(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_elem_s* y);

void zx_mm7_QueryStatusReq_ADD_TransactionID(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_mm7_TransactionID_s* z);
void zx_mm7_QueryStatusReq_ADD_MessageType(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_QueryStatusReq_ADD_MM7Version(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_QueryStatusReq_ADD_VASPID(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_QueryStatusReq_ADD_VASID(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_QueryStatusReq_ADD_MessageID(struct zx_mm7_QueryStatusReq_s* x, int n, struct zx_elem_s* z);

void zx_mm7_QueryStatusReq_DEL_TransactionID(struct zx_mm7_QueryStatusReq_s* x, int n);
void zx_mm7_QueryStatusReq_DEL_MessageType(struct zx_mm7_QueryStatusReq_s* x, int n);
void zx_mm7_QueryStatusReq_DEL_MM7Version(struct zx_mm7_QueryStatusReq_s* x, int n);
void zx_mm7_QueryStatusReq_DEL_VASPID(struct zx_mm7_QueryStatusReq_s* x, int n);
void zx_mm7_QueryStatusReq_DEL_VASID(struct zx_mm7_QueryStatusReq_s* x, int n);
void zx_mm7_QueryStatusReq_DEL_MessageID(struct zx_mm7_QueryStatusReq_s* x, int n);

void zx_mm7_QueryStatusReq_REV_TransactionID(struct zx_mm7_QueryStatusReq_s* x);
void zx_mm7_QueryStatusReq_REV_MessageType(struct zx_mm7_QueryStatusReq_s* x);
void zx_mm7_QueryStatusReq_REV_MM7Version(struct zx_mm7_QueryStatusReq_s* x);
void zx_mm7_QueryStatusReq_REV_VASPID(struct zx_mm7_QueryStatusReq_s* x);
void zx_mm7_QueryStatusReq_REV_VASID(struct zx_mm7_QueryStatusReq_s* x);
void zx_mm7_QueryStatusReq_REV_MessageID(struct zx_mm7_QueryStatusReq_s* x);

#endif
/* -------------------------- mm7_QueryStatusRsp -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_QueryStatusRsp_EXT
#define zx_mm7_QueryStatusRsp_EXT
#endif

struct zx_mm7_QueryStatusRsp_s* zx_DEC_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_QueryStatusRsp_s* zx_NEW_mm7_QueryStatusRsp(struct zx_ctx* c);
void zx_FREE_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_mm7_QueryStatusRsp_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_QueryStatusRsp_s* zx_DEEP_CLONE_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_mm7_QueryStatusRsp_s* x, int dup_strs);
void zx_DUP_STRS_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_mm7_QueryStatusRsp_s* x);
int zx_WALK_SO_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_mm7_QueryStatusRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_mm7_QueryStatusRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_mm7_QueryStatusRsp_s* x);
int zx_LEN_WO_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_mm7_QueryStatusRsp_s* x);
char* zx_ENC_SO_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_mm7_QueryStatusRsp_s* x, char* p);
char* zx_ENC_WO_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_mm7_QueryStatusRsp_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_mm7_QueryStatusRsp_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_QueryStatusRsp(struct zx_ctx* c, struct zx_mm7_QueryStatusRsp_s* x);

struct zx_mm7_QueryStatusRsp_s {
  ZX_ELEM_EXT
  zx_mm7_QueryStatusRsp_EXT
  struct zx_mm7_TransactionID_s* TransactionID;	/* {1,1} nada */
  struct zx_elem_s* MessageType;	/* {1,1} xs:string */
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_elem_s* StatusCode;	/* {1,1} xs:positiveInteger */
  struct zx_elem_s* StatusText;	/* {1,1} xs:string */
  struct zx_mm7_Details_s* Details;	/* {0,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_TransactionID_s* zx_mm7_QueryStatusRsp_GET_TransactionID(struct zx_mm7_QueryStatusRsp_s* x, int n);
struct zx_elem_s* zx_mm7_QueryStatusRsp_GET_MessageType(struct zx_mm7_QueryStatusRsp_s* x, int n);
struct zx_elem_s* zx_mm7_QueryStatusRsp_GET_MM7Version(struct zx_mm7_QueryStatusRsp_s* x, int n);
struct zx_elem_s* zx_mm7_QueryStatusRsp_GET_StatusCode(struct zx_mm7_QueryStatusRsp_s* x, int n);
struct zx_elem_s* zx_mm7_QueryStatusRsp_GET_StatusText(struct zx_mm7_QueryStatusRsp_s* x, int n);
struct zx_mm7_Details_s* zx_mm7_QueryStatusRsp_GET_Details(struct zx_mm7_QueryStatusRsp_s* x, int n);

int zx_mm7_QueryStatusRsp_NUM_TransactionID(struct zx_mm7_QueryStatusRsp_s* x);
int zx_mm7_QueryStatusRsp_NUM_MessageType(struct zx_mm7_QueryStatusRsp_s* x);
int zx_mm7_QueryStatusRsp_NUM_MM7Version(struct zx_mm7_QueryStatusRsp_s* x);
int zx_mm7_QueryStatusRsp_NUM_StatusCode(struct zx_mm7_QueryStatusRsp_s* x);
int zx_mm7_QueryStatusRsp_NUM_StatusText(struct zx_mm7_QueryStatusRsp_s* x);
int zx_mm7_QueryStatusRsp_NUM_Details(struct zx_mm7_QueryStatusRsp_s* x);

struct zx_mm7_TransactionID_s* zx_mm7_QueryStatusRsp_POP_TransactionID(struct zx_mm7_QueryStatusRsp_s* x);
struct zx_elem_s* zx_mm7_QueryStatusRsp_POP_MessageType(struct zx_mm7_QueryStatusRsp_s* x);
struct zx_elem_s* zx_mm7_QueryStatusRsp_POP_MM7Version(struct zx_mm7_QueryStatusRsp_s* x);
struct zx_elem_s* zx_mm7_QueryStatusRsp_POP_StatusCode(struct zx_mm7_QueryStatusRsp_s* x);
struct zx_elem_s* zx_mm7_QueryStatusRsp_POP_StatusText(struct zx_mm7_QueryStatusRsp_s* x);
struct zx_mm7_Details_s* zx_mm7_QueryStatusRsp_POP_Details(struct zx_mm7_QueryStatusRsp_s* x);

void zx_mm7_QueryStatusRsp_PUSH_TransactionID(struct zx_mm7_QueryStatusRsp_s* x, struct zx_mm7_TransactionID_s* y);
void zx_mm7_QueryStatusRsp_PUSH_MessageType(struct zx_mm7_QueryStatusRsp_s* x, struct zx_elem_s* y);
void zx_mm7_QueryStatusRsp_PUSH_MM7Version(struct zx_mm7_QueryStatusRsp_s* x, struct zx_elem_s* y);
void zx_mm7_QueryStatusRsp_PUSH_StatusCode(struct zx_mm7_QueryStatusRsp_s* x, struct zx_elem_s* y);
void zx_mm7_QueryStatusRsp_PUSH_StatusText(struct zx_mm7_QueryStatusRsp_s* x, struct zx_elem_s* y);
void zx_mm7_QueryStatusRsp_PUSH_Details(struct zx_mm7_QueryStatusRsp_s* x, struct zx_mm7_Details_s* y);


void zx_mm7_QueryStatusRsp_PUT_TransactionID(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_mm7_TransactionID_s* y);
void zx_mm7_QueryStatusRsp_PUT_MessageType(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_QueryStatusRsp_PUT_MM7Version(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_QueryStatusRsp_PUT_StatusCode(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_QueryStatusRsp_PUT_StatusText(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_QueryStatusRsp_PUT_Details(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_mm7_Details_s* y);

void zx_mm7_QueryStatusRsp_ADD_TransactionID(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_mm7_TransactionID_s* z);
void zx_mm7_QueryStatusRsp_ADD_MessageType(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_QueryStatusRsp_ADD_MM7Version(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_QueryStatusRsp_ADD_StatusCode(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_QueryStatusRsp_ADD_StatusText(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_QueryStatusRsp_ADD_Details(struct zx_mm7_QueryStatusRsp_s* x, int n, struct zx_mm7_Details_s* z);

void zx_mm7_QueryStatusRsp_DEL_TransactionID(struct zx_mm7_QueryStatusRsp_s* x, int n);
void zx_mm7_QueryStatusRsp_DEL_MessageType(struct zx_mm7_QueryStatusRsp_s* x, int n);
void zx_mm7_QueryStatusRsp_DEL_MM7Version(struct zx_mm7_QueryStatusRsp_s* x, int n);
void zx_mm7_QueryStatusRsp_DEL_StatusCode(struct zx_mm7_QueryStatusRsp_s* x, int n);
void zx_mm7_QueryStatusRsp_DEL_StatusText(struct zx_mm7_QueryStatusRsp_s* x, int n);
void zx_mm7_QueryStatusRsp_DEL_Details(struct zx_mm7_QueryStatusRsp_s* x, int n);

void zx_mm7_QueryStatusRsp_REV_TransactionID(struct zx_mm7_QueryStatusRsp_s* x);
void zx_mm7_QueryStatusRsp_REV_MessageType(struct zx_mm7_QueryStatusRsp_s* x);
void zx_mm7_QueryStatusRsp_REV_MM7Version(struct zx_mm7_QueryStatusRsp_s* x);
void zx_mm7_QueryStatusRsp_REV_StatusCode(struct zx_mm7_QueryStatusRsp_s* x);
void zx_mm7_QueryStatusRsp_REV_StatusText(struct zx_mm7_QueryStatusRsp_s* x);
void zx_mm7_QueryStatusRsp_REV_Details(struct zx_mm7_QueryStatusRsp_s* x);

#endif
/* -------------------------- mm7_RFC2822Address -------------------------- */
/* refby( zx_mm7_Cc_s zx_mm7_SenderAddress_s zx_mm7_Bcc_s zx_mm7_ThirdPartyPayer_s zx_mm7_Sender_s zx_mm7_UserAgent_s zx_mm7_Recipient_s zx_mm7_To_s ) */
#ifndef zx_mm7_RFC2822Address_EXT
#define zx_mm7_RFC2822Address_EXT
#endif

struct zx_mm7_RFC2822Address_s* zx_DEC_mm7_RFC2822Address(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_RFC2822Address_s* zx_NEW_mm7_RFC2822Address(struct zx_ctx* c);
void zx_FREE_mm7_RFC2822Address(struct zx_ctx* c, struct zx_mm7_RFC2822Address_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_RFC2822Address_s* zx_DEEP_CLONE_mm7_RFC2822Address(struct zx_ctx* c, struct zx_mm7_RFC2822Address_s* x, int dup_strs);
void zx_DUP_STRS_mm7_RFC2822Address(struct zx_ctx* c, struct zx_mm7_RFC2822Address_s* x);
int zx_WALK_SO_mm7_RFC2822Address(struct zx_ctx* c, struct zx_mm7_RFC2822Address_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_RFC2822Address(struct zx_ctx* c, struct zx_mm7_RFC2822Address_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_RFC2822Address(struct zx_ctx* c, struct zx_mm7_RFC2822Address_s* x);
int zx_LEN_WO_mm7_RFC2822Address(struct zx_ctx* c, struct zx_mm7_RFC2822Address_s* x);
char* zx_ENC_SO_mm7_RFC2822Address(struct zx_ctx* c, struct zx_mm7_RFC2822Address_s* x, char* p);
char* zx_ENC_WO_mm7_RFC2822Address(struct zx_ctx* c, struct zx_mm7_RFC2822Address_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_RFC2822Address(struct zx_ctx* c, struct zx_mm7_RFC2822Address_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_RFC2822Address(struct zx_ctx* c, struct zx_mm7_RFC2822Address_s* x);

struct zx_mm7_RFC2822Address_s {
  ZX_ELEM_EXT
  zx_mm7_RFC2822Address_EXT
  struct zx_str* addressCoding;	/* {0,1} attribute mm7:addressCodingType */
  struct zx_str* displayOnly;	/* {0,1} attribute xs:boolean */
  struct zx_str* id;	/* {0,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_mm7_RFC2822Address_GET_addressCoding(struct zx_mm7_RFC2822Address_s* x);
struct zx_str* zx_mm7_RFC2822Address_GET_displayOnly(struct zx_mm7_RFC2822Address_s* x);
struct zx_str* zx_mm7_RFC2822Address_GET_id(struct zx_mm7_RFC2822Address_s* x);





void zx_mm7_RFC2822Address_PUT_addressCoding(struct zx_mm7_RFC2822Address_s* x, struct zx_str* y);
void zx_mm7_RFC2822Address_PUT_displayOnly(struct zx_mm7_RFC2822Address_s* x, struct zx_str* y);
void zx_mm7_RFC2822Address_PUT_id(struct zx_mm7_RFC2822Address_s* x, struct zx_str* y);





#endif
/* -------------------------- mm7_RSErrorRsp -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_RSErrorRsp_EXT
#define zx_mm7_RSErrorRsp_EXT
#endif

struct zx_mm7_RSErrorRsp_s* zx_DEC_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_RSErrorRsp_s* zx_NEW_mm7_RSErrorRsp(struct zx_ctx* c);
void zx_FREE_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_mm7_RSErrorRsp_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_RSErrorRsp_s* zx_DEEP_CLONE_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_mm7_RSErrorRsp_s* x, int dup_strs);
void zx_DUP_STRS_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_mm7_RSErrorRsp_s* x);
int zx_WALK_SO_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_mm7_RSErrorRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_mm7_RSErrorRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_mm7_RSErrorRsp_s* x);
int zx_LEN_WO_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_mm7_RSErrorRsp_s* x);
char* zx_ENC_SO_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_mm7_RSErrorRsp_s* x, char* p);
char* zx_ENC_WO_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_mm7_RSErrorRsp_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_mm7_RSErrorRsp_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_RSErrorRsp(struct zx_ctx* c, struct zx_mm7_RSErrorRsp_s* x);

struct zx_mm7_RSErrorRsp_s {
  ZX_ELEM_EXT
  zx_mm7_RSErrorRsp_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_Status_s* Status;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_RSErrorRsp_GET_MM7Version(struct zx_mm7_RSErrorRsp_s* x, int n);
struct zx_mm7_Status_s* zx_mm7_RSErrorRsp_GET_Status(struct zx_mm7_RSErrorRsp_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_RSErrorRsp_GET_Extension(struct zx_mm7_RSErrorRsp_s* x, int n);

int zx_mm7_RSErrorRsp_NUM_MM7Version(struct zx_mm7_RSErrorRsp_s* x);
int zx_mm7_RSErrorRsp_NUM_Status(struct zx_mm7_RSErrorRsp_s* x);
int zx_mm7_RSErrorRsp_NUM_Extension(struct zx_mm7_RSErrorRsp_s* x);

struct zx_elem_s* zx_mm7_RSErrorRsp_POP_MM7Version(struct zx_mm7_RSErrorRsp_s* x);
struct zx_mm7_Status_s* zx_mm7_RSErrorRsp_POP_Status(struct zx_mm7_RSErrorRsp_s* x);
struct zx_mm7_Extension_s* zx_mm7_RSErrorRsp_POP_Extension(struct zx_mm7_RSErrorRsp_s* x);

void zx_mm7_RSErrorRsp_PUSH_MM7Version(struct zx_mm7_RSErrorRsp_s* x, struct zx_elem_s* y);
void zx_mm7_RSErrorRsp_PUSH_Status(struct zx_mm7_RSErrorRsp_s* x, struct zx_mm7_Status_s* y);
void zx_mm7_RSErrorRsp_PUSH_Extension(struct zx_mm7_RSErrorRsp_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_RSErrorRsp_PUT_MM7Version(struct zx_mm7_RSErrorRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_RSErrorRsp_PUT_Status(struct zx_mm7_RSErrorRsp_s* x, int n, struct zx_mm7_Status_s* y);
void zx_mm7_RSErrorRsp_PUT_Extension(struct zx_mm7_RSErrorRsp_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_RSErrorRsp_ADD_MM7Version(struct zx_mm7_RSErrorRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_RSErrorRsp_ADD_Status(struct zx_mm7_RSErrorRsp_s* x, int n, struct zx_mm7_Status_s* z);
void zx_mm7_RSErrorRsp_ADD_Extension(struct zx_mm7_RSErrorRsp_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_RSErrorRsp_DEL_MM7Version(struct zx_mm7_RSErrorRsp_s* x, int n);
void zx_mm7_RSErrorRsp_DEL_Status(struct zx_mm7_RSErrorRsp_s* x, int n);
void zx_mm7_RSErrorRsp_DEL_Extension(struct zx_mm7_RSErrorRsp_s* x, int n);

void zx_mm7_RSErrorRsp_REV_MM7Version(struct zx_mm7_RSErrorRsp_s* x);
void zx_mm7_RSErrorRsp_REV_Status(struct zx_mm7_RSErrorRsp_s* x);
void zx_mm7_RSErrorRsp_REV_Extension(struct zx_mm7_RSErrorRsp_s* x);

#endif
/* -------------------------- mm7_ReadReplyReq -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_ReadReplyReq_EXT
#define zx_mm7_ReadReplyReq_EXT
#endif

struct zx_mm7_ReadReplyReq_s* zx_DEC_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_ReadReplyReq_s* zx_NEW_mm7_ReadReplyReq(struct zx_ctx* c);
void zx_FREE_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_mm7_ReadReplyReq_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_ReadReplyReq_s* zx_DEEP_CLONE_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_mm7_ReadReplyReq_s* x, int dup_strs);
void zx_DUP_STRS_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_mm7_ReadReplyReq_s* x);
int zx_WALK_SO_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_mm7_ReadReplyReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_mm7_ReadReplyReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_mm7_ReadReplyReq_s* x);
int zx_LEN_WO_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_mm7_ReadReplyReq_s* x);
char* zx_ENC_SO_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_mm7_ReadReplyReq_s* x, char* p);
char* zx_ENC_WO_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_mm7_ReadReplyReq_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_mm7_ReadReplyReq_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_ReadReplyReq(struct zx_ctx* c, struct zx_mm7_ReadReplyReq_s* x);

struct zx_mm7_ReadReplyReq_s {
  ZX_ELEM_EXT
  zx_mm7_ReadReplyReq_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_elem_s* MMSRelayServerID;	/* {0,1} xs:string */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
  struct zx_elem_s* MessageID;	/* {1,1} xs:string */
  struct zx_mm7_Recipient_s* Recipient;	/* {1,1}  */
  struct zx_mm7_Sender_s* Sender;	/* {1,1}  */
  struct zx_elem_s* TimeStamp;	/* {1,1} xs:dateTime */
  struct zx_elem_s* MMStatus;	/* {1,1} Indeterminate */
  struct zx_elem_s* StatusText;	/* {0,1} xs:string */
  struct zx_elem_s* ApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* ReplyApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* AuxApplicInfo;	/* {0,1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_ReadReplyReq_GET_MM7Version(struct zx_mm7_ReadReplyReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReadReplyReq_GET_MMSRelayServerID(struct zx_mm7_ReadReplyReq_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_ReadReplyReq_GET_Extension(struct zx_mm7_ReadReplyReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReadReplyReq_GET_MessageID(struct zx_mm7_ReadReplyReq_s* x, int n);
struct zx_mm7_Recipient_s* zx_mm7_ReadReplyReq_GET_Recipient(struct zx_mm7_ReadReplyReq_s* x, int n);
struct zx_mm7_Sender_s* zx_mm7_ReadReplyReq_GET_Sender(struct zx_mm7_ReadReplyReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReadReplyReq_GET_TimeStamp(struct zx_mm7_ReadReplyReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReadReplyReq_GET_MMStatus(struct zx_mm7_ReadReplyReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReadReplyReq_GET_StatusText(struct zx_mm7_ReadReplyReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReadReplyReq_GET_ApplicID(struct zx_mm7_ReadReplyReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReadReplyReq_GET_ReplyApplicID(struct zx_mm7_ReadReplyReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReadReplyReq_GET_AuxApplicInfo(struct zx_mm7_ReadReplyReq_s* x, int n);

int zx_mm7_ReadReplyReq_NUM_MM7Version(struct zx_mm7_ReadReplyReq_s* x);
int zx_mm7_ReadReplyReq_NUM_MMSRelayServerID(struct zx_mm7_ReadReplyReq_s* x);
int zx_mm7_ReadReplyReq_NUM_Extension(struct zx_mm7_ReadReplyReq_s* x);
int zx_mm7_ReadReplyReq_NUM_MessageID(struct zx_mm7_ReadReplyReq_s* x);
int zx_mm7_ReadReplyReq_NUM_Recipient(struct zx_mm7_ReadReplyReq_s* x);
int zx_mm7_ReadReplyReq_NUM_Sender(struct zx_mm7_ReadReplyReq_s* x);
int zx_mm7_ReadReplyReq_NUM_TimeStamp(struct zx_mm7_ReadReplyReq_s* x);
int zx_mm7_ReadReplyReq_NUM_MMStatus(struct zx_mm7_ReadReplyReq_s* x);
int zx_mm7_ReadReplyReq_NUM_StatusText(struct zx_mm7_ReadReplyReq_s* x);
int zx_mm7_ReadReplyReq_NUM_ApplicID(struct zx_mm7_ReadReplyReq_s* x);
int zx_mm7_ReadReplyReq_NUM_ReplyApplicID(struct zx_mm7_ReadReplyReq_s* x);
int zx_mm7_ReadReplyReq_NUM_AuxApplicInfo(struct zx_mm7_ReadReplyReq_s* x);

struct zx_elem_s* zx_mm7_ReadReplyReq_POP_MM7Version(struct zx_mm7_ReadReplyReq_s* x);
struct zx_elem_s* zx_mm7_ReadReplyReq_POP_MMSRelayServerID(struct zx_mm7_ReadReplyReq_s* x);
struct zx_mm7_Extension_s* zx_mm7_ReadReplyReq_POP_Extension(struct zx_mm7_ReadReplyReq_s* x);
struct zx_elem_s* zx_mm7_ReadReplyReq_POP_MessageID(struct zx_mm7_ReadReplyReq_s* x);
struct zx_mm7_Recipient_s* zx_mm7_ReadReplyReq_POP_Recipient(struct zx_mm7_ReadReplyReq_s* x);
struct zx_mm7_Sender_s* zx_mm7_ReadReplyReq_POP_Sender(struct zx_mm7_ReadReplyReq_s* x);
struct zx_elem_s* zx_mm7_ReadReplyReq_POP_TimeStamp(struct zx_mm7_ReadReplyReq_s* x);
struct zx_elem_s* zx_mm7_ReadReplyReq_POP_MMStatus(struct zx_mm7_ReadReplyReq_s* x);
struct zx_elem_s* zx_mm7_ReadReplyReq_POP_StatusText(struct zx_mm7_ReadReplyReq_s* x);
struct zx_elem_s* zx_mm7_ReadReplyReq_POP_ApplicID(struct zx_mm7_ReadReplyReq_s* x);
struct zx_elem_s* zx_mm7_ReadReplyReq_POP_ReplyApplicID(struct zx_mm7_ReadReplyReq_s* x);
struct zx_elem_s* zx_mm7_ReadReplyReq_POP_AuxApplicInfo(struct zx_mm7_ReadReplyReq_s* x);

void zx_mm7_ReadReplyReq_PUSH_MM7Version(struct zx_mm7_ReadReplyReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUSH_MMSRelayServerID(struct zx_mm7_ReadReplyReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUSH_Extension(struct zx_mm7_ReadReplyReq_s* x, struct zx_mm7_Extension_s* y);
void zx_mm7_ReadReplyReq_PUSH_MessageID(struct zx_mm7_ReadReplyReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUSH_Recipient(struct zx_mm7_ReadReplyReq_s* x, struct zx_mm7_Recipient_s* y);
void zx_mm7_ReadReplyReq_PUSH_Sender(struct zx_mm7_ReadReplyReq_s* x, struct zx_mm7_Sender_s* y);
void zx_mm7_ReadReplyReq_PUSH_TimeStamp(struct zx_mm7_ReadReplyReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUSH_MMStatus(struct zx_mm7_ReadReplyReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUSH_StatusText(struct zx_mm7_ReadReplyReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUSH_ApplicID(struct zx_mm7_ReadReplyReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUSH_ReplyApplicID(struct zx_mm7_ReadReplyReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUSH_AuxApplicInfo(struct zx_mm7_ReadReplyReq_s* x, struct zx_elem_s* y);


void zx_mm7_ReadReplyReq_PUT_MM7Version(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUT_MMSRelayServerID(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUT_Extension(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_mm7_Extension_s* y);
void zx_mm7_ReadReplyReq_PUT_MessageID(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUT_Recipient(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_mm7_Recipient_s* y);
void zx_mm7_ReadReplyReq_PUT_Sender(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_mm7_Sender_s* y);
void zx_mm7_ReadReplyReq_PUT_TimeStamp(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUT_MMStatus(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUT_StatusText(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUT_ApplicID(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUT_ReplyApplicID(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReadReplyReq_PUT_AuxApplicInfo(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* y);

void zx_mm7_ReadReplyReq_ADD_MM7Version(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReadReplyReq_ADD_MMSRelayServerID(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReadReplyReq_ADD_Extension(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_mm7_Extension_s* z);
void zx_mm7_ReadReplyReq_ADD_MessageID(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReadReplyReq_ADD_Recipient(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_mm7_Recipient_s* z);
void zx_mm7_ReadReplyReq_ADD_Sender(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_mm7_Sender_s* z);
void zx_mm7_ReadReplyReq_ADD_TimeStamp(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReadReplyReq_ADD_MMStatus(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReadReplyReq_ADD_StatusText(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReadReplyReq_ADD_ApplicID(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReadReplyReq_ADD_ReplyApplicID(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReadReplyReq_ADD_AuxApplicInfo(struct zx_mm7_ReadReplyReq_s* x, int n, struct zx_elem_s* z);

void zx_mm7_ReadReplyReq_DEL_MM7Version(struct zx_mm7_ReadReplyReq_s* x, int n);
void zx_mm7_ReadReplyReq_DEL_MMSRelayServerID(struct zx_mm7_ReadReplyReq_s* x, int n);
void zx_mm7_ReadReplyReq_DEL_Extension(struct zx_mm7_ReadReplyReq_s* x, int n);
void zx_mm7_ReadReplyReq_DEL_MessageID(struct zx_mm7_ReadReplyReq_s* x, int n);
void zx_mm7_ReadReplyReq_DEL_Recipient(struct zx_mm7_ReadReplyReq_s* x, int n);
void zx_mm7_ReadReplyReq_DEL_Sender(struct zx_mm7_ReadReplyReq_s* x, int n);
void zx_mm7_ReadReplyReq_DEL_TimeStamp(struct zx_mm7_ReadReplyReq_s* x, int n);
void zx_mm7_ReadReplyReq_DEL_MMStatus(struct zx_mm7_ReadReplyReq_s* x, int n);
void zx_mm7_ReadReplyReq_DEL_StatusText(struct zx_mm7_ReadReplyReq_s* x, int n);
void zx_mm7_ReadReplyReq_DEL_ApplicID(struct zx_mm7_ReadReplyReq_s* x, int n);
void zx_mm7_ReadReplyReq_DEL_ReplyApplicID(struct zx_mm7_ReadReplyReq_s* x, int n);
void zx_mm7_ReadReplyReq_DEL_AuxApplicInfo(struct zx_mm7_ReadReplyReq_s* x, int n);

void zx_mm7_ReadReplyReq_REV_MM7Version(struct zx_mm7_ReadReplyReq_s* x);
void zx_mm7_ReadReplyReq_REV_MMSRelayServerID(struct zx_mm7_ReadReplyReq_s* x);
void zx_mm7_ReadReplyReq_REV_Extension(struct zx_mm7_ReadReplyReq_s* x);
void zx_mm7_ReadReplyReq_REV_MessageID(struct zx_mm7_ReadReplyReq_s* x);
void zx_mm7_ReadReplyReq_REV_Recipient(struct zx_mm7_ReadReplyReq_s* x);
void zx_mm7_ReadReplyReq_REV_Sender(struct zx_mm7_ReadReplyReq_s* x);
void zx_mm7_ReadReplyReq_REV_TimeStamp(struct zx_mm7_ReadReplyReq_s* x);
void zx_mm7_ReadReplyReq_REV_MMStatus(struct zx_mm7_ReadReplyReq_s* x);
void zx_mm7_ReadReplyReq_REV_StatusText(struct zx_mm7_ReadReplyReq_s* x);
void zx_mm7_ReadReplyReq_REV_ApplicID(struct zx_mm7_ReadReplyReq_s* x);
void zx_mm7_ReadReplyReq_REV_ReplyApplicID(struct zx_mm7_ReadReplyReq_s* x);
void zx_mm7_ReadReplyReq_REV_AuxApplicInfo(struct zx_mm7_ReadReplyReq_s* x);

#endif
/* -------------------------- mm7_ReadReplyRsp -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_ReadReplyRsp_EXT
#define zx_mm7_ReadReplyRsp_EXT
#endif

struct zx_mm7_ReadReplyRsp_s* zx_DEC_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_ReadReplyRsp_s* zx_NEW_mm7_ReadReplyRsp(struct zx_ctx* c);
void zx_FREE_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_mm7_ReadReplyRsp_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_ReadReplyRsp_s* zx_DEEP_CLONE_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_mm7_ReadReplyRsp_s* x, int dup_strs);
void zx_DUP_STRS_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_mm7_ReadReplyRsp_s* x);
int zx_WALK_SO_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_mm7_ReadReplyRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_mm7_ReadReplyRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_mm7_ReadReplyRsp_s* x);
int zx_LEN_WO_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_mm7_ReadReplyRsp_s* x);
char* zx_ENC_SO_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_mm7_ReadReplyRsp_s* x, char* p);
char* zx_ENC_WO_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_mm7_ReadReplyRsp_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_mm7_ReadReplyRsp_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_ReadReplyRsp(struct zx_ctx* c, struct zx_mm7_ReadReplyRsp_s* x);

struct zx_mm7_ReadReplyRsp_s {
  ZX_ELEM_EXT
  zx_mm7_ReadReplyRsp_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_Status_s* Status;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_ReadReplyRsp_GET_MM7Version(struct zx_mm7_ReadReplyRsp_s* x, int n);
struct zx_mm7_Status_s* zx_mm7_ReadReplyRsp_GET_Status(struct zx_mm7_ReadReplyRsp_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_ReadReplyRsp_GET_Extension(struct zx_mm7_ReadReplyRsp_s* x, int n);

int zx_mm7_ReadReplyRsp_NUM_MM7Version(struct zx_mm7_ReadReplyRsp_s* x);
int zx_mm7_ReadReplyRsp_NUM_Status(struct zx_mm7_ReadReplyRsp_s* x);
int zx_mm7_ReadReplyRsp_NUM_Extension(struct zx_mm7_ReadReplyRsp_s* x);

struct zx_elem_s* zx_mm7_ReadReplyRsp_POP_MM7Version(struct zx_mm7_ReadReplyRsp_s* x);
struct zx_mm7_Status_s* zx_mm7_ReadReplyRsp_POP_Status(struct zx_mm7_ReadReplyRsp_s* x);
struct zx_mm7_Extension_s* zx_mm7_ReadReplyRsp_POP_Extension(struct zx_mm7_ReadReplyRsp_s* x);

void zx_mm7_ReadReplyRsp_PUSH_MM7Version(struct zx_mm7_ReadReplyRsp_s* x, struct zx_elem_s* y);
void zx_mm7_ReadReplyRsp_PUSH_Status(struct zx_mm7_ReadReplyRsp_s* x, struct zx_mm7_Status_s* y);
void zx_mm7_ReadReplyRsp_PUSH_Extension(struct zx_mm7_ReadReplyRsp_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_ReadReplyRsp_PUT_MM7Version(struct zx_mm7_ReadReplyRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReadReplyRsp_PUT_Status(struct zx_mm7_ReadReplyRsp_s* x, int n, struct zx_mm7_Status_s* y);
void zx_mm7_ReadReplyRsp_PUT_Extension(struct zx_mm7_ReadReplyRsp_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_ReadReplyRsp_ADD_MM7Version(struct zx_mm7_ReadReplyRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReadReplyRsp_ADD_Status(struct zx_mm7_ReadReplyRsp_s* x, int n, struct zx_mm7_Status_s* z);
void zx_mm7_ReadReplyRsp_ADD_Extension(struct zx_mm7_ReadReplyRsp_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_ReadReplyRsp_DEL_MM7Version(struct zx_mm7_ReadReplyRsp_s* x, int n);
void zx_mm7_ReadReplyRsp_DEL_Status(struct zx_mm7_ReadReplyRsp_s* x, int n);
void zx_mm7_ReadReplyRsp_DEL_Extension(struct zx_mm7_ReadReplyRsp_s* x, int n);

void zx_mm7_ReadReplyRsp_REV_MM7Version(struct zx_mm7_ReadReplyRsp_s* x);
void zx_mm7_ReadReplyRsp_REV_Status(struct zx_mm7_ReadReplyRsp_s* x);
void zx_mm7_ReadReplyRsp_REV_Extension(struct zx_mm7_ReadReplyRsp_s* x);

#endif
/* -------------------------- mm7_Recipient -------------------------- */
/* refby( zx_mm7_ReadReplyReq_s zx_mm7_DeliveryReportReq_s ) */
#ifndef zx_mm7_Recipient_EXT
#define zx_mm7_Recipient_EXT
#endif

struct zx_mm7_Recipient_s* zx_DEC_mm7_Recipient(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Recipient_s* zx_NEW_mm7_Recipient(struct zx_ctx* c);
void zx_FREE_mm7_Recipient(struct zx_ctx* c, struct zx_mm7_Recipient_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Recipient_s* zx_DEEP_CLONE_mm7_Recipient(struct zx_ctx* c, struct zx_mm7_Recipient_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Recipient(struct zx_ctx* c, struct zx_mm7_Recipient_s* x);
int zx_WALK_SO_mm7_Recipient(struct zx_ctx* c, struct zx_mm7_Recipient_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Recipient(struct zx_ctx* c, struct zx_mm7_Recipient_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Recipient(struct zx_ctx* c, struct zx_mm7_Recipient_s* x);
int zx_LEN_WO_mm7_Recipient(struct zx_ctx* c, struct zx_mm7_Recipient_s* x);
char* zx_ENC_SO_mm7_Recipient(struct zx_ctx* c, struct zx_mm7_Recipient_s* x, char* p);
char* zx_ENC_WO_mm7_Recipient(struct zx_ctx* c, struct zx_mm7_Recipient_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Recipient(struct zx_ctx* c, struct zx_mm7_Recipient_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Recipient(struct zx_ctx* c, struct zx_mm7_Recipient_s* x);

struct zx_mm7_Recipient_s {
  ZX_ELEM_EXT
  zx_mm7_Recipient_EXT
  struct zx_mm7_RFC2822Address_s* RFC2822Address;	/* {0,1} nada */
  struct zx_mm7_Number_s* Number;	/* {0,1} nada */
  struct zx_mm7_ShortCode_s* ShortCode;	/* {0,1} nada */
  struct zx_mm7_Extension_s* Extension;	/* {0,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_RFC2822Address_s* zx_mm7_Recipient_GET_RFC2822Address(struct zx_mm7_Recipient_s* x, int n);
struct zx_mm7_Number_s* zx_mm7_Recipient_GET_Number(struct zx_mm7_Recipient_s* x, int n);
struct zx_mm7_ShortCode_s* zx_mm7_Recipient_GET_ShortCode(struct zx_mm7_Recipient_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_Recipient_GET_Extension(struct zx_mm7_Recipient_s* x, int n);

int zx_mm7_Recipient_NUM_RFC2822Address(struct zx_mm7_Recipient_s* x);
int zx_mm7_Recipient_NUM_Number(struct zx_mm7_Recipient_s* x);
int zx_mm7_Recipient_NUM_ShortCode(struct zx_mm7_Recipient_s* x);
int zx_mm7_Recipient_NUM_Extension(struct zx_mm7_Recipient_s* x);

struct zx_mm7_RFC2822Address_s* zx_mm7_Recipient_POP_RFC2822Address(struct zx_mm7_Recipient_s* x);
struct zx_mm7_Number_s* zx_mm7_Recipient_POP_Number(struct zx_mm7_Recipient_s* x);
struct zx_mm7_ShortCode_s* zx_mm7_Recipient_POP_ShortCode(struct zx_mm7_Recipient_s* x);
struct zx_mm7_Extension_s* zx_mm7_Recipient_POP_Extension(struct zx_mm7_Recipient_s* x);

void zx_mm7_Recipient_PUSH_RFC2822Address(struct zx_mm7_Recipient_s* x, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_Recipient_PUSH_Number(struct zx_mm7_Recipient_s* x, struct zx_mm7_Number_s* y);
void zx_mm7_Recipient_PUSH_ShortCode(struct zx_mm7_Recipient_s* x, struct zx_mm7_ShortCode_s* y);
void zx_mm7_Recipient_PUSH_Extension(struct zx_mm7_Recipient_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_Recipient_PUT_RFC2822Address(struct zx_mm7_Recipient_s* x, int n, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_Recipient_PUT_Number(struct zx_mm7_Recipient_s* x, int n, struct zx_mm7_Number_s* y);
void zx_mm7_Recipient_PUT_ShortCode(struct zx_mm7_Recipient_s* x, int n, struct zx_mm7_ShortCode_s* y);
void zx_mm7_Recipient_PUT_Extension(struct zx_mm7_Recipient_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_Recipient_ADD_RFC2822Address(struct zx_mm7_Recipient_s* x, int n, struct zx_mm7_RFC2822Address_s* z);
void zx_mm7_Recipient_ADD_Number(struct zx_mm7_Recipient_s* x, int n, struct zx_mm7_Number_s* z);
void zx_mm7_Recipient_ADD_ShortCode(struct zx_mm7_Recipient_s* x, int n, struct zx_mm7_ShortCode_s* z);
void zx_mm7_Recipient_ADD_Extension(struct zx_mm7_Recipient_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_Recipient_DEL_RFC2822Address(struct zx_mm7_Recipient_s* x, int n);
void zx_mm7_Recipient_DEL_Number(struct zx_mm7_Recipient_s* x, int n);
void zx_mm7_Recipient_DEL_ShortCode(struct zx_mm7_Recipient_s* x, int n);
void zx_mm7_Recipient_DEL_Extension(struct zx_mm7_Recipient_s* x, int n);

void zx_mm7_Recipient_REV_RFC2822Address(struct zx_mm7_Recipient_s* x);
void zx_mm7_Recipient_REV_Number(struct zx_mm7_Recipient_s* x);
void zx_mm7_Recipient_REV_ShortCode(struct zx_mm7_Recipient_s* x);
void zx_mm7_Recipient_REV_Extension(struct zx_mm7_Recipient_s* x);

#endif
/* -------------------------- mm7_Recipients -------------------------- */
/* refby( zx_mm7_CancelReq_s zx_mm7_SubmitReq_s zx_mm7_DeliverReq_s ) */
#ifndef zx_mm7_Recipients_EXT
#define zx_mm7_Recipients_EXT
#endif

struct zx_mm7_Recipients_s* zx_DEC_mm7_Recipients(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Recipients_s* zx_NEW_mm7_Recipients(struct zx_ctx* c);
void zx_FREE_mm7_Recipients(struct zx_ctx* c, struct zx_mm7_Recipients_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Recipients_s* zx_DEEP_CLONE_mm7_Recipients(struct zx_ctx* c, struct zx_mm7_Recipients_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Recipients(struct zx_ctx* c, struct zx_mm7_Recipients_s* x);
int zx_WALK_SO_mm7_Recipients(struct zx_ctx* c, struct zx_mm7_Recipients_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Recipients(struct zx_ctx* c, struct zx_mm7_Recipients_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Recipients(struct zx_ctx* c, struct zx_mm7_Recipients_s* x);
int zx_LEN_WO_mm7_Recipients(struct zx_ctx* c, struct zx_mm7_Recipients_s* x);
char* zx_ENC_SO_mm7_Recipients(struct zx_ctx* c, struct zx_mm7_Recipients_s* x, char* p);
char* zx_ENC_WO_mm7_Recipients(struct zx_ctx* c, struct zx_mm7_Recipients_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Recipients(struct zx_ctx* c, struct zx_mm7_Recipients_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Recipients(struct zx_ctx* c, struct zx_mm7_Recipients_s* x);

struct zx_mm7_Recipients_s {
  ZX_ELEM_EXT
  zx_mm7_Recipients_EXT
  struct zx_mm7_To_s* To;	/* {0,1} nada */
  struct zx_mm7_Cc_s* Cc;	/* {0,1} nada */
  struct zx_mm7_Bcc_s* Bcc;	/* {0,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_To_s* zx_mm7_Recipients_GET_To(struct zx_mm7_Recipients_s* x, int n);
struct zx_mm7_Cc_s* zx_mm7_Recipients_GET_Cc(struct zx_mm7_Recipients_s* x, int n);
struct zx_mm7_Bcc_s* zx_mm7_Recipients_GET_Bcc(struct zx_mm7_Recipients_s* x, int n);

int zx_mm7_Recipients_NUM_To(struct zx_mm7_Recipients_s* x);
int zx_mm7_Recipients_NUM_Cc(struct zx_mm7_Recipients_s* x);
int zx_mm7_Recipients_NUM_Bcc(struct zx_mm7_Recipients_s* x);

struct zx_mm7_To_s* zx_mm7_Recipients_POP_To(struct zx_mm7_Recipients_s* x);
struct zx_mm7_Cc_s* zx_mm7_Recipients_POP_Cc(struct zx_mm7_Recipients_s* x);
struct zx_mm7_Bcc_s* zx_mm7_Recipients_POP_Bcc(struct zx_mm7_Recipients_s* x);

void zx_mm7_Recipients_PUSH_To(struct zx_mm7_Recipients_s* x, struct zx_mm7_To_s* y);
void zx_mm7_Recipients_PUSH_Cc(struct zx_mm7_Recipients_s* x, struct zx_mm7_Cc_s* y);
void zx_mm7_Recipients_PUSH_Bcc(struct zx_mm7_Recipients_s* x, struct zx_mm7_Bcc_s* y);


void zx_mm7_Recipients_PUT_To(struct zx_mm7_Recipients_s* x, int n, struct zx_mm7_To_s* y);
void zx_mm7_Recipients_PUT_Cc(struct zx_mm7_Recipients_s* x, int n, struct zx_mm7_Cc_s* y);
void zx_mm7_Recipients_PUT_Bcc(struct zx_mm7_Recipients_s* x, int n, struct zx_mm7_Bcc_s* y);

void zx_mm7_Recipients_ADD_To(struct zx_mm7_Recipients_s* x, int n, struct zx_mm7_To_s* z);
void zx_mm7_Recipients_ADD_Cc(struct zx_mm7_Recipients_s* x, int n, struct zx_mm7_Cc_s* z);
void zx_mm7_Recipients_ADD_Bcc(struct zx_mm7_Recipients_s* x, int n, struct zx_mm7_Bcc_s* z);

void zx_mm7_Recipients_DEL_To(struct zx_mm7_Recipients_s* x, int n);
void zx_mm7_Recipients_DEL_Cc(struct zx_mm7_Recipients_s* x, int n);
void zx_mm7_Recipients_DEL_Bcc(struct zx_mm7_Recipients_s* x, int n);

void zx_mm7_Recipients_REV_To(struct zx_mm7_Recipients_s* x);
void zx_mm7_Recipients_REV_Cc(struct zx_mm7_Recipients_s* x);
void zx_mm7_Recipients_REV_Bcc(struct zx_mm7_Recipients_s* x);

#endif
/* -------------------------- mm7_ReplaceReq -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_ReplaceReq_EXT
#define zx_mm7_ReplaceReq_EXT
#endif

struct zx_mm7_ReplaceReq_s* zx_DEC_mm7_ReplaceReq(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_ReplaceReq_s* zx_NEW_mm7_ReplaceReq(struct zx_ctx* c);
void zx_FREE_mm7_ReplaceReq(struct zx_ctx* c, struct zx_mm7_ReplaceReq_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_ReplaceReq_s* zx_DEEP_CLONE_mm7_ReplaceReq(struct zx_ctx* c, struct zx_mm7_ReplaceReq_s* x, int dup_strs);
void zx_DUP_STRS_mm7_ReplaceReq(struct zx_ctx* c, struct zx_mm7_ReplaceReq_s* x);
int zx_WALK_SO_mm7_ReplaceReq(struct zx_ctx* c, struct zx_mm7_ReplaceReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_ReplaceReq(struct zx_ctx* c, struct zx_mm7_ReplaceReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_ReplaceReq(struct zx_ctx* c, struct zx_mm7_ReplaceReq_s* x);
int zx_LEN_WO_mm7_ReplaceReq(struct zx_ctx* c, struct zx_mm7_ReplaceReq_s* x);
char* zx_ENC_SO_mm7_ReplaceReq(struct zx_ctx* c, struct zx_mm7_ReplaceReq_s* x, char* p);
char* zx_ENC_WO_mm7_ReplaceReq(struct zx_ctx* c, struct zx_mm7_ReplaceReq_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_ReplaceReq(struct zx_ctx* c, struct zx_mm7_ReplaceReq_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_ReplaceReq(struct zx_ctx* c, struct zx_mm7_ReplaceReq_s* x);

struct zx_mm7_ReplaceReq_s {
  ZX_ELEM_EXT
  zx_mm7_ReplaceReq_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_SenderIdentification_s* SenderIdentification;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
  struct zx_elem_s* MessageID;	/* {1,1} xs:string */
  struct zx_mm7_ServiceCode_s* ServiceCode;	/* {0,1}  */
  struct zx_elem_s* TimeStamp;	/* {0,1} xs:dateTime */
  struct zx_elem_s* ReadReply;	/* {0,1} xs:boolean */
  struct zx_elem_s* EarliestDeliveryTime;	/* {0,1} xs:string */
  struct zx_elem_s* DistributionIndicator;	/* {0,1} xs:boolean */
  struct zx_elem_s* ContentClass;	/* {0,1} text */
  struct zx_elem_s* DRMContent;	/* {0,1} xs:boolean */
  struct zx_elem_s* ApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* ReplyApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* AuxApplicInfo;	/* {0,1} xs:string */
  struct zx_mm7_Content_s* Content;	/* {0,-1}  */
  struct zx_mm7_AdditionalInformation_s* AdditionalInformation;	/* {0,-1}  */
  struct zx_mm7_MessageExtraData_s* MessageExtraData;	/* {0,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_ReplaceReq_GET_MM7Version(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_mm7_SenderIdentification_s* zx_mm7_ReplaceReq_GET_SenderIdentification(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_ReplaceReq_GET_Extension(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReplaceReq_GET_MessageID(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_mm7_ServiceCode_s* zx_mm7_ReplaceReq_GET_ServiceCode(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReplaceReq_GET_TimeStamp(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReplaceReq_GET_ReadReply(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReplaceReq_GET_EarliestDeliveryTime(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReplaceReq_GET_DistributionIndicator(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReplaceReq_GET_ContentClass(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReplaceReq_GET_DRMContent(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReplaceReq_GET_ApplicID(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReplaceReq_GET_ReplyApplicID(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_ReplaceReq_GET_AuxApplicInfo(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_mm7_Content_s* zx_mm7_ReplaceReq_GET_Content(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_mm7_AdditionalInformation_s* zx_mm7_ReplaceReq_GET_AdditionalInformation(struct zx_mm7_ReplaceReq_s* x, int n);
struct zx_mm7_MessageExtraData_s* zx_mm7_ReplaceReq_GET_MessageExtraData(struct zx_mm7_ReplaceReq_s* x, int n);

int zx_mm7_ReplaceReq_NUM_MM7Version(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_SenderIdentification(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_Extension(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_MessageID(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_ServiceCode(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_TimeStamp(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_ReadReply(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_EarliestDeliveryTime(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_DistributionIndicator(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_ContentClass(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_DRMContent(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_ApplicID(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_ReplyApplicID(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_AuxApplicInfo(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_Content(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_AdditionalInformation(struct zx_mm7_ReplaceReq_s* x);
int zx_mm7_ReplaceReq_NUM_MessageExtraData(struct zx_mm7_ReplaceReq_s* x);

struct zx_elem_s* zx_mm7_ReplaceReq_POP_MM7Version(struct zx_mm7_ReplaceReq_s* x);
struct zx_mm7_SenderIdentification_s* zx_mm7_ReplaceReq_POP_SenderIdentification(struct zx_mm7_ReplaceReq_s* x);
struct zx_mm7_Extension_s* zx_mm7_ReplaceReq_POP_Extension(struct zx_mm7_ReplaceReq_s* x);
struct zx_elem_s* zx_mm7_ReplaceReq_POP_MessageID(struct zx_mm7_ReplaceReq_s* x);
struct zx_mm7_ServiceCode_s* zx_mm7_ReplaceReq_POP_ServiceCode(struct zx_mm7_ReplaceReq_s* x);
struct zx_elem_s* zx_mm7_ReplaceReq_POP_TimeStamp(struct zx_mm7_ReplaceReq_s* x);
struct zx_elem_s* zx_mm7_ReplaceReq_POP_ReadReply(struct zx_mm7_ReplaceReq_s* x);
struct zx_elem_s* zx_mm7_ReplaceReq_POP_EarliestDeliveryTime(struct zx_mm7_ReplaceReq_s* x);
struct zx_elem_s* zx_mm7_ReplaceReq_POP_DistributionIndicator(struct zx_mm7_ReplaceReq_s* x);
struct zx_elem_s* zx_mm7_ReplaceReq_POP_ContentClass(struct zx_mm7_ReplaceReq_s* x);
struct zx_elem_s* zx_mm7_ReplaceReq_POP_DRMContent(struct zx_mm7_ReplaceReq_s* x);
struct zx_elem_s* zx_mm7_ReplaceReq_POP_ApplicID(struct zx_mm7_ReplaceReq_s* x);
struct zx_elem_s* zx_mm7_ReplaceReq_POP_ReplyApplicID(struct zx_mm7_ReplaceReq_s* x);
struct zx_elem_s* zx_mm7_ReplaceReq_POP_AuxApplicInfo(struct zx_mm7_ReplaceReq_s* x);
struct zx_mm7_Content_s* zx_mm7_ReplaceReq_POP_Content(struct zx_mm7_ReplaceReq_s* x);
struct zx_mm7_AdditionalInformation_s* zx_mm7_ReplaceReq_POP_AdditionalInformation(struct zx_mm7_ReplaceReq_s* x);
struct zx_mm7_MessageExtraData_s* zx_mm7_ReplaceReq_POP_MessageExtraData(struct zx_mm7_ReplaceReq_s* x);

void zx_mm7_ReplaceReq_PUSH_MM7Version(struct zx_mm7_ReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUSH_SenderIdentification(struct zx_mm7_ReplaceReq_s* x, struct zx_mm7_SenderIdentification_s* y);
void zx_mm7_ReplaceReq_PUSH_Extension(struct zx_mm7_ReplaceReq_s* x, struct zx_mm7_Extension_s* y);
void zx_mm7_ReplaceReq_PUSH_MessageID(struct zx_mm7_ReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUSH_ServiceCode(struct zx_mm7_ReplaceReq_s* x, struct zx_mm7_ServiceCode_s* y);
void zx_mm7_ReplaceReq_PUSH_TimeStamp(struct zx_mm7_ReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUSH_ReadReply(struct zx_mm7_ReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUSH_EarliestDeliveryTime(struct zx_mm7_ReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUSH_DistributionIndicator(struct zx_mm7_ReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUSH_ContentClass(struct zx_mm7_ReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUSH_DRMContent(struct zx_mm7_ReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUSH_ApplicID(struct zx_mm7_ReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUSH_ReplyApplicID(struct zx_mm7_ReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUSH_AuxApplicInfo(struct zx_mm7_ReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUSH_Content(struct zx_mm7_ReplaceReq_s* x, struct zx_mm7_Content_s* y);
void zx_mm7_ReplaceReq_PUSH_AdditionalInformation(struct zx_mm7_ReplaceReq_s* x, struct zx_mm7_AdditionalInformation_s* y);
void zx_mm7_ReplaceReq_PUSH_MessageExtraData(struct zx_mm7_ReplaceReq_s* x, struct zx_mm7_MessageExtraData_s* y);


void zx_mm7_ReplaceReq_PUT_MM7Version(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUT_SenderIdentification(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_SenderIdentification_s* y);
void zx_mm7_ReplaceReq_PUT_Extension(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_Extension_s* y);
void zx_mm7_ReplaceReq_PUT_MessageID(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUT_ServiceCode(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_ServiceCode_s* y);
void zx_mm7_ReplaceReq_PUT_TimeStamp(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUT_ReadReply(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUT_EarliestDeliveryTime(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUT_DistributionIndicator(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUT_ContentClass(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUT_DRMContent(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUT_ApplicID(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUT_ReplyApplicID(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUT_AuxApplicInfo(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceReq_PUT_Content(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_Content_s* y);
void zx_mm7_ReplaceReq_PUT_AdditionalInformation(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_AdditionalInformation_s* y);
void zx_mm7_ReplaceReq_PUT_MessageExtraData(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_MessageExtraData_s* y);

void zx_mm7_ReplaceReq_ADD_MM7Version(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceReq_ADD_SenderIdentification(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_SenderIdentification_s* z);
void zx_mm7_ReplaceReq_ADD_Extension(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_Extension_s* z);
void zx_mm7_ReplaceReq_ADD_MessageID(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceReq_ADD_ServiceCode(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_ServiceCode_s* z);
void zx_mm7_ReplaceReq_ADD_TimeStamp(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceReq_ADD_ReadReply(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceReq_ADD_EarliestDeliveryTime(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceReq_ADD_DistributionIndicator(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceReq_ADD_ContentClass(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceReq_ADD_DRMContent(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceReq_ADD_ApplicID(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceReq_ADD_ReplyApplicID(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceReq_ADD_AuxApplicInfo(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceReq_ADD_Content(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_Content_s* z);
void zx_mm7_ReplaceReq_ADD_AdditionalInformation(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_AdditionalInformation_s* z);
void zx_mm7_ReplaceReq_ADD_MessageExtraData(struct zx_mm7_ReplaceReq_s* x, int n, struct zx_mm7_MessageExtraData_s* z);

void zx_mm7_ReplaceReq_DEL_MM7Version(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_SenderIdentification(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_Extension(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_MessageID(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_ServiceCode(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_TimeStamp(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_ReadReply(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_EarliestDeliveryTime(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_DistributionIndicator(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_ContentClass(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_DRMContent(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_ApplicID(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_ReplyApplicID(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_AuxApplicInfo(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_Content(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_AdditionalInformation(struct zx_mm7_ReplaceReq_s* x, int n);
void zx_mm7_ReplaceReq_DEL_MessageExtraData(struct zx_mm7_ReplaceReq_s* x, int n);

void zx_mm7_ReplaceReq_REV_MM7Version(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_SenderIdentification(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_Extension(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_MessageID(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_ServiceCode(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_TimeStamp(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_ReadReply(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_EarliestDeliveryTime(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_DistributionIndicator(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_ContentClass(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_DRMContent(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_ApplicID(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_ReplyApplicID(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_AuxApplicInfo(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_Content(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_AdditionalInformation(struct zx_mm7_ReplaceReq_s* x);
void zx_mm7_ReplaceReq_REV_MessageExtraData(struct zx_mm7_ReplaceReq_s* x);

#endif
/* -------------------------- mm7_ReplaceRsp -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_ReplaceRsp_EXT
#define zx_mm7_ReplaceRsp_EXT
#endif

struct zx_mm7_ReplaceRsp_s* zx_DEC_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_ReplaceRsp_s* zx_NEW_mm7_ReplaceRsp(struct zx_ctx* c);
void zx_FREE_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_mm7_ReplaceRsp_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_ReplaceRsp_s* zx_DEEP_CLONE_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_mm7_ReplaceRsp_s* x, int dup_strs);
void zx_DUP_STRS_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_mm7_ReplaceRsp_s* x);
int zx_WALK_SO_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_mm7_ReplaceRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_mm7_ReplaceRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_mm7_ReplaceRsp_s* x);
int zx_LEN_WO_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_mm7_ReplaceRsp_s* x);
char* zx_ENC_SO_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_mm7_ReplaceRsp_s* x, char* p);
char* zx_ENC_WO_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_mm7_ReplaceRsp_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_mm7_ReplaceRsp_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_ReplaceRsp(struct zx_ctx* c, struct zx_mm7_ReplaceRsp_s* x);

struct zx_mm7_ReplaceRsp_s {
  ZX_ELEM_EXT
  zx_mm7_ReplaceRsp_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_Status_s* Status;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_ReplaceRsp_GET_MM7Version(struct zx_mm7_ReplaceRsp_s* x, int n);
struct zx_mm7_Status_s* zx_mm7_ReplaceRsp_GET_Status(struct zx_mm7_ReplaceRsp_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_ReplaceRsp_GET_Extension(struct zx_mm7_ReplaceRsp_s* x, int n);

int zx_mm7_ReplaceRsp_NUM_MM7Version(struct zx_mm7_ReplaceRsp_s* x);
int zx_mm7_ReplaceRsp_NUM_Status(struct zx_mm7_ReplaceRsp_s* x);
int zx_mm7_ReplaceRsp_NUM_Extension(struct zx_mm7_ReplaceRsp_s* x);

struct zx_elem_s* zx_mm7_ReplaceRsp_POP_MM7Version(struct zx_mm7_ReplaceRsp_s* x);
struct zx_mm7_Status_s* zx_mm7_ReplaceRsp_POP_Status(struct zx_mm7_ReplaceRsp_s* x);
struct zx_mm7_Extension_s* zx_mm7_ReplaceRsp_POP_Extension(struct zx_mm7_ReplaceRsp_s* x);

void zx_mm7_ReplaceRsp_PUSH_MM7Version(struct zx_mm7_ReplaceRsp_s* x, struct zx_elem_s* y);
void zx_mm7_ReplaceRsp_PUSH_Status(struct zx_mm7_ReplaceRsp_s* x, struct zx_mm7_Status_s* y);
void zx_mm7_ReplaceRsp_PUSH_Extension(struct zx_mm7_ReplaceRsp_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_ReplaceRsp_PUT_MM7Version(struct zx_mm7_ReplaceRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_ReplaceRsp_PUT_Status(struct zx_mm7_ReplaceRsp_s* x, int n, struct zx_mm7_Status_s* y);
void zx_mm7_ReplaceRsp_PUT_Extension(struct zx_mm7_ReplaceRsp_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_ReplaceRsp_ADD_MM7Version(struct zx_mm7_ReplaceRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_ReplaceRsp_ADD_Status(struct zx_mm7_ReplaceRsp_s* x, int n, struct zx_mm7_Status_s* z);
void zx_mm7_ReplaceRsp_ADD_Extension(struct zx_mm7_ReplaceRsp_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_ReplaceRsp_DEL_MM7Version(struct zx_mm7_ReplaceRsp_s* x, int n);
void zx_mm7_ReplaceRsp_DEL_Status(struct zx_mm7_ReplaceRsp_s* x, int n);
void zx_mm7_ReplaceRsp_DEL_Extension(struct zx_mm7_ReplaceRsp_s* x, int n);

void zx_mm7_ReplaceRsp_REV_MM7Version(struct zx_mm7_ReplaceRsp_s* x);
void zx_mm7_ReplaceRsp_REV_Status(struct zx_mm7_ReplaceRsp_s* x);
void zx_mm7_ReplaceRsp_REV_Extension(struct zx_mm7_ReplaceRsp_s* x);

#endif
/* -------------------------- mm7_ReplyCharging -------------------------- */
/* refby( zx_mm7_SubmitReq_s ) */
#ifndef zx_mm7_ReplyCharging_EXT
#define zx_mm7_ReplyCharging_EXT
#endif

struct zx_mm7_ReplyCharging_s* zx_DEC_mm7_ReplyCharging(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_ReplyCharging_s* zx_NEW_mm7_ReplyCharging(struct zx_ctx* c);
void zx_FREE_mm7_ReplyCharging(struct zx_ctx* c, struct zx_mm7_ReplyCharging_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_ReplyCharging_s* zx_DEEP_CLONE_mm7_ReplyCharging(struct zx_ctx* c, struct zx_mm7_ReplyCharging_s* x, int dup_strs);
void zx_DUP_STRS_mm7_ReplyCharging(struct zx_ctx* c, struct zx_mm7_ReplyCharging_s* x);
int zx_WALK_SO_mm7_ReplyCharging(struct zx_ctx* c, struct zx_mm7_ReplyCharging_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_ReplyCharging(struct zx_ctx* c, struct zx_mm7_ReplyCharging_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_ReplyCharging(struct zx_ctx* c, struct zx_mm7_ReplyCharging_s* x);
int zx_LEN_WO_mm7_ReplyCharging(struct zx_ctx* c, struct zx_mm7_ReplyCharging_s* x);
char* zx_ENC_SO_mm7_ReplyCharging(struct zx_ctx* c, struct zx_mm7_ReplyCharging_s* x, char* p);
char* zx_ENC_WO_mm7_ReplyCharging(struct zx_ctx* c, struct zx_mm7_ReplyCharging_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_ReplyCharging(struct zx_ctx* c, struct zx_mm7_ReplyCharging_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_ReplyCharging(struct zx_ctx* c, struct zx_mm7_ReplyCharging_s* x);

struct zx_mm7_ReplyCharging_s {
  ZX_ELEM_EXT
  zx_mm7_ReplyCharging_EXT
  struct zx_str* replyChargingSize;	/* {0,1} attribute xs:positiveInteger */
  struct zx_str* replyDeadline;	/* {0,1} attribute mm7:relativeOrAbsoluteDateType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_mm7_ReplyCharging_GET_replyChargingSize(struct zx_mm7_ReplyCharging_s* x);
struct zx_str* zx_mm7_ReplyCharging_GET_replyDeadline(struct zx_mm7_ReplyCharging_s* x);





void zx_mm7_ReplyCharging_PUT_replyChargingSize(struct zx_mm7_ReplyCharging_s* x, struct zx_str* y);
void zx_mm7_ReplyCharging_PUT_replyDeadline(struct zx_mm7_ReplyCharging_s* x, struct zx_str* y);





#endif
/* -------------------------- mm7_Sender -------------------------- */
/* refby( zx_mm7_ReadReplyReq_s zx_mm7_DeliveryReportReq_s zx_mm7_DeliverReq_s ) */
#ifndef zx_mm7_Sender_EXT
#define zx_mm7_Sender_EXT
#endif

struct zx_mm7_Sender_s* zx_DEC_mm7_Sender(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Sender_s* zx_NEW_mm7_Sender(struct zx_ctx* c);
void zx_FREE_mm7_Sender(struct zx_ctx* c, struct zx_mm7_Sender_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Sender_s* zx_DEEP_CLONE_mm7_Sender(struct zx_ctx* c, struct zx_mm7_Sender_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Sender(struct zx_ctx* c, struct zx_mm7_Sender_s* x);
int zx_WALK_SO_mm7_Sender(struct zx_ctx* c, struct zx_mm7_Sender_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Sender(struct zx_ctx* c, struct zx_mm7_Sender_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Sender(struct zx_ctx* c, struct zx_mm7_Sender_s* x);
int zx_LEN_WO_mm7_Sender(struct zx_ctx* c, struct zx_mm7_Sender_s* x);
char* zx_ENC_SO_mm7_Sender(struct zx_ctx* c, struct zx_mm7_Sender_s* x, char* p);
char* zx_ENC_WO_mm7_Sender(struct zx_ctx* c, struct zx_mm7_Sender_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Sender(struct zx_ctx* c, struct zx_mm7_Sender_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Sender(struct zx_ctx* c, struct zx_mm7_Sender_s* x);

struct zx_mm7_Sender_s {
  ZX_ELEM_EXT
  zx_mm7_Sender_EXT
  struct zx_mm7_RFC2822Address_s* RFC2822Address;	/* {0,1} nada */
  struct zx_mm7_Number_s* Number;	/* {0,1} nada */
  struct zx_mm7_ShortCode_s* ShortCode;	/* {0,1} nada */
  struct zx_mm7_Extension_s* Extension;	/* {0,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_RFC2822Address_s* zx_mm7_Sender_GET_RFC2822Address(struct zx_mm7_Sender_s* x, int n);
struct zx_mm7_Number_s* zx_mm7_Sender_GET_Number(struct zx_mm7_Sender_s* x, int n);
struct zx_mm7_ShortCode_s* zx_mm7_Sender_GET_ShortCode(struct zx_mm7_Sender_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_Sender_GET_Extension(struct zx_mm7_Sender_s* x, int n);

int zx_mm7_Sender_NUM_RFC2822Address(struct zx_mm7_Sender_s* x);
int zx_mm7_Sender_NUM_Number(struct zx_mm7_Sender_s* x);
int zx_mm7_Sender_NUM_ShortCode(struct zx_mm7_Sender_s* x);
int zx_mm7_Sender_NUM_Extension(struct zx_mm7_Sender_s* x);

struct zx_mm7_RFC2822Address_s* zx_mm7_Sender_POP_RFC2822Address(struct zx_mm7_Sender_s* x);
struct zx_mm7_Number_s* zx_mm7_Sender_POP_Number(struct zx_mm7_Sender_s* x);
struct zx_mm7_ShortCode_s* zx_mm7_Sender_POP_ShortCode(struct zx_mm7_Sender_s* x);
struct zx_mm7_Extension_s* zx_mm7_Sender_POP_Extension(struct zx_mm7_Sender_s* x);

void zx_mm7_Sender_PUSH_RFC2822Address(struct zx_mm7_Sender_s* x, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_Sender_PUSH_Number(struct zx_mm7_Sender_s* x, struct zx_mm7_Number_s* y);
void zx_mm7_Sender_PUSH_ShortCode(struct zx_mm7_Sender_s* x, struct zx_mm7_ShortCode_s* y);
void zx_mm7_Sender_PUSH_Extension(struct zx_mm7_Sender_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_Sender_PUT_RFC2822Address(struct zx_mm7_Sender_s* x, int n, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_Sender_PUT_Number(struct zx_mm7_Sender_s* x, int n, struct zx_mm7_Number_s* y);
void zx_mm7_Sender_PUT_ShortCode(struct zx_mm7_Sender_s* x, int n, struct zx_mm7_ShortCode_s* y);
void zx_mm7_Sender_PUT_Extension(struct zx_mm7_Sender_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_Sender_ADD_RFC2822Address(struct zx_mm7_Sender_s* x, int n, struct zx_mm7_RFC2822Address_s* z);
void zx_mm7_Sender_ADD_Number(struct zx_mm7_Sender_s* x, int n, struct zx_mm7_Number_s* z);
void zx_mm7_Sender_ADD_ShortCode(struct zx_mm7_Sender_s* x, int n, struct zx_mm7_ShortCode_s* z);
void zx_mm7_Sender_ADD_Extension(struct zx_mm7_Sender_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_Sender_DEL_RFC2822Address(struct zx_mm7_Sender_s* x, int n);
void zx_mm7_Sender_DEL_Number(struct zx_mm7_Sender_s* x, int n);
void zx_mm7_Sender_DEL_ShortCode(struct zx_mm7_Sender_s* x, int n);
void zx_mm7_Sender_DEL_Extension(struct zx_mm7_Sender_s* x, int n);

void zx_mm7_Sender_REV_RFC2822Address(struct zx_mm7_Sender_s* x);
void zx_mm7_Sender_REV_Number(struct zx_mm7_Sender_s* x);
void zx_mm7_Sender_REV_ShortCode(struct zx_mm7_Sender_s* x);
void zx_mm7_Sender_REV_Extension(struct zx_mm7_Sender_s* x);

#endif
/* -------------------------- mm7_SenderAddress -------------------------- */
/* refby( zx_mm7_SenderIdentification_s ) */
#ifndef zx_mm7_SenderAddress_EXT
#define zx_mm7_SenderAddress_EXT
#endif

struct zx_mm7_SenderAddress_s* zx_DEC_mm7_SenderAddress(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_SenderAddress_s* zx_NEW_mm7_SenderAddress(struct zx_ctx* c);
void zx_FREE_mm7_SenderAddress(struct zx_ctx* c, struct zx_mm7_SenderAddress_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_SenderAddress_s* zx_DEEP_CLONE_mm7_SenderAddress(struct zx_ctx* c, struct zx_mm7_SenderAddress_s* x, int dup_strs);
void zx_DUP_STRS_mm7_SenderAddress(struct zx_ctx* c, struct zx_mm7_SenderAddress_s* x);
int zx_WALK_SO_mm7_SenderAddress(struct zx_ctx* c, struct zx_mm7_SenderAddress_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_SenderAddress(struct zx_ctx* c, struct zx_mm7_SenderAddress_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_SenderAddress(struct zx_ctx* c, struct zx_mm7_SenderAddress_s* x);
int zx_LEN_WO_mm7_SenderAddress(struct zx_ctx* c, struct zx_mm7_SenderAddress_s* x);
char* zx_ENC_SO_mm7_SenderAddress(struct zx_ctx* c, struct zx_mm7_SenderAddress_s* x, char* p);
char* zx_ENC_WO_mm7_SenderAddress(struct zx_ctx* c, struct zx_mm7_SenderAddress_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_SenderAddress(struct zx_ctx* c, struct zx_mm7_SenderAddress_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_SenderAddress(struct zx_ctx* c, struct zx_mm7_SenderAddress_s* x);

struct zx_mm7_SenderAddress_s {
  ZX_ELEM_EXT
  zx_mm7_SenderAddress_EXT
  struct zx_mm7_RFC2822Address_s* RFC2822Address;	/* {0,1} nada */
  struct zx_mm7_Number_s* Number;	/* {0,1} nada */
  struct zx_mm7_ShortCode_s* ShortCode;	/* {0,1} nada */
  struct zx_mm7_Extension_s* Extension;	/* {0,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_RFC2822Address_s* zx_mm7_SenderAddress_GET_RFC2822Address(struct zx_mm7_SenderAddress_s* x, int n);
struct zx_mm7_Number_s* zx_mm7_SenderAddress_GET_Number(struct zx_mm7_SenderAddress_s* x, int n);
struct zx_mm7_ShortCode_s* zx_mm7_SenderAddress_GET_ShortCode(struct zx_mm7_SenderAddress_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_SenderAddress_GET_Extension(struct zx_mm7_SenderAddress_s* x, int n);

int zx_mm7_SenderAddress_NUM_RFC2822Address(struct zx_mm7_SenderAddress_s* x);
int zx_mm7_SenderAddress_NUM_Number(struct zx_mm7_SenderAddress_s* x);
int zx_mm7_SenderAddress_NUM_ShortCode(struct zx_mm7_SenderAddress_s* x);
int zx_mm7_SenderAddress_NUM_Extension(struct zx_mm7_SenderAddress_s* x);

struct zx_mm7_RFC2822Address_s* zx_mm7_SenderAddress_POP_RFC2822Address(struct zx_mm7_SenderAddress_s* x);
struct zx_mm7_Number_s* zx_mm7_SenderAddress_POP_Number(struct zx_mm7_SenderAddress_s* x);
struct zx_mm7_ShortCode_s* zx_mm7_SenderAddress_POP_ShortCode(struct zx_mm7_SenderAddress_s* x);
struct zx_mm7_Extension_s* zx_mm7_SenderAddress_POP_Extension(struct zx_mm7_SenderAddress_s* x);

void zx_mm7_SenderAddress_PUSH_RFC2822Address(struct zx_mm7_SenderAddress_s* x, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_SenderAddress_PUSH_Number(struct zx_mm7_SenderAddress_s* x, struct zx_mm7_Number_s* y);
void zx_mm7_SenderAddress_PUSH_ShortCode(struct zx_mm7_SenderAddress_s* x, struct zx_mm7_ShortCode_s* y);
void zx_mm7_SenderAddress_PUSH_Extension(struct zx_mm7_SenderAddress_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_SenderAddress_PUT_RFC2822Address(struct zx_mm7_SenderAddress_s* x, int n, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_SenderAddress_PUT_Number(struct zx_mm7_SenderAddress_s* x, int n, struct zx_mm7_Number_s* y);
void zx_mm7_SenderAddress_PUT_ShortCode(struct zx_mm7_SenderAddress_s* x, int n, struct zx_mm7_ShortCode_s* y);
void zx_mm7_SenderAddress_PUT_Extension(struct zx_mm7_SenderAddress_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_SenderAddress_ADD_RFC2822Address(struct zx_mm7_SenderAddress_s* x, int n, struct zx_mm7_RFC2822Address_s* z);
void zx_mm7_SenderAddress_ADD_Number(struct zx_mm7_SenderAddress_s* x, int n, struct zx_mm7_Number_s* z);
void zx_mm7_SenderAddress_ADD_ShortCode(struct zx_mm7_SenderAddress_s* x, int n, struct zx_mm7_ShortCode_s* z);
void zx_mm7_SenderAddress_ADD_Extension(struct zx_mm7_SenderAddress_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_SenderAddress_DEL_RFC2822Address(struct zx_mm7_SenderAddress_s* x, int n);
void zx_mm7_SenderAddress_DEL_Number(struct zx_mm7_SenderAddress_s* x, int n);
void zx_mm7_SenderAddress_DEL_ShortCode(struct zx_mm7_SenderAddress_s* x, int n);
void zx_mm7_SenderAddress_DEL_Extension(struct zx_mm7_SenderAddress_s* x, int n);

void zx_mm7_SenderAddress_REV_RFC2822Address(struct zx_mm7_SenderAddress_s* x);
void zx_mm7_SenderAddress_REV_Number(struct zx_mm7_SenderAddress_s* x);
void zx_mm7_SenderAddress_REV_ShortCode(struct zx_mm7_SenderAddress_s* x);
void zx_mm7_SenderAddress_REV_Extension(struct zx_mm7_SenderAddress_s* x);

#endif
/* -------------------------- mm7_SenderIdentification -------------------------- */
/* refby( zx_mm7_ReplaceReq_s zx_mm7_CancelReq_s zx_mm7_SubmitReq_s zx_mm7_extendedCancelReq_s ) */
#ifndef zx_mm7_SenderIdentification_EXT
#define zx_mm7_SenderIdentification_EXT
#endif

struct zx_mm7_SenderIdentification_s* zx_DEC_mm7_SenderIdentification(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_SenderIdentification_s* zx_NEW_mm7_SenderIdentification(struct zx_ctx* c);
void zx_FREE_mm7_SenderIdentification(struct zx_ctx* c, struct zx_mm7_SenderIdentification_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_SenderIdentification_s* zx_DEEP_CLONE_mm7_SenderIdentification(struct zx_ctx* c, struct zx_mm7_SenderIdentification_s* x, int dup_strs);
void zx_DUP_STRS_mm7_SenderIdentification(struct zx_ctx* c, struct zx_mm7_SenderIdentification_s* x);
int zx_WALK_SO_mm7_SenderIdentification(struct zx_ctx* c, struct zx_mm7_SenderIdentification_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_SenderIdentification(struct zx_ctx* c, struct zx_mm7_SenderIdentification_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_SenderIdentification(struct zx_ctx* c, struct zx_mm7_SenderIdentification_s* x);
int zx_LEN_WO_mm7_SenderIdentification(struct zx_ctx* c, struct zx_mm7_SenderIdentification_s* x);
char* zx_ENC_SO_mm7_SenderIdentification(struct zx_ctx* c, struct zx_mm7_SenderIdentification_s* x, char* p);
char* zx_ENC_WO_mm7_SenderIdentification(struct zx_ctx* c, struct zx_mm7_SenderIdentification_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_SenderIdentification(struct zx_ctx* c, struct zx_mm7_SenderIdentification_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_SenderIdentification(struct zx_ctx* c, struct zx_mm7_SenderIdentification_s* x);

struct zx_mm7_SenderIdentification_s {
  ZX_ELEM_EXT
  zx_mm7_SenderIdentification_EXT
  struct zx_elem_s* VASPID;	/* {0,1} xs:string */
  struct zx_elem_s* VASID;	/* {0,1} xs:string */
  struct zx_mm7_SenderAddress_s* SenderAddress;	/* {0,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_SenderIdentification_GET_VASPID(struct zx_mm7_SenderIdentification_s* x, int n);
struct zx_elem_s* zx_mm7_SenderIdentification_GET_VASID(struct zx_mm7_SenderIdentification_s* x, int n);
struct zx_mm7_SenderAddress_s* zx_mm7_SenderIdentification_GET_SenderAddress(struct zx_mm7_SenderIdentification_s* x, int n);

int zx_mm7_SenderIdentification_NUM_VASPID(struct zx_mm7_SenderIdentification_s* x);
int zx_mm7_SenderIdentification_NUM_VASID(struct zx_mm7_SenderIdentification_s* x);
int zx_mm7_SenderIdentification_NUM_SenderAddress(struct zx_mm7_SenderIdentification_s* x);

struct zx_elem_s* zx_mm7_SenderIdentification_POP_VASPID(struct zx_mm7_SenderIdentification_s* x);
struct zx_elem_s* zx_mm7_SenderIdentification_POP_VASID(struct zx_mm7_SenderIdentification_s* x);
struct zx_mm7_SenderAddress_s* zx_mm7_SenderIdentification_POP_SenderAddress(struct zx_mm7_SenderIdentification_s* x);

void zx_mm7_SenderIdentification_PUSH_VASPID(struct zx_mm7_SenderIdentification_s* x, struct zx_elem_s* y);
void zx_mm7_SenderIdentification_PUSH_VASID(struct zx_mm7_SenderIdentification_s* x, struct zx_elem_s* y);
void zx_mm7_SenderIdentification_PUSH_SenderAddress(struct zx_mm7_SenderIdentification_s* x, struct zx_mm7_SenderAddress_s* y);


void zx_mm7_SenderIdentification_PUT_VASPID(struct zx_mm7_SenderIdentification_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SenderIdentification_PUT_VASID(struct zx_mm7_SenderIdentification_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SenderIdentification_PUT_SenderAddress(struct zx_mm7_SenderIdentification_s* x, int n, struct zx_mm7_SenderAddress_s* y);

void zx_mm7_SenderIdentification_ADD_VASPID(struct zx_mm7_SenderIdentification_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SenderIdentification_ADD_VASID(struct zx_mm7_SenderIdentification_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SenderIdentification_ADD_SenderAddress(struct zx_mm7_SenderIdentification_s* x, int n, struct zx_mm7_SenderAddress_s* z);

void zx_mm7_SenderIdentification_DEL_VASPID(struct zx_mm7_SenderIdentification_s* x, int n);
void zx_mm7_SenderIdentification_DEL_VASID(struct zx_mm7_SenderIdentification_s* x, int n);
void zx_mm7_SenderIdentification_DEL_SenderAddress(struct zx_mm7_SenderIdentification_s* x, int n);

void zx_mm7_SenderIdentification_REV_VASPID(struct zx_mm7_SenderIdentification_s* x);
void zx_mm7_SenderIdentification_REV_VASID(struct zx_mm7_SenderIdentification_s* x);
void zx_mm7_SenderIdentification_REV_SenderAddress(struct zx_mm7_SenderIdentification_s* x);

#endif
/* -------------------------- mm7_ServiceCode -------------------------- */
/* refby( zx_mm7_ReplaceReq_s zx_mm7_extendedReplaceReq_s zx_mm7_SubmitReq_s zx_mm7_DeliverRsp_s ) */
#ifndef zx_mm7_ServiceCode_EXT
#define zx_mm7_ServiceCode_EXT
#endif

struct zx_mm7_ServiceCode_s* zx_DEC_mm7_ServiceCode(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_ServiceCode_s* zx_NEW_mm7_ServiceCode(struct zx_ctx* c);
void zx_FREE_mm7_ServiceCode(struct zx_ctx* c, struct zx_mm7_ServiceCode_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_ServiceCode_s* zx_DEEP_CLONE_mm7_ServiceCode(struct zx_ctx* c, struct zx_mm7_ServiceCode_s* x, int dup_strs);
void zx_DUP_STRS_mm7_ServiceCode(struct zx_ctx* c, struct zx_mm7_ServiceCode_s* x);
int zx_WALK_SO_mm7_ServiceCode(struct zx_ctx* c, struct zx_mm7_ServiceCode_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_ServiceCode(struct zx_ctx* c, struct zx_mm7_ServiceCode_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_ServiceCode(struct zx_ctx* c, struct zx_mm7_ServiceCode_s* x);
int zx_LEN_WO_mm7_ServiceCode(struct zx_ctx* c, struct zx_mm7_ServiceCode_s* x);
char* zx_ENC_SO_mm7_ServiceCode(struct zx_ctx* c, struct zx_mm7_ServiceCode_s* x, char* p);
char* zx_ENC_WO_mm7_ServiceCode(struct zx_ctx* c, struct zx_mm7_ServiceCode_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_ServiceCode(struct zx_ctx* c, struct zx_mm7_ServiceCode_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_ServiceCode(struct zx_ctx* c, struct zx_mm7_ServiceCode_s* x);

struct zx_mm7_ServiceCode_s {
  ZX_ELEM_EXT
  zx_mm7_ServiceCode_EXT
};

#ifdef ZX_ENA_GETPUT










#endif
/* -------------------------- mm7_ShortCode -------------------------- */
/* refby( zx_mm7_Cc_s zx_mm7_SenderAddress_s zx_mm7_Bcc_s zx_mm7_ThirdPartyPayer_s zx_mm7_Sender_s zx_mm7_UserAgent_s zx_mm7_Recipient_s zx_mm7_To_s ) */
#ifndef zx_mm7_ShortCode_EXT
#define zx_mm7_ShortCode_EXT
#endif

struct zx_mm7_ShortCode_s* zx_DEC_mm7_ShortCode(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_ShortCode_s* zx_NEW_mm7_ShortCode(struct zx_ctx* c);
void zx_FREE_mm7_ShortCode(struct zx_ctx* c, struct zx_mm7_ShortCode_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_ShortCode_s* zx_DEEP_CLONE_mm7_ShortCode(struct zx_ctx* c, struct zx_mm7_ShortCode_s* x, int dup_strs);
void zx_DUP_STRS_mm7_ShortCode(struct zx_ctx* c, struct zx_mm7_ShortCode_s* x);
int zx_WALK_SO_mm7_ShortCode(struct zx_ctx* c, struct zx_mm7_ShortCode_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_ShortCode(struct zx_ctx* c, struct zx_mm7_ShortCode_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_ShortCode(struct zx_ctx* c, struct zx_mm7_ShortCode_s* x);
int zx_LEN_WO_mm7_ShortCode(struct zx_ctx* c, struct zx_mm7_ShortCode_s* x);
char* zx_ENC_SO_mm7_ShortCode(struct zx_ctx* c, struct zx_mm7_ShortCode_s* x, char* p);
char* zx_ENC_WO_mm7_ShortCode(struct zx_ctx* c, struct zx_mm7_ShortCode_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_ShortCode(struct zx_ctx* c, struct zx_mm7_ShortCode_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_ShortCode(struct zx_ctx* c, struct zx_mm7_ShortCode_s* x);

struct zx_mm7_ShortCode_s {
  ZX_ELEM_EXT
  zx_mm7_ShortCode_EXT
  struct zx_str* addressCoding;	/* {0,1} attribute mm7:addressCodingType */
  struct zx_str* displayOnly;	/* {0,1} attribute xs:boolean */
  struct zx_str* id;	/* {0,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_mm7_ShortCode_GET_addressCoding(struct zx_mm7_ShortCode_s* x);
struct zx_str* zx_mm7_ShortCode_GET_displayOnly(struct zx_mm7_ShortCode_s* x);
struct zx_str* zx_mm7_ShortCode_GET_id(struct zx_mm7_ShortCode_s* x);





void zx_mm7_ShortCode_PUT_addressCoding(struct zx_mm7_ShortCode_s* x, struct zx_str* y);
void zx_mm7_ShortCode_PUT_displayOnly(struct zx_mm7_ShortCode_s* x, struct zx_str* y);
void zx_mm7_ShortCode_PUT_id(struct zx_mm7_ShortCode_s* x, struct zx_str* y);





#endif
/* -------------------------- mm7_Status -------------------------- */
/* refby( zx_mm7_extendedCancelRsp_s zx_mm7_extendedReplaceRsp_s zx_mm7_RSErrorRsp_s zx_mm7_ReplaceRsp_s zx_mm7_DeliverRsp_s zx_mm7_DeliveryReportRsp_s zx_mm7_ReadReplyRsp_s zx_mm7_CancelRsp_s zx_mm7_VASPErrorRsp_s zx_mm7_SubmitRsp_s ) */
#ifndef zx_mm7_Status_EXT
#define zx_mm7_Status_EXT
#endif

struct zx_mm7_Status_s* zx_DEC_mm7_Status(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_Status_s* zx_NEW_mm7_Status(struct zx_ctx* c);
void zx_FREE_mm7_Status(struct zx_ctx* c, struct zx_mm7_Status_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_Status_s* zx_DEEP_CLONE_mm7_Status(struct zx_ctx* c, struct zx_mm7_Status_s* x, int dup_strs);
void zx_DUP_STRS_mm7_Status(struct zx_ctx* c, struct zx_mm7_Status_s* x);
int zx_WALK_SO_mm7_Status(struct zx_ctx* c, struct zx_mm7_Status_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_Status(struct zx_ctx* c, struct zx_mm7_Status_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_Status(struct zx_ctx* c, struct zx_mm7_Status_s* x);
int zx_LEN_WO_mm7_Status(struct zx_ctx* c, struct zx_mm7_Status_s* x);
char* zx_ENC_SO_mm7_Status(struct zx_ctx* c, struct zx_mm7_Status_s* x, char* p);
char* zx_ENC_WO_mm7_Status(struct zx_ctx* c, struct zx_mm7_Status_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_Status(struct zx_ctx* c, struct zx_mm7_Status_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_Status(struct zx_ctx* c, struct zx_mm7_Status_s* x);

struct zx_mm7_Status_s {
  ZX_ELEM_EXT
  zx_mm7_Status_EXT
  struct zx_elem_s* StatusCode;	/* {1,1} xs:positiveInteger */
  struct zx_elem_s* StatusText;	/* {1,1} xs:string */
  struct zx_mm7_Details_s* Details;	/* {0,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_Status_GET_StatusCode(struct zx_mm7_Status_s* x, int n);
struct zx_elem_s* zx_mm7_Status_GET_StatusText(struct zx_mm7_Status_s* x, int n);
struct zx_mm7_Details_s* zx_mm7_Status_GET_Details(struct zx_mm7_Status_s* x, int n);

int zx_mm7_Status_NUM_StatusCode(struct zx_mm7_Status_s* x);
int zx_mm7_Status_NUM_StatusText(struct zx_mm7_Status_s* x);
int zx_mm7_Status_NUM_Details(struct zx_mm7_Status_s* x);

struct zx_elem_s* zx_mm7_Status_POP_StatusCode(struct zx_mm7_Status_s* x);
struct zx_elem_s* zx_mm7_Status_POP_StatusText(struct zx_mm7_Status_s* x);
struct zx_mm7_Details_s* zx_mm7_Status_POP_Details(struct zx_mm7_Status_s* x);

void zx_mm7_Status_PUSH_StatusCode(struct zx_mm7_Status_s* x, struct zx_elem_s* y);
void zx_mm7_Status_PUSH_StatusText(struct zx_mm7_Status_s* x, struct zx_elem_s* y);
void zx_mm7_Status_PUSH_Details(struct zx_mm7_Status_s* x, struct zx_mm7_Details_s* y);


void zx_mm7_Status_PUT_StatusCode(struct zx_mm7_Status_s* x, int n, struct zx_elem_s* y);
void zx_mm7_Status_PUT_StatusText(struct zx_mm7_Status_s* x, int n, struct zx_elem_s* y);
void zx_mm7_Status_PUT_Details(struct zx_mm7_Status_s* x, int n, struct zx_mm7_Details_s* y);

void zx_mm7_Status_ADD_StatusCode(struct zx_mm7_Status_s* x, int n, struct zx_elem_s* z);
void zx_mm7_Status_ADD_StatusText(struct zx_mm7_Status_s* x, int n, struct zx_elem_s* z);
void zx_mm7_Status_ADD_Details(struct zx_mm7_Status_s* x, int n, struct zx_mm7_Details_s* z);

void zx_mm7_Status_DEL_StatusCode(struct zx_mm7_Status_s* x, int n);
void zx_mm7_Status_DEL_StatusText(struct zx_mm7_Status_s* x, int n);
void zx_mm7_Status_DEL_Details(struct zx_mm7_Status_s* x, int n);

void zx_mm7_Status_REV_StatusCode(struct zx_mm7_Status_s* x);
void zx_mm7_Status_REV_StatusText(struct zx_mm7_Status_s* x);
void zx_mm7_Status_REV_Details(struct zx_mm7_Status_s* x);

#endif
/* -------------------------- mm7_SubmitReq -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_SubmitReq_EXT
#define zx_mm7_SubmitReq_EXT
#endif

struct zx_mm7_SubmitReq_s* zx_DEC_mm7_SubmitReq(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_SubmitReq_s* zx_NEW_mm7_SubmitReq(struct zx_ctx* c);
void zx_FREE_mm7_SubmitReq(struct zx_ctx* c, struct zx_mm7_SubmitReq_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_SubmitReq_s* zx_DEEP_CLONE_mm7_SubmitReq(struct zx_ctx* c, struct zx_mm7_SubmitReq_s* x, int dup_strs);
void zx_DUP_STRS_mm7_SubmitReq(struct zx_ctx* c, struct zx_mm7_SubmitReq_s* x);
int zx_WALK_SO_mm7_SubmitReq(struct zx_ctx* c, struct zx_mm7_SubmitReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_SubmitReq(struct zx_ctx* c, struct zx_mm7_SubmitReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_SubmitReq(struct zx_ctx* c, struct zx_mm7_SubmitReq_s* x);
int zx_LEN_WO_mm7_SubmitReq(struct zx_ctx* c, struct zx_mm7_SubmitReq_s* x);
char* zx_ENC_SO_mm7_SubmitReq(struct zx_ctx* c, struct zx_mm7_SubmitReq_s* x, char* p);
char* zx_ENC_WO_mm7_SubmitReq(struct zx_ctx* c, struct zx_mm7_SubmitReq_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_SubmitReq(struct zx_ctx* c, struct zx_mm7_SubmitReq_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_SubmitReq(struct zx_ctx* c, struct zx_mm7_SubmitReq_s* x);

struct zx_mm7_SubmitReq_s {
  ZX_ELEM_EXT
  zx_mm7_SubmitReq_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_SenderIdentification_s* SenderIdentification;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
  struct zx_mm7_Recipients_s* Recipients;	/* {1,1}  */
  struct zx_mm7_PreferredChannels_s* PreferredChannels;	/* {0,1}  */
  struct zx_mm7_ServiceCode_s* ServiceCode;	/* {0,1}  */
  struct zx_elem_s* LinkedID;	/* {0,1} xs:string */
  struct zx_elem_s* MessageClass;	/* {0,1} Personal */
  struct zx_elem_s* TimeStamp;	/* {0,1} xs:dateTime */
  struct zx_mm7_ReplyCharging_s* ReplyCharging;	/* {0,1}  */
  struct zx_elem_s* EarliestDeliveryTime;	/* {0,1} xs:string */
  struct zx_elem_s* ExpiryDate;	/* {0,1} xs:string */
  struct zx_elem_s* DeliveryReport;	/* {0,1} xs:boolean */
  struct zx_elem_s* ReadReply;	/* {0,1} xs:boolean */
  struct zx_elem_s* Priority;	/* {0,1} Normal */
  struct zx_elem_s* Subject;	/* {0,1} xs:string */
  struct zx_elem_s* ChargedParty;	/* {0,1} Sender */
  struct zx_elem_s* ChargedPartyID;	/* {0,1} xs:string */
  struct zx_mm7_ThirdPartyPayer_s* ThirdPartyPayer;	/* {0,1}  */
  struct zx_elem_s* DistributionIndicator;	/* {0,1} xs:boolean */
  struct zx_mm7_DeliveryCondition_s* DeliveryCondition;	/* {0,1}  */
  struct zx_elem_s* ApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* ReplyApplicID;	/* {0,1} xs:string */
  struct zx_elem_s* AuxApplicInfo;	/* {0,1} xs:string */
  struct zx_elem_s* ContentClass;	/* {0,1} text */
  struct zx_elem_s* DRMContent;	/* {0,1} xs:boolean */
  struct zx_mm7_Content_s* Content;	/* {0,-1}  */
  struct zx_mm7_AdditionalInformation_s* AdditionalInformation;	/* {0,-1}  */
  struct zx_mm7_MessageExtraData_s* MessageExtraData;	/* {0,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_SubmitReq_GET_MM7Version(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_mm7_SenderIdentification_s* zx_mm7_SubmitReq_GET_SenderIdentification(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_SubmitReq_GET_Extension(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_mm7_Recipients_s* zx_mm7_SubmitReq_GET_Recipients(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_mm7_PreferredChannels_s* zx_mm7_SubmitReq_GET_PreferredChannels(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_mm7_ServiceCode_s* zx_mm7_SubmitReq_GET_ServiceCode(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_LinkedID(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_MessageClass(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_TimeStamp(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_mm7_ReplyCharging_s* zx_mm7_SubmitReq_GET_ReplyCharging(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_EarliestDeliveryTime(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_ExpiryDate(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_DeliveryReport(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_ReadReply(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_Priority(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_Subject(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_ChargedParty(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_ChargedPartyID(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_mm7_ThirdPartyPayer_s* zx_mm7_SubmitReq_GET_ThirdPartyPayer(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_DistributionIndicator(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_mm7_DeliveryCondition_s* zx_mm7_SubmitReq_GET_DeliveryCondition(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_ApplicID(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_ReplyApplicID(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_AuxApplicInfo(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_ContentClass(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitReq_GET_DRMContent(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_mm7_Content_s* zx_mm7_SubmitReq_GET_Content(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_mm7_AdditionalInformation_s* zx_mm7_SubmitReq_GET_AdditionalInformation(struct zx_mm7_SubmitReq_s* x, int n);
struct zx_mm7_MessageExtraData_s* zx_mm7_SubmitReq_GET_MessageExtraData(struct zx_mm7_SubmitReq_s* x, int n);

int zx_mm7_SubmitReq_NUM_MM7Version(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_SenderIdentification(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_Extension(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_Recipients(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_PreferredChannels(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_ServiceCode(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_LinkedID(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_MessageClass(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_TimeStamp(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_ReplyCharging(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_EarliestDeliveryTime(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_ExpiryDate(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_DeliveryReport(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_ReadReply(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_Priority(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_Subject(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_ChargedParty(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_ChargedPartyID(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_ThirdPartyPayer(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_DistributionIndicator(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_DeliveryCondition(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_ApplicID(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_ReplyApplicID(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_AuxApplicInfo(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_ContentClass(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_DRMContent(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_Content(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_AdditionalInformation(struct zx_mm7_SubmitReq_s* x);
int zx_mm7_SubmitReq_NUM_MessageExtraData(struct zx_mm7_SubmitReq_s* x);

struct zx_elem_s* zx_mm7_SubmitReq_POP_MM7Version(struct zx_mm7_SubmitReq_s* x);
struct zx_mm7_SenderIdentification_s* zx_mm7_SubmitReq_POP_SenderIdentification(struct zx_mm7_SubmitReq_s* x);
struct zx_mm7_Extension_s* zx_mm7_SubmitReq_POP_Extension(struct zx_mm7_SubmitReq_s* x);
struct zx_mm7_Recipients_s* zx_mm7_SubmitReq_POP_Recipients(struct zx_mm7_SubmitReq_s* x);
struct zx_mm7_PreferredChannels_s* zx_mm7_SubmitReq_POP_PreferredChannels(struct zx_mm7_SubmitReq_s* x);
struct zx_mm7_ServiceCode_s* zx_mm7_SubmitReq_POP_ServiceCode(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_LinkedID(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_MessageClass(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_TimeStamp(struct zx_mm7_SubmitReq_s* x);
struct zx_mm7_ReplyCharging_s* zx_mm7_SubmitReq_POP_ReplyCharging(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_EarliestDeliveryTime(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_ExpiryDate(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_DeliveryReport(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_ReadReply(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_Priority(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_Subject(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_ChargedParty(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_ChargedPartyID(struct zx_mm7_SubmitReq_s* x);
struct zx_mm7_ThirdPartyPayer_s* zx_mm7_SubmitReq_POP_ThirdPartyPayer(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_DistributionIndicator(struct zx_mm7_SubmitReq_s* x);
struct zx_mm7_DeliveryCondition_s* zx_mm7_SubmitReq_POP_DeliveryCondition(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_ApplicID(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_ReplyApplicID(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_AuxApplicInfo(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_ContentClass(struct zx_mm7_SubmitReq_s* x);
struct zx_elem_s* zx_mm7_SubmitReq_POP_DRMContent(struct zx_mm7_SubmitReq_s* x);
struct zx_mm7_Content_s* zx_mm7_SubmitReq_POP_Content(struct zx_mm7_SubmitReq_s* x);
struct zx_mm7_AdditionalInformation_s* zx_mm7_SubmitReq_POP_AdditionalInformation(struct zx_mm7_SubmitReq_s* x);
struct zx_mm7_MessageExtraData_s* zx_mm7_SubmitReq_POP_MessageExtraData(struct zx_mm7_SubmitReq_s* x);

void zx_mm7_SubmitReq_PUSH_MM7Version(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_SenderIdentification(struct zx_mm7_SubmitReq_s* x, struct zx_mm7_SenderIdentification_s* y);
void zx_mm7_SubmitReq_PUSH_Extension(struct zx_mm7_SubmitReq_s* x, struct zx_mm7_Extension_s* y);
void zx_mm7_SubmitReq_PUSH_Recipients(struct zx_mm7_SubmitReq_s* x, struct zx_mm7_Recipients_s* y);
void zx_mm7_SubmitReq_PUSH_PreferredChannels(struct zx_mm7_SubmitReq_s* x, struct zx_mm7_PreferredChannels_s* y);
void zx_mm7_SubmitReq_PUSH_ServiceCode(struct zx_mm7_SubmitReq_s* x, struct zx_mm7_ServiceCode_s* y);
void zx_mm7_SubmitReq_PUSH_LinkedID(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_MessageClass(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_TimeStamp(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_ReplyCharging(struct zx_mm7_SubmitReq_s* x, struct zx_mm7_ReplyCharging_s* y);
void zx_mm7_SubmitReq_PUSH_EarliestDeliveryTime(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_ExpiryDate(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_DeliveryReport(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_ReadReply(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_Priority(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_Subject(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_ChargedParty(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_ChargedPartyID(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_ThirdPartyPayer(struct zx_mm7_SubmitReq_s* x, struct zx_mm7_ThirdPartyPayer_s* y);
void zx_mm7_SubmitReq_PUSH_DistributionIndicator(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_DeliveryCondition(struct zx_mm7_SubmitReq_s* x, struct zx_mm7_DeliveryCondition_s* y);
void zx_mm7_SubmitReq_PUSH_ApplicID(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_ReplyApplicID(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_AuxApplicInfo(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_ContentClass(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_DRMContent(struct zx_mm7_SubmitReq_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUSH_Content(struct zx_mm7_SubmitReq_s* x, struct zx_mm7_Content_s* y);
void zx_mm7_SubmitReq_PUSH_AdditionalInformation(struct zx_mm7_SubmitReq_s* x, struct zx_mm7_AdditionalInformation_s* y);
void zx_mm7_SubmitReq_PUSH_MessageExtraData(struct zx_mm7_SubmitReq_s* x, struct zx_mm7_MessageExtraData_s* y);


void zx_mm7_SubmitReq_PUT_MM7Version(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_SenderIdentification(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_SenderIdentification_s* y);
void zx_mm7_SubmitReq_PUT_Extension(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_Extension_s* y);
void zx_mm7_SubmitReq_PUT_Recipients(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_Recipients_s* y);
void zx_mm7_SubmitReq_PUT_PreferredChannels(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_PreferredChannels_s* y);
void zx_mm7_SubmitReq_PUT_ServiceCode(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_ServiceCode_s* y);
void zx_mm7_SubmitReq_PUT_LinkedID(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_MessageClass(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_TimeStamp(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_ReplyCharging(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_ReplyCharging_s* y);
void zx_mm7_SubmitReq_PUT_EarliestDeliveryTime(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_ExpiryDate(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_DeliveryReport(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_ReadReply(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_Priority(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_Subject(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_ChargedParty(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_ChargedPartyID(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_ThirdPartyPayer(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_ThirdPartyPayer_s* y);
void zx_mm7_SubmitReq_PUT_DistributionIndicator(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_DeliveryCondition(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_DeliveryCondition_s* y);
void zx_mm7_SubmitReq_PUT_ApplicID(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_ReplyApplicID(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_AuxApplicInfo(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_ContentClass(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_DRMContent(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitReq_PUT_Content(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_Content_s* y);
void zx_mm7_SubmitReq_PUT_AdditionalInformation(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_AdditionalInformation_s* y);
void zx_mm7_SubmitReq_PUT_MessageExtraData(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_MessageExtraData_s* y);

void zx_mm7_SubmitReq_ADD_MM7Version(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_SenderIdentification(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_SenderIdentification_s* z);
void zx_mm7_SubmitReq_ADD_Extension(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_Extension_s* z);
void zx_mm7_SubmitReq_ADD_Recipients(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_Recipients_s* z);
void zx_mm7_SubmitReq_ADD_PreferredChannels(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_PreferredChannels_s* z);
void zx_mm7_SubmitReq_ADD_ServiceCode(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_ServiceCode_s* z);
void zx_mm7_SubmitReq_ADD_LinkedID(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_MessageClass(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_TimeStamp(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_ReplyCharging(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_ReplyCharging_s* z);
void zx_mm7_SubmitReq_ADD_EarliestDeliveryTime(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_ExpiryDate(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_DeliveryReport(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_ReadReply(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_Priority(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_Subject(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_ChargedParty(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_ChargedPartyID(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_ThirdPartyPayer(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_ThirdPartyPayer_s* z);
void zx_mm7_SubmitReq_ADD_DistributionIndicator(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_DeliveryCondition(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_DeliveryCondition_s* z);
void zx_mm7_SubmitReq_ADD_ApplicID(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_ReplyApplicID(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_AuxApplicInfo(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_ContentClass(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_DRMContent(struct zx_mm7_SubmitReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitReq_ADD_Content(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_Content_s* z);
void zx_mm7_SubmitReq_ADD_AdditionalInformation(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_AdditionalInformation_s* z);
void zx_mm7_SubmitReq_ADD_MessageExtraData(struct zx_mm7_SubmitReq_s* x, int n, struct zx_mm7_MessageExtraData_s* z);

void zx_mm7_SubmitReq_DEL_MM7Version(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_SenderIdentification(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_Extension(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_Recipients(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_PreferredChannels(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_ServiceCode(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_LinkedID(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_MessageClass(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_TimeStamp(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_ReplyCharging(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_EarliestDeliveryTime(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_ExpiryDate(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_DeliveryReport(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_ReadReply(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_Priority(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_Subject(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_ChargedParty(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_ChargedPartyID(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_ThirdPartyPayer(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_DistributionIndicator(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_DeliveryCondition(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_ApplicID(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_ReplyApplicID(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_AuxApplicInfo(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_ContentClass(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_DRMContent(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_Content(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_AdditionalInformation(struct zx_mm7_SubmitReq_s* x, int n);
void zx_mm7_SubmitReq_DEL_MessageExtraData(struct zx_mm7_SubmitReq_s* x, int n);

void zx_mm7_SubmitReq_REV_MM7Version(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_SenderIdentification(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_Extension(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_Recipients(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_PreferredChannels(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_ServiceCode(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_LinkedID(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_MessageClass(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_TimeStamp(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_ReplyCharging(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_EarliestDeliveryTime(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_ExpiryDate(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_DeliveryReport(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_ReadReply(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_Priority(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_Subject(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_ChargedParty(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_ChargedPartyID(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_ThirdPartyPayer(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_DistributionIndicator(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_DeliveryCondition(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_ApplicID(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_ReplyApplicID(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_AuxApplicInfo(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_ContentClass(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_DRMContent(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_Content(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_AdditionalInformation(struct zx_mm7_SubmitReq_s* x);
void zx_mm7_SubmitReq_REV_MessageExtraData(struct zx_mm7_SubmitReq_s* x);

#endif
/* -------------------------- mm7_SubmitRsp -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_SubmitRsp_EXT
#define zx_mm7_SubmitRsp_EXT
#endif

struct zx_mm7_SubmitRsp_s* zx_DEC_mm7_SubmitRsp(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_SubmitRsp_s* zx_NEW_mm7_SubmitRsp(struct zx_ctx* c);
void zx_FREE_mm7_SubmitRsp(struct zx_ctx* c, struct zx_mm7_SubmitRsp_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_SubmitRsp_s* zx_DEEP_CLONE_mm7_SubmitRsp(struct zx_ctx* c, struct zx_mm7_SubmitRsp_s* x, int dup_strs);
void zx_DUP_STRS_mm7_SubmitRsp(struct zx_ctx* c, struct zx_mm7_SubmitRsp_s* x);
int zx_WALK_SO_mm7_SubmitRsp(struct zx_ctx* c, struct zx_mm7_SubmitRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_SubmitRsp(struct zx_ctx* c, struct zx_mm7_SubmitRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_SubmitRsp(struct zx_ctx* c, struct zx_mm7_SubmitRsp_s* x);
int zx_LEN_WO_mm7_SubmitRsp(struct zx_ctx* c, struct zx_mm7_SubmitRsp_s* x);
char* zx_ENC_SO_mm7_SubmitRsp(struct zx_ctx* c, struct zx_mm7_SubmitRsp_s* x, char* p);
char* zx_ENC_WO_mm7_SubmitRsp(struct zx_ctx* c, struct zx_mm7_SubmitRsp_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_SubmitRsp(struct zx_ctx* c, struct zx_mm7_SubmitRsp_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_SubmitRsp(struct zx_ctx* c, struct zx_mm7_SubmitRsp_s* x);

struct zx_mm7_SubmitRsp_s {
  ZX_ELEM_EXT
  zx_mm7_SubmitRsp_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_Status_s* Status;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
  struct zx_elem_s* MessageID;	/* {1,1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_SubmitRsp_GET_MM7Version(struct zx_mm7_SubmitRsp_s* x, int n);
struct zx_mm7_Status_s* zx_mm7_SubmitRsp_GET_Status(struct zx_mm7_SubmitRsp_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_SubmitRsp_GET_Extension(struct zx_mm7_SubmitRsp_s* x, int n);
struct zx_elem_s* zx_mm7_SubmitRsp_GET_MessageID(struct zx_mm7_SubmitRsp_s* x, int n);

int zx_mm7_SubmitRsp_NUM_MM7Version(struct zx_mm7_SubmitRsp_s* x);
int zx_mm7_SubmitRsp_NUM_Status(struct zx_mm7_SubmitRsp_s* x);
int zx_mm7_SubmitRsp_NUM_Extension(struct zx_mm7_SubmitRsp_s* x);
int zx_mm7_SubmitRsp_NUM_MessageID(struct zx_mm7_SubmitRsp_s* x);

struct zx_elem_s* zx_mm7_SubmitRsp_POP_MM7Version(struct zx_mm7_SubmitRsp_s* x);
struct zx_mm7_Status_s* zx_mm7_SubmitRsp_POP_Status(struct zx_mm7_SubmitRsp_s* x);
struct zx_mm7_Extension_s* zx_mm7_SubmitRsp_POP_Extension(struct zx_mm7_SubmitRsp_s* x);
struct zx_elem_s* zx_mm7_SubmitRsp_POP_MessageID(struct zx_mm7_SubmitRsp_s* x);

void zx_mm7_SubmitRsp_PUSH_MM7Version(struct zx_mm7_SubmitRsp_s* x, struct zx_elem_s* y);
void zx_mm7_SubmitRsp_PUSH_Status(struct zx_mm7_SubmitRsp_s* x, struct zx_mm7_Status_s* y);
void zx_mm7_SubmitRsp_PUSH_Extension(struct zx_mm7_SubmitRsp_s* x, struct zx_mm7_Extension_s* y);
void zx_mm7_SubmitRsp_PUSH_MessageID(struct zx_mm7_SubmitRsp_s* x, struct zx_elem_s* y);


void zx_mm7_SubmitRsp_PUT_MM7Version(struct zx_mm7_SubmitRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_SubmitRsp_PUT_Status(struct zx_mm7_SubmitRsp_s* x, int n, struct zx_mm7_Status_s* y);
void zx_mm7_SubmitRsp_PUT_Extension(struct zx_mm7_SubmitRsp_s* x, int n, struct zx_mm7_Extension_s* y);
void zx_mm7_SubmitRsp_PUT_MessageID(struct zx_mm7_SubmitRsp_s* x, int n, struct zx_elem_s* y);

void zx_mm7_SubmitRsp_ADD_MM7Version(struct zx_mm7_SubmitRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_SubmitRsp_ADD_Status(struct zx_mm7_SubmitRsp_s* x, int n, struct zx_mm7_Status_s* z);
void zx_mm7_SubmitRsp_ADD_Extension(struct zx_mm7_SubmitRsp_s* x, int n, struct zx_mm7_Extension_s* z);
void zx_mm7_SubmitRsp_ADD_MessageID(struct zx_mm7_SubmitRsp_s* x, int n, struct zx_elem_s* z);

void zx_mm7_SubmitRsp_DEL_MM7Version(struct zx_mm7_SubmitRsp_s* x, int n);
void zx_mm7_SubmitRsp_DEL_Status(struct zx_mm7_SubmitRsp_s* x, int n);
void zx_mm7_SubmitRsp_DEL_Extension(struct zx_mm7_SubmitRsp_s* x, int n);
void zx_mm7_SubmitRsp_DEL_MessageID(struct zx_mm7_SubmitRsp_s* x, int n);

void zx_mm7_SubmitRsp_REV_MM7Version(struct zx_mm7_SubmitRsp_s* x);
void zx_mm7_SubmitRsp_REV_Status(struct zx_mm7_SubmitRsp_s* x);
void zx_mm7_SubmitRsp_REV_Extension(struct zx_mm7_SubmitRsp_s* x);
void zx_mm7_SubmitRsp_REV_MessageID(struct zx_mm7_SubmitRsp_s* x);

#endif
/* -------------------------- mm7_ThirdPartyPayer -------------------------- */
/* refby( zx_mm7_SubmitReq_s ) */
#ifndef zx_mm7_ThirdPartyPayer_EXT
#define zx_mm7_ThirdPartyPayer_EXT
#endif

struct zx_mm7_ThirdPartyPayer_s* zx_DEC_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_ThirdPartyPayer_s* zx_NEW_mm7_ThirdPartyPayer(struct zx_ctx* c);
void zx_FREE_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_mm7_ThirdPartyPayer_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_ThirdPartyPayer_s* zx_DEEP_CLONE_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_mm7_ThirdPartyPayer_s* x, int dup_strs);
void zx_DUP_STRS_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_mm7_ThirdPartyPayer_s* x);
int zx_WALK_SO_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_mm7_ThirdPartyPayer_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_mm7_ThirdPartyPayer_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_mm7_ThirdPartyPayer_s* x);
int zx_LEN_WO_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_mm7_ThirdPartyPayer_s* x);
char* zx_ENC_SO_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_mm7_ThirdPartyPayer_s* x, char* p);
char* zx_ENC_WO_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_mm7_ThirdPartyPayer_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_mm7_ThirdPartyPayer_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_ThirdPartyPayer(struct zx_ctx* c, struct zx_mm7_ThirdPartyPayer_s* x);

struct zx_mm7_ThirdPartyPayer_s {
  ZX_ELEM_EXT
  zx_mm7_ThirdPartyPayer_EXT
  struct zx_mm7_RFC2822Address_s* RFC2822Address;	/* {0,1} nada */
  struct zx_mm7_Number_s* Number;	/* {0,1} nada */
  struct zx_mm7_ShortCode_s* ShortCode;	/* {0,1} nada */
  struct zx_mm7_Extension_s* Extension;	/* {0,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_RFC2822Address_s* zx_mm7_ThirdPartyPayer_GET_RFC2822Address(struct zx_mm7_ThirdPartyPayer_s* x, int n);
struct zx_mm7_Number_s* zx_mm7_ThirdPartyPayer_GET_Number(struct zx_mm7_ThirdPartyPayer_s* x, int n);
struct zx_mm7_ShortCode_s* zx_mm7_ThirdPartyPayer_GET_ShortCode(struct zx_mm7_ThirdPartyPayer_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_ThirdPartyPayer_GET_Extension(struct zx_mm7_ThirdPartyPayer_s* x, int n);

int zx_mm7_ThirdPartyPayer_NUM_RFC2822Address(struct zx_mm7_ThirdPartyPayer_s* x);
int zx_mm7_ThirdPartyPayer_NUM_Number(struct zx_mm7_ThirdPartyPayer_s* x);
int zx_mm7_ThirdPartyPayer_NUM_ShortCode(struct zx_mm7_ThirdPartyPayer_s* x);
int zx_mm7_ThirdPartyPayer_NUM_Extension(struct zx_mm7_ThirdPartyPayer_s* x);

struct zx_mm7_RFC2822Address_s* zx_mm7_ThirdPartyPayer_POP_RFC2822Address(struct zx_mm7_ThirdPartyPayer_s* x);
struct zx_mm7_Number_s* zx_mm7_ThirdPartyPayer_POP_Number(struct zx_mm7_ThirdPartyPayer_s* x);
struct zx_mm7_ShortCode_s* zx_mm7_ThirdPartyPayer_POP_ShortCode(struct zx_mm7_ThirdPartyPayer_s* x);
struct zx_mm7_Extension_s* zx_mm7_ThirdPartyPayer_POP_Extension(struct zx_mm7_ThirdPartyPayer_s* x);

void zx_mm7_ThirdPartyPayer_PUSH_RFC2822Address(struct zx_mm7_ThirdPartyPayer_s* x, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_ThirdPartyPayer_PUSH_Number(struct zx_mm7_ThirdPartyPayer_s* x, struct zx_mm7_Number_s* y);
void zx_mm7_ThirdPartyPayer_PUSH_ShortCode(struct zx_mm7_ThirdPartyPayer_s* x, struct zx_mm7_ShortCode_s* y);
void zx_mm7_ThirdPartyPayer_PUSH_Extension(struct zx_mm7_ThirdPartyPayer_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_ThirdPartyPayer_PUT_RFC2822Address(struct zx_mm7_ThirdPartyPayer_s* x, int n, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_ThirdPartyPayer_PUT_Number(struct zx_mm7_ThirdPartyPayer_s* x, int n, struct zx_mm7_Number_s* y);
void zx_mm7_ThirdPartyPayer_PUT_ShortCode(struct zx_mm7_ThirdPartyPayer_s* x, int n, struct zx_mm7_ShortCode_s* y);
void zx_mm7_ThirdPartyPayer_PUT_Extension(struct zx_mm7_ThirdPartyPayer_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_ThirdPartyPayer_ADD_RFC2822Address(struct zx_mm7_ThirdPartyPayer_s* x, int n, struct zx_mm7_RFC2822Address_s* z);
void zx_mm7_ThirdPartyPayer_ADD_Number(struct zx_mm7_ThirdPartyPayer_s* x, int n, struct zx_mm7_Number_s* z);
void zx_mm7_ThirdPartyPayer_ADD_ShortCode(struct zx_mm7_ThirdPartyPayer_s* x, int n, struct zx_mm7_ShortCode_s* z);
void zx_mm7_ThirdPartyPayer_ADD_Extension(struct zx_mm7_ThirdPartyPayer_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_ThirdPartyPayer_DEL_RFC2822Address(struct zx_mm7_ThirdPartyPayer_s* x, int n);
void zx_mm7_ThirdPartyPayer_DEL_Number(struct zx_mm7_ThirdPartyPayer_s* x, int n);
void zx_mm7_ThirdPartyPayer_DEL_ShortCode(struct zx_mm7_ThirdPartyPayer_s* x, int n);
void zx_mm7_ThirdPartyPayer_DEL_Extension(struct zx_mm7_ThirdPartyPayer_s* x, int n);

void zx_mm7_ThirdPartyPayer_REV_RFC2822Address(struct zx_mm7_ThirdPartyPayer_s* x);
void zx_mm7_ThirdPartyPayer_REV_Number(struct zx_mm7_ThirdPartyPayer_s* x);
void zx_mm7_ThirdPartyPayer_REV_ShortCode(struct zx_mm7_ThirdPartyPayer_s* x);
void zx_mm7_ThirdPartyPayer_REV_Extension(struct zx_mm7_ThirdPartyPayer_s* x);

#endif
/* -------------------------- mm7_To -------------------------- */
/* refby( zx_mm7_Recipients_s ) */
#ifndef zx_mm7_To_EXT
#define zx_mm7_To_EXT
#endif

struct zx_mm7_To_s* zx_DEC_mm7_To(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_To_s* zx_NEW_mm7_To(struct zx_ctx* c);
void zx_FREE_mm7_To(struct zx_ctx* c, struct zx_mm7_To_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_To_s* zx_DEEP_CLONE_mm7_To(struct zx_ctx* c, struct zx_mm7_To_s* x, int dup_strs);
void zx_DUP_STRS_mm7_To(struct zx_ctx* c, struct zx_mm7_To_s* x);
int zx_WALK_SO_mm7_To(struct zx_ctx* c, struct zx_mm7_To_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_To(struct zx_ctx* c, struct zx_mm7_To_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_To(struct zx_ctx* c, struct zx_mm7_To_s* x);
int zx_LEN_WO_mm7_To(struct zx_ctx* c, struct zx_mm7_To_s* x);
char* zx_ENC_SO_mm7_To(struct zx_ctx* c, struct zx_mm7_To_s* x, char* p);
char* zx_ENC_WO_mm7_To(struct zx_ctx* c, struct zx_mm7_To_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_To(struct zx_ctx* c, struct zx_mm7_To_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_To(struct zx_ctx* c, struct zx_mm7_To_s* x);

struct zx_mm7_To_s {
  ZX_ELEM_EXT
  zx_mm7_To_EXT
  struct zx_mm7_RFC2822Address_s* RFC2822Address;	/* {0,1} nada */
  struct zx_mm7_Number_s* Number;	/* {0,1} nada */
  struct zx_mm7_ShortCode_s* ShortCode;	/* {0,1} nada */
  struct zx_mm7_Extension_s* Extension;	/* {0,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_mm7_RFC2822Address_s* zx_mm7_To_GET_RFC2822Address(struct zx_mm7_To_s* x, int n);
struct zx_mm7_Number_s* zx_mm7_To_GET_Number(struct zx_mm7_To_s* x, int n);
struct zx_mm7_ShortCode_s* zx_mm7_To_GET_ShortCode(struct zx_mm7_To_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_To_GET_Extension(struct zx_mm7_To_s* x, int n);

int zx_mm7_To_NUM_RFC2822Address(struct zx_mm7_To_s* x);
int zx_mm7_To_NUM_Number(struct zx_mm7_To_s* x);
int zx_mm7_To_NUM_ShortCode(struct zx_mm7_To_s* x);
int zx_mm7_To_NUM_Extension(struct zx_mm7_To_s* x);

struct zx_mm7_RFC2822Address_s* zx_mm7_To_POP_RFC2822Address(struct zx_mm7_To_s* x);
struct zx_mm7_Number_s* zx_mm7_To_POP_Number(struct zx_mm7_To_s* x);
struct zx_mm7_ShortCode_s* zx_mm7_To_POP_ShortCode(struct zx_mm7_To_s* x);
struct zx_mm7_Extension_s* zx_mm7_To_POP_Extension(struct zx_mm7_To_s* x);

void zx_mm7_To_PUSH_RFC2822Address(struct zx_mm7_To_s* x, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_To_PUSH_Number(struct zx_mm7_To_s* x, struct zx_mm7_Number_s* y);
void zx_mm7_To_PUSH_ShortCode(struct zx_mm7_To_s* x, struct zx_mm7_ShortCode_s* y);
void zx_mm7_To_PUSH_Extension(struct zx_mm7_To_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_To_PUT_RFC2822Address(struct zx_mm7_To_s* x, int n, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_To_PUT_Number(struct zx_mm7_To_s* x, int n, struct zx_mm7_Number_s* y);
void zx_mm7_To_PUT_ShortCode(struct zx_mm7_To_s* x, int n, struct zx_mm7_ShortCode_s* y);
void zx_mm7_To_PUT_Extension(struct zx_mm7_To_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_To_ADD_RFC2822Address(struct zx_mm7_To_s* x, int n, struct zx_mm7_RFC2822Address_s* z);
void zx_mm7_To_ADD_Number(struct zx_mm7_To_s* x, int n, struct zx_mm7_Number_s* z);
void zx_mm7_To_ADD_ShortCode(struct zx_mm7_To_s* x, int n, struct zx_mm7_ShortCode_s* z);
void zx_mm7_To_ADD_Extension(struct zx_mm7_To_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_To_DEL_RFC2822Address(struct zx_mm7_To_s* x, int n);
void zx_mm7_To_DEL_Number(struct zx_mm7_To_s* x, int n);
void zx_mm7_To_DEL_ShortCode(struct zx_mm7_To_s* x, int n);
void zx_mm7_To_DEL_Extension(struct zx_mm7_To_s* x, int n);

void zx_mm7_To_REV_RFC2822Address(struct zx_mm7_To_s* x);
void zx_mm7_To_REV_Number(struct zx_mm7_To_s* x);
void zx_mm7_To_REV_ShortCode(struct zx_mm7_To_s* x);
void zx_mm7_To_REV_Extension(struct zx_mm7_To_s* x);

#endif
/* -------------------------- mm7_TransactionID -------------------------- */
/* refby( zx_mm7_QueryStatusReq_s zx_mm7_QueryStatusRsp_s zx_e_Header_s ) */
#ifndef zx_mm7_TransactionID_EXT
#define zx_mm7_TransactionID_EXT
#endif

struct zx_mm7_TransactionID_s* zx_DEC_mm7_TransactionID(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_TransactionID_s* zx_NEW_mm7_TransactionID(struct zx_ctx* c);
void zx_FREE_mm7_TransactionID(struct zx_ctx* c, struct zx_mm7_TransactionID_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_TransactionID_s* zx_DEEP_CLONE_mm7_TransactionID(struct zx_ctx* c, struct zx_mm7_TransactionID_s* x, int dup_strs);
void zx_DUP_STRS_mm7_TransactionID(struct zx_ctx* c, struct zx_mm7_TransactionID_s* x);
int zx_WALK_SO_mm7_TransactionID(struct zx_ctx* c, struct zx_mm7_TransactionID_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_TransactionID(struct zx_ctx* c, struct zx_mm7_TransactionID_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_TransactionID(struct zx_ctx* c, struct zx_mm7_TransactionID_s* x);
int zx_LEN_WO_mm7_TransactionID(struct zx_ctx* c, struct zx_mm7_TransactionID_s* x);
char* zx_ENC_SO_mm7_TransactionID(struct zx_ctx* c, struct zx_mm7_TransactionID_s* x, char* p);
char* zx_ENC_WO_mm7_TransactionID(struct zx_ctx* c, struct zx_mm7_TransactionID_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_TransactionID(struct zx_ctx* c, struct zx_mm7_TransactionID_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_TransactionID(struct zx_ctx* c, struct zx_mm7_TransactionID_s* x);

struct zx_mm7_TransactionID_s {
  ZX_ELEM_EXT
  zx_mm7_TransactionID_EXT
  struct zx_str* actor;	/* {0,1} attribute xs:anyURI */
  struct zx_str* encodingStyle;	/* {0,1} attribute xs:anyURI */
  struct zx_str* mustUnderstand;	/* {0,1} attribute xs:boolean */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_mm7_TransactionID_GET_actor(struct zx_mm7_TransactionID_s* x);
struct zx_str* zx_mm7_TransactionID_GET_encodingStyle(struct zx_mm7_TransactionID_s* x);
struct zx_str* zx_mm7_TransactionID_GET_mustUnderstand(struct zx_mm7_TransactionID_s* x);





void zx_mm7_TransactionID_PUT_actor(struct zx_mm7_TransactionID_s* x, struct zx_str* y);
void zx_mm7_TransactionID_PUT_encodingStyle(struct zx_mm7_TransactionID_s* x, struct zx_str* y);
void zx_mm7_TransactionID_PUT_mustUnderstand(struct zx_mm7_TransactionID_s* x, struct zx_str* y);





#endif
/* -------------------------- mm7_UACapabilities -------------------------- */
/* refby( zx_mm7_DeliveryReportReq_s zx_mm7_DeliverReq_s ) */
#ifndef zx_mm7_UACapabilities_EXT
#define zx_mm7_UACapabilities_EXT
#endif

struct zx_mm7_UACapabilities_s* zx_DEC_mm7_UACapabilities(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_UACapabilities_s* zx_NEW_mm7_UACapabilities(struct zx_ctx* c);
void zx_FREE_mm7_UACapabilities(struct zx_ctx* c, struct zx_mm7_UACapabilities_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_UACapabilities_s* zx_DEEP_CLONE_mm7_UACapabilities(struct zx_ctx* c, struct zx_mm7_UACapabilities_s* x, int dup_strs);
void zx_DUP_STRS_mm7_UACapabilities(struct zx_ctx* c, struct zx_mm7_UACapabilities_s* x);
int zx_WALK_SO_mm7_UACapabilities(struct zx_ctx* c, struct zx_mm7_UACapabilities_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_UACapabilities(struct zx_ctx* c, struct zx_mm7_UACapabilities_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_UACapabilities(struct zx_ctx* c, struct zx_mm7_UACapabilities_s* x);
int zx_LEN_WO_mm7_UACapabilities(struct zx_ctx* c, struct zx_mm7_UACapabilities_s* x);
char* zx_ENC_SO_mm7_UACapabilities(struct zx_ctx* c, struct zx_mm7_UACapabilities_s* x, char* p);
char* zx_ENC_WO_mm7_UACapabilities(struct zx_ctx* c, struct zx_mm7_UACapabilities_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_UACapabilities(struct zx_ctx* c, struct zx_mm7_UACapabilities_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_UACapabilities(struct zx_ctx* c, struct zx_mm7_UACapabilities_s* x);

struct zx_mm7_UACapabilities_s {
  ZX_ELEM_EXT
  zx_mm7_UACapabilities_EXT
  struct zx_str* TimeStamp;	/* {0,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* UAProf;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_mm7_UACapabilities_GET_TimeStamp(struct zx_mm7_UACapabilities_s* x);
struct zx_str* zx_mm7_UACapabilities_GET_UAProf(struct zx_mm7_UACapabilities_s* x);





void zx_mm7_UACapabilities_PUT_TimeStamp(struct zx_mm7_UACapabilities_s* x, struct zx_str* y);
void zx_mm7_UACapabilities_PUT_UAProf(struct zx_mm7_UACapabilities_s* x, struct zx_str* y);





#endif
/* -------------------------- mm7_UserAgent -------------------------- */
/* refby( zx_mm7_Previouslysentby_s ) */
#ifndef zx_mm7_UserAgent_EXT
#define zx_mm7_UserAgent_EXT
#endif

struct zx_mm7_UserAgent_s* zx_DEC_mm7_UserAgent(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_UserAgent_s* zx_NEW_mm7_UserAgent(struct zx_ctx* c);
void zx_FREE_mm7_UserAgent(struct zx_ctx* c, struct zx_mm7_UserAgent_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_UserAgent_s* zx_DEEP_CLONE_mm7_UserAgent(struct zx_ctx* c, struct zx_mm7_UserAgent_s* x, int dup_strs);
void zx_DUP_STRS_mm7_UserAgent(struct zx_ctx* c, struct zx_mm7_UserAgent_s* x);
int zx_WALK_SO_mm7_UserAgent(struct zx_ctx* c, struct zx_mm7_UserAgent_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_UserAgent(struct zx_ctx* c, struct zx_mm7_UserAgent_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_UserAgent(struct zx_ctx* c, struct zx_mm7_UserAgent_s* x);
int zx_LEN_WO_mm7_UserAgent(struct zx_ctx* c, struct zx_mm7_UserAgent_s* x);
char* zx_ENC_SO_mm7_UserAgent(struct zx_ctx* c, struct zx_mm7_UserAgent_s* x, char* p);
char* zx_ENC_WO_mm7_UserAgent(struct zx_ctx* c, struct zx_mm7_UserAgent_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_UserAgent(struct zx_ctx* c, struct zx_mm7_UserAgent_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_UserAgent(struct zx_ctx* c, struct zx_mm7_UserAgent_s* x);

struct zx_mm7_UserAgent_s {
  ZX_ELEM_EXT
  zx_mm7_UserAgent_EXT
  struct zx_mm7_RFC2822Address_s* RFC2822Address;	/* {0,1} nada */
  struct zx_mm7_Number_s* Number;	/* {0,1} nada */
  struct zx_mm7_ShortCode_s* ShortCode;	/* {0,1} nada */
  struct zx_mm7_Extension_s* Extension;	/* {0,1} nada */
  struct zx_str* sequence;	/* {0,1} attribute xs:positiveInteger */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_mm7_UserAgent_GET_sequence(struct zx_mm7_UserAgent_s* x);

struct zx_mm7_RFC2822Address_s* zx_mm7_UserAgent_GET_RFC2822Address(struct zx_mm7_UserAgent_s* x, int n);
struct zx_mm7_Number_s* zx_mm7_UserAgent_GET_Number(struct zx_mm7_UserAgent_s* x, int n);
struct zx_mm7_ShortCode_s* zx_mm7_UserAgent_GET_ShortCode(struct zx_mm7_UserAgent_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_UserAgent_GET_Extension(struct zx_mm7_UserAgent_s* x, int n);

int zx_mm7_UserAgent_NUM_RFC2822Address(struct zx_mm7_UserAgent_s* x);
int zx_mm7_UserAgent_NUM_Number(struct zx_mm7_UserAgent_s* x);
int zx_mm7_UserAgent_NUM_ShortCode(struct zx_mm7_UserAgent_s* x);
int zx_mm7_UserAgent_NUM_Extension(struct zx_mm7_UserAgent_s* x);

struct zx_mm7_RFC2822Address_s* zx_mm7_UserAgent_POP_RFC2822Address(struct zx_mm7_UserAgent_s* x);
struct zx_mm7_Number_s* zx_mm7_UserAgent_POP_Number(struct zx_mm7_UserAgent_s* x);
struct zx_mm7_ShortCode_s* zx_mm7_UserAgent_POP_ShortCode(struct zx_mm7_UserAgent_s* x);
struct zx_mm7_Extension_s* zx_mm7_UserAgent_POP_Extension(struct zx_mm7_UserAgent_s* x);

void zx_mm7_UserAgent_PUSH_RFC2822Address(struct zx_mm7_UserAgent_s* x, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_UserAgent_PUSH_Number(struct zx_mm7_UserAgent_s* x, struct zx_mm7_Number_s* y);
void zx_mm7_UserAgent_PUSH_ShortCode(struct zx_mm7_UserAgent_s* x, struct zx_mm7_ShortCode_s* y);
void zx_mm7_UserAgent_PUSH_Extension(struct zx_mm7_UserAgent_s* x, struct zx_mm7_Extension_s* y);

void zx_mm7_UserAgent_PUT_sequence(struct zx_mm7_UserAgent_s* x, struct zx_str* y);

void zx_mm7_UserAgent_PUT_RFC2822Address(struct zx_mm7_UserAgent_s* x, int n, struct zx_mm7_RFC2822Address_s* y);
void zx_mm7_UserAgent_PUT_Number(struct zx_mm7_UserAgent_s* x, int n, struct zx_mm7_Number_s* y);
void zx_mm7_UserAgent_PUT_ShortCode(struct zx_mm7_UserAgent_s* x, int n, struct zx_mm7_ShortCode_s* y);
void zx_mm7_UserAgent_PUT_Extension(struct zx_mm7_UserAgent_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_UserAgent_ADD_RFC2822Address(struct zx_mm7_UserAgent_s* x, int n, struct zx_mm7_RFC2822Address_s* z);
void zx_mm7_UserAgent_ADD_Number(struct zx_mm7_UserAgent_s* x, int n, struct zx_mm7_Number_s* z);
void zx_mm7_UserAgent_ADD_ShortCode(struct zx_mm7_UserAgent_s* x, int n, struct zx_mm7_ShortCode_s* z);
void zx_mm7_UserAgent_ADD_Extension(struct zx_mm7_UserAgent_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_UserAgent_DEL_RFC2822Address(struct zx_mm7_UserAgent_s* x, int n);
void zx_mm7_UserAgent_DEL_Number(struct zx_mm7_UserAgent_s* x, int n);
void zx_mm7_UserAgent_DEL_ShortCode(struct zx_mm7_UserAgent_s* x, int n);
void zx_mm7_UserAgent_DEL_Extension(struct zx_mm7_UserAgent_s* x, int n);

void zx_mm7_UserAgent_REV_RFC2822Address(struct zx_mm7_UserAgent_s* x);
void zx_mm7_UserAgent_REV_Number(struct zx_mm7_UserAgent_s* x);
void zx_mm7_UserAgent_REV_ShortCode(struct zx_mm7_UserAgent_s* x);
void zx_mm7_UserAgent_REV_Extension(struct zx_mm7_UserAgent_s* x);

#endif
/* -------------------------- mm7_VASPErrorRsp -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_VASPErrorRsp_EXT
#define zx_mm7_VASPErrorRsp_EXT
#endif

struct zx_mm7_VASPErrorRsp_s* zx_DEC_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_VASPErrorRsp_s* zx_NEW_mm7_VASPErrorRsp(struct zx_ctx* c);
void zx_FREE_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_mm7_VASPErrorRsp_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_VASPErrorRsp_s* zx_DEEP_CLONE_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_mm7_VASPErrorRsp_s* x, int dup_strs);
void zx_DUP_STRS_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_mm7_VASPErrorRsp_s* x);
int zx_WALK_SO_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_mm7_VASPErrorRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_mm7_VASPErrorRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_mm7_VASPErrorRsp_s* x);
int zx_LEN_WO_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_mm7_VASPErrorRsp_s* x);
char* zx_ENC_SO_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_mm7_VASPErrorRsp_s* x, char* p);
char* zx_ENC_WO_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_mm7_VASPErrorRsp_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_mm7_VASPErrorRsp_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_VASPErrorRsp(struct zx_ctx* c, struct zx_mm7_VASPErrorRsp_s* x);

struct zx_mm7_VASPErrorRsp_s {
  ZX_ELEM_EXT
  zx_mm7_VASPErrorRsp_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_Status_s* Status;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_VASPErrorRsp_GET_MM7Version(struct zx_mm7_VASPErrorRsp_s* x, int n);
struct zx_mm7_Status_s* zx_mm7_VASPErrorRsp_GET_Status(struct zx_mm7_VASPErrorRsp_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_VASPErrorRsp_GET_Extension(struct zx_mm7_VASPErrorRsp_s* x, int n);

int zx_mm7_VASPErrorRsp_NUM_MM7Version(struct zx_mm7_VASPErrorRsp_s* x);
int zx_mm7_VASPErrorRsp_NUM_Status(struct zx_mm7_VASPErrorRsp_s* x);
int zx_mm7_VASPErrorRsp_NUM_Extension(struct zx_mm7_VASPErrorRsp_s* x);

struct zx_elem_s* zx_mm7_VASPErrorRsp_POP_MM7Version(struct zx_mm7_VASPErrorRsp_s* x);
struct zx_mm7_Status_s* zx_mm7_VASPErrorRsp_POP_Status(struct zx_mm7_VASPErrorRsp_s* x);
struct zx_mm7_Extension_s* zx_mm7_VASPErrorRsp_POP_Extension(struct zx_mm7_VASPErrorRsp_s* x);

void zx_mm7_VASPErrorRsp_PUSH_MM7Version(struct zx_mm7_VASPErrorRsp_s* x, struct zx_elem_s* y);
void zx_mm7_VASPErrorRsp_PUSH_Status(struct zx_mm7_VASPErrorRsp_s* x, struct zx_mm7_Status_s* y);
void zx_mm7_VASPErrorRsp_PUSH_Extension(struct zx_mm7_VASPErrorRsp_s* x, struct zx_mm7_Extension_s* y);


void zx_mm7_VASPErrorRsp_PUT_MM7Version(struct zx_mm7_VASPErrorRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_VASPErrorRsp_PUT_Status(struct zx_mm7_VASPErrorRsp_s* x, int n, struct zx_mm7_Status_s* y);
void zx_mm7_VASPErrorRsp_PUT_Extension(struct zx_mm7_VASPErrorRsp_s* x, int n, struct zx_mm7_Extension_s* y);

void zx_mm7_VASPErrorRsp_ADD_MM7Version(struct zx_mm7_VASPErrorRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_VASPErrorRsp_ADD_Status(struct zx_mm7_VASPErrorRsp_s* x, int n, struct zx_mm7_Status_s* z);
void zx_mm7_VASPErrorRsp_ADD_Extension(struct zx_mm7_VASPErrorRsp_s* x, int n, struct zx_mm7_Extension_s* z);

void zx_mm7_VASPErrorRsp_DEL_MM7Version(struct zx_mm7_VASPErrorRsp_s* x, int n);
void zx_mm7_VASPErrorRsp_DEL_Status(struct zx_mm7_VASPErrorRsp_s* x, int n);
void zx_mm7_VASPErrorRsp_DEL_Extension(struct zx_mm7_VASPErrorRsp_s* x, int n);

void zx_mm7_VASPErrorRsp_REV_MM7Version(struct zx_mm7_VASPErrorRsp_s* x);
void zx_mm7_VASPErrorRsp_REV_Status(struct zx_mm7_VASPErrorRsp_s* x);
void zx_mm7_VASPErrorRsp_REV_Extension(struct zx_mm7_VASPErrorRsp_s* x);

#endif
/* -------------------------- mm7_element -------------------------- */
/* refby( zx_mm7_MessageExtraData_s ) */
#ifndef zx_mm7_element_EXT
#define zx_mm7_element_EXT
#endif

struct zx_mm7_element_s* zx_DEC_mm7_element(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_element_s* zx_NEW_mm7_element(struct zx_ctx* c);
void zx_FREE_mm7_element(struct zx_ctx* c, struct zx_mm7_element_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_element_s* zx_DEEP_CLONE_mm7_element(struct zx_ctx* c, struct zx_mm7_element_s* x, int dup_strs);
void zx_DUP_STRS_mm7_element(struct zx_ctx* c, struct zx_mm7_element_s* x);
int zx_WALK_SO_mm7_element(struct zx_ctx* c, struct zx_mm7_element_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_element(struct zx_ctx* c, struct zx_mm7_element_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_element(struct zx_ctx* c, struct zx_mm7_element_s* x);
int zx_LEN_WO_mm7_element(struct zx_ctx* c, struct zx_mm7_element_s* x);
char* zx_ENC_SO_mm7_element(struct zx_ctx* c, struct zx_mm7_element_s* x, char* p);
char* zx_ENC_WO_mm7_element(struct zx_ctx* c, struct zx_mm7_element_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_element(struct zx_ctx* c, struct zx_mm7_element_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_element(struct zx_ctx* c, struct zx_mm7_element_s* x);

struct zx_mm7_element_s {
  ZX_ELEM_EXT
  zx_mm7_element_EXT
  struct zx_elem_s* key;	/* {1,1} xs:string */
  struct zx_elem_s* value;	/* {1,1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_element_GET_key(struct zx_mm7_element_s* x, int n);
struct zx_elem_s* zx_mm7_element_GET_value(struct zx_mm7_element_s* x, int n);

int zx_mm7_element_NUM_key(struct zx_mm7_element_s* x);
int zx_mm7_element_NUM_value(struct zx_mm7_element_s* x);

struct zx_elem_s* zx_mm7_element_POP_key(struct zx_mm7_element_s* x);
struct zx_elem_s* zx_mm7_element_POP_value(struct zx_mm7_element_s* x);

void zx_mm7_element_PUSH_key(struct zx_mm7_element_s* x, struct zx_elem_s* y);
void zx_mm7_element_PUSH_value(struct zx_mm7_element_s* x, struct zx_elem_s* y);


void zx_mm7_element_PUT_key(struct zx_mm7_element_s* x, int n, struct zx_elem_s* y);
void zx_mm7_element_PUT_value(struct zx_mm7_element_s* x, int n, struct zx_elem_s* y);

void zx_mm7_element_ADD_key(struct zx_mm7_element_s* x, int n, struct zx_elem_s* z);
void zx_mm7_element_ADD_value(struct zx_mm7_element_s* x, int n, struct zx_elem_s* z);

void zx_mm7_element_DEL_key(struct zx_mm7_element_s* x, int n);
void zx_mm7_element_DEL_value(struct zx_mm7_element_s* x, int n);

void zx_mm7_element_REV_key(struct zx_mm7_element_s* x);
void zx_mm7_element_REV_value(struct zx_mm7_element_s* x);

#endif
/* -------------------------- mm7_extendedCancelReq -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_extendedCancelReq_EXT
#define zx_mm7_extendedCancelReq_EXT
#endif

struct zx_mm7_extendedCancelReq_s* zx_DEC_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_extendedCancelReq_s* zx_NEW_mm7_extendedCancelReq(struct zx_ctx* c);
void zx_FREE_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_mm7_extendedCancelReq_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_extendedCancelReq_s* zx_DEEP_CLONE_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_mm7_extendedCancelReq_s* x, int dup_strs);
void zx_DUP_STRS_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_mm7_extendedCancelReq_s* x);
int zx_WALK_SO_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_mm7_extendedCancelReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_mm7_extendedCancelReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_mm7_extendedCancelReq_s* x);
int zx_LEN_WO_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_mm7_extendedCancelReq_s* x);
char* zx_ENC_SO_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_mm7_extendedCancelReq_s* x, char* p);
char* zx_ENC_WO_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_mm7_extendedCancelReq_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_mm7_extendedCancelReq_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_extendedCancelReq(struct zx_ctx* c, struct zx_mm7_extendedCancelReq_s* x);

struct zx_mm7_extendedCancelReq_s {
  ZX_ELEM_EXT
  zx_mm7_extendedCancelReq_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_SenderIdentification_s* SenderIdentification;	/* {1,1}  */
  struct zx_mm7_Extension_s* Extension;	/* {0,-1} nada */
  struct zx_elem_s* CancelID;	/* {1,1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_extendedCancelReq_GET_MM7Version(struct zx_mm7_extendedCancelReq_s* x, int n);
struct zx_mm7_SenderIdentification_s* zx_mm7_extendedCancelReq_GET_SenderIdentification(struct zx_mm7_extendedCancelReq_s* x, int n);
struct zx_mm7_Extension_s* zx_mm7_extendedCancelReq_GET_Extension(struct zx_mm7_extendedCancelReq_s* x, int n);
struct zx_elem_s* zx_mm7_extendedCancelReq_GET_CancelID(struct zx_mm7_extendedCancelReq_s* x, int n);

int zx_mm7_extendedCancelReq_NUM_MM7Version(struct zx_mm7_extendedCancelReq_s* x);
int zx_mm7_extendedCancelReq_NUM_SenderIdentification(struct zx_mm7_extendedCancelReq_s* x);
int zx_mm7_extendedCancelReq_NUM_Extension(struct zx_mm7_extendedCancelReq_s* x);
int zx_mm7_extendedCancelReq_NUM_CancelID(struct zx_mm7_extendedCancelReq_s* x);

struct zx_elem_s* zx_mm7_extendedCancelReq_POP_MM7Version(struct zx_mm7_extendedCancelReq_s* x);
struct zx_mm7_SenderIdentification_s* zx_mm7_extendedCancelReq_POP_SenderIdentification(struct zx_mm7_extendedCancelReq_s* x);
struct zx_mm7_Extension_s* zx_mm7_extendedCancelReq_POP_Extension(struct zx_mm7_extendedCancelReq_s* x);
struct zx_elem_s* zx_mm7_extendedCancelReq_POP_CancelID(struct zx_mm7_extendedCancelReq_s* x);

void zx_mm7_extendedCancelReq_PUSH_MM7Version(struct zx_mm7_extendedCancelReq_s* x, struct zx_elem_s* y);
void zx_mm7_extendedCancelReq_PUSH_SenderIdentification(struct zx_mm7_extendedCancelReq_s* x, struct zx_mm7_SenderIdentification_s* y);
void zx_mm7_extendedCancelReq_PUSH_Extension(struct zx_mm7_extendedCancelReq_s* x, struct zx_mm7_Extension_s* y);
void zx_mm7_extendedCancelReq_PUSH_CancelID(struct zx_mm7_extendedCancelReq_s* x, struct zx_elem_s* y);


void zx_mm7_extendedCancelReq_PUT_MM7Version(struct zx_mm7_extendedCancelReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedCancelReq_PUT_SenderIdentification(struct zx_mm7_extendedCancelReq_s* x, int n, struct zx_mm7_SenderIdentification_s* y);
void zx_mm7_extendedCancelReq_PUT_Extension(struct zx_mm7_extendedCancelReq_s* x, int n, struct zx_mm7_Extension_s* y);
void zx_mm7_extendedCancelReq_PUT_CancelID(struct zx_mm7_extendedCancelReq_s* x, int n, struct zx_elem_s* y);

void zx_mm7_extendedCancelReq_ADD_MM7Version(struct zx_mm7_extendedCancelReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedCancelReq_ADD_SenderIdentification(struct zx_mm7_extendedCancelReq_s* x, int n, struct zx_mm7_SenderIdentification_s* z);
void zx_mm7_extendedCancelReq_ADD_Extension(struct zx_mm7_extendedCancelReq_s* x, int n, struct zx_mm7_Extension_s* z);
void zx_mm7_extendedCancelReq_ADD_CancelID(struct zx_mm7_extendedCancelReq_s* x, int n, struct zx_elem_s* z);

void zx_mm7_extendedCancelReq_DEL_MM7Version(struct zx_mm7_extendedCancelReq_s* x, int n);
void zx_mm7_extendedCancelReq_DEL_SenderIdentification(struct zx_mm7_extendedCancelReq_s* x, int n);
void zx_mm7_extendedCancelReq_DEL_Extension(struct zx_mm7_extendedCancelReq_s* x, int n);
void zx_mm7_extendedCancelReq_DEL_CancelID(struct zx_mm7_extendedCancelReq_s* x, int n);

void zx_mm7_extendedCancelReq_REV_MM7Version(struct zx_mm7_extendedCancelReq_s* x);
void zx_mm7_extendedCancelReq_REV_SenderIdentification(struct zx_mm7_extendedCancelReq_s* x);
void zx_mm7_extendedCancelReq_REV_Extension(struct zx_mm7_extendedCancelReq_s* x);
void zx_mm7_extendedCancelReq_REV_CancelID(struct zx_mm7_extendedCancelReq_s* x);

#endif
/* -------------------------- mm7_extendedCancelRsp -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_extendedCancelRsp_EXT
#define zx_mm7_extendedCancelRsp_EXT
#endif

struct zx_mm7_extendedCancelRsp_s* zx_DEC_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_extendedCancelRsp_s* zx_NEW_mm7_extendedCancelRsp(struct zx_ctx* c);
void zx_FREE_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_mm7_extendedCancelRsp_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_extendedCancelRsp_s* zx_DEEP_CLONE_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_mm7_extendedCancelRsp_s* x, int dup_strs);
void zx_DUP_STRS_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_mm7_extendedCancelRsp_s* x);
int zx_WALK_SO_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_mm7_extendedCancelRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_mm7_extendedCancelRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_mm7_extendedCancelRsp_s* x);
int zx_LEN_WO_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_mm7_extendedCancelRsp_s* x);
char* zx_ENC_SO_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_mm7_extendedCancelRsp_s* x, char* p);
char* zx_ENC_WO_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_mm7_extendedCancelRsp_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_mm7_extendedCancelRsp_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_extendedCancelRsp(struct zx_ctx* c, struct zx_mm7_extendedCancelRsp_s* x);

struct zx_mm7_extendedCancelRsp_s {
  ZX_ELEM_EXT
  zx_mm7_extendedCancelRsp_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_mm7_Status_s* Status;	/* {1,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_extendedCancelRsp_GET_MM7Version(struct zx_mm7_extendedCancelRsp_s* x, int n);
struct zx_mm7_Status_s* zx_mm7_extendedCancelRsp_GET_Status(struct zx_mm7_extendedCancelRsp_s* x, int n);

int zx_mm7_extendedCancelRsp_NUM_MM7Version(struct zx_mm7_extendedCancelRsp_s* x);
int zx_mm7_extendedCancelRsp_NUM_Status(struct zx_mm7_extendedCancelRsp_s* x);

struct zx_elem_s* zx_mm7_extendedCancelRsp_POP_MM7Version(struct zx_mm7_extendedCancelRsp_s* x);
struct zx_mm7_Status_s* zx_mm7_extendedCancelRsp_POP_Status(struct zx_mm7_extendedCancelRsp_s* x);

void zx_mm7_extendedCancelRsp_PUSH_MM7Version(struct zx_mm7_extendedCancelRsp_s* x, struct zx_elem_s* y);
void zx_mm7_extendedCancelRsp_PUSH_Status(struct zx_mm7_extendedCancelRsp_s* x, struct zx_mm7_Status_s* y);


void zx_mm7_extendedCancelRsp_PUT_MM7Version(struct zx_mm7_extendedCancelRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedCancelRsp_PUT_Status(struct zx_mm7_extendedCancelRsp_s* x, int n, struct zx_mm7_Status_s* y);

void zx_mm7_extendedCancelRsp_ADD_MM7Version(struct zx_mm7_extendedCancelRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedCancelRsp_ADD_Status(struct zx_mm7_extendedCancelRsp_s* x, int n, struct zx_mm7_Status_s* z);

void zx_mm7_extendedCancelRsp_DEL_MM7Version(struct zx_mm7_extendedCancelRsp_s* x, int n);
void zx_mm7_extendedCancelRsp_DEL_Status(struct zx_mm7_extendedCancelRsp_s* x, int n);

void zx_mm7_extendedCancelRsp_REV_MM7Version(struct zx_mm7_extendedCancelRsp_s* x);
void zx_mm7_extendedCancelRsp_REV_Status(struct zx_mm7_extendedCancelRsp_s* x);

#endif
/* -------------------------- mm7_extendedReplaceReq -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_extendedReplaceReq_EXT
#define zx_mm7_extendedReplaceReq_EXT
#endif

struct zx_mm7_extendedReplaceReq_s* zx_DEC_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_extendedReplaceReq_s* zx_NEW_mm7_extendedReplaceReq(struct zx_ctx* c);
void zx_FREE_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_mm7_extendedReplaceReq_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_extendedReplaceReq_s* zx_DEEP_CLONE_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_mm7_extendedReplaceReq_s* x, int dup_strs);
void zx_DUP_STRS_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_mm7_extendedReplaceReq_s* x);
int zx_WALK_SO_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_mm7_extendedReplaceReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_mm7_extendedReplaceReq_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_mm7_extendedReplaceReq_s* x);
int zx_LEN_WO_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_mm7_extendedReplaceReq_s* x);
char* zx_ENC_SO_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_mm7_extendedReplaceReq_s* x, char* p);
char* zx_ENC_WO_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_mm7_extendedReplaceReq_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_mm7_extendedReplaceReq_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_extendedReplaceReq(struct zx_ctx* c, struct zx_mm7_extendedReplaceReq_s* x);

struct zx_mm7_extendedReplaceReq_s {
  ZX_ELEM_EXT
  zx_mm7_extendedReplaceReq_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_elem_s* VASPID;	/* {0,1} xs:string */
  struct zx_elem_s* VASID;	/* {0,1} xs:string */
  struct zx_mm7_ServiceCode_s* ServiceCode;	/* {0,1}  */
  struct zx_elem_s* ReplaceID;	/* {0,1} xs:string */
  struct zx_elem_s* TimeStamp;	/* {0,1} xs:dateTime */
  struct zx_elem_s* EarliestDeliveryTime;	/* {0,1} xs:string */
  struct zx_elem_s* ExpiryDate;	/* {0,1} xs:string */
  struct zx_elem_s* ReadReply;	/* {0,1} xs:boolean */
  struct zx_elem_s* DeliveryReport;	/* {0,1} xs:boolean */
  struct zx_mm7_Content_s* Content;	/* {0,-1}  */
  struct zx_mm7_AdditionalInformation_s* AdditionalInformation;	/* {0,-1}  */
  struct zx_mm7_MessageExtraData_s* MessageExtraData;	/* {0,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_extendedReplaceReq_GET_MM7Version(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_extendedReplaceReq_GET_VASPID(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_extendedReplaceReq_GET_VASID(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_mm7_ServiceCode_s* zx_mm7_extendedReplaceReq_GET_ServiceCode(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_extendedReplaceReq_GET_ReplaceID(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_extendedReplaceReq_GET_TimeStamp(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_extendedReplaceReq_GET_EarliestDeliveryTime(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_extendedReplaceReq_GET_ExpiryDate(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_extendedReplaceReq_GET_ReadReply(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_elem_s* zx_mm7_extendedReplaceReq_GET_DeliveryReport(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_mm7_Content_s* zx_mm7_extendedReplaceReq_GET_Content(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_mm7_AdditionalInformation_s* zx_mm7_extendedReplaceReq_GET_AdditionalInformation(struct zx_mm7_extendedReplaceReq_s* x, int n);
struct zx_mm7_MessageExtraData_s* zx_mm7_extendedReplaceReq_GET_MessageExtraData(struct zx_mm7_extendedReplaceReq_s* x, int n);

int zx_mm7_extendedReplaceReq_NUM_MM7Version(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_VASPID(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_VASID(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_ServiceCode(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_ReplaceID(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_TimeStamp(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_EarliestDeliveryTime(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_ExpiryDate(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_ReadReply(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_DeliveryReport(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_Content(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_AdditionalInformation(struct zx_mm7_extendedReplaceReq_s* x);
int zx_mm7_extendedReplaceReq_NUM_MessageExtraData(struct zx_mm7_extendedReplaceReq_s* x);

struct zx_elem_s* zx_mm7_extendedReplaceReq_POP_MM7Version(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_elem_s* zx_mm7_extendedReplaceReq_POP_VASPID(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_elem_s* zx_mm7_extendedReplaceReq_POP_VASID(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_mm7_ServiceCode_s* zx_mm7_extendedReplaceReq_POP_ServiceCode(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_elem_s* zx_mm7_extendedReplaceReq_POP_ReplaceID(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_elem_s* zx_mm7_extendedReplaceReq_POP_TimeStamp(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_elem_s* zx_mm7_extendedReplaceReq_POP_EarliestDeliveryTime(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_elem_s* zx_mm7_extendedReplaceReq_POP_ExpiryDate(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_elem_s* zx_mm7_extendedReplaceReq_POP_ReadReply(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_elem_s* zx_mm7_extendedReplaceReq_POP_DeliveryReport(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_mm7_Content_s* zx_mm7_extendedReplaceReq_POP_Content(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_mm7_AdditionalInformation_s* zx_mm7_extendedReplaceReq_POP_AdditionalInformation(struct zx_mm7_extendedReplaceReq_s* x);
struct zx_mm7_MessageExtraData_s* zx_mm7_extendedReplaceReq_POP_MessageExtraData(struct zx_mm7_extendedReplaceReq_s* x);

void zx_mm7_extendedReplaceReq_PUSH_MM7Version(struct zx_mm7_extendedReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUSH_VASPID(struct zx_mm7_extendedReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUSH_VASID(struct zx_mm7_extendedReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUSH_ServiceCode(struct zx_mm7_extendedReplaceReq_s* x, struct zx_mm7_ServiceCode_s* y);
void zx_mm7_extendedReplaceReq_PUSH_ReplaceID(struct zx_mm7_extendedReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUSH_TimeStamp(struct zx_mm7_extendedReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUSH_EarliestDeliveryTime(struct zx_mm7_extendedReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUSH_ExpiryDate(struct zx_mm7_extendedReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUSH_ReadReply(struct zx_mm7_extendedReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUSH_DeliveryReport(struct zx_mm7_extendedReplaceReq_s* x, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUSH_Content(struct zx_mm7_extendedReplaceReq_s* x, struct zx_mm7_Content_s* y);
void zx_mm7_extendedReplaceReq_PUSH_AdditionalInformation(struct zx_mm7_extendedReplaceReq_s* x, struct zx_mm7_AdditionalInformation_s* y);
void zx_mm7_extendedReplaceReq_PUSH_MessageExtraData(struct zx_mm7_extendedReplaceReq_s* x, struct zx_mm7_MessageExtraData_s* y);


void zx_mm7_extendedReplaceReq_PUT_MM7Version(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUT_VASPID(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUT_VASID(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUT_ServiceCode(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_mm7_ServiceCode_s* y);
void zx_mm7_extendedReplaceReq_PUT_ReplaceID(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUT_TimeStamp(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUT_EarliestDeliveryTime(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUT_ExpiryDate(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUT_ReadReply(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUT_DeliveryReport(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedReplaceReq_PUT_Content(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_mm7_Content_s* y);
void zx_mm7_extendedReplaceReq_PUT_AdditionalInformation(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_mm7_AdditionalInformation_s* y);
void zx_mm7_extendedReplaceReq_PUT_MessageExtraData(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_mm7_MessageExtraData_s* y);

void zx_mm7_extendedReplaceReq_ADD_MM7Version(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedReplaceReq_ADD_VASPID(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedReplaceReq_ADD_VASID(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedReplaceReq_ADD_ServiceCode(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_mm7_ServiceCode_s* z);
void zx_mm7_extendedReplaceReq_ADD_ReplaceID(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedReplaceReq_ADD_TimeStamp(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedReplaceReq_ADD_EarliestDeliveryTime(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedReplaceReq_ADD_ExpiryDate(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedReplaceReq_ADD_ReadReply(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedReplaceReq_ADD_DeliveryReport(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedReplaceReq_ADD_Content(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_mm7_Content_s* z);
void zx_mm7_extendedReplaceReq_ADD_AdditionalInformation(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_mm7_AdditionalInformation_s* z);
void zx_mm7_extendedReplaceReq_ADD_MessageExtraData(struct zx_mm7_extendedReplaceReq_s* x, int n, struct zx_mm7_MessageExtraData_s* z);

void zx_mm7_extendedReplaceReq_DEL_MM7Version(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_VASPID(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_VASID(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_ServiceCode(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_ReplaceID(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_TimeStamp(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_EarliestDeliveryTime(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_ExpiryDate(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_ReadReply(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_DeliveryReport(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_Content(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_AdditionalInformation(struct zx_mm7_extendedReplaceReq_s* x, int n);
void zx_mm7_extendedReplaceReq_DEL_MessageExtraData(struct zx_mm7_extendedReplaceReq_s* x, int n);

void zx_mm7_extendedReplaceReq_REV_MM7Version(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_VASPID(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_VASID(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_ServiceCode(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_ReplaceID(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_TimeStamp(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_EarliestDeliveryTime(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_ExpiryDate(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_ReadReply(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_DeliveryReport(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_Content(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_AdditionalInformation(struct zx_mm7_extendedReplaceReq_s* x);
void zx_mm7_extendedReplaceReq_REV_MessageExtraData(struct zx_mm7_extendedReplaceReq_s* x);

#endif
/* -------------------------- mm7_extendedReplaceRsp -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_mm7_extendedReplaceRsp_EXT
#define zx_mm7_extendedReplaceRsp_EXT
#endif

struct zx_mm7_extendedReplaceRsp_s* zx_DEC_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_mm7_extendedReplaceRsp_s* zx_NEW_mm7_extendedReplaceRsp(struct zx_ctx* c);
void zx_FREE_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_mm7_extendedReplaceRsp_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_mm7_extendedReplaceRsp_s* zx_DEEP_CLONE_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_mm7_extendedReplaceRsp_s* x, int dup_strs);
void zx_DUP_STRS_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_mm7_extendedReplaceRsp_s* x);
int zx_WALK_SO_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_mm7_extendedReplaceRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_mm7_extendedReplaceRsp_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_mm7_extendedReplaceRsp_s* x);
int zx_LEN_WO_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_mm7_extendedReplaceRsp_s* x);
char* zx_ENC_SO_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_mm7_extendedReplaceRsp_s* x, char* p);
char* zx_ENC_WO_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_mm7_extendedReplaceRsp_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_mm7_extendedReplaceRsp_s* x);
struct zx_str* zx_EASY_ENC_WO_mm7_extendedReplaceRsp(struct zx_ctx* c, struct zx_mm7_extendedReplaceRsp_s* x);

struct zx_mm7_extendedReplaceRsp_s {
  ZX_ELEM_EXT
  zx_mm7_extendedReplaceRsp_EXT
  struct zx_elem_s* MM7Version;	/* {1,1} 6.8.0 */
  struct zx_elem_s* MessageID;	/* {1,1} xs:string */
  struct zx_mm7_Status_s* Status;	/* {1,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_mm7_extendedReplaceRsp_GET_MM7Version(struct zx_mm7_extendedReplaceRsp_s* x, int n);
struct zx_elem_s* zx_mm7_extendedReplaceRsp_GET_MessageID(struct zx_mm7_extendedReplaceRsp_s* x, int n);
struct zx_mm7_Status_s* zx_mm7_extendedReplaceRsp_GET_Status(struct zx_mm7_extendedReplaceRsp_s* x, int n);

int zx_mm7_extendedReplaceRsp_NUM_MM7Version(struct zx_mm7_extendedReplaceRsp_s* x);
int zx_mm7_extendedReplaceRsp_NUM_MessageID(struct zx_mm7_extendedReplaceRsp_s* x);
int zx_mm7_extendedReplaceRsp_NUM_Status(struct zx_mm7_extendedReplaceRsp_s* x);

struct zx_elem_s* zx_mm7_extendedReplaceRsp_POP_MM7Version(struct zx_mm7_extendedReplaceRsp_s* x);
struct zx_elem_s* zx_mm7_extendedReplaceRsp_POP_MessageID(struct zx_mm7_extendedReplaceRsp_s* x);
struct zx_mm7_Status_s* zx_mm7_extendedReplaceRsp_POP_Status(struct zx_mm7_extendedReplaceRsp_s* x);

void zx_mm7_extendedReplaceRsp_PUSH_MM7Version(struct zx_mm7_extendedReplaceRsp_s* x, struct zx_elem_s* y);
void zx_mm7_extendedReplaceRsp_PUSH_MessageID(struct zx_mm7_extendedReplaceRsp_s* x, struct zx_elem_s* y);
void zx_mm7_extendedReplaceRsp_PUSH_Status(struct zx_mm7_extendedReplaceRsp_s* x, struct zx_mm7_Status_s* y);


void zx_mm7_extendedReplaceRsp_PUT_MM7Version(struct zx_mm7_extendedReplaceRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedReplaceRsp_PUT_MessageID(struct zx_mm7_extendedReplaceRsp_s* x, int n, struct zx_elem_s* y);
void zx_mm7_extendedReplaceRsp_PUT_Status(struct zx_mm7_extendedReplaceRsp_s* x, int n, struct zx_mm7_Status_s* y);

void zx_mm7_extendedReplaceRsp_ADD_MM7Version(struct zx_mm7_extendedReplaceRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedReplaceRsp_ADD_MessageID(struct zx_mm7_extendedReplaceRsp_s* x, int n, struct zx_elem_s* z);
void zx_mm7_extendedReplaceRsp_ADD_Status(struct zx_mm7_extendedReplaceRsp_s* x, int n, struct zx_mm7_Status_s* z);

void zx_mm7_extendedReplaceRsp_DEL_MM7Version(struct zx_mm7_extendedReplaceRsp_s* x, int n);
void zx_mm7_extendedReplaceRsp_DEL_MessageID(struct zx_mm7_extendedReplaceRsp_s* x, int n);
void zx_mm7_extendedReplaceRsp_DEL_Status(struct zx_mm7_extendedReplaceRsp_s* x, int n);

void zx_mm7_extendedReplaceRsp_REV_MM7Version(struct zx_mm7_extendedReplaceRsp_s* x);
void zx_mm7_extendedReplaceRsp_REV_MessageID(struct zx_mm7_extendedReplaceRsp_s* x);
void zx_mm7_extendedReplaceRsp_REV_Status(struct zx_mm7_extendedReplaceRsp_s* x);

#endif

#endif
