/* c/zx-ecp-data.h - WARNING: This header was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Datastructure design, topography, and layout
 * Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for
 * terms and conditions of use. Element and attributes names as well
 * as some topography are derived from schema descriptions that were used as
 * input and may be subject to their own copright. */

#ifndef _c_zx_ecp_data_h
#define _c_zx_ecp_data_h

#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"

#ifndef ZX_ELEM_EXT
#define ZX_ELEM_EXT  /* This extension point should be defined by who includes this file. */
#endif

/* -------------------------- ecp_RelayState -------------------------- */
/* refby( zx_e_Header_s ) */
#ifndef zx_ecp_RelayState_EXT
#define zx_ecp_RelayState_EXT
#endif

struct zx_ecp_RelayState_s* zx_DEC_ecp_RelayState(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ecp_RelayState_s* zx_NEW_ecp_RelayState(struct zx_ctx* c);
void zx_FREE_ecp_RelayState(struct zx_ctx* c, struct zx_ecp_RelayState_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ecp_RelayState_s* zx_DEEP_CLONE_ecp_RelayState(struct zx_ctx* c, struct zx_ecp_RelayState_s* x, int dup_strs);
void zx_DUP_STRS_ecp_RelayState(struct zx_ctx* c, struct zx_ecp_RelayState_s* x);
int zx_WALK_SO_ecp_RelayState(struct zx_ctx* c, struct zx_ecp_RelayState_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ecp_RelayState(struct zx_ctx* c, struct zx_ecp_RelayState_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ecp_RelayState(struct zx_ctx* c, struct zx_ecp_RelayState_s* x);
int zx_LEN_WO_ecp_RelayState(struct zx_ctx* c, struct zx_ecp_RelayState_s* x);
char* zx_ENC_SO_ecp_RelayState(struct zx_ctx* c, struct zx_ecp_RelayState_s* x, char* p);
char* zx_ENC_WO_ecp_RelayState(struct zx_ctx* c, struct zx_ecp_RelayState_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ecp_RelayState(struct zx_ctx* c, struct zx_ecp_RelayState_s* x);
struct zx_str* zx_EASY_ENC_WO_ecp_RelayState(struct zx_ctx* c, struct zx_ecp_RelayState_s* x);

struct zx_ecp_RelayState_s {
  ZX_ELEM_EXT
  zx_ecp_RelayState_EXT
  struct zx_str* actor;	/* {1,1} attribute xs:anyURI */
  struct zx_str* mustUnderstand;	/* {1,1} attribute xs:boolean */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ecp_RelayState_GET_actor(struct zx_ecp_RelayState_s* x);
struct zx_str* zx_ecp_RelayState_GET_mustUnderstand(struct zx_ecp_RelayState_s* x);





void zx_ecp_RelayState_PUT_actor(struct zx_ecp_RelayState_s* x, struct zx_str* y);
void zx_ecp_RelayState_PUT_mustUnderstand(struct zx_ecp_RelayState_s* x, struct zx_str* y);





#endif
/* -------------------------- ecp_Request -------------------------- */
/* refby( zx_e_Header_s ) */
#ifndef zx_ecp_Request_EXT
#define zx_ecp_Request_EXT
#endif

struct zx_ecp_Request_s* zx_DEC_ecp_Request(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ecp_Request_s* zx_NEW_ecp_Request(struct zx_ctx* c);
void zx_FREE_ecp_Request(struct zx_ctx* c, struct zx_ecp_Request_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ecp_Request_s* zx_DEEP_CLONE_ecp_Request(struct zx_ctx* c, struct zx_ecp_Request_s* x, int dup_strs);
void zx_DUP_STRS_ecp_Request(struct zx_ctx* c, struct zx_ecp_Request_s* x);
int zx_WALK_SO_ecp_Request(struct zx_ctx* c, struct zx_ecp_Request_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ecp_Request(struct zx_ctx* c, struct zx_ecp_Request_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ecp_Request(struct zx_ctx* c, struct zx_ecp_Request_s* x);
int zx_LEN_WO_ecp_Request(struct zx_ctx* c, struct zx_ecp_Request_s* x);
char* zx_ENC_SO_ecp_Request(struct zx_ctx* c, struct zx_ecp_Request_s* x, char* p);
char* zx_ENC_WO_ecp_Request(struct zx_ctx* c, struct zx_ecp_Request_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ecp_Request(struct zx_ctx* c, struct zx_ecp_Request_s* x);
struct zx_str* zx_EASY_ENC_WO_ecp_Request(struct zx_ctx* c, struct zx_ecp_Request_s* x);

struct zx_ecp_Request_s {
  ZX_ELEM_EXT
  zx_ecp_Request_EXT
  struct zx_sa_Issuer_s* Issuer;	/* {1,1} nada */
  struct zx_sp_IDPList_s* IDPList;	/* {0,1} nada */
  struct zx_str* IsPassive;	/* {0,1} attribute xs:boolean */
  struct zx_str* ProviderName;	/* {0,1} attribute xs:string */
  struct zx_str* actor;	/* {1,1} attribute xs:anyURI */
  struct zx_str* mustUnderstand;	/* {1,1} attribute xs:boolean */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ecp_Request_GET_IsPassive(struct zx_ecp_Request_s* x);
struct zx_str* zx_ecp_Request_GET_ProviderName(struct zx_ecp_Request_s* x);
struct zx_str* zx_ecp_Request_GET_actor(struct zx_ecp_Request_s* x);
struct zx_str* zx_ecp_Request_GET_mustUnderstand(struct zx_ecp_Request_s* x);

struct zx_sa_Issuer_s* zx_ecp_Request_GET_Issuer(struct zx_ecp_Request_s* x, int n);
struct zx_sp_IDPList_s* zx_ecp_Request_GET_IDPList(struct zx_ecp_Request_s* x, int n);

int zx_ecp_Request_NUM_Issuer(struct zx_ecp_Request_s* x);
int zx_ecp_Request_NUM_IDPList(struct zx_ecp_Request_s* x);

struct zx_sa_Issuer_s* zx_ecp_Request_POP_Issuer(struct zx_ecp_Request_s* x);
struct zx_sp_IDPList_s* zx_ecp_Request_POP_IDPList(struct zx_ecp_Request_s* x);

void zx_ecp_Request_PUSH_Issuer(struct zx_ecp_Request_s* x, struct zx_sa_Issuer_s* y);
void zx_ecp_Request_PUSH_IDPList(struct zx_ecp_Request_s* x, struct zx_sp_IDPList_s* y);

void zx_ecp_Request_PUT_IsPassive(struct zx_ecp_Request_s* x, struct zx_str* y);
void zx_ecp_Request_PUT_ProviderName(struct zx_ecp_Request_s* x, struct zx_str* y);
void zx_ecp_Request_PUT_actor(struct zx_ecp_Request_s* x, struct zx_str* y);
void zx_ecp_Request_PUT_mustUnderstand(struct zx_ecp_Request_s* x, struct zx_str* y);

void zx_ecp_Request_PUT_Issuer(struct zx_ecp_Request_s* x, int n, struct zx_sa_Issuer_s* y);
void zx_ecp_Request_PUT_IDPList(struct zx_ecp_Request_s* x, int n, struct zx_sp_IDPList_s* y);

void zx_ecp_Request_ADD_Issuer(struct zx_ecp_Request_s* x, int n, struct zx_sa_Issuer_s* z);
void zx_ecp_Request_ADD_IDPList(struct zx_ecp_Request_s* x, int n, struct zx_sp_IDPList_s* z);

void zx_ecp_Request_DEL_Issuer(struct zx_ecp_Request_s* x, int n);
void zx_ecp_Request_DEL_IDPList(struct zx_ecp_Request_s* x, int n);

void zx_ecp_Request_REV_Issuer(struct zx_ecp_Request_s* x);
void zx_ecp_Request_REV_IDPList(struct zx_ecp_Request_s* x);

#endif
/* -------------------------- ecp_Response -------------------------- */
/* refby( zx_e_Header_s ) */
#ifndef zx_ecp_Response_EXT
#define zx_ecp_Response_EXT
#endif

struct zx_ecp_Response_s* zx_DEC_ecp_Response(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ecp_Response_s* zx_NEW_ecp_Response(struct zx_ctx* c);
void zx_FREE_ecp_Response(struct zx_ctx* c, struct zx_ecp_Response_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ecp_Response_s* zx_DEEP_CLONE_ecp_Response(struct zx_ctx* c, struct zx_ecp_Response_s* x, int dup_strs);
void zx_DUP_STRS_ecp_Response(struct zx_ctx* c, struct zx_ecp_Response_s* x);
int zx_WALK_SO_ecp_Response(struct zx_ctx* c, struct zx_ecp_Response_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ecp_Response(struct zx_ctx* c, struct zx_ecp_Response_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ecp_Response(struct zx_ctx* c, struct zx_ecp_Response_s* x);
int zx_LEN_WO_ecp_Response(struct zx_ctx* c, struct zx_ecp_Response_s* x);
char* zx_ENC_SO_ecp_Response(struct zx_ctx* c, struct zx_ecp_Response_s* x, char* p);
char* zx_ENC_WO_ecp_Response(struct zx_ctx* c, struct zx_ecp_Response_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ecp_Response(struct zx_ctx* c, struct zx_ecp_Response_s* x);
struct zx_str* zx_EASY_ENC_WO_ecp_Response(struct zx_ctx* c, struct zx_ecp_Response_s* x);

struct zx_ecp_Response_s {
  ZX_ELEM_EXT
  zx_ecp_Response_EXT
  struct zx_str* AssertionConsumerServiceURL;	/* {1,1} attribute xs:anyURI */
  struct zx_str* actor;	/* {1,1} attribute xs:anyURI */
  struct zx_str* mustUnderstand;	/* {1,1} attribute xs:boolean */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ecp_Response_GET_AssertionConsumerServiceURL(struct zx_ecp_Response_s* x);
struct zx_str* zx_ecp_Response_GET_actor(struct zx_ecp_Response_s* x);
struct zx_str* zx_ecp_Response_GET_mustUnderstand(struct zx_ecp_Response_s* x);





void zx_ecp_Response_PUT_AssertionConsumerServiceURL(struct zx_ecp_Response_s* x, struct zx_str* y);
void zx_ecp_Response_PUT_actor(struct zx_ecp_Response_s* x, struct zx_str* y);
void zx_ecp_Response_PUT_mustUnderstand(struct zx_ecp_Response_s* x, struct zx_str* y);





#endif

#endif
