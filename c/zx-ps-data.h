/* c/zx-ps-data.h - WARNING: This header was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Datastructure design, topography, and layout
 * Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for
 * terms and conditions of use. Element and attributes names as well
 * as some topography are derived from schema descriptions that were used as
 * input and may be subject to their own copright. */

#ifndef _c_zx_ps_data_h
#define _c_zx_ps_data_h

#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"

#ifndef ZX_ELEM_EXT
#define ZX_ELEM_EXT  /* This extension point should be defined by who includes this file. */
#endif

/* -------------------------- ps_AddCollectionRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_AddCollectionRequest_EXT
#define zx_ps_AddCollectionRequest_EXT
#endif

struct zx_ps_AddCollectionRequest_s* zx_DEC_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_AddCollectionRequest_s* zx_NEW_ps_AddCollectionRequest(struct zx_ctx* c);
void zx_FREE_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ps_AddCollectionRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_AddCollectionRequest_s* zx_DEEP_CLONE_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ps_AddCollectionRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ps_AddCollectionRequest_s* x);
int zx_WALK_SO_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ps_AddCollectionRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ps_AddCollectionRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ps_AddCollectionRequest_s* x);
int zx_LEN_WO_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ps_AddCollectionRequest_s* x);
char* zx_ENC_SO_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ps_AddCollectionRequest_s* x, char* p);
char* zx_ENC_WO_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ps_AddCollectionRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ps_AddCollectionRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_AddCollectionRequest(struct zx_ctx* c, struct zx_ps_AddCollectionRequest_s* x);

struct zx_ps_AddCollectionRequest_s {
  ZX_ELEM_EXT
  zx_ps_AddCollectionRequest_EXT
  struct zx_ps_Object_s* Object;	/* {1,1} nada */
  struct zx_ps_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_AddCollectionRequest_GET_id(struct zx_ps_AddCollectionRequest_s* x);

struct zx_ps_Object_s* zx_ps_AddCollectionRequest_GET_Object(struct zx_ps_AddCollectionRequest_s* x, int n);
struct zx_ps_Subscription_s* zx_ps_AddCollectionRequest_GET_Subscription(struct zx_ps_AddCollectionRequest_s* x, int n);

int zx_ps_AddCollectionRequest_NUM_Object(struct zx_ps_AddCollectionRequest_s* x);
int zx_ps_AddCollectionRequest_NUM_Subscription(struct zx_ps_AddCollectionRequest_s* x);

struct zx_ps_Object_s* zx_ps_AddCollectionRequest_POP_Object(struct zx_ps_AddCollectionRequest_s* x);
struct zx_ps_Subscription_s* zx_ps_AddCollectionRequest_POP_Subscription(struct zx_ps_AddCollectionRequest_s* x);

void zx_ps_AddCollectionRequest_PUSH_Object(struct zx_ps_AddCollectionRequest_s* x, struct zx_ps_Object_s* y);
void zx_ps_AddCollectionRequest_PUSH_Subscription(struct zx_ps_AddCollectionRequest_s* x, struct zx_ps_Subscription_s* y);

void zx_ps_AddCollectionRequest_PUT_id(struct zx_ps_AddCollectionRequest_s* x, struct zx_str* y);

void zx_ps_AddCollectionRequest_PUT_Object(struct zx_ps_AddCollectionRequest_s* x, int n, struct zx_ps_Object_s* y);
void zx_ps_AddCollectionRequest_PUT_Subscription(struct zx_ps_AddCollectionRequest_s* x, int n, struct zx_ps_Subscription_s* y);

void zx_ps_AddCollectionRequest_ADD_Object(struct zx_ps_AddCollectionRequest_s* x, int n, struct zx_ps_Object_s* z);
void zx_ps_AddCollectionRequest_ADD_Subscription(struct zx_ps_AddCollectionRequest_s* x, int n, struct zx_ps_Subscription_s* z);

void zx_ps_AddCollectionRequest_DEL_Object(struct zx_ps_AddCollectionRequest_s* x, int n);
void zx_ps_AddCollectionRequest_DEL_Subscription(struct zx_ps_AddCollectionRequest_s* x, int n);

void zx_ps_AddCollectionRequest_REV_Object(struct zx_ps_AddCollectionRequest_s* x);
void zx_ps_AddCollectionRequest_REV_Subscription(struct zx_ps_AddCollectionRequest_s* x);

#endif
/* -------------------------- ps_AddCollectionResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_AddCollectionResponse_EXT
#define zx_ps_AddCollectionResponse_EXT
#endif

struct zx_ps_AddCollectionResponse_s* zx_DEC_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_AddCollectionResponse_s* zx_NEW_ps_AddCollectionResponse(struct zx_ctx* c);
void zx_FREE_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ps_AddCollectionResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_AddCollectionResponse_s* zx_DEEP_CLONE_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ps_AddCollectionResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ps_AddCollectionResponse_s* x);
int zx_WALK_SO_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ps_AddCollectionResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ps_AddCollectionResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ps_AddCollectionResponse_s* x);
int zx_LEN_WO_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ps_AddCollectionResponse_s* x);
char* zx_ENC_SO_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ps_AddCollectionResponse_s* x, char* p);
char* zx_ENC_WO_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ps_AddCollectionResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ps_AddCollectionResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_AddCollectionResponse(struct zx_ctx* c, struct zx_ps_AddCollectionResponse_s* x);

struct zx_ps_AddCollectionResponse_s {
  ZX_ELEM_EXT
  zx_ps_AddCollectionResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_ps_Object_s* Object;	/* {0,1} nada */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_AddCollectionResponse_GET_TimeStamp(struct zx_ps_AddCollectionResponse_s* x);
struct zx_str* zx_ps_AddCollectionResponse_GET_id(struct zx_ps_AddCollectionResponse_s* x);

struct zx_lu_Status_s* zx_ps_AddCollectionResponse_GET_Status(struct zx_ps_AddCollectionResponse_s* x, int n);
struct zx_ps_Object_s* zx_ps_AddCollectionResponse_GET_Object(struct zx_ps_AddCollectionResponse_s* x, int n);

int zx_ps_AddCollectionResponse_NUM_Status(struct zx_ps_AddCollectionResponse_s* x);
int zx_ps_AddCollectionResponse_NUM_Object(struct zx_ps_AddCollectionResponse_s* x);

struct zx_lu_Status_s* zx_ps_AddCollectionResponse_POP_Status(struct zx_ps_AddCollectionResponse_s* x);
struct zx_ps_Object_s* zx_ps_AddCollectionResponse_POP_Object(struct zx_ps_AddCollectionResponse_s* x);

void zx_ps_AddCollectionResponse_PUSH_Status(struct zx_ps_AddCollectionResponse_s* x, struct zx_lu_Status_s* y);
void zx_ps_AddCollectionResponse_PUSH_Object(struct zx_ps_AddCollectionResponse_s* x, struct zx_ps_Object_s* y);

void zx_ps_AddCollectionResponse_PUT_TimeStamp(struct zx_ps_AddCollectionResponse_s* x, struct zx_str* y);
void zx_ps_AddCollectionResponse_PUT_id(struct zx_ps_AddCollectionResponse_s* x, struct zx_str* y);

void zx_ps_AddCollectionResponse_PUT_Status(struct zx_ps_AddCollectionResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_ps_AddCollectionResponse_PUT_Object(struct zx_ps_AddCollectionResponse_s* x, int n, struct zx_ps_Object_s* y);

void zx_ps_AddCollectionResponse_ADD_Status(struct zx_ps_AddCollectionResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_ps_AddCollectionResponse_ADD_Object(struct zx_ps_AddCollectionResponse_s* x, int n, struct zx_ps_Object_s* z);

void zx_ps_AddCollectionResponse_DEL_Status(struct zx_ps_AddCollectionResponse_s* x, int n);
void zx_ps_AddCollectionResponse_DEL_Object(struct zx_ps_AddCollectionResponse_s* x, int n);

void zx_ps_AddCollectionResponse_REV_Status(struct zx_ps_AddCollectionResponse_s* x);
void zx_ps_AddCollectionResponse_REV_Object(struct zx_ps_AddCollectionResponse_s* x);

#endif
/* -------------------------- ps_AddEntityRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_AddEntityRequest_EXT
#define zx_ps_AddEntityRequest_EXT
#endif

struct zx_ps_AddEntityRequest_s* zx_DEC_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_AddEntityRequest_s* zx_NEW_ps_AddEntityRequest(struct zx_ctx* c);
void zx_FREE_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ps_AddEntityRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_AddEntityRequest_s* zx_DEEP_CLONE_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ps_AddEntityRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ps_AddEntityRequest_s* x);
int zx_WALK_SO_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ps_AddEntityRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ps_AddEntityRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ps_AddEntityRequest_s* x);
int zx_LEN_WO_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ps_AddEntityRequest_s* x);
char* zx_ENC_SO_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ps_AddEntityRequest_s* x, char* p);
char* zx_ENC_WO_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ps_AddEntityRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ps_AddEntityRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_AddEntityRequest(struct zx_ctx* c, struct zx_ps_AddEntityRequest_s* x);

struct zx_ps_AddEntityRequest_s {
  ZX_ELEM_EXT
  zx_ps_AddEntityRequest_EXT
  struct zx_ps_Object_s* Object;	/* {1,1} nada */
  struct zx_elem_s* PStoSPRedirectURL;	/* {0,1} xs:anyURI */
  struct zx_ps_CreatePSObject_s* CreatePSObject;	/* {0,1} nada */
  struct zx_ps_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_sec_TokenPolicy_s* TokenPolicy;	/* {0,1} nada */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_AddEntityRequest_GET_id(struct zx_ps_AddEntityRequest_s* x);

struct zx_ps_Object_s* zx_ps_AddEntityRequest_GET_Object(struct zx_ps_AddEntityRequest_s* x, int n);
struct zx_elem_s* zx_ps_AddEntityRequest_GET_PStoSPRedirectURL(struct zx_ps_AddEntityRequest_s* x, int n);
struct zx_ps_CreatePSObject_s* zx_ps_AddEntityRequest_GET_CreatePSObject(struct zx_ps_AddEntityRequest_s* x, int n);
struct zx_ps_Subscription_s* zx_ps_AddEntityRequest_GET_Subscription(struct zx_ps_AddEntityRequest_s* x, int n);
struct zx_sec_TokenPolicy_s* zx_ps_AddEntityRequest_GET_TokenPolicy(struct zx_ps_AddEntityRequest_s* x, int n);

int zx_ps_AddEntityRequest_NUM_Object(struct zx_ps_AddEntityRequest_s* x);
int zx_ps_AddEntityRequest_NUM_PStoSPRedirectURL(struct zx_ps_AddEntityRequest_s* x);
int zx_ps_AddEntityRequest_NUM_CreatePSObject(struct zx_ps_AddEntityRequest_s* x);
int zx_ps_AddEntityRequest_NUM_Subscription(struct zx_ps_AddEntityRequest_s* x);
int zx_ps_AddEntityRequest_NUM_TokenPolicy(struct zx_ps_AddEntityRequest_s* x);

struct zx_ps_Object_s* zx_ps_AddEntityRequest_POP_Object(struct zx_ps_AddEntityRequest_s* x);
struct zx_elem_s* zx_ps_AddEntityRequest_POP_PStoSPRedirectURL(struct zx_ps_AddEntityRequest_s* x);
struct zx_ps_CreatePSObject_s* zx_ps_AddEntityRequest_POP_CreatePSObject(struct zx_ps_AddEntityRequest_s* x);
struct zx_ps_Subscription_s* zx_ps_AddEntityRequest_POP_Subscription(struct zx_ps_AddEntityRequest_s* x);
struct zx_sec_TokenPolicy_s* zx_ps_AddEntityRequest_POP_TokenPolicy(struct zx_ps_AddEntityRequest_s* x);

void zx_ps_AddEntityRequest_PUSH_Object(struct zx_ps_AddEntityRequest_s* x, struct zx_ps_Object_s* y);
void zx_ps_AddEntityRequest_PUSH_PStoSPRedirectURL(struct zx_ps_AddEntityRequest_s* x, struct zx_elem_s* y);
void zx_ps_AddEntityRequest_PUSH_CreatePSObject(struct zx_ps_AddEntityRequest_s* x, struct zx_ps_CreatePSObject_s* y);
void zx_ps_AddEntityRequest_PUSH_Subscription(struct zx_ps_AddEntityRequest_s* x, struct zx_ps_Subscription_s* y);
void zx_ps_AddEntityRequest_PUSH_TokenPolicy(struct zx_ps_AddEntityRequest_s* x, struct zx_sec_TokenPolicy_s* y);

void zx_ps_AddEntityRequest_PUT_id(struct zx_ps_AddEntityRequest_s* x, struct zx_str* y);

void zx_ps_AddEntityRequest_PUT_Object(struct zx_ps_AddEntityRequest_s* x, int n, struct zx_ps_Object_s* y);
void zx_ps_AddEntityRequest_PUT_PStoSPRedirectURL(struct zx_ps_AddEntityRequest_s* x, int n, struct zx_elem_s* y);
void zx_ps_AddEntityRequest_PUT_CreatePSObject(struct zx_ps_AddEntityRequest_s* x, int n, struct zx_ps_CreatePSObject_s* y);
void zx_ps_AddEntityRequest_PUT_Subscription(struct zx_ps_AddEntityRequest_s* x, int n, struct zx_ps_Subscription_s* y);
void zx_ps_AddEntityRequest_PUT_TokenPolicy(struct zx_ps_AddEntityRequest_s* x, int n, struct zx_sec_TokenPolicy_s* y);

void zx_ps_AddEntityRequest_ADD_Object(struct zx_ps_AddEntityRequest_s* x, int n, struct zx_ps_Object_s* z);
void zx_ps_AddEntityRequest_ADD_PStoSPRedirectURL(struct zx_ps_AddEntityRequest_s* x, int n, struct zx_elem_s* z);
void zx_ps_AddEntityRequest_ADD_CreatePSObject(struct zx_ps_AddEntityRequest_s* x, int n, struct zx_ps_CreatePSObject_s* z);
void zx_ps_AddEntityRequest_ADD_Subscription(struct zx_ps_AddEntityRequest_s* x, int n, struct zx_ps_Subscription_s* z);
void zx_ps_AddEntityRequest_ADD_TokenPolicy(struct zx_ps_AddEntityRequest_s* x, int n, struct zx_sec_TokenPolicy_s* z);

void zx_ps_AddEntityRequest_DEL_Object(struct zx_ps_AddEntityRequest_s* x, int n);
void zx_ps_AddEntityRequest_DEL_PStoSPRedirectURL(struct zx_ps_AddEntityRequest_s* x, int n);
void zx_ps_AddEntityRequest_DEL_CreatePSObject(struct zx_ps_AddEntityRequest_s* x, int n);
void zx_ps_AddEntityRequest_DEL_Subscription(struct zx_ps_AddEntityRequest_s* x, int n);
void zx_ps_AddEntityRequest_DEL_TokenPolicy(struct zx_ps_AddEntityRequest_s* x, int n);

void zx_ps_AddEntityRequest_REV_Object(struct zx_ps_AddEntityRequest_s* x);
void zx_ps_AddEntityRequest_REV_PStoSPRedirectURL(struct zx_ps_AddEntityRequest_s* x);
void zx_ps_AddEntityRequest_REV_CreatePSObject(struct zx_ps_AddEntityRequest_s* x);
void zx_ps_AddEntityRequest_REV_Subscription(struct zx_ps_AddEntityRequest_s* x);
void zx_ps_AddEntityRequest_REV_TokenPolicy(struct zx_ps_AddEntityRequest_s* x);

#endif
/* -------------------------- ps_AddEntityResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_AddEntityResponse_EXT
#define zx_ps_AddEntityResponse_EXT
#endif

struct zx_ps_AddEntityResponse_s* zx_DEC_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_AddEntityResponse_s* zx_NEW_ps_AddEntityResponse(struct zx_ctx* c);
void zx_FREE_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ps_AddEntityResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_AddEntityResponse_s* zx_DEEP_CLONE_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ps_AddEntityResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ps_AddEntityResponse_s* x);
int zx_WALK_SO_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ps_AddEntityResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ps_AddEntityResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ps_AddEntityResponse_s* x);
int zx_LEN_WO_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ps_AddEntityResponse_s* x);
char* zx_ENC_SO_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ps_AddEntityResponse_s* x, char* p);
char* zx_ENC_WO_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ps_AddEntityResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ps_AddEntityResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_AddEntityResponse(struct zx_ctx* c, struct zx_ps_AddEntityResponse_s* x);

struct zx_ps_AddEntityResponse_s {
  ZX_ELEM_EXT
  zx_ps_AddEntityResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_ps_Object_s* Object;	/* {0,1} nada */
  struct zx_elem_s* SPtoPSRedirectURL;	/* {0,1} xs:anyURI */
  struct zx_elem_s* QueryString;	/* {0,1} xs:string */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_AddEntityResponse_GET_TimeStamp(struct zx_ps_AddEntityResponse_s* x);
struct zx_str* zx_ps_AddEntityResponse_GET_id(struct zx_ps_AddEntityResponse_s* x);

struct zx_lu_Status_s* zx_ps_AddEntityResponse_GET_Status(struct zx_ps_AddEntityResponse_s* x, int n);
struct zx_ps_Object_s* zx_ps_AddEntityResponse_GET_Object(struct zx_ps_AddEntityResponse_s* x, int n);
struct zx_elem_s* zx_ps_AddEntityResponse_GET_SPtoPSRedirectURL(struct zx_ps_AddEntityResponse_s* x, int n);
struct zx_elem_s* zx_ps_AddEntityResponse_GET_QueryString(struct zx_ps_AddEntityResponse_s* x, int n);

int zx_ps_AddEntityResponse_NUM_Status(struct zx_ps_AddEntityResponse_s* x);
int zx_ps_AddEntityResponse_NUM_Object(struct zx_ps_AddEntityResponse_s* x);
int zx_ps_AddEntityResponse_NUM_SPtoPSRedirectURL(struct zx_ps_AddEntityResponse_s* x);
int zx_ps_AddEntityResponse_NUM_QueryString(struct zx_ps_AddEntityResponse_s* x);

struct zx_lu_Status_s* zx_ps_AddEntityResponse_POP_Status(struct zx_ps_AddEntityResponse_s* x);
struct zx_ps_Object_s* zx_ps_AddEntityResponse_POP_Object(struct zx_ps_AddEntityResponse_s* x);
struct zx_elem_s* zx_ps_AddEntityResponse_POP_SPtoPSRedirectURL(struct zx_ps_AddEntityResponse_s* x);
struct zx_elem_s* zx_ps_AddEntityResponse_POP_QueryString(struct zx_ps_AddEntityResponse_s* x);

void zx_ps_AddEntityResponse_PUSH_Status(struct zx_ps_AddEntityResponse_s* x, struct zx_lu_Status_s* y);
void zx_ps_AddEntityResponse_PUSH_Object(struct zx_ps_AddEntityResponse_s* x, struct zx_ps_Object_s* y);
void zx_ps_AddEntityResponse_PUSH_SPtoPSRedirectURL(struct zx_ps_AddEntityResponse_s* x, struct zx_elem_s* y);
void zx_ps_AddEntityResponse_PUSH_QueryString(struct zx_ps_AddEntityResponse_s* x, struct zx_elem_s* y);

void zx_ps_AddEntityResponse_PUT_TimeStamp(struct zx_ps_AddEntityResponse_s* x, struct zx_str* y);
void zx_ps_AddEntityResponse_PUT_id(struct zx_ps_AddEntityResponse_s* x, struct zx_str* y);

void zx_ps_AddEntityResponse_PUT_Status(struct zx_ps_AddEntityResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_ps_AddEntityResponse_PUT_Object(struct zx_ps_AddEntityResponse_s* x, int n, struct zx_ps_Object_s* y);
void zx_ps_AddEntityResponse_PUT_SPtoPSRedirectURL(struct zx_ps_AddEntityResponse_s* x, int n, struct zx_elem_s* y);
void zx_ps_AddEntityResponse_PUT_QueryString(struct zx_ps_AddEntityResponse_s* x, int n, struct zx_elem_s* y);

void zx_ps_AddEntityResponse_ADD_Status(struct zx_ps_AddEntityResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_ps_AddEntityResponse_ADD_Object(struct zx_ps_AddEntityResponse_s* x, int n, struct zx_ps_Object_s* z);
void zx_ps_AddEntityResponse_ADD_SPtoPSRedirectURL(struct zx_ps_AddEntityResponse_s* x, int n, struct zx_elem_s* z);
void zx_ps_AddEntityResponse_ADD_QueryString(struct zx_ps_AddEntityResponse_s* x, int n, struct zx_elem_s* z);

void zx_ps_AddEntityResponse_DEL_Status(struct zx_ps_AddEntityResponse_s* x, int n);
void zx_ps_AddEntityResponse_DEL_Object(struct zx_ps_AddEntityResponse_s* x, int n);
void zx_ps_AddEntityResponse_DEL_SPtoPSRedirectURL(struct zx_ps_AddEntityResponse_s* x, int n);
void zx_ps_AddEntityResponse_DEL_QueryString(struct zx_ps_AddEntityResponse_s* x, int n);

void zx_ps_AddEntityResponse_REV_Status(struct zx_ps_AddEntityResponse_s* x);
void zx_ps_AddEntityResponse_REV_Object(struct zx_ps_AddEntityResponse_s* x);
void zx_ps_AddEntityResponse_REV_SPtoPSRedirectURL(struct zx_ps_AddEntityResponse_s* x);
void zx_ps_AddEntityResponse_REV_QueryString(struct zx_ps_AddEntityResponse_s* x);

#endif
/* -------------------------- ps_AddKnownEntityRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_AddKnownEntityRequest_EXT
#define zx_ps_AddKnownEntityRequest_EXT
#endif

struct zx_ps_AddKnownEntityRequest_s* zx_DEC_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_AddKnownEntityRequest_s* zx_NEW_ps_AddKnownEntityRequest(struct zx_ctx* c);
void zx_FREE_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ps_AddKnownEntityRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_AddKnownEntityRequest_s* zx_DEEP_CLONE_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ps_AddKnownEntityRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ps_AddKnownEntityRequest_s* x);
int zx_WALK_SO_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ps_AddKnownEntityRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ps_AddKnownEntityRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ps_AddKnownEntityRequest_s* x);
int zx_LEN_WO_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ps_AddKnownEntityRequest_s* x);
char* zx_ENC_SO_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ps_AddKnownEntityRequest_s* x, char* p);
char* zx_ENC_WO_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ps_AddKnownEntityRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ps_AddKnownEntityRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_AddKnownEntityRequest(struct zx_ctx* c, struct zx_ps_AddKnownEntityRequest_s* x);

struct zx_ps_AddKnownEntityRequest_s {
  ZX_ELEM_EXT
  zx_ps_AddKnownEntityRequest_EXT
  struct zx_ps_Object_s* Object;	/* {1,1} nada */
  struct zx_sec_Token_s* Token;	/* {1,1} nada */
  struct zx_ps_CreatePSObject_s* CreatePSObject;	/* {0,1} nada */
  struct zx_ps_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_sec_TokenPolicy_s* TokenPolicy;	/* {0,1} nada */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_AddKnownEntityRequest_GET_id(struct zx_ps_AddKnownEntityRequest_s* x);

struct zx_ps_Object_s* zx_ps_AddKnownEntityRequest_GET_Object(struct zx_ps_AddKnownEntityRequest_s* x, int n);
struct zx_sec_Token_s* zx_ps_AddKnownEntityRequest_GET_Token(struct zx_ps_AddKnownEntityRequest_s* x, int n);
struct zx_ps_CreatePSObject_s* zx_ps_AddKnownEntityRequest_GET_CreatePSObject(struct zx_ps_AddKnownEntityRequest_s* x, int n);
struct zx_ps_Subscription_s* zx_ps_AddKnownEntityRequest_GET_Subscription(struct zx_ps_AddKnownEntityRequest_s* x, int n);
struct zx_sec_TokenPolicy_s* zx_ps_AddKnownEntityRequest_GET_TokenPolicy(struct zx_ps_AddKnownEntityRequest_s* x, int n);

int zx_ps_AddKnownEntityRequest_NUM_Object(struct zx_ps_AddKnownEntityRequest_s* x);
int zx_ps_AddKnownEntityRequest_NUM_Token(struct zx_ps_AddKnownEntityRequest_s* x);
int zx_ps_AddKnownEntityRequest_NUM_CreatePSObject(struct zx_ps_AddKnownEntityRequest_s* x);
int zx_ps_AddKnownEntityRequest_NUM_Subscription(struct zx_ps_AddKnownEntityRequest_s* x);
int zx_ps_AddKnownEntityRequest_NUM_TokenPolicy(struct zx_ps_AddKnownEntityRequest_s* x);

struct zx_ps_Object_s* zx_ps_AddKnownEntityRequest_POP_Object(struct zx_ps_AddKnownEntityRequest_s* x);
struct zx_sec_Token_s* zx_ps_AddKnownEntityRequest_POP_Token(struct zx_ps_AddKnownEntityRequest_s* x);
struct zx_ps_CreatePSObject_s* zx_ps_AddKnownEntityRequest_POP_CreatePSObject(struct zx_ps_AddKnownEntityRequest_s* x);
struct zx_ps_Subscription_s* zx_ps_AddKnownEntityRequest_POP_Subscription(struct zx_ps_AddKnownEntityRequest_s* x);
struct zx_sec_TokenPolicy_s* zx_ps_AddKnownEntityRequest_POP_TokenPolicy(struct zx_ps_AddKnownEntityRequest_s* x);

void zx_ps_AddKnownEntityRequest_PUSH_Object(struct zx_ps_AddKnownEntityRequest_s* x, struct zx_ps_Object_s* y);
void zx_ps_AddKnownEntityRequest_PUSH_Token(struct zx_ps_AddKnownEntityRequest_s* x, struct zx_sec_Token_s* y);
void zx_ps_AddKnownEntityRequest_PUSH_CreatePSObject(struct zx_ps_AddKnownEntityRequest_s* x, struct zx_ps_CreatePSObject_s* y);
void zx_ps_AddKnownEntityRequest_PUSH_Subscription(struct zx_ps_AddKnownEntityRequest_s* x, struct zx_ps_Subscription_s* y);
void zx_ps_AddKnownEntityRequest_PUSH_TokenPolicy(struct zx_ps_AddKnownEntityRequest_s* x, struct zx_sec_TokenPolicy_s* y);

void zx_ps_AddKnownEntityRequest_PUT_id(struct zx_ps_AddKnownEntityRequest_s* x, struct zx_str* y);

void zx_ps_AddKnownEntityRequest_PUT_Object(struct zx_ps_AddKnownEntityRequest_s* x, int n, struct zx_ps_Object_s* y);
void zx_ps_AddKnownEntityRequest_PUT_Token(struct zx_ps_AddKnownEntityRequest_s* x, int n, struct zx_sec_Token_s* y);
void zx_ps_AddKnownEntityRequest_PUT_CreatePSObject(struct zx_ps_AddKnownEntityRequest_s* x, int n, struct zx_ps_CreatePSObject_s* y);
void zx_ps_AddKnownEntityRequest_PUT_Subscription(struct zx_ps_AddKnownEntityRequest_s* x, int n, struct zx_ps_Subscription_s* y);
void zx_ps_AddKnownEntityRequest_PUT_TokenPolicy(struct zx_ps_AddKnownEntityRequest_s* x, int n, struct zx_sec_TokenPolicy_s* y);

void zx_ps_AddKnownEntityRequest_ADD_Object(struct zx_ps_AddKnownEntityRequest_s* x, int n, struct zx_ps_Object_s* z);
void zx_ps_AddKnownEntityRequest_ADD_Token(struct zx_ps_AddKnownEntityRequest_s* x, int n, struct zx_sec_Token_s* z);
void zx_ps_AddKnownEntityRequest_ADD_CreatePSObject(struct zx_ps_AddKnownEntityRequest_s* x, int n, struct zx_ps_CreatePSObject_s* z);
void zx_ps_AddKnownEntityRequest_ADD_Subscription(struct zx_ps_AddKnownEntityRequest_s* x, int n, struct zx_ps_Subscription_s* z);
void zx_ps_AddKnownEntityRequest_ADD_TokenPolicy(struct zx_ps_AddKnownEntityRequest_s* x, int n, struct zx_sec_TokenPolicy_s* z);

void zx_ps_AddKnownEntityRequest_DEL_Object(struct zx_ps_AddKnownEntityRequest_s* x, int n);
void zx_ps_AddKnownEntityRequest_DEL_Token(struct zx_ps_AddKnownEntityRequest_s* x, int n);
void zx_ps_AddKnownEntityRequest_DEL_CreatePSObject(struct zx_ps_AddKnownEntityRequest_s* x, int n);
void zx_ps_AddKnownEntityRequest_DEL_Subscription(struct zx_ps_AddKnownEntityRequest_s* x, int n);
void zx_ps_AddKnownEntityRequest_DEL_TokenPolicy(struct zx_ps_AddKnownEntityRequest_s* x, int n);

void zx_ps_AddKnownEntityRequest_REV_Object(struct zx_ps_AddKnownEntityRequest_s* x);
void zx_ps_AddKnownEntityRequest_REV_Token(struct zx_ps_AddKnownEntityRequest_s* x);
void zx_ps_AddKnownEntityRequest_REV_CreatePSObject(struct zx_ps_AddKnownEntityRequest_s* x);
void zx_ps_AddKnownEntityRequest_REV_Subscription(struct zx_ps_AddKnownEntityRequest_s* x);
void zx_ps_AddKnownEntityRequest_REV_TokenPolicy(struct zx_ps_AddKnownEntityRequest_s* x);

#endif
/* -------------------------- ps_AddKnownEntityResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_AddKnownEntityResponse_EXT
#define zx_ps_AddKnownEntityResponse_EXT
#endif

struct zx_ps_AddKnownEntityResponse_s* zx_DEC_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_AddKnownEntityResponse_s* zx_NEW_ps_AddKnownEntityResponse(struct zx_ctx* c);
void zx_FREE_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ps_AddKnownEntityResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_AddKnownEntityResponse_s* zx_DEEP_CLONE_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ps_AddKnownEntityResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ps_AddKnownEntityResponse_s* x);
int zx_WALK_SO_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ps_AddKnownEntityResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ps_AddKnownEntityResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ps_AddKnownEntityResponse_s* x);
int zx_LEN_WO_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ps_AddKnownEntityResponse_s* x);
char* zx_ENC_SO_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ps_AddKnownEntityResponse_s* x, char* p);
char* zx_ENC_WO_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ps_AddKnownEntityResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ps_AddKnownEntityResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_AddKnownEntityResponse(struct zx_ctx* c, struct zx_ps_AddKnownEntityResponse_s* x);

struct zx_ps_AddKnownEntityResponse_s {
  ZX_ELEM_EXT
  zx_ps_AddKnownEntityResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_ps_Object_s* Object;	/* {0,1} nada */
  struct zx_elem_s* SPtoPSRedirectURL;	/* {0,1} xs:anyURI */
  struct zx_elem_s* QueryString;	/* {0,1} xs:string */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_AddKnownEntityResponse_GET_TimeStamp(struct zx_ps_AddKnownEntityResponse_s* x);
struct zx_str* zx_ps_AddKnownEntityResponse_GET_id(struct zx_ps_AddKnownEntityResponse_s* x);

struct zx_lu_Status_s* zx_ps_AddKnownEntityResponse_GET_Status(struct zx_ps_AddKnownEntityResponse_s* x, int n);
struct zx_ps_Object_s* zx_ps_AddKnownEntityResponse_GET_Object(struct zx_ps_AddKnownEntityResponse_s* x, int n);
struct zx_elem_s* zx_ps_AddKnownEntityResponse_GET_SPtoPSRedirectURL(struct zx_ps_AddKnownEntityResponse_s* x, int n);
struct zx_elem_s* zx_ps_AddKnownEntityResponse_GET_QueryString(struct zx_ps_AddKnownEntityResponse_s* x, int n);

int zx_ps_AddKnownEntityResponse_NUM_Status(struct zx_ps_AddKnownEntityResponse_s* x);
int zx_ps_AddKnownEntityResponse_NUM_Object(struct zx_ps_AddKnownEntityResponse_s* x);
int zx_ps_AddKnownEntityResponse_NUM_SPtoPSRedirectURL(struct zx_ps_AddKnownEntityResponse_s* x);
int zx_ps_AddKnownEntityResponse_NUM_QueryString(struct zx_ps_AddKnownEntityResponse_s* x);

struct zx_lu_Status_s* zx_ps_AddKnownEntityResponse_POP_Status(struct zx_ps_AddKnownEntityResponse_s* x);
struct zx_ps_Object_s* zx_ps_AddKnownEntityResponse_POP_Object(struct zx_ps_AddKnownEntityResponse_s* x);
struct zx_elem_s* zx_ps_AddKnownEntityResponse_POP_SPtoPSRedirectURL(struct zx_ps_AddKnownEntityResponse_s* x);
struct zx_elem_s* zx_ps_AddKnownEntityResponse_POP_QueryString(struct zx_ps_AddKnownEntityResponse_s* x);

void zx_ps_AddKnownEntityResponse_PUSH_Status(struct zx_ps_AddKnownEntityResponse_s* x, struct zx_lu_Status_s* y);
void zx_ps_AddKnownEntityResponse_PUSH_Object(struct zx_ps_AddKnownEntityResponse_s* x, struct zx_ps_Object_s* y);
void zx_ps_AddKnownEntityResponse_PUSH_SPtoPSRedirectURL(struct zx_ps_AddKnownEntityResponse_s* x, struct zx_elem_s* y);
void zx_ps_AddKnownEntityResponse_PUSH_QueryString(struct zx_ps_AddKnownEntityResponse_s* x, struct zx_elem_s* y);

void zx_ps_AddKnownEntityResponse_PUT_TimeStamp(struct zx_ps_AddKnownEntityResponse_s* x, struct zx_str* y);
void zx_ps_AddKnownEntityResponse_PUT_id(struct zx_ps_AddKnownEntityResponse_s* x, struct zx_str* y);

void zx_ps_AddKnownEntityResponse_PUT_Status(struct zx_ps_AddKnownEntityResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_ps_AddKnownEntityResponse_PUT_Object(struct zx_ps_AddKnownEntityResponse_s* x, int n, struct zx_ps_Object_s* y);
void zx_ps_AddKnownEntityResponse_PUT_SPtoPSRedirectURL(struct zx_ps_AddKnownEntityResponse_s* x, int n, struct zx_elem_s* y);
void zx_ps_AddKnownEntityResponse_PUT_QueryString(struct zx_ps_AddKnownEntityResponse_s* x, int n, struct zx_elem_s* y);

void zx_ps_AddKnownEntityResponse_ADD_Status(struct zx_ps_AddKnownEntityResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_ps_AddKnownEntityResponse_ADD_Object(struct zx_ps_AddKnownEntityResponse_s* x, int n, struct zx_ps_Object_s* z);
void zx_ps_AddKnownEntityResponse_ADD_SPtoPSRedirectURL(struct zx_ps_AddKnownEntityResponse_s* x, int n, struct zx_elem_s* z);
void zx_ps_AddKnownEntityResponse_ADD_QueryString(struct zx_ps_AddKnownEntityResponse_s* x, int n, struct zx_elem_s* z);

void zx_ps_AddKnownEntityResponse_DEL_Status(struct zx_ps_AddKnownEntityResponse_s* x, int n);
void zx_ps_AddKnownEntityResponse_DEL_Object(struct zx_ps_AddKnownEntityResponse_s* x, int n);
void zx_ps_AddKnownEntityResponse_DEL_SPtoPSRedirectURL(struct zx_ps_AddKnownEntityResponse_s* x, int n);
void zx_ps_AddKnownEntityResponse_DEL_QueryString(struct zx_ps_AddKnownEntityResponse_s* x, int n);

void zx_ps_AddKnownEntityResponse_REV_Status(struct zx_ps_AddKnownEntityResponse_s* x);
void zx_ps_AddKnownEntityResponse_REV_Object(struct zx_ps_AddKnownEntityResponse_s* x);
void zx_ps_AddKnownEntityResponse_REV_SPtoPSRedirectURL(struct zx_ps_AddKnownEntityResponse_s* x);
void zx_ps_AddKnownEntityResponse_REV_QueryString(struct zx_ps_AddKnownEntityResponse_s* x);

#endif
/* -------------------------- ps_AddToCollectionRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_AddToCollectionRequest_EXT
#define zx_ps_AddToCollectionRequest_EXT
#endif

struct zx_ps_AddToCollectionRequest_s* zx_DEC_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_AddToCollectionRequest_s* zx_NEW_ps_AddToCollectionRequest(struct zx_ctx* c);
void zx_FREE_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ps_AddToCollectionRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_AddToCollectionRequest_s* zx_DEEP_CLONE_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ps_AddToCollectionRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ps_AddToCollectionRequest_s* x);
int zx_WALK_SO_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ps_AddToCollectionRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ps_AddToCollectionRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ps_AddToCollectionRequest_s* x);
int zx_LEN_WO_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ps_AddToCollectionRequest_s* x);
char* zx_ENC_SO_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ps_AddToCollectionRequest_s* x, char* p);
char* zx_ENC_WO_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ps_AddToCollectionRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ps_AddToCollectionRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_AddToCollectionRequest(struct zx_ctx* c, struct zx_ps_AddToCollectionRequest_s* x);

struct zx_ps_AddToCollectionRequest_s {
  ZX_ELEM_EXT
  zx_ps_AddToCollectionRequest_EXT
  struct zx_elem_s* TargetObjectID;	/* {1,1} xs:anyURI */
  struct zx_elem_s* ObjectID;	/* {1,-1} xs:anyURI */
  struct zx_ps_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_AddToCollectionRequest_GET_id(struct zx_ps_AddToCollectionRequest_s* x);

struct zx_elem_s* zx_ps_AddToCollectionRequest_GET_TargetObjectID(struct zx_ps_AddToCollectionRequest_s* x, int n);
struct zx_elem_s* zx_ps_AddToCollectionRequest_GET_ObjectID(struct zx_ps_AddToCollectionRequest_s* x, int n);
struct zx_ps_Subscription_s* zx_ps_AddToCollectionRequest_GET_Subscription(struct zx_ps_AddToCollectionRequest_s* x, int n);

int zx_ps_AddToCollectionRequest_NUM_TargetObjectID(struct zx_ps_AddToCollectionRequest_s* x);
int zx_ps_AddToCollectionRequest_NUM_ObjectID(struct zx_ps_AddToCollectionRequest_s* x);
int zx_ps_AddToCollectionRequest_NUM_Subscription(struct zx_ps_AddToCollectionRequest_s* x);

struct zx_elem_s* zx_ps_AddToCollectionRequest_POP_TargetObjectID(struct zx_ps_AddToCollectionRequest_s* x);
struct zx_elem_s* zx_ps_AddToCollectionRequest_POP_ObjectID(struct zx_ps_AddToCollectionRequest_s* x);
struct zx_ps_Subscription_s* zx_ps_AddToCollectionRequest_POP_Subscription(struct zx_ps_AddToCollectionRequest_s* x);

void zx_ps_AddToCollectionRequest_PUSH_TargetObjectID(struct zx_ps_AddToCollectionRequest_s* x, struct zx_elem_s* y);
void zx_ps_AddToCollectionRequest_PUSH_ObjectID(struct zx_ps_AddToCollectionRequest_s* x, struct zx_elem_s* y);
void zx_ps_AddToCollectionRequest_PUSH_Subscription(struct zx_ps_AddToCollectionRequest_s* x, struct zx_ps_Subscription_s* y);

void zx_ps_AddToCollectionRequest_PUT_id(struct zx_ps_AddToCollectionRequest_s* x, struct zx_str* y);

void zx_ps_AddToCollectionRequest_PUT_TargetObjectID(struct zx_ps_AddToCollectionRequest_s* x, int n, struct zx_elem_s* y);
void zx_ps_AddToCollectionRequest_PUT_ObjectID(struct zx_ps_AddToCollectionRequest_s* x, int n, struct zx_elem_s* y);
void zx_ps_AddToCollectionRequest_PUT_Subscription(struct zx_ps_AddToCollectionRequest_s* x, int n, struct zx_ps_Subscription_s* y);

void zx_ps_AddToCollectionRequest_ADD_TargetObjectID(struct zx_ps_AddToCollectionRequest_s* x, int n, struct zx_elem_s* z);
void zx_ps_AddToCollectionRequest_ADD_ObjectID(struct zx_ps_AddToCollectionRequest_s* x, int n, struct zx_elem_s* z);
void zx_ps_AddToCollectionRequest_ADD_Subscription(struct zx_ps_AddToCollectionRequest_s* x, int n, struct zx_ps_Subscription_s* z);

void zx_ps_AddToCollectionRequest_DEL_TargetObjectID(struct zx_ps_AddToCollectionRequest_s* x, int n);
void zx_ps_AddToCollectionRequest_DEL_ObjectID(struct zx_ps_AddToCollectionRequest_s* x, int n);
void zx_ps_AddToCollectionRequest_DEL_Subscription(struct zx_ps_AddToCollectionRequest_s* x, int n);

void zx_ps_AddToCollectionRequest_REV_TargetObjectID(struct zx_ps_AddToCollectionRequest_s* x);
void zx_ps_AddToCollectionRequest_REV_ObjectID(struct zx_ps_AddToCollectionRequest_s* x);
void zx_ps_AddToCollectionRequest_REV_Subscription(struct zx_ps_AddToCollectionRequest_s* x);

#endif
/* -------------------------- ps_AddToCollectionResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_AddToCollectionResponse_EXT
#define zx_ps_AddToCollectionResponse_EXT
#endif

struct zx_ps_AddToCollectionResponse_s* zx_DEC_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_AddToCollectionResponse_s* zx_NEW_ps_AddToCollectionResponse(struct zx_ctx* c);
void zx_FREE_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ps_AddToCollectionResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_AddToCollectionResponse_s* zx_DEEP_CLONE_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ps_AddToCollectionResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ps_AddToCollectionResponse_s* x);
int zx_WALK_SO_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ps_AddToCollectionResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ps_AddToCollectionResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ps_AddToCollectionResponse_s* x);
int zx_LEN_WO_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ps_AddToCollectionResponse_s* x);
char* zx_ENC_SO_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ps_AddToCollectionResponse_s* x, char* p);
char* zx_ENC_WO_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ps_AddToCollectionResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ps_AddToCollectionResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_AddToCollectionResponse(struct zx_ctx* c, struct zx_ps_AddToCollectionResponse_s* x);

struct zx_ps_AddToCollectionResponse_s {
  ZX_ELEM_EXT
  zx_ps_AddToCollectionResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_AddToCollectionResponse_GET_TimeStamp(struct zx_ps_AddToCollectionResponse_s* x);
struct zx_str* zx_ps_AddToCollectionResponse_GET_id(struct zx_ps_AddToCollectionResponse_s* x);

struct zx_lu_Status_s* zx_ps_AddToCollectionResponse_GET_Status(struct zx_ps_AddToCollectionResponse_s* x, int n);

int zx_ps_AddToCollectionResponse_NUM_Status(struct zx_ps_AddToCollectionResponse_s* x);

struct zx_lu_Status_s* zx_ps_AddToCollectionResponse_POP_Status(struct zx_ps_AddToCollectionResponse_s* x);

void zx_ps_AddToCollectionResponse_PUSH_Status(struct zx_ps_AddToCollectionResponse_s* x, struct zx_lu_Status_s* y);

void zx_ps_AddToCollectionResponse_PUT_TimeStamp(struct zx_ps_AddToCollectionResponse_s* x, struct zx_str* y);
void zx_ps_AddToCollectionResponse_PUT_id(struct zx_ps_AddToCollectionResponse_s* x, struct zx_str* y);

void zx_ps_AddToCollectionResponse_PUT_Status(struct zx_ps_AddToCollectionResponse_s* x, int n, struct zx_lu_Status_s* y);

void zx_ps_AddToCollectionResponse_ADD_Status(struct zx_ps_AddToCollectionResponse_s* x, int n, struct zx_lu_Status_s* z);

void zx_ps_AddToCollectionResponse_DEL_Status(struct zx_ps_AddToCollectionResponse_s* x, int n);

void zx_ps_AddToCollectionResponse_REV_Status(struct zx_ps_AddToCollectionResponse_s* x);

#endif
/* -------------------------- ps_CreatePSObject -------------------------- */
/* refby( zx_ps_AddKnownEntityRequest_s zx_ps_AddEntityRequest_s ) */
#ifndef zx_ps_CreatePSObject_EXT
#define zx_ps_CreatePSObject_EXT
#endif

struct zx_ps_CreatePSObject_s* zx_DEC_ps_CreatePSObject(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_CreatePSObject_s* zx_NEW_ps_CreatePSObject(struct zx_ctx* c);
void zx_FREE_ps_CreatePSObject(struct zx_ctx* c, struct zx_ps_CreatePSObject_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_CreatePSObject_s* zx_DEEP_CLONE_ps_CreatePSObject(struct zx_ctx* c, struct zx_ps_CreatePSObject_s* x, int dup_strs);
void zx_DUP_STRS_ps_CreatePSObject(struct zx_ctx* c, struct zx_ps_CreatePSObject_s* x);
int zx_WALK_SO_ps_CreatePSObject(struct zx_ctx* c, struct zx_ps_CreatePSObject_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_CreatePSObject(struct zx_ctx* c, struct zx_ps_CreatePSObject_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_CreatePSObject(struct zx_ctx* c, struct zx_ps_CreatePSObject_s* x);
int zx_LEN_WO_ps_CreatePSObject(struct zx_ctx* c, struct zx_ps_CreatePSObject_s* x);
char* zx_ENC_SO_ps_CreatePSObject(struct zx_ctx* c, struct zx_ps_CreatePSObject_s* x, char* p);
char* zx_ENC_WO_ps_CreatePSObject(struct zx_ctx* c, struct zx_ps_CreatePSObject_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_CreatePSObject(struct zx_ctx* c, struct zx_ps_CreatePSObject_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_CreatePSObject(struct zx_ctx* c, struct zx_ps_CreatePSObject_s* x);

struct zx_ps_CreatePSObject_s {
  ZX_ELEM_EXT
  zx_ps_CreatePSObject_EXT
};

#ifdef ZX_ENA_GETPUT










#endif
/* -------------------------- ps_DisplayName -------------------------- */
/* refby( zx_ps_Object_s ) */
#ifndef zx_ps_DisplayName_EXT
#define zx_ps_DisplayName_EXT
#endif

struct zx_ps_DisplayName_s* zx_DEC_ps_DisplayName(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_DisplayName_s* zx_NEW_ps_DisplayName(struct zx_ctx* c);
void zx_FREE_ps_DisplayName(struct zx_ctx* c, struct zx_ps_DisplayName_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_DisplayName_s* zx_DEEP_CLONE_ps_DisplayName(struct zx_ctx* c, struct zx_ps_DisplayName_s* x, int dup_strs);
void zx_DUP_STRS_ps_DisplayName(struct zx_ctx* c, struct zx_ps_DisplayName_s* x);
int zx_WALK_SO_ps_DisplayName(struct zx_ctx* c, struct zx_ps_DisplayName_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_DisplayName(struct zx_ctx* c, struct zx_ps_DisplayName_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_DisplayName(struct zx_ctx* c, struct zx_ps_DisplayName_s* x);
int zx_LEN_WO_ps_DisplayName(struct zx_ctx* c, struct zx_ps_DisplayName_s* x);
char* zx_ENC_SO_ps_DisplayName(struct zx_ctx* c, struct zx_ps_DisplayName_s* x, char* p);
char* zx_ENC_WO_ps_DisplayName(struct zx_ctx* c, struct zx_ps_DisplayName_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_DisplayName(struct zx_ctx* c, struct zx_ps_DisplayName_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_DisplayName(struct zx_ctx* c, struct zx_ps_DisplayName_s* x);

struct zx_ps_DisplayName_s {
  ZX_ELEM_EXT
  zx_ps_DisplayName_EXT
  struct zx_str* IsDefault;	/* {0,1} attribute xs:boolean */
  struct zx_str* Locale;	/* {1,1} attribute xs:language */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_DisplayName_GET_IsDefault(struct zx_ps_DisplayName_s* x);
struct zx_str* zx_ps_DisplayName_GET_Locale(struct zx_ps_DisplayName_s* x);





void zx_ps_DisplayName_PUT_IsDefault(struct zx_ps_DisplayName_s* x, struct zx_str* y);
void zx_ps_DisplayName_PUT_Locale(struct zx_ps_DisplayName_s* x, struct zx_str* y);





#endif
/* -------------------------- ps_GetObjectInfoRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_GetObjectInfoRequest_EXT
#define zx_ps_GetObjectInfoRequest_EXT
#endif

struct zx_ps_GetObjectInfoRequest_s* zx_DEC_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_GetObjectInfoRequest_s* zx_NEW_ps_GetObjectInfoRequest(struct zx_ctx* c);
void zx_FREE_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_GetObjectInfoRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_GetObjectInfoRequest_s* zx_DEEP_CLONE_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_GetObjectInfoRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_GetObjectInfoRequest_s* x);
int zx_WALK_SO_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_GetObjectInfoRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_GetObjectInfoRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_GetObjectInfoRequest_s* x);
int zx_LEN_WO_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_GetObjectInfoRequest_s* x);
char* zx_ENC_SO_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_GetObjectInfoRequest_s* x, char* p);
char* zx_ENC_WO_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_GetObjectInfoRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_GetObjectInfoRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_GetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_GetObjectInfoRequest_s* x);

struct zx_ps_GetObjectInfoRequest_s {
  ZX_ELEM_EXT
  zx_ps_GetObjectInfoRequest_EXT
  struct zx_elem_s* TargetObjectID;	/* {0,1} xs:anyURI */
  struct zx_ps_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_GetObjectInfoRequest_GET_id(struct zx_ps_GetObjectInfoRequest_s* x);

struct zx_elem_s* zx_ps_GetObjectInfoRequest_GET_TargetObjectID(struct zx_ps_GetObjectInfoRequest_s* x, int n);
struct zx_ps_Subscription_s* zx_ps_GetObjectInfoRequest_GET_Subscription(struct zx_ps_GetObjectInfoRequest_s* x, int n);

int zx_ps_GetObjectInfoRequest_NUM_TargetObjectID(struct zx_ps_GetObjectInfoRequest_s* x);
int zx_ps_GetObjectInfoRequest_NUM_Subscription(struct zx_ps_GetObjectInfoRequest_s* x);

struct zx_elem_s* zx_ps_GetObjectInfoRequest_POP_TargetObjectID(struct zx_ps_GetObjectInfoRequest_s* x);
struct zx_ps_Subscription_s* zx_ps_GetObjectInfoRequest_POP_Subscription(struct zx_ps_GetObjectInfoRequest_s* x);

void zx_ps_GetObjectInfoRequest_PUSH_TargetObjectID(struct zx_ps_GetObjectInfoRequest_s* x, struct zx_elem_s* y);
void zx_ps_GetObjectInfoRequest_PUSH_Subscription(struct zx_ps_GetObjectInfoRequest_s* x, struct zx_ps_Subscription_s* y);

void zx_ps_GetObjectInfoRequest_PUT_id(struct zx_ps_GetObjectInfoRequest_s* x, struct zx_str* y);

void zx_ps_GetObjectInfoRequest_PUT_TargetObjectID(struct zx_ps_GetObjectInfoRequest_s* x, int n, struct zx_elem_s* y);
void zx_ps_GetObjectInfoRequest_PUT_Subscription(struct zx_ps_GetObjectInfoRequest_s* x, int n, struct zx_ps_Subscription_s* y);

void zx_ps_GetObjectInfoRequest_ADD_TargetObjectID(struct zx_ps_GetObjectInfoRequest_s* x, int n, struct zx_elem_s* z);
void zx_ps_GetObjectInfoRequest_ADD_Subscription(struct zx_ps_GetObjectInfoRequest_s* x, int n, struct zx_ps_Subscription_s* z);

void zx_ps_GetObjectInfoRequest_DEL_TargetObjectID(struct zx_ps_GetObjectInfoRequest_s* x, int n);
void zx_ps_GetObjectInfoRequest_DEL_Subscription(struct zx_ps_GetObjectInfoRequest_s* x, int n);

void zx_ps_GetObjectInfoRequest_REV_TargetObjectID(struct zx_ps_GetObjectInfoRequest_s* x);
void zx_ps_GetObjectInfoRequest_REV_Subscription(struct zx_ps_GetObjectInfoRequest_s* x);

#endif
/* -------------------------- ps_GetObjectInfoResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_GetObjectInfoResponse_EXT
#define zx_ps_GetObjectInfoResponse_EXT
#endif

struct zx_ps_GetObjectInfoResponse_s* zx_DEC_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_GetObjectInfoResponse_s* zx_NEW_ps_GetObjectInfoResponse(struct zx_ctx* c);
void zx_FREE_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_GetObjectInfoResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_GetObjectInfoResponse_s* zx_DEEP_CLONE_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_GetObjectInfoResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_GetObjectInfoResponse_s* x);
int zx_WALK_SO_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_GetObjectInfoResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_GetObjectInfoResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_GetObjectInfoResponse_s* x);
int zx_LEN_WO_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_GetObjectInfoResponse_s* x);
char* zx_ENC_SO_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_GetObjectInfoResponse_s* x, char* p);
char* zx_ENC_WO_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_GetObjectInfoResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_GetObjectInfoResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_GetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_GetObjectInfoResponse_s* x);

struct zx_ps_GetObjectInfoResponse_s {
  ZX_ELEM_EXT
  zx_ps_GetObjectInfoResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_ps_Object_s* Object;	/* {0,1} nada */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_GetObjectInfoResponse_GET_TimeStamp(struct zx_ps_GetObjectInfoResponse_s* x);
struct zx_str* zx_ps_GetObjectInfoResponse_GET_id(struct zx_ps_GetObjectInfoResponse_s* x);

struct zx_lu_Status_s* zx_ps_GetObjectInfoResponse_GET_Status(struct zx_ps_GetObjectInfoResponse_s* x, int n);
struct zx_ps_Object_s* zx_ps_GetObjectInfoResponse_GET_Object(struct zx_ps_GetObjectInfoResponse_s* x, int n);

int zx_ps_GetObjectInfoResponse_NUM_Status(struct zx_ps_GetObjectInfoResponse_s* x);
int zx_ps_GetObjectInfoResponse_NUM_Object(struct zx_ps_GetObjectInfoResponse_s* x);

struct zx_lu_Status_s* zx_ps_GetObjectInfoResponse_POP_Status(struct zx_ps_GetObjectInfoResponse_s* x);
struct zx_ps_Object_s* zx_ps_GetObjectInfoResponse_POP_Object(struct zx_ps_GetObjectInfoResponse_s* x);

void zx_ps_GetObjectInfoResponse_PUSH_Status(struct zx_ps_GetObjectInfoResponse_s* x, struct zx_lu_Status_s* y);
void zx_ps_GetObjectInfoResponse_PUSH_Object(struct zx_ps_GetObjectInfoResponse_s* x, struct zx_ps_Object_s* y);

void zx_ps_GetObjectInfoResponse_PUT_TimeStamp(struct zx_ps_GetObjectInfoResponse_s* x, struct zx_str* y);
void zx_ps_GetObjectInfoResponse_PUT_id(struct zx_ps_GetObjectInfoResponse_s* x, struct zx_str* y);

void zx_ps_GetObjectInfoResponse_PUT_Status(struct zx_ps_GetObjectInfoResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_ps_GetObjectInfoResponse_PUT_Object(struct zx_ps_GetObjectInfoResponse_s* x, int n, struct zx_ps_Object_s* y);

void zx_ps_GetObjectInfoResponse_ADD_Status(struct zx_ps_GetObjectInfoResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_ps_GetObjectInfoResponse_ADD_Object(struct zx_ps_GetObjectInfoResponse_s* x, int n, struct zx_ps_Object_s* z);

void zx_ps_GetObjectInfoResponse_DEL_Status(struct zx_ps_GetObjectInfoResponse_s* x, int n);
void zx_ps_GetObjectInfoResponse_DEL_Object(struct zx_ps_GetObjectInfoResponse_s* x, int n);

void zx_ps_GetObjectInfoResponse_REV_Status(struct zx_ps_GetObjectInfoResponse_s* x);
void zx_ps_GetObjectInfoResponse_REV_Object(struct zx_ps_GetObjectInfoResponse_s* x);

#endif
/* -------------------------- ps_ItemData -------------------------- */
/* refby( zx_ps_Notification_s ) */
#ifndef zx_ps_ItemData_EXT
#define zx_ps_ItemData_EXT
#endif

struct zx_ps_ItemData_s* zx_DEC_ps_ItemData(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_ItemData_s* zx_NEW_ps_ItemData(struct zx_ctx* c);
void zx_FREE_ps_ItemData(struct zx_ctx* c, struct zx_ps_ItemData_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_ItemData_s* zx_DEEP_CLONE_ps_ItemData(struct zx_ctx* c, struct zx_ps_ItemData_s* x, int dup_strs);
void zx_DUP_STRS_ps_ItemData(struct zx_ctx* c, struct zx_ps_ItemData_s* x);
int zx_WALK_SO_ps_ItemData(struct zx_ctx* c, struct zx_ps_ItemData_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_ItemData(struct zx_ctx* c, struct zx_ps_ItemData_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_ItemData(struct zx_ctx* c, struct zx_ps_ItemData_s* x);
int zx_LEN_WO_ps_ItemData(struct zx_ctx* c, struct zx_ps_ItemData_s* x);
char* zx_ENC_SO_ps_ItemData(struct zx_ctx* c, struct zx_ps_ItemData_s* x, char* p);
char* zx_ENC_WO_ps_ItemData(struct zx_ctx* c, struct zx_ps_ItemData_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_ItemData(struct zx_ctx* c, struct zx_ps_ItemData_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_ItemData(struct zx_ctx* c, struct zx_ps_ItemData_s* x);

struct zx_ps_ItemData_s {
  ZX_ELEM_EXT
  zx_ps_ItemData_EXT
  struct zx_ps_Object_s* Object;	/* {1,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_ps_Object_s* zx_ps_ItemData_GET_Object(struct zx_ps_ItemData_s* x, int n);

int zx_ps_ItemData_NUM_Object(struct zx_ps_ItemData_s* x);

struct zx_ps_Object_s* zx_ps_ItemData_POP_Object(struct zx_ps_ItemData_s* x);

void zx_ps_ItemData_PUSH_Object(struct zx_ps_ItemData_s* x, struct zx_ps_Object_s* y);


void zx_ps_ItemData_PUT_Object(struct zx_ps_ItemData_s* x, int n, struct zx_ps_Object_s* y);

void zx_ps_ItemData_ADD_Object(struct zx_ps_ItemData_s* x, int n, struct zx_ps_Object_s* z);

void zx_ps_ItemData_DEL_Object(struct zx_ps_ItemData_s* x, int n);

void zx_ps_ItemData_REV_Object(struct zx_ps_ItemData_s* x);

#endif
/* -------------------------- ps_ListMembersRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_ListMembersRequest_EXT
#define zx_ps_ListMembersRequest_EXT
#endif

struct zx_ps_ListMembersRequest_s* zx_DEC_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_ListMembersRequest_s* zx_NEW_ps_ListMembersRequest(struct zx_ctx* c);
void zx_FREE_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ps_ListMembersRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_ListMembersRequest_s* zx_DEEP_CLONE_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ps_ListMembersRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ps_ListMembersRequest_s* x);
int zx_WALK_SO_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ps_ListMembersRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ps_ListMembersRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ps_ListMembersRequest_s* x);
int zx_LEN_WO_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ps_ListMembersRequest_s* x);
char* zx_ENC_SO_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ps_ListMembersRequest_s* x, char* p);
char* zx_ENC_WO_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ps_ListMembersRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ps_ListMembersRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_ListMembersRequest(struct zx_ctx* c, struct zx_ps_ListMembersRequest_s* x);

struct zx_ps_ListMembersRequest_s {
  ZX_ELEM_EXT
  zx_ps_ListMembersRequest_EXT
  struct zx_elem_s* TargetObjectID;	/* {0,1} xs:anyURI */
  struct zx_ps_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_str* Count;	/* {0,1} attribute xs:nonNegativeInteger */
  struct zx_str* Offset;	/* {0,1} attribute xs:nonNegativeInteger */
  struct zx_str* Structured;	/* {0,1} attribute xs:anyURI */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_ListMembersRequest_GET_Count(struct zx_ps_ListMembersRequest_s* x);
struct zx_str* zx_ps_ListMembersRequest_GET_Offset(struct zx_ps_ListMembersRequest_s* x);
struct zx_str* zx_ps_ListMembersRequest_GET_Structured(struct zx_ps_ListMembersRequest_s* x);
struct zx_str* zx_ps_ListMembersRequest_GET_id(struct zx_ps_ListMembersRequest_s* x);

struct zx_elem_s* zx_ps_ListMembersRequest_GET_TargetObjectID(struct zx_ps_ListMembersRequest_s* x, int n);
struct zx_ps_Subscription_s* zx_ps_ListMembersRequest_GET_Subscription(struct zx_ps_ListMembersRequest_s* x, int n);

int zx_ps_ListMembersRequest_NUM_TargetObjectID(struct zx_ps_ListMembersRequest_s* x);
int zx_ps_ListMembersRequest_NUM_Subscription(struct zx_ps_ListMembersRequest_s* x);

struct zx_elem_s* zx_ps_ListMembersRequest_POP_TargetObjectID(struct zx_ps_ListMembersRequest_s* x);
struct zx_ps_Subscription_s* zx_ps_ListMembersRequest_POP_Subscription(struct zx_ps_ListMembersRequest_s* x);

void zx_ps_ListMembersRequest_PUSH_TargetObjectID(struct zx_ps_ListMembersRequest_s* x, struct zx_elem_s* y);
void zx_ps_ListMembersRequest_PUSH_Subscription(struct zx_ps_ListMembersRequest_s* x, struct zx_ps_Subscription_s* y);

void zx_ps_ListMembersRequest_PUT_Count(struct zx_ps_ListMembersRequest_s* x, struct zx_str* y);
void zx_ps_ListMembersRequest_PUT_Offset(struct zx_ps_ListMembersRequest_s* x, struct zx_str* y);
void zx_ps_ListMembersRequest_PUT_Structured(struct zx_ps_ListMembersRequest_s* x, struct zx_str* y);
void zx_ps_ListMembersRequest_PUT_id(struct zx_ps_ListMembersRequest_s* x, struct zx_str* y);

void zx_ps_ListMembersRequest_PUT_TargetObjectID(struct zx_ps_ListMembersRequest_s* x, int n, struct zx_elem_s* y);
void zx_ps_ListMembersRequest_PUT_Subscription(struct zx_ps_ListMembersRequest_s* x, int n, struct zx_ps_Subscription_s* y);

void zx_ps_ListMembersRequest_ADD_TargetObjectID(struct zx_ps_ListMembersRequest_s* x, int n, struct zx_elem_s* z);
void zx_ps_ListMembersRequest_ADD_Subscription(struct zx_ps_ListMembersRequest_s* x, int n, struct zx_ps_Subscription_s* z);

void zx_ps_ListMembersRequest_DEL_TargetObjectID(struct zx_ps_ListMembersRequest_s* x, int n);
void zx_ps_ListMembersRequest_DEL_Subscription(struct zx_ps_ListMembersRequest_s* x, int n);

void zx_ps_ListMembersRequest_REV_TargetObjectID(struct zx_ps_ListMembersRequest_s* x);
void zx_ps_ListMembersRequest_REV_Subscription(struct zx_ps_ListMembersRequest_s* x);

#endif
/* -------------------------- ps_ListMembersResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_ListMembersResponse_EXT
#define zx_ps_ListMembersResponse_EXT
#endif

struct zx_ps_ListMembersResponse_s* zx_DEC_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_ListMembersResponse_s* zx_NEW_ps_ListMembersResponse(struct zx_ctx* c);
void zx_FREE_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ps_ListMembersResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_ListMembersResponse_s* zx_DEEP_CLONE_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ps_ListMembersResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ps_ListMembersResponse_s* x);
int zx_WALK_SO_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ps_ListMembersResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ps_ListMembersResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ps_ListMembersResponse_s* x);
int zx_LEN_WO_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ps_ListMembersResponse_s* x);
char* zx_ENC_SO_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ps_ListMembersResponse_s* x, char* p);
char* zx_ENC_WO_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ps_ListMembersResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ps_ListMembersResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_ListMembersResponse(struct zx_ctx* c, struct zx_ps_ListMembersResponse_s* x);

struct zx_ps_ListMembersResponse_s {
  ZX_ELEM_EXT
  zx_ps_ListMembersResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_ps_Object_s* Object;	/* {0,-1} nada */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_ListMembersResponse_GET_TimeStamp(struct zx_ps_ListMembersResponse_s* x);
struct zx_str* zx_ps_ListMembersResponse_GET_id(struct zx_ps_ListMembersResponse_s* x);

struct zx_lu_Status_s* zx_ps_ListMembersResponse_GET_Status(struct zx_ps_ListMembersResponse_s* x, int n);
struct zx_ps_Object_s* zx_ps_ListMembersResponse_GET_Object(struct zx_ps_ListMembersResponse_s* x, int n);

int zx_ps_ListMembersResponse_NUM_Status(struct zx_ps_ListMembersResponse_s* x);
int zx_ps_ListMembersResponse_NUM_Object(struct zx_ps_ListMembersResponse_s* x);

struct zx_lu_Status_s* zx_ps_ListMembersResponse_POP_Status(struct zx_ps_ListMembersResponse_s* x);
struct zx_ps_Object_s* zx_ps_ListMembersResponse_POP_Object(struct zx_ps_ListMembersResponse_s* x);

void zx_ps_ListMembersResponse_PUSH_Status(struct zx_ps_ListMembersResponse_s* x, struct zx_lu_Status_s* y);
void zx_ps_ListMembersResponse_PUSH_Object(struct zx_ps_ListMembersResponse_s* x, struct zx_ps_Object_s* y);

void zx_ps_ListMembersResponse_PUT_TimeStamp(struct zx_ps_ListMembersResponse_s* x, struct zx_str* y);
void zx_ps_ListMembersResponse_PUT_id(struct zx_ps_ListMembersResponse_s* x, struct zx_str* y);

void zx_ps_ListMembersResponse_PUT_Status(struct zx_ps_ListMembersResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_ps_ListMembersResponse_PUT_Object(struct zx_ps_ListMembersResponse_s* x, int n, struct zx_ps_Object_s* y);

void zx_ps_ListMembersResponse_ADD_Status(struct zx_ps_ListMembersResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_ps_ListMembersResponse_ADD_Object(struct zx_ps_ListMembersResponse_s* x, int n, struct zx_ps_Object_s* z);

void zx_ps_ListMembersResponse_DEL_Status(struct zx_ps_ListMembersResponse_s* x, int n);
void zx_ps_ListMembersResponse_DEL_Object(struct zx_ps_ListMembersResponse_s* x, int n);

void zx_ps_ListMembersResponse_REV_Status(struct zx_ps_ListMembersResponse_s* x);
void zx_ps_ListMembersResponse_REV_Object(struct zx_ps_ListMembersResponse_s* x);

#endif
/* -------------------------- ps_Notification -------------------------- */
/* refby( zx_ps_Notify_s ) */
#ifndef zx_ps_Notification_EXT
#define zx_ps_Notification_EXT
#endif

struct zx_ps_Notification_s* zx_DEC_ps_Notification(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_Notification_s* zx_NEW_ps_Notification(struct zx_ctx* c);
void zx_FREE_ps_Notification(struct zx_ctx* c, struct zx_ps_Notification_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_Notification_s* zx_DEEP_CLONE_ps_Notification(struct zx_ctx* c, struct zx_ps_Notification_s* x, int dup_strs);
void zx_DUP_STRS_ps_Notification(struct zx_ctx* c, struct zx_ps_Notification_s* x);
int zx_WALK_SO_ps_Notification(struct zx_ctx* c, struct zx_ps_Notification_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_Notification(struct zx_ctx* c, struct zx_ps_Notification_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_Notification(struct zx_ctx* c, struct zx_ps_Notification_s* x);
int zx_LEN_WO_ps_Notification(struct zx_ctx* c, struct zx_ps_Notification_s* x);
char* zx_ENC_SO_ps_Notification(struct zx_ctx* c, struct zx_ps_Notification_s* x, char* p);
char* zx_ENC_WO_ps_Notification(struct zx_ctx* c, struct zx_ps_Notification_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_Notification(struct zx_ctx* c, struct zx_ps_Notification_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_Notification(struct zx_ctx* c, struct zx_ps_Notification_s* x);

struct zx_ps_Notification_s {
  ZX_ELEM_EXT
  zx_ps_Notification_EXT
  struct zx_lu_TestResult_s* TestResult;	/* {0,-1} nada */
  struct zx_ps_ItemData_s* ItemData;	/* {0,-1}  */
  struct zx_str* endReason;	/* {0,1} attribute xs:anyURI */
  struct zx_str* expires;	/* {0,1} attribute xs:dateTime */
  struct zx_str* id;	/* {0,1} attribute xs:ID */
  struct zx_str* subscriptionID;	/* {1,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_Notification_GET_endReason(struct zx_ps_Notification_s* x);
struct zx_str* zx_ps_Notification_GET_expires(struct zx_ps_Notification_s* x);
struct zx_str* zx_ps_Notification_GET_id(struct zx_ps_Notification_s* x);
struct zx_str* zx_ps_Notification_GET_subscriptionID(struct zx_ps_Notification_s* x);

struct zx_lu_TestResult_s* zx_ps_Notification_GET_TestResult(struct zx_ps_Notification_s* x, int n);
struct zx_ps_ItemData_s* zx_ps_Notification_GET_ItemData(struct zx_ps_Notification_s* x, int n);

int zx_ps_Notification_NUM_TestResult(struct zx_ps_Notification_s* x);
int zx_ps_Notification_NUM_ItemData(struct zx_ps_Notification_s* x);

struct zx_lu_TestResult_s* zx_ps_Notification_POP_TestResult(struct zx_ps_Notification_s* x);
struct zx_ps_ItemData_s* zx_ps_Notification_POP_ItemData(struct zx_ps_Notification_s* x);

void zx_ps_Notification_PUSH_TestResult(struct zx_ps_Notification_s* x, struct zx_lu_TestResult_s* y);
void zx_ps_Notification_PUSH_ItemData(struct zx_ps_Notification_s* x, struct zx_ps_ItemData_s* y);

void zx_ps_Notification_PUT_endReason(struct zx_ps_Notification_s* x, struct zx_str* y);
void zx_ps_Notification_PUT_expires(struct zx_ps_Notification_s* x, struct zx_str* y);
void zx_ps_Notification_PUT_id(struct zx_ps_Notification_s* x, struct zx_str* y);
void zx_ps_Notification_PUT_subscriptionID(struct zx_ps_Notification_s* x, struct zx_str* y);

void zx_ps_Notification_PUT_TestResult(struct zx_ps_Notification_s* x, int n, struct zx_lu_TestResult_s* y);
void zx_ps_Notification_PUT_ItemData(struct zx_ps_Notification_s* x, int n, struct zx_ps_ItemData_s* y);

void zx_ps_Notification_ADD_TestResult(struct zx_ps_Notification_s* x, int n, struct zx_lu_TestResult_s* z);
void zx_ps_Notification_ADD_ItemData(struct zx_ps_Notification_s* x, int n, struct zx_ps_ItemData_s* z);

void zx_ps_Notification_DEL_TestResult(struct zx_ps_Notification_s* x, int n);
void zx_ps_Notification_DEL_ItemData(struct zx_ps_Notification_s* x, int n);

void zx_ps_Notification_REV_TestResult(struct zx_ps_Notification_s* x);
void zx_ps_Notification_REV_ItemData(struct zx_ps_Notification_s* x);

#endif
/* -------------------------- ps_Notify -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_Notify_EXT
#define zx_ps_Notify_EXT
#endif

struct zx_ps_Notify_s* zx_DEC_ps_Notify(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_Notify_s* zx_NEW_ps_Notify(struct zx_ctx* c);
void zx_FREE_ps_Notify(struct zx_ctx* c, struct zx_ps_Notify_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_Notify_s* zx_DEEP_CLONE_ps_Notify(struct zx_ctx* c, struct zx_ps_Notify_s* x, int dup_strs);
void zx_DUP_STRS_ps_Notify(struct zx_ctx* c, struct zx_ps_Notify_s* x);
int zx_WALK_SO_ps_Notify(struct zx_ctx* c, struct zx_ps_Notify_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_Notify(struct zx_ctx* c, struct zx_ps_Notify_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_Notify(struct zx_ctx* c, struct zx_ps_Notify_s* x);
int zx_LEN_WO_ps_Notify(struct zx_ctx* c, struct zx_ps_Notify_s* x);
char* zx_ENC_SO_ps_Notify(struct zx_ctx* c, struct zx_ps_Notify_s* x, char* p);
char* zx_ENC_WO_ps_Notify(struct zx_ctx* c, struct zx_ps_Notify_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_Notify(struct zx_ctx* c, struct zx_ps_Notify_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_Notify(struct zx_ctx* c, struct zx_ps_Notify_s* x);

struct zx_ps_Notify_s {
  ZX_ELEM_EXT
  zx_ps_Notify_EXT
  struct zx_ps_Notification_s* Notification;	/* {0,-1} nada */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
  struct zx_str* timeStamp;	/* {0,1} attribute xs:dateTime */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_Notify_GET_id(struct zx_ps_Notify_s* x);
struct zx_str* zx_ps_Notify_GET_timeStamp(struct zx_ps_Notify_s* x);

struct zx_ps_Notification_s* zx_ps_Notify_GET_Notification(struct zx_ps_Notify_s* x, int n);

int zx_ps_Notify_NUM_Notification(struct zx_ps_Notify_s* x);

struct zx_ps_Notification_s* zx_ps_Notify_POP_Notification(struct zx_ps_Notify_s* x);

void zx_ps_Notify_PUSH_Notification(struct zx_ps_Notify_s* x, struct zx_ps_Notification_s* y);

void zx_ps_Notify_PUT_id(struct zx_ps_Notify_s* x, struct zx_str* y);
void zx_ps_Notify_PUT_timeStamp(struct zx_ps_Notify_s* x, struct zx_str* y);

void zx_ps_Notify_PUT_Notification(struct zx_ps_Notify_s* x, int n, struct zx_ps_Notification_s* y);

void zx_ps_Notify_ADD_Notification(struct zx_ps_Notify_s* x, int n, struct zx_ps_Notification_s* z);

void zx_ps_Notify_DEL_Notification(struct zx_ps_Notify_s* x, int n);

void zx_ps_Notify_REV_Notification(struct zx_ps_Notify_s* x);

#endif
/* -------------------------- ps_NotifyResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_NotifyResponse_EXT
#define zx_ps_NotifyResponse_EXT
#endif

struct zx_ps_NotifyResponse_s* zx_DEC_ps_NotifyResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_NotifyResponse_s* zx_NEW_ps_NotifyResponse(struct zx_ctx* c);
void zx_FREE_ps_NotifyResponse(struct zx_ctx* c, struct zx_ps_NotifyResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_NotifyResponse_s* zx_DEEP_CLONE_ps_NotifyResponse(struct zx_ctx* c, struct zx_ps_NotifyResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_NotifyResponse(struct zx_ctx* c, struct zx_ps_NotifyResponse_s* x);
int zx_WALK_SO_ps_NotifyResponse(struct zx_ctx* c, struct zx_ps_NotifyResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_NotifyResponse(struct zx_ctx* c, struct zx_ps_NotifyResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_NotifyResponse(struct zx_ctx* c, struct zx_ps_NotifyResponse_s* x);
int zx_LEN_WO_ps_NotifyResponse(struct zx_ctx* c, struct zx_ps_NotifyResponse_s* x);
char* zx_ENC_SO_ps_NotifyResponse(struct zx_ctx* c, struct zx_ps_NotifyResponse_s* x, char* p);
char* zx_ENC_WO_ps_NotifyResponse(struct zx_ctx* c, struct zx_ps_NotifyResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_NotifyResponse(struct zx_ctx* c, struct zx_ps_NotifyResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_NotifyResponse(struct zx_ctx* c, struct zx_ps_NotifyResponse_s* x);

struct zx_ps_NotifyResponse_s {
  ZX_ELEM_EXT
  zx_ps_NotifyResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_str* itemIDRef;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_NotifyResponse_GET_itemIDRef(struct zx_ps_NotifyResponse_s* x);

struct zx_lu_Status_s* zx_ps_NotifyResponse_GET_Status(struct zx_ps_NotifyResponse_s* x, int n);
struct zx_lu_Extension_s* zx_ps_NotifyResponse_GET_Extension(struct zx_ps_NotifyResponse_s* x, int n);

int zx_ps_NotifyResponse_NUM_Status(struct zx_ps_NotifyResponse_s* x);
int zx_ps_NotifyResponse_NUM_Extension(struct zx_ps_NotifyResponse_s* x);

struct zx_lu_Status_s* zx_ps_NotifyResponse_POP_Status(struct zx_ps_NotifyResponse_s* x);
struct zx_lu_Extension_s* zx_ps_NotifyResponse_POP_Extension(struct zx_ps_NotifyResponse_s* x);

void zx_ps_NotifyResponse_PUSH_Status(struct zx_ps_NotifyResponse_s* x, struct zx_lu_Status_s* y);
void zx_ps_NotifyResponse_PUSH_Extension(struct zx_ps_NotifyResponse_s* x, struct zx_lu_Extension_s* y);

void zx_ps_NotifyResponse_PUT_itemIDRef(struct zx_ps_NotifyResponse_s* x, struct zx_str* y);

void zx_ps_NotifyResponse_PUT_Status(struct zx_ps_NotifyResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_ps_NotifyResponse_PUT_Extension(struct zx_ps_NotifyResponse_s* x, int n, struct zx_lu_Extension_s* y);

void zx_ps_NotifyResponse_ADD_Status(struct zx_ps_NotifyResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_ps_NotifyResponse_ADD_Extension(struct zx_ps_NotifyResponse_s* x, int n, struct zx_lu_Extension_s* z);

void zx_ps_NotifyResponse_DEL_Status(struct zx_ps_NotifyResponse_s* x, int n);
void zx_ps_NotifyResponse_DEL_Extension(struct zx_ps_NotifyResponse_s* x, int n);

void zx_ps_NotifyResponse_REV_Status(struct zx_ps_NotifyResponse_s* x);
void zx_ps_NotifyResponse_REV_Extension(struct zx_ps_NotifyResponse_s* x);

#endif
/* -------------------------- ps_Object -------------------------- */
/* refby( zx_ps_QueryObjectsResponse_s zx_ps_AddKnownEntityResponse_s zx_ps_AddCollectionRequest_s zx_ps_AddCollectionResponse_s zx_ps_ItemData_s zx_ps_AddKnownEntityRequest_s zx_ps_GetObjectInfoResponse_s zx_ps_AddEntityResponse_s zx_ps_SetObjectInfoRequest_s zx_ps_Object_s zx_ps_ListMembersResponse_s zx_ps_AddEntityRequest_s ) */
#ifndef zx_ps_Object_EXT
#define zx_ps_Object_EXT
#endif

struct zx_ps_Object_s* zx_DEC_ps_Object(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_Object_s* zx_NEW_ps_Object(struct zx_ctx* c);
void zx_FREE_ps_Object(struct zx_ctx* c, struct zx_ps_Object_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_Object_s* zx_DEEP_CLONE_ps_Object(struct zx_ctx* c, struct zx_ps_Object_s* x, int dup_strs);
void zx_DUP_STRS_ps_Object(struct zx_ctx* c, struct zx_ps_Object_s* x);
int zx_WALK_SO_ps_Object(struct zx_ctx* c, struct zx_ps_Object_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_Object(struct zx_ctx* c, struct zx_ps_Object_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_Object(struct zx_ctx* c, struct zx_ps_Object_s* x);
int zx_LEN_WO_ps_Object(struct zx_ctx* c, struct zx_ps_Object_s* x);
char* zx_ENC_SO_ps_Object(struct zx_ctx* c, struct zx_ps_Object_s* x, char* p);
char* zx_ENC_WO_ps_Object(struct zx_ctx* c, struct zx_ps_Object_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_Object(struct zx_ctx* c, struct zx_ps_Object_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_Object(struct zx_ctx* c, struct zx_ps_Object_s* x);

struct zx_ps_Object_s {
  ZX_ELEM_EXT
  zx_ps_Object_EXT
  struct zx_elem_s* ObjectID;	/* {0,1} xs:anyURI */
  struct zx_ps_DisplayName_s* DisplayName;	/* {1,-1}  */
  struct zx_ps_Tag_s* Tag;	/* {0,1}  */
  struct zx_ps_Object_s* Object;	/* {0,-1} nada */
  struct zx_elem_s* ObjectRef;	/* {0,-1} xs:anyURI */
  struct zx_str* CreatedDateTime;	/* {0,1} attribute xs:dateTime */
  struct zx_str* ModifiedDateTime;	/* {0,1} attribute xs:dateTime */
  struct zx_str* NodeType;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_Object_GET_CreatedDateTime(struct zx_ps_Object_s* x);
struct zx_str* zx_ps_Object_GET_ModifiedDateTime(struct zx_ps_Object_s* x);
struct zx_str* zx_ps_Object_GET_NodeType(struct zx_ps_Object_s* x);

struct zx_elem_s* zx_ps_Object_GET_ObjectID(struct zx_ps_Object_s* x, int n);
struct zx_ps_DisplayName_s* zx_ps_Object_GET_DisplayName(struct zx_ps_Object_s* x, int n);
struct zx_ps_Tag_s* zx_ps_Object_GET_Tag(struct zx_ps_Object_s* x, int n);
struct zx_ps_Object_s* zx_ps_Object_GET_Object(struct zx_ps_Object_s* x, int n);
struct zx_elem_s* zx_ps_Object_GET_ObjectRef(struct zx_ps_Object_s* x, int n);

int zx_ps_Object_NUM_ObjectID(struct zx_ps_Object_s* x);
int zx_ps_Object_NUM_DisplayName(struct zx_ps_Object_s* x);
int zx_ps_Object_NUM_Tag(struct zx_ps_Object_s* x);
int zx_ps_Object_NUM_Object(struct zx_ps_Object_s* x);
int zx_ps_Object_NUM_ObjectRef(struct zx_ps_Object_s* x);

struct zx_elem_s* zx_ps_Object_POP_ObjectID(struct zx_ps_Object_s* x);
struct zx_ps_DisplayName_s* zx_ps_Object_POP_DisplayName(struct zx_ps_Object_s* x);
struct zx_ps_Tag_s* zx_ps_Object_POP_Tag(struct zx_ps_Object_s* x);
struct zx_ps_Object_s* zx_ps_Object_POP_Object(struct zx_ps_Object_s* x);
struct zx_elem_s* zx_ps_Object_POP_ObjectRef(struct zx_ps_Object_s* x);

void zx_ps_Object_PUSH_ObjectID(struct zx_ps_Object_s* x, struct zx_elem_s* y);
void zx_ps_Object_PUSH_DisplayName(struct zx_ps_Object_s* x, struct zx_ps_DisplayName_s* y);
void zx_ps_Object_PUSH_Tag(struct zx_ps_Object_s* x, struct zx_ps_Tag_s* y);
void zx_ps_Object_PUSH_Object(struct zx_ps_Object_s* x, struct zx_ps_Object_s* y);
void zx_ps_Object_PUSH_ObjectRef(struct zx_ps_Object_s* x, struct zx_elem_s* y);

void zx_ps_Object_PUT_CreatedDateTime(struct zx_ps_Object_s* x, struct zx_str* y);
void zx_ps_Object_PUT_ModifiedDateTime(struct zx_ps_Object_s* x, struct zx_str* y);
void zx_ps_Object_PUT_NodeType(struct zx_ps_Object_s* x, struct zx_str* y);

void zx_ps_Object_PUT_ObjectID(struct zx_ps_Object_s* x, int n, struct zx_elem_s* y);
void zx_ps_Object_PUT_DisplayName(struct zx_ps_Object_s* x, int n, struct zx_ps_DisplayName_s* y);
void zx_ps_Object_PUT_Tag(struct zx_ps_Object_s* x, int n, struct zx_ps_Tag_s* y);
void zx_ps_Object_PUT_Object(struct zx_ps_Object_s* x, int n, struct zx_ps_Object_s* y);
void zx_ps_Object_PUT_ObjectRef(struct zx_ps_Object_s* x, int n, struct zx_elem_s* y);

void zx_ps_Object_ADD_ObjectID(struct zx_ps_Object_s* x, int n, struct zx_elem_s* z);
void zx_ps_Object_ADD_DisplayName(struct zx_ps_Object_s* x, int n, struct zx_ps_DisplayName_s* z);
void zx_ps_Object_ADD_Tag(struct zx_ps_Object_s* x, int n, struct zx_ps_Tag_s* z);
void zx_ps_Object_ADD_Object(struct zx_ps_Object_s* x, int n, struct zx_ps_Object_s* z);
void zx_ps_Object_ADD_ObjectRef(struct zx_ps_Object_s* x, int n, struct zx_elem_s* z);

void zx_ps_Object_DEL_ObjectID(struct zx_ps_Object_s* x, int n);
void zx_ps_Object_DEL_DisplayName(struct zx_ps_Object_s* x, int n);
void zx_ps_Object_DEL_Tag(struct zx_ps_Object_s* x, int n);
void zx_ps_Object_DEL_Object(struct zx_ps_Object_s* x, int n);
void zx_ps_Object_DEL_ObjectRef(struct zx_ps_Object_s* x, int n);

void zx_ps_Object_REV_ObjectID(struct zx_ps_Object_s* x);
void zx_ps_Object_REV_DisplayName(struct zx_ps_Object_s* x);
void zx_ps_Object_REV_Tag(struct zx_ps_Object_s* x);
void zx_ps_Object_REV_Object(struct zx_ps_Object_s* x);
void zx_ps_Object_REV_ObjectRef(struct zx_ps_Object_s* x);

#endif
/* -------------------------- ps_QueryObjectsRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_QueryObjectsRequest_EXT
#define zx_ps_QueryObjectsRequest_EXT
#endif

struct zx_ps_QueryObjectsRequest_s* zx_DEC_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_QueryObjectsRequest_s* zx_NEW_ps_QueryObjectsRequest(struct zx_ctx* c);
void zx_FREE_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ps_QueryObjectsRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_QueryObjectsRequest_s* zx_DEEP_CLONE_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ps_QueryObjectsRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ps_QueryObjectsRequest_s* x);
int zx_WALK_SO_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ps_QueryObjectsRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ps_QueryObjectsRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ps_QueryObjectsRequest_s* x);
int zx_LEN_WO_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ps_QueryObjectsRequest_s* x);
char* zx_ENC_SO_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ps_QueryObjectsRequest_s* x, char* p);
char* zx_ENC_WO_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ps_QueryObjectsRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ps_QueryObjectsRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_QueryObjectsRequest(struct zx_ctx* c, struct zx_ps_QueryObjectsRequest_s* x);

struct zx_ps_QueryObjectsRequest_s {
  ZX_ELEM_EXT
  zx_ps_QueryObjectsRequest_EXT
  struct zx_elem_s* Filter;	/* {1,1} xs:string */
  struct zx_ps_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_str* Count;	/* {0,1} attribute xs:nonNegativeInteger */
  struct zx_str* Offset;	/* {0,1} attribute xs:nonNegativeInteger */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_QueryObjectsRequest_GET_Count(struct zx_ps_QueryObjectsRequest_s* x);
struct zx_str* zx_ps_QueryObjectsRequest_GET_Offset(struct zx_ps_QueryObjectsRequest_s* x);
struct zx_str* zx_ps_QueryObjectsRequest_GET_id(struct zx_ps_QueryObjectsRequest_s* x);

struct zx_elem_s* zx_ps_QueryObjectsRequest_GET_Filter(struct zx_ps_QueryObjectsRequest_s* x, int n);
struct zx_ps_Subscription_s* zx_ps_QueryObjectsRequest_GET_Subscription(struct zx_ps_QueryObjectsRequest_s* x, int n);

int zx_ps_QueryObjectsRequest_NUM_Filter(struct zx_ps_QueryObjectsRequest_s* x);
int zx_ps_QueryObjectsRequest_NUM_Subscription(struct zx_ps_QueryObjectsRequest_s* x);

struct zx_elem_s* zx_ps_QueryObjectsRequest_POP_Filter(struct zx_ps_QueryObjectsRequest_s* x);
struct zx_ps_Subscription_s* zx_ps_QueryObjectsRequest_POP_Subscription(struct zx_ps_QueryObjectsRequest_s* x);

void zx_ps_QueryObjectsRequest_PUSH_Filter(struct zx_ps_QueryObjectsRequest_s* x, struct zx_elem_s* y);
void zx_ps_QueryObjectsRequest_PUSH_Subscription(struct zx_ps_QueryObjectsRequest_s* x, struct zx_ps_Subscription_s* y);

void zx_ps_QueryObjectsRequest_PUT_Count(struct zx_ps_QueryObjectsRequest_s* x, struct zx_str* y);
void zx_ps_QueryObjectsRequest_PUT_Offset(struct zx_ps_QueryObjectsRequest_s* x, struct zx_str* y);
void zx_ps_QueryObjectsRequest_PUT_id(struct zx_ps_QueryObjectsRequest_s* x, struct zx_str* y);

void zx_ps_QueryObjectsRequest_PUT_Filter(struct zx_ps_QueryObjectsRequest_s* x, int n, struct zx_elem_s* y);
void zx_ps_QueryObjectsRequest_PUT_Subscription(struct zx_ps_QueryObjectsRequest_s* x, int n, struct zx_ps_Subscription_s* y);

void zx_ps_QueryObjectsRequest_ADD_Filter(struct zx_ps_QueryObjectsRequest_s* x, int n, struct zx_elem_s* z);
void zx_ps_QueryObjectsRequest_ADD_Subscription(struct zx_ps_QueryObjectsRequest_s* x, int n, struct zx_ps_Subscription_s* z);

void zx_ps_QueryObjectsRequest_DEL_Filter(struct zx_ps_QueryObjectsRequest_s* x, int n);
void zx_ps_QueryObjectsRequest_DEL_Subscription(struct zx_ps_QueryObjectsRequest_s* x, int n);

void zx_ps_QueryObjectsRequest_REV_Filter(struct zx_ps_QueryObjectsRequest_s* x);
void zx_ps_QueryObjectsRequest_REV_Subscription(struct zx_ps_QueryObjectsRequest_s* x);

#endif
/* -------------------------- ps_QueryObjectsResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_QueryObjectsResponse_EXT
#define zx_ps_QueryObjectsResponse_EXT
#endif

struct zx_ps_QueryObjectsResponse_s* zx_DEC_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_QueryObjectsResponse_s* zx_NEW_ps_QueryObjectsResponse(struct zx_ctx* c);
void zx_FREE_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ps_QueryObjectsResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_QueryObjectsResponse_s* zx_DEEP_CLONE_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ps_QueryObjectsResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ps_QueryObjectsResponse_s* x);
int zx_WALK_SO_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ps_QueryObjectsResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ps_QueryObjectsResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ps_QueryObjectsResponse_s* x);
int zx_LEN_WO_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ps_QueryObjectsResponse_s* x);
char* zx_ENC_SO_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ps_QueryObjectsResponse_s* x, char* p);
char* zx_ENC_WO_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ps_QueryObjectsResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ps_QueryObjectsResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_QueryObjectsResponse(struct zx_ctx* c, struct zx_ps_QueryObjectsResponse_s* x);

struct zx_ps_QueryObjectsResponse_s {
  ZX_ELEM_EXT
  zx_ps_QueryObjectsResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_ps_Object_s* Object;	/* {0,-1} nada */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_QueryObjectsResponse_GET_TimeStamp(struct zx_ps_QueryObjectsResponse_s* x);
struct zx_str* zx_ps_QueryObjectsResponse_GET_id(struct zx_ps_QueryObjectsResponse_s* x);

struct zx_lu_Status_s* zx_ps_QueryObjectsResponse_GET_Status(struct zx_ps_QueryObjectsResponse_s* x, int n);
struct zx_ps_Object_s* zx_ps_QueryObjectsResponse_GET_Object(struct zx_ps_QueryObjectsResponse_s* x, int n);

int zx_ps_QueryObjectsResponse_NUM_Status(struct zx_ps_QueryObjectsResponse_s* x);
int zx_ps_QueryObjectsResponse_NUM_Object(struct zx_ps_QueryObjectsResponse_s* x);

struct zx_lu_Status_s* zx_ps_QueryObjectsResponse_POP_Status(struct zx_ps_QueryObjectsResponse_s* x);
struct zx_ps_Object_s* zx_ps_QueryObjectsResponse_POP_Object(struct zx_ps_QueryObjectsResponse_s* x);

void zx_ps_QueryObjectsResponse_PUSH_Status(struct zx_ps_QueryObjectsResponse_s* x, struct zx_lu_Status_s* y);
void zx_ps_QueryObjectsResponse_PUSH_Object(struct zx_ps_QueryObjectsResponse_s* x, struct zx_ps_Object_s* y);

void zx_ps_QueryObjectsResponse_PUT_TimeStamp(struct zx_ps_QueryObjectsResponse_s* x, struct zx_str* y);
void zx_ps_QueryObjectsResponse_PUT_id(struct zx_ps_QueryObjectsResponse_s* x, struct zx_str* y);

void zx_ps_QueryObjectsResponse_PUT_Status(struct zx_ps_QueryObjectsResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_ps_QueryObjectsResponse_PUT_Object(struct zx_ps_QueryObjectsResponse_s* x, int n, struct zx_ps_Object_s* y);

void zx_ps_QueryObjectsResponse_ADD_Status(struct zx_ps_QueryObjectsResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_ps_QueryObjectsResponse_ADD_Object(struct zx_ps_QueryObjectsResponse_s* x, int n, struct zx_ps_Object_s* z);

void zx_ps_QueryObjectsResponse_DEL_Status(struct zx_ps_QueryObjectsResponse_s* x, int n);
void zx_ps_QueryObjectsResponse_DEL_Object(struct zx_ps_QueryObjectsResponse_s* x, int n);

void zx_ps_QueryObjectsResponse_REV_Status(struct zx_ps_QueryObjectsResponse_s* x);
void zx_ps_QueryObjectsResponse_REV_Object(struct zx_ps_QueryObjectsResponse_s* x);

#endif
/* -------------------------- ps_RemoveCollectionRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_RemoveCollectionRequest_EXT
#define zx_ps_RemoveCollectionRequest_EXT
#endif

struct zx_ps_RemoveCollectionRequest_s* zx_DEC_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_RemoveCollectionRequest_s* zx_NEW_ps_RemoveCollectionRequest(struct zx_ctx* c);
void zx_FREE_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveCollectionRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_RemoveCollectionRequest_s* zx_DEEP_CLONE_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveCollectionRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveCollectionRequest_s* x);
int zx_WALK_SO_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveCollectionRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveCollectionRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveCollectionRequest_s* x);
int zx_LEN_WO_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveCollectionRequest_s* x);
char* zx_ENC_SO_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveCollectionRequest_s* x, char* p);
char* zx_ENC_WO_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveCollectionRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveCollectionRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_RemoveCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveCollectionRequest_s* x);

struct zx_ps_RemoveCollectionRequest_s {
  ZX_ELEM_EXT
  zx_ps_RemoveCollectionRequest_EXT
  struct zx_elem_s* TargetObjectID;	/* {1,-1} xs:anyURI */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_RemoveCollectionRequest_GET_id(struct zx_ps_RemoveCollectionRequest_s* x);

struct zx_elem_s* zx_ps_RemoveCollectionRequest_GET_TargetObjectID(struct zx_ps_RemoveCollectionRequest_s* x, int n);

int zx_ps_RemoveCollectionRequest_NUM_TargetObjectID(struct zx_ps_RemoveCollectionRequest_s* x);

struct zx_elem_s* zx_ps_RemoveCollectionRequest_POP_TargetObjectID(struct zx_ps_RemoveCollectionRequest_s* x);

void zx_ps_RemoveCollectionRequest_PUSH_TargetObjectID(struct zx_ps_RemoveCollectionRequest_s* x, struct zx_elem_s* y);

void zx_ps_RemoveCollectionRequest_PUT_id(struct zx_ps_RemoveCollectionRequest_s* x, struct zx_str* y);

void zx_ps_RemoveCollectionRequest_PUT_TargetObjectID(struct zx_ps_RemoveCollectionRequest_s* x, int n, struct zx_elem_s* y);

void zx_ps_RemoveCollectionRequest_ADD_TargetObjectID(struct zx_ps_RemoveCollectionRequest_s* x, int n, struct zx_elem_s* z);

void zx_ps_RemoveCollectionRequest_DEL_TargetObjectID(struct zx_ps_RemoveCollectionRequest_s* x, int n);

void zx_ps_RemoveCollectionRequest_REV_TargetObjectID(struct zx_ps_RemoveCollectionRequest_s* x);

#endif
/* -------------------------- ps_RemoveCollectionResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_RemoveCollectionResponse_EXT
#define zx_ps_RemoveCollectionResponse_EXT
#endif

struct zx_ps_RemoveCollectionResponse_s* zx_DEC_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_RemoveCollectionResponse_s* zx_NEW_ps_RemoveCollectionResponse(struct zx_ctx* c);
void zx_FREE_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveCollectionResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_RemoveCollectionResponse_s* zx_DEEP_CLONE_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveCollectionResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveCollectionResponse_s* x);
int zx_WALK_SO_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveCollectionResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveCollectionResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveCollectionResponse_s* x);
int zx_LEN_WO_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveCollectionResponse_s* x);
char* zx_ENC_SO_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveCollectionResponse_s* x, char* p);
char* zx_ENC_WO_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveCollectionResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveCollectionResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_RemoveCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveCollectionResponse_s* x);

struct zx_ps_RemoveCollectionResponse_s {
  ZX_ELEM_EXT
  zx_ps_RemoveCollectionResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_RemoveCollectionResponse_GET_TimeStamp(struct zx_ps_RemoveCollectionResponse_s* x);
struct zx_str* zx_ps_RemoveCollectionResponse_GET_id(struct zx_ps_RemoveCollectionResponse_s* x);

struct zx_lu_Status_s* zx_ps_RemoveCollectionResponse_GET_Status(struct zx_ps_RemoveCollectionResponse_s* x, int n);

int zx_ps_RemoveCollectionResponse_NUM_Status(struct zx_ps_RemoveCollectionResponse_s* x);

struct zx_lu_Status_s* zx_ps_RemoveCollectionResponse_POP_Status(struct zx_ps_RemoveCollectionResponse_s* x);

void zx_ps_RemoveCollectionResponse_PUSH_Status(struct zx_ps_RemoveCollectionResponse_s* x, struct zx_lu_Status_s* y);

void zx_ps_RemoveCollectionResponse_PUT_TimeStamp(struct zx_ps_RemoveCollectionResponse_s* x, struct zx_str* y);
void zx_ps_RemoveCollectionResponse_PUT_id(struct zx_ps_RemoveCollectionResponse_s* x, struct zx_str* y);

void zx_ps_RemoveCollectionResponse_PUT_Status(struct zx_ps_RemoveCollectionResponse_s* x, int n, struct zx_lu_Status_s* y);

void zx_ps_RemoveCollectionResponse_ADD_Status(struct zx_ps_RemoveCollectionResponse_s* x, int n, struct zx_lu_Status_s* z);

void zx_ps_RemoveCollectionResponse_DEL_Status(struct zx_ps_RemoveCollectionResponse_s* x, int n);

void zx_ps_RemoveCollectionResponse_REV_Status(struct zx_ps_RemoveCollectionResponse_s* x);

#endif
/* -------------------------- ps_RemoveEntityRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_RemoveEntityRequest_EXT
#define zx_ps_RemoveEntityRequest_EXT
#endif

struct zx_ps_RemoveEntityRequest_s* zx_DEC_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_RemoveEntityRequest_s* zx_NEW_ps_RemoveEntityRequest(struct zx_ctx* c);
void zx_FREE_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ps_RemoveEntityRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_RemoveEntityRequest_s* zx_DEEP_CLONE_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ps_RemoveEntityRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ps_RemoveEntityRequest_s* x);
int zx_WALK_SO_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ps_RemoveEntityRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ps_RemoveEntityRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ps_RemoveEntityRequest_s* x);
int zx_LEN_WO_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ps_RemoveEntityRequest_s* x);
char* zx_ENC_SO_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ps_RemoveEntityRequest_s* x, char* p);
char* zx_ENC_WO_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ps_RemoveEntityRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ps_RemoveEntityRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_RemoveEntityRequest(struct zx_ctx* c, struct zx_ps_RemoveEntityRequest_s* x);

struct zx_ps_RemoveEntityRequest_s {
  ZX_ELEM_EXT
  zx_ps_RemoveEntityRequest_EXT
  struct zx_elem_s* TargetObjectID;	/* {1,-1} xs:anyURI */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_RemoveEntityRequest_GET_id(struct zx_ps_RemoveEntityRequest_s* x);

struct zx_elem_s* zx_ps_RemoveEntityRequest_GET_TargetObjectID(struct zx_ps_RemoveEntityRequest_s* x, int n);

int zx_ps_RemoveEntityRequest_NUM_TargetObjectID(struct zx_ps_RemoveEntityRequest_s* x);

struct zx_elem_s* zx_ps_RemoveEntityRequest_POP_TargetObjectID(struct zx_ps_RemoveEntityRequest_s* x);

void zx_ps_RemoveEntityRequest_PUSH_TargetObjectID(struct zx_ps_RemoveEntityRequest_s* x, struct zx_elem_s* y);

void zx_ps_RemoveEntityRequest_PUT_id(struct zx_ps_RemoveEntityRequest_s* x, struct zx_str* y);

void zx_ps_RemoveEntityRequest_PUT_TargetObjectID(struct zx_ps_RemoveEntityRequest_s* x, int n, struct zx_elem_s* y);

void zx_ps_RemoveEntityRequest_ADD_TargetObjectID(struct zx_ps_RemoveEntityRequest_s* x, int n, struct zx_elem_s* z);

void zx_ps_RemoveEntityRequest_DEL_TargetObjectID(struct zx_ps_RemoveEntityRequest_s* x, int n);

void zx_ps_RemoveEntityRequest_REV_TargetObjectID(struct zx_ps_RemoveEntityRequest_s* x);

#endif
/* -------------------------- ps_RemoveEntityResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_RemoveEntityResponse_EXT
#define zx_ps_RemoveEntityResponse_EXT
#endif

struct zx_ps_RemoveEntityResponse_s* zx_DEC_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_RemoveEntityResponse_s* zx_NEW_ps_RemoveEntityResponse(struct zx_ctx* c);
void zx_FREE_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ps_RemoveEntityResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_RemoveEntityResponse_s* zx_DEEP_CLONE_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ps_RemoveEntityResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ps_RemoveEntityResponse_s* x);
int zx_WALK_SO_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ps_RemoveEntityResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ps_RemoveEntityResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ps_RemoveEntityResponse_s* x);
int zx_LEN_WO_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ps_RemoveEntityResponse_s* x);
char* zx_ENC_SO_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ps_RemoveEntityResponse_s* x, char* p);
char* zx_ENC_WO_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ps_RemoveEntityResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ps_RemoveEntityResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_RemoveEntityResponse(struct zx_ctx* c, struct zx_ps_RemoveEntityResponse_s* x);

struct zx_ps_RemoveEntityResponse_s {
  ZX_ELEM_EXT
  zx_ps_RemoveEntityResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_RemoveEntityResponse_GET_TimeStamp(struct zx_ps_RemoveEntityResponse_s* x);
struct zx_str* zx_ps_RemoveEntityResponse_GET_id(struct zx_ps_RemoveEntityResponse_s* x);

struct zx_lu_Status_s* zx_ps_RemoveEntityResponse_GET_Status(struct zx_ps_RemoveEntityResponse_s* x, int n);

int zx_ps_RemoveEntityResponse_NUM_Status(struct zx_ps_RemoveEntityResponse_s* x);

struct zx_lu_Status_s* zx_ps_RemoveEntityResponse_POP_Status(struct zx_ps_RemoveEntityResponse_s* x);

void zx_ps_RemoveEntityResponse_PUSH_Status(struct zx_ps_RemoveEntityResponse_s* x, struct zx_lu_Status_s* y);

void zx_ps_RemoveEntityResponse_PUT_TimeStamp(struct zx_ps_RemoveEntityResponse_s* x, struct zx_str* y);
void zx_ps_RemoveEntityResponse_PUT_id(struct zx_ps_RemoveEntityResponse_s* x, struct zx_str* y);

void zx_ps_RemoveEntityResponse_PUT_Status(struct zx_ps_RemoveEntityResponse_s* x, int n, struct zx_lu_Status_s* y);

void zx_ps_RemoveEntityResponse_ADD_Status(struct zx_ps_RemoveEntityResponse_s* x, int n, struct zx_lu_Status_s* z);

void zx_ps_RemoveEntityResponse_DEL_Status(struct zx_ps_RemoveEntityResponse_s* x, int n);

void zx_ps_RemoveEntityResponse_REV_Status(struct zx_ps_RemoveEntityResponse_s* x);

#endif
/* -------------------------- ps_RemoveFromCollectionRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_RemoveFromCollectionRequest_EXT
#define zx_ps_RemoveFromCollectionRequest_EXT
#endif

struct zx_ps_RemoveFromCollectionRequest_s* zx_DEC_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_RemoveFromCollectionRequest_s* zx_NEW_ps_RemoveFromCollectionRequest(struct zx_ctx* c);
void zx_FREE_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_RemoveFromCollectionRequest_s* zx_DEEP_CLONE_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionRequest_s* x);
int zx_WALK_SO_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionRequest_s* x);
int zx_LEN_WO_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionRequest_s* x);
char* zx_ENC_SO_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionRequest_s* x, char* p);
char* zx_ENC_WO_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_RemoveFromCollectionRequest(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionRequest_s* x);

struct zx_ps_RemoveFromCollectionRequest_s {
  ZX_ELEM_EXT
  zx_ps_RemoveFromCollectionRequest_EXT
  struct zx_elem_s* TargetObjectID;	/* {1,1} xs:anyURI */
  struct zx_elem_s* ObjectID;	/* {1,-1} xs:anyURI */
  struct zx_ps_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_RemoveFromCollectionRequest_GET_id(struct zx_ps_RemoveFromCollectionRequest_s* x);

struct zx_elem_s* zx_ps_RemoveFromCollectionRequest_GET_TargetObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x, int n);
struct zx_elem_s* zx_ps_RemoveFromCollectionRequest_GET_ObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x, int n);
struct zx_ps_Subscription_s* zx_ps_RemoveFromCollectionRequest_GET_Subscription(struct zx_ps_RemoveFromCollectionRequest_s* x, int n);

int zx_ps_RemoveFromCollectionRequest_NUM_TargetObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x);
int zx_ps_RemoveFromCollectionRequest_NUM_ObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x);
int zx_ps_RemoveFromCollectionRequest_NUM_Subscription(struct zx_ps_RemoveFromCollectionRequest_s* x);

struct zx_elem_s* zx_ps_RemoveFromCollectionRequest_POP_TargetObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x);
struct zx_elem_s* zx_ps_RemoveFromCollectionRequest_POP_ObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x);
struct zx_ps_Subscription_s* zx_ps_RemoveFromCollectionRequest_POP_Subscription(struct zx_ps_RemoveFromCollectionRequest_s* x);

void zx_ps_RemoveFromCollectionRequest_PUSH_TargetObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x, struct zx_elem_s* y);
void zx_ps_RemoveFromCollectionRequest_PUSH_ObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x, struct zx_elem_s* y);
void zx_ps_RemoveFromCollectionRequest_PUSH_Subscription(struct zx_ps_RemoveFromCollectionRequest_s* x, struct zx_ps_Subscription_s* y);

void zx_ps_RemoveFromCollectionRequest_PUT_id(struct zx_ps_RemoveFromCollectionRequest_s* x, struct zx_str* y);

void zx_ps_RemoveFromCollectionRequest_PUT_TargetObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x, int n, struct zx_elem_s* y);
void zx_ps_RemoveFromCollectionRequest_PUT_ObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x, int n, struct zx_elem_s* y);
void zx_ps_RemoveFromCollectionRequest_PUT_Subscription(struct zx_ps_RemoveFromCollectionRequest_s* x, int n, struct zx_ps_Subscription_s* y);

void zx_ps_RemoveFromCollectionRequest_ADD_TargetObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x, int n, struct zx_elem_s* z);
void zx_ps_RemoveFromCollectionRequest_ADD_ObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x, int n, struct zx_elem_s* z);
void zx_ps_RemoveFromCollectionRequest_ADD_Subscription(struct zx_ps_RemoveFromCollectionRequest_s* x, int n, struct zx_ps_Subscription_s* z);

void zx_ps_RemoveFromCollectionRequest_DEL_TargetObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x, int n);
void zx_ps_RemoveFromCollectionRequest_DEL_ObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x, int n);
void zx_ps_RemoveFromCollectionRequest_DEL_Subscription(struct zx_ps_RemoveFromCollectionRequest_s* x, int n);

void zx_ps_RemoveFromCollectionRequest_REV_TargetObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x);
void zx_ps_RemoveFromCollectionRequest_REV_ObjectID(struct zx_ps_RemoveFromCollectionRequest_s* x);
void zx_ps_RemoveFromCollectionRequest_REV_Subscription(struct zx_ps_RemoveFromCollectionRequest_s* x);

#endif
/* -------------------------- ps_RemoveFromCollectionResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_RemoveFromCollectionResponse_EXT
#define zx_ps_RemoveFromCollectionResponse_EXT
#endif

struct zx_ps_RemoveFromCollectionResponse_s* zx_DEC_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_RemoveFromCollectionResponse_s* zx_NEW_ps_RemoveFromCollectionResponse(struct zx_ctx* c);
void zx_FREE_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_RemoveFromCollectionResponse_s* zx_DEEP_CLONE_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionResponse_s* x);
int zx_WALK_SO_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionResponse_s* x);
int zx_LEN_WO_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionResponse_s* x);
char* zx_ENC_SO_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionResponse_s* x, char* p);
char* zx_ENC_WO_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_RemoveFromCollectionResponse(struct zx_ctx* c, struct zx_ps_RemoveFromCollectionResponse_s* x);

struct zx_ps_RemoveFromCollectionResponse_s {
  ZX_ELEM_EXT
  zx_ps_RemoveFromCollectionResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_RemoveFromCollectionResponse_GET_TimeStamp(struct zx_ps_RemoveFromCollectionResponse_s* x);
struct zx_str* zx_ps_RemoveFromCollectionResponse_GET_id(struct zx_ps_RemoveFromCollectionResponse_s* x);

struct zx_lu_Status_s* zx_ps_RemoveFromCollectionResponse_GET_Status(struct zx_ps_RemoveFromCollectionResponse_s* x, int n);

int zx_ps_RemoveFromCollectionResponse_NUM_Status(struct zx_ps_RemoveFromCollectionResponse_s* x);

struct zx_lu_Status_s* zx_ps_RemoveFromCollectionResponse_POP_Status(struct zx_ps_RemoveFromCollectionResponse_s* x);

void zx_ps_RemoveFromCollectionResponse_PUSH_Status(struct zx_ps_RemoveFromCollectionResponse_s* x, struct zx_lu_Status_s* y);

void zx_ps_RemoveFromCollectionResponse_PUT_TimeStamp(struct zx_ps_RemoveFromCollectionResponse_s* x, struct zx_str* y);
void zx_ps_RemoveFromCollectionResponse_PUT_id(struct zx_ps_RemoveFromCollectionResponse_s* x, struct zx_str* y);

void zx_ps_RemoveFromCollectionResponse_PUT_Status(struct zx_ps_RemoveFromCollectionResponse_s* x, int n, struct zx_lu_Status_s* y);

void zx_ps_RemoveFromCollectionResponse_ADD_Status(struct zx_ps_RemoveFromCollectionResponse_s* x, int n, struct zx_lu_Status_s* z);

void zx_ps_RemoveFromCollectionResponse_DEL_Status(struct zx_ps_RemoveFromCollectionResponse_s* x, int n);

void zx_ps_RemoveFromCollectionResponse_REV_Status(struct zx_ps_RemoveFromCollectionResponse_s* x);

#endif
/* -------------------------- ps_ResolveIdentifierRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_ResolveIdentifierRequest_EXT
#define zx_ps_ResolveIdentifierRequest_EXT
#endif

struct zx_ps_ResolveIdentifierRequest_s* zx_DEC_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_ResolveIdentifierRequest_s* zx_NEW_ps_ResolveIdentifierRequest(struct zx_ctx* c);
void zx_FREE_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ps_ResolveIdentifierRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_ResolveIdentifierRequest_s* zx_DEEP_CLONE_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ps_ResolveIdentifierRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ps_ResolveIdentifierRequest_s* x);
int zx_WALK_SO_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ps_ResolveIdentifierRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ps_ResolveIdentifierRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ps_ResolveIdentifierRequest_s* x);
int zx_LEN_WO_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ps_ResolveIdentifierRequest_s* x);
char* zx_ENC_SO_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ps_ResolveIdentifierRequest_s* x, char* p);
char* zx_ENC_WO_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ps_ResolveIdentifierRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ps_ResolveIdentifierRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_ResolveIdentifierRequest(struct zx_ctx* c, struct zx_ps_ResolveIdentifierRequest_s* x);

struct zx_ps_ResolveIdentifierRequest_s {
  ZX_ELEM_EXT
  zx_ps_ResolveIdentifierRequest_EXT
  struct zx_ps_ResolveInput_s* ResolveInput;	/* {1,-1} nada */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_ResolveIdentifierRequest_GET_id(struct zx_ps_ResolveIdentifierRequest_s* x);

struct zx_ps_ResolveInput_s* zx_ps_ResolveIdentifierRequest_GET_ResolveInput(struct zx_ps_ResolveIdentifierRequest_s* x, int n);

int zx_ps_ResolveIdentifierRequest_NUM_ResolveInput(struct zx_ps_ResolveIdentifierRequest_s* x);

struct zx_ps_ResolveInput_s* zx_ps_ResolveIdentifierRequest_POP_ResolveInput(struct zx_ps_ResolveIdentifierRequest_s* x);

void zx_ps_ResolveIdentifierRequest_PUSH_ResolveInput(struct zx_ps_ResolveIdentifierRequest_s* x, struct zx_ps_ResolveInput_s* y);

void zx_ps_ResolveIdentifierRequest_PUT_id(struct zx_ps_ResolveIdentifierRequest_s* x, struct zx_str* y);

void zx_ps_ResolveIdentifierRequest_PUT_ResolveInput(struct zx_ps_ResolveIdentifierRequest_s* x, int n, struct zx_ps_ResolveInput_s* y);

void zx_ps_ResolveIdentifierRequest_ADD_ResolveInput(struct zx_ps_ResolveIdentifierRequest_s* x, int n, struct zx_ps_ResolveInput_s* z);

void zx_ps_ResolveIdentifierRequest_DEL_ResolveInput(struct zx_ps_ResolveIdentifierRequest_s* x, int n);

void zx_ps_ResolveIdentifierRequest_REV_ResolveInput(struct zx_ps_ResolveIdentifierRequest_s* x);

#endif
/* -------------------------- ps_ResolveIdentifierResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_ResolveIdentifierResponse_EXT
#define zx_ps_ResolveIdentifierResponse_EXT
#endif

struct zx_ps_ResolveIdentifierResponse_s* zx_DEC_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_ResolveIdentifierResponse_s* zx_NEW_ps_ResolveIdentifierResponse(struct zx_ctx* c);
void zx_FREE_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ps_ResolveIdentifierResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_ResolveIdentifierResponse_s* zx_DEEP_CLONE_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ps_ResolveIdentifierResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ps_ResolveIdentifierResponse_s* x);
int zx_WALK_SO_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ps_ResolveIdentifierResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ps_ResolveIdentifierResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ps_ResolveIdentifierResponse_s* x);
int zx_LEN_WO_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ps_ResolveIdentifierResponse_s* x);
char* zx_ENC_SO_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ps_ResolveIdentifierResponse_s* x, char* p);
char* zx_ENC_WO_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ps_ResolveIdentifierResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ps_ResolveIdentifierResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_ResolveIdentifierResponse(struct zx_ctx* c, struct zx_ps_ResolveIdentifierResponse_s* x);

struct zx_ps_ResolveIdentifierResponse_s {
  ZX_ELEM_EXT
  zx_ps_ResolveIdentifierResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_ps_ResolveOutput_s* ResolveOutput;	/* {1,-1} nada */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_ResolveIdentifierResponse_GET_TimeStamp(struct zx_ps_ResolveIdentifierResponse_s* x);
struct zx_str* zx_ps_ResolveIdentifierResponse_GET_id(struct zx_ps_ResolveIdentifierResponse_s* x);

struct zx_lu_Status_s* zx_ps_ResolveIdentifierResponse_GET_Status(struct zx_ps_ResolveIdentifierResponse_s* x, int n);
struct zx_ps_ResolveOutput_s* zx_ps_ResolveIdentifierResponse_GET_ResolveOutput(struct zx_ps_ResolveIdentifierResponse_s* x, int n);

int zx_ps_ResolveIdentifierResponse_NUM_Status(struct zx_ps_ResolveIdentifierResponse_s* x);
int zx_ps_ResolveIdentifierResponse_NUM_ResolveOutput(struct zx_ps_ResolveIdentifierResponse_s* x);

struct zx_lu_Status_s* zx_ps_ResolveIdentifierResponse_POP_Status(struct zx_ps_ResolveIdentifierResponse_s* x);
struct zx_ps_ResolveOutput_s* zx_ps_ResolveIdentifierResponse_POP_ResolveOutput(struct zx_ps_ResolveIdentifierResponse_s* x);

void zx_ps_ResolveIdentifierResponse_PUSH_Status(struct zx_ps_ResolveIdentifierResponse_s* x, struct zx_lu_Status_s* y);
void zx_ps_ResolveIdentifierResponse_PUSH_ResolveOutput(struct zx_ps_ResolveIdentifierResponse_s* x, struct zx_ps_ResolveOutput_s* y);

void zx_ps_ResolveIdentifierResponse_PUT_TimeStamp(struct zx_ps_ResolveIdentifierResponse_s* x, struct zx_str* y);
void zx_ps_ResolveIdentifierResponse_PUT_id(struct zx_ps_ResolveIdentifierResponse_s* x, struct zx_str* y);

void zx_ps_ResolveIdentifierResponse_PUT_Status(struct zx_ps_ResolveIdentifierResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_ps_ResolveIdentifierResponse_PUT_ResolveOutput(struct zx_ps_ResolveIdentifierResponse_s* x, int n, struct zx_ps_ResolveOutput_s* y);

void zx_ps_ResolveIdentifierResponse_ADD_Status(struct zx_ps_ResolveIdentifierResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_ps_ResolveIdentifierResponse_ADD_ResolveOutput(struct zx_ps_ResolveIdentifierResponse_s* x, int n, struct zx_ps_ResolveOutput_s* z);

void zx_ps_ResolveIdentifierResponse_DEL_Status(struct zx_ps_ResolveIdentifierResponse_s* x, int n);
void zx_ps_ResolveIdentifierResponse_DEL_ResolveOutput(struct zx_ps_ResolveIdentifierResponse_s* x, int n);

void zx_ps_ResolveIdentifierResponse_REV_Status(struct zx_ps_ResolveIdentifierResponse_s* x);
void zx_ps_ResolveIdentifierResponse_REV_ResolveOutput(struct zx_ps_ResolveIdentifierResponse_s* x);

#endif
/* -------------------------- ps_ResolveInput -------------------------- */
/* refby( zx_ps_ResolveIdentifierRequest_s ) */
#ifndef zx_ps_ResolveInput_EXT
#define zx_ps_ResolveInput_EXT
#endif

struct zx_ps_ResolveInput_s* zx_DEC_ps_ResolveInput(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_ResolveInput_s* zx_NEW_ps_ResolveInput(struct zx_ctx* c);
void zx_FREE_ps_ResolveInput(struct zx_ctx* c, struct zx_ps_ResolveInput_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_ResolveInput_s* zx_DEEP_CLONE_ps_ResolveInput(struct zx_ctx* c, struct zx_ps_ResolveInput_s* x, int dup_strs);
void zx_DUP_STRS_ps_ResolveInput(struct zx_ctx* c, struct zx_ps_ResolveInput_s* x);
int zx_WALK_SO_ps_ResolveInput(struct zx_ctx* c, struct zx_ps_ResolveInput_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_ResolveInput(struct zx_ctx* c, struct zx_ps_ResolveInput_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_ResolveInput(struct zx_ctx* c, struct zx_ps_ResolveInput_s* x);
int zx_LEN_WO_ps_ResolveInput(struct zx_ctx* c, struct zx_ps_ResolveInput_s* x);
char* zx_ENC_SO_ps_ResolveInput(struct zx_ctx* c, struct zx_ps_ResolveInput_s* x, char* p);
char* zx_ENC_WO_ps_ResolveInput(struct zx_ctx* c, struct zx_ps_ResolveInput_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_ResolveInput(struct zx_ctx* c, struct zx_ps_ResolveInput_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_ResolveInput(struct zx_ctx* c, struct zx_ps_ResolveInput_s* x);

struct zx_ps_ResolveInput_s {
  ZX_ELEM_EXT
  zx_ps_ResolveInput_EXT
  struct zx_sec_TokenPolicy_s* TokenPolicy;	/* {0,1} nada */
  struct zx_sec_Token_s* Token;	/* {0,1} nada */
  struct zx_elem_s* TargetObjectID;	/* {0,1} xs:anyURI */
  struct zx_str* reqID;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_ResolveInput_GET_reqID(struct zx_ps_ResolveInput_s* x);

struct zx_sec_TokenPolicy_s* zx_ps_ResolveInput_GET_TokenPolicy(struct zx_ps_ResolveInput_s* x, int n);
struct zx_sec_Token_s* zx_ps_ResolveInput_GET_Token(struct zx_ps_ResolveInput_s* x, int n);
struct zx_elem_s* zx_ps_ResolveInput_GET_TargetObjectID(struct zx_ps_ResolveInput_s* x, int n);

int zx_ps_ResolveInput_NUM_TokenPolicy(struct zx_ps_ResolveInput_s* x);
int zx_ps_ResolveInput_NUM_Token(struct zx_ps_ResolveInput_s* x);
int zx_ps_ResolveInput_NUM_TargetObjectID(struct zx_ps_ResolveInput_s* x);

struct zx_sec_TokenPolicy_s* zx_ps_ResolveInput_POP_TokenPolicy(struct zx_ps_ResolveInput_s* x);
struct zx_sec_Token_s* zx_ps_ResolveInput_POP_Token(struct zx_ps_ResolveInput_s* x);
struct zx_elem_s* zx_ps_ResolveInput_POP_TargetObjectID(struct zx_ps_ResolveInput_s* x);

void zx_ps_ResolveInput_PUSH_TokenPolicy(struct zx_ps_ResolveInput_s* x, struct zx_sec_TokenPolicy_s* y);
void zx_ps_ResolveInput_PUSH_Token(struct zx_ps_ResolveInput_s* x, struct zx_sec_Token_s* y);
void zx_ps_ResolveInput_PUSH_TargetObjectID(struct zx_ps_ResolveInput_s* x, struct zx_elem_s* y);

void zx_ps_ResolveInput_PUT_reqID(struct zx_ps_ResolveInput_s* x, struct zx_str* y);

void zx_ps_ResolveInput_PUT_TokenPolicy(struct zx_ps_ResolveInput_s* x, int n, struct zx_sec_TokenPolicy_s* y);
void zx_ps_ResolveInput_PUT_Token(struct zx_ps_ResolveInput_s* x, int n, struct zx_sec_Token_s* y);
void zx_ps_ResolveInput_PUT_TargetObjectID(struct zx_ps_ResolveInput_s* x, int n, struct zx_elem_s* y);

void zx_ps_ResolveInput_ADD_TokenPolicy(struct zx_ps_ResolveInput_s* x, int n, struct zx_sec_TokenPolicy_s* z);
void zx_ps_ResolveInput_ADD_Token(struct zx_ps_ResolveInput_s* x, int n, struct zx_sec_Token_s* z);
void zx_ps_ResolveInput_ADD_TargetObjectID(struct zx_ps_ResolveInput_s* x, int n, struct zx_elem_s* z);

void zx_ps_ResolveInput_DEL_TokenPolicy(struct zx_ps_ResolveInput_s* x, int n);
void zx_ps_ResolveInput_DEL_Token(struct zx_ps_ResolveInput_s* x, int n);
void zx_ps_ResolveInput_DEL_TargetObjectID(struct zx_ps_ResolveInput_s* x, int n);

void zx_ps_ResolveInput_REV_TokenPolicy(struct zx_ps_ResolveInput_s* x);
void zx_ps_ResolveInput_REV_Token(struct zx_ps_ResolveInput_s* x);
void zx_ps_ResolveInput_REV_TargetObjectID(struct zx_ps_ResolveInput_s* x);

#endif
/* -------------------------- ps_ResolveOutput -------------------------- */
/* refby( zx_ps_ResolveIdentifierResponse_s ) */
#ifndef zx_ps_ResolveOutput_EXT
#define zx_ps_ResolveOutput_EXT
#endif

struct zx_ps_ResolveOutput_s* zx_DEC_ps_ResolveOutput(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_ResolveOutput_s* zx_NEW_ps_ResolveOutput(struct zx_ctx* c);
void zx_FREE_ps_ResolveOutput(struct zx_ctx* c, struct zx_ps_ResolveOutput_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_ResolveOutput_s* zx_DEEP_CLONE_ps_ResolveOutput(struct zx_ctx* c, struct zx_ps_ResolveOutput_s* x, int dup_strs);
void zx_DUP_STRS_ps_ResolveOutput(struct zx_ctx* c, struct zx_ps_ResolveOutput_s* x);
int zx_WALK_SO_ps_ResolveOutput(struct zx_ctx* c, struct zx_ps_ResolveOutput_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_ResolveOutput(struct zx_ctx* c, struct zx_ps_ResolveOutput_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_ResolveOutput(struct zx_ctx* c, struct zx_ps_ResolveOutput_s* x);
int zx_LEN_WO_ps_ResolveOutput(struct zx_ctx* c, struct zx_ps_ResolveOutput_s* x);
char* zx_ENC_SO_ps_ResolveOutput(struct zx_ctx* c, struct zx_ps_ResolveOutput_s* x, char* p);
char* zx_ENC_WO_ps_ResolveOutput(struct zx_ctx* c, struct zx_ps_ResolveOutput_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_ResolveOutput(struct zx_ctx* c, struct zx_ps_ResolveOutput_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_ResolveOutput(struct zx_ctx* c, struct zx_ps_ResolveOutput_s* x);

struct zx_ps_ResolveOutput_s {
  ZX_ELEM_EXT
  zx_ps_ResolveOutput_EXT
  struct zx_sec_Token_s* Token;	/* {1,1} nada */
  struct zx_str* reqRef;	/* {0,1} attribute lu:IDReferenceType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_ResolveOutput_GET_reqRef(struct zx_ps_ResolveOutput_s* x);

struct zx_sec_Token_s* zx_ps_ResolveOutput_GET_Token(struct zx_ps_ResolveOutput_s* x, int n);

int zx_ps_ResolveOutput_NUM_Token(struct zx_ps_ResolveOutput_s* x);

struct zx_sec_Token_s* zx_ps_ResolveOutput_POP_Token(struct zx_ps_ResolveOutput_s* x);

void zx_ps_ResolveOutput_PUSH_Token(struct zx_ps_ResolveOutput_s* x, struct zx_sec_Token_s* y);

void zx_ps_ResolveOutput_PUT_reqRef(struct zx_ps_ResolveOutput_s* x, struct zx_str* y);

void zx_ps_ResolveOutput_PUT_Token(struct zx_ps_ResolveOutput_s* x, int n, struct zx_sec_Token_s* y);

void zx_ps_ResolveOutput_ADD_Token(struct zx_ps_ResolveOutput_s* x, int n, struct zx_sec_Token_s* z);

void zx_ps_ResolveOutput_DEL_Token(struct zx_ps_ResolveOutput_s* x, int n);

void zx_ps_ResolveOutput_REV_Token(struct zx_ps_ResolveOutput_s* x);

#endif
/* -------------------------- ps_SetObjectInfoRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_SetObjectInfoRequest_EXT
#define zx_ps_SetObjectInfoRequest_EXT
#endif

struct zx_ps_SetObjectInfoRequest_s* zx_DEC_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_SetObjectInfoRequest_s* zx_NEW_ps_SetObjectInfoRequest(struct zx_ctx* c);
void zx_FREE_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_SetObjectInfoRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_SetObjectInfoRequest_s* zx_DEEP_CLONE_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_SetObjectInfoRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_SetObjectInfoRequest_s* x);
int zx_WALK_SO_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_SetObjectInfoRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_SetObjectInfoRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_SetObjectInfoRequest_s* x);
int zx_LEN_WO_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_SetObjectInfoRequest_s* x);
char* zx_ENC_SO_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_SetObjectInfoRequest_s* x, char* p);
char* zx_ENC_WO_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_SetObjectInfoRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_SetObjectInfoRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_SetObjectInfoRequest(struct zx_ctx* c, struct zx_ps_SetObjectInfoRequest_s* x);

struct zx_ps_SetObjectInfoRequest_s {
  ZX_ELEM_EXT
  zx_ps_SetObjectInfoRequest_EXT
  struct zx_ps_Object_s* Object;	/* {1,-1} nada */
  struct zx_ps_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_SetObjectInfoRequest_GET_id(struct zx_ps_SetObjectInfoRequest_s* x);

struct zx_ps_Object_s* zx_ps_SetObjectInfoRequest_GET_Object(struct zx_ps_SetObjectInfoRequest_s* x, int n);
struct zx_ps_Subscription_s* zx_ps_SetObjectInfoRequest_GET_Subscription(struct zx_ps_SetObjectInfoRequest_s* x, int n);

int zx_ps_SetObjectInfoRequest_NUM_Object(struct zx_ps_SetObjectInfoRequest_s* x);
int zx_ps_SetObjectInfoRequest_NUM_Subscription(struct zx_ps_SetObjectInfoRequest_s* x);

struct zx_ps_Object_s* zx_ps_SetObjectInfoRequest_POP_Object(struct zx_ps_SetObjectInfoRequest_s* x);
struct zx_ps_Subscription_s* zx_ps_SetObjectInfoRequest_POP_Subscription(struct zx_ps_SetObjectInfoRequest_s* x);

void zx_ps_SetObjectInfoRequest_PUSH_Object(struct zx_ps_SetObjectInfoRequest_s* x, struct zx_ps_Object_s* y);
void zx_ps_SetObjectInfoRequest_PUSH_Subscription(struct zx_ps_SetObjectInfoRequest_s* x, struct zx_ps_Subscription_s* y);

void zx_ps_SetObjectInfoRequest_PUT_id(struct zx_ps_SetObjectInfoRequest_s* x, struct zx_str* y);

void zx_ps_SetObjectInfoRequest_PUT_Object(struct zx_ps_SetObjectInfoRequest_s* x, int n, struct zx_ps_Object_s* y);
void zx_ps_SetObjectInfoRequest_PUT_Subscription(struct zx_ps_SetObjectInfoRequest_s* x, int n, struct zx_ps_Subscription_s* y);

void zx_ps_SetObjectInfoRequest_ADD_Object(struct zx_ps_SetObjectInfoRequest_s* x, int n, struct zx_ps_Object_s* z);
void zx_ps_SetObjectInfoRequest_ADD_Subscription(struct zx_ps_SetObjectInfoRequest_s* x, int n, struct zx_ps_Subscription_s* z);

void zx_ps_SetObjectInfoRequest_DEL_Object(struct zx_ps_SetObjectInfoRequest_s* x, int n);
void zx_ps_SetObjectInfoRequest_DEL_Subscription(struct zx_ps_SetObjectInfoRequest_s* x, int n);

void zx_ps_SetObjectInfoRequest_REV_Object(struct zx_ps_SetObjectInfoRequest_s* x);
void zx_ps_SetObjectInfoRequest_REV_Subscription(struct zx_ps_SetObjectInfoRequest_s* x);

#endif
/* -------------------------- ps_SetObjectInfoResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_SetObjectInfoResponse_EXT
#define zx_ps_SetObjectInfoResponse_EXT
#endif

struct zx_ps_SetObjectInfoResponse_s* zx_DEC_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_SetObjectInfoResponse_s* zx_NEW_ps_SetObjectInfoResponse(struct zx_ctx* c);
void zx_FREE_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_SetObjectInfoResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_SetObjectInfoResponse_s* zx_DEEP_CLONE_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_SetObjectInfoResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_SetObjectInfoResponse_s* x);
int zx_WALK_SO_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_SetObjectInfoResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_SetObjectInfoResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_SetObjectInfoResponse_s* x);
int zx_LEN_WO_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_SetObjectInfoResponse_s* x);
char* zx_ENC_SO_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_SetObjectInfoResponse_s* x, char* p);
char* zx_ENC_WO_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_SetObjectInfoResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_SetObjectInfoResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_SetObjectInfoResponse(struct zx_ctx* c, struct zx_ps_SetObjectInfoResponse_s* x);

struct zx_ps_SetObjectInfoResponse_s {
  ZX_ELEM_EXT
  zx_ps_SetObjectInfoResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_SetObjectInfoResponse_GET_TimeStamp(struct zx_ps_SetObjectInfoResponse_s* x);
struct zx_str* zx_ps_SetObjectInfoResponse_GET_id(struct zx_ps_SetObjectInfoResponse_s* x);

struct zx_lu_Status_s* zx_ps_SetObjectInfoResponse_GET_Status(struct zx_ps_SetObjectInfoResponse_s* x, int n);

int zx_ps_SetObjectInfoResponse_NUM_Status(struct zx_ps_SetObjectInfoResponse_s* x);

struct zx_lu_Status_s* zx_ps_SetObjectInfoResponse_POP_Status(struct zx_ps_SetObjectInfoResponse_s* x);

void zx_ps_SetObjectInfoResponse_PUSH_Status(struct zx_ps_SetObjectInfoResponse_s* x, struct zx_lu_Status_s* y);

void zx_ps_SetObjectInfoResponse_PUT_TimeStamp(struct zx_ps_SetObjectInfoResponse_s* x, struct zx_str* y);
void zx_ps_SetObjectInfoResponse_PUT_id(struct zx_ps_SetObjectInfoResponse_s* x, struct zx_str* y);

void zx_ps_SetObjectInfoResponse_PUT_Status(struct zx_ps_SetObjectInfoResponse_s* x, int n, struct zx_lu_Status_s* y);

void zx_ps_SetObjectInfoResponse_ADD_Status(struct zx_ps_SetObjectInfoResponse_s* x, int n, struct zx_lu_Status_s* z);

void zx_ps_SetObjectInfoResponse_DEL_Status(struct zx_ps_SetObjectInfoResponse_s* x, int n);

void zx_ps_SetObjectInfoResponse_REV_Status(struct zx_ps_SetObjectInfoResponse_s* x);

#endif
/* -------------------------- ps_Subscription -------------------------- */
/* refby( zx_ps_AddCollectionRequest_s zx_ps_AddToCollectionRequest_s zx_ps_AddKnownEntityRequest_s zx_ps_TestMembershipRequest_s zx_ps_SetObjectInfoRequest_s zx_ps_ListMembersRequest_s zx_ps_QueryObjectsRequest_s zx_ps_RemoveFromCollectionRequest_s zx_ps_GetObjectInfoRequest_s zx_ps_AddEntityRequest_s ) */
#ifndef zx_ps_Subscription_EXT
#define zx_ps_Subscription_EXT
#endif

struct zx_ps_Subscription_s* zx_DEC_ps_Subscription(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_Subscription_s* zx_NEW_ps_Subscription(struct zx_ctx* c);
void zx_FREE_ps_Subscription(struct zx_ctx* c, struct zx_ps_Subscription_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_Subscription_s* zx_DEEP_CLONE_ps_Subscription(struct zx_ctx* c, struct zx_ps_Subscription_s* x, int dup_strs);
void zx_DUP_STRS_ps_Subscription(struct zx_ctx* c, struct zx_ps_Subscription_s* x);
int zx_WALK_SO_ps_Subscription(struct zx_ctx* c, struct zx_ps_Subscription_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_Subscription(struct zx_ctx* c, struct zx_ps_Subscription_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_Subscription(struct zx_ctx* c, struct zx_ps_Subscription_s* x);
int zx_LEN_WO_ps_Subscription(struct zx_ctx* c, struct zx_ps_Subscription_s* x);
char* zx_ENC_SO_ps_Subscription(struct zx_ctx* c, struct zx_ps_Subscription_s* x, char* p);
char* zx_ENC_WO_ps_Subscription(struct zx_ctx* c, struct zx_ps_Subscription_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_Subscription(struct zx_ctx* c, struct zx_ps_Subscription_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_Subscription(struct zx_ctx* c, struct zx_ps_Subscription_s* x);

struct zx_ps_Subscription_s {
  ZX_ELEM_EXT
  zx_ps_Subscription_EXT
  struct zx_subs_RefItem_s* RefItem;	/* {0,-1} nada */
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_str* adminNotifyToRef;	/* {0,1} attribute xs:anyURI */
  struct zx_str* expires;	/* {0,1} attribute xs:dateTime */
  struct zx_str* id;	/* {0,1} attribute xs:ID */
  struct zx_str* includeData;	/* {0,1} attribute Yes */
  struct zx_str* notifyToRef;	/* {1,1} attribute xs:anyURI */
  struct zx_str* starts;	/* {0,1} attribute xs:dateTime */
  struct zx_str* subscriptionID;	/* {1,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_Subscription_GET_adminNotifyToRef(struct zx_ps_Subscription_s* x);
struct zx_str* zx_ps_Subscription_GET_expires(struct zx_ps_Subscription_s* x);
struct zx_str* zx_ps_Subscription_GET_id(struct zx_ps_Subscription_s* x);
struct zx_str* zx_ps_Subscription_GET_includeData(struct zx_ps_Subscription_s* x);
struct zx_str* zx_ps_Subscription_GET_notifyToRef(struct zx_ps_Subscription_s* x);
struct zx_str* zx_ps_Subscription_GET_starts(struct zx_ps_Subscription_s* x);
struct zx_str* zx_ps_Subscription_GET_subscriptionID(struct zx_ps_Subscription_s* x);

struct zx_subs_RefItem_s* zx_ps_Subscription_GET_RefItem(struct zx_ps_Subscription_s* x, int n);
struct zx_lu_Extension_s* zx_ps_Subscription_GET_Extension(struct zx_ps_Subscription_s* x, int n);

int zx_ps_Subscription_NUM_RefItem(struct zx_ps_Subscription_s* x);
int zx_ps_Subscription_NUM_Extension(struct zx_ps_Subscription_s* x);

struct zx_subs_RefItem_s* zx_ps_Subscription_POP_RefItem(struct zx_ps_Subscription_s* x);
struct zx_lu_Extension_s* zx_ps_Subscription_POP_Extension(struct zx_ps_Subscription_s* x);

void zx_ps_Subscription_PUSH_RefItem(struct zx_ps_Subscription_s* x, struct zx_subs_RefItem_s* y);
void zx_ps_Subscription_PUSH_Extension(struct zx_ps_Subscription_s* x, struct zx_lu_Extension_s* y);

void zx_ps_Subscription_PUT_adminNotifyToRef(struct zx_ps_Subscription_s* x, struct zx_str* y);
void zx_ps_Subscription_PUT_expires(struct zx_ps_Subscription_s* x, struct zx_str* y);
void zx_ps_Subscription_PUT_id(struct zx_ps_Subscription_s* x, struct zx_str* y);
void zx_ps_Subscription_PUT_includeData(struct zx_ps_Subscription_s* x, struct zx_str* y);
void zx_ps_Subscription_PUT_notifyToRef(struct zx_ps_Subscription_s* x, struct zx_str* y);
void zx_ps_Subscription_PUT_starts(struct zx_ps_Subscription_s* x, struct zx_str* y);
void zx_ps_Subscription_PUT_subscriptionID(struct zx_ps_Subscription_s* x, struct zx_str* y);

void zx_ps_Subscription_PUT_RefItem(struct zx_ps_Subscription_s* x, int n, struct zx_subs_RefItem_s* y);
void zx_ps_Subscription_PUT_Extension(struct zx_ps_Subscription_s* x, int n, struct zx_lu_Extension_s* y);

void zx_ps_Subscription_ADD_RefItem(struct zx_ps_Subscription_s* x, int n, struct zx_subs_RefItem_s* z);
void zx_ps_Subscription_ADD_Extension(struct zx_ps_Subscription_s* x, int n, struct zx_lu_Extension_s* z);

void zx_ps_Subscription_DEL_RefItem(struct zx_ps_Subscription_s* x, int n);
void zx_ps_Subscription_DEL_Extension(struct zx_ps_Subscription_s* x, int n);

void zx_ps_Subscription_REV_RefItem(struct zx_ps_Subscription_s* x);
void zx_ps_Subscription_REV_Extension(struct zx_ps_Subscription_s* x);

#endif
/* -------------------------- ps_Tag -------------------------- */
/* refby( zx_ps_Object_s ) */
#ifndef zx_ps_Tag_EXT
#define zx_ps_Tag_EXT
#endif

struct zx_ps_Tag_s* zx_DEC_ps_Tag(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_Tag_s* zx_NEW_ps_Tag(struct zx_ctx* c);
void zx_FREE_ps_Tag(struct zx_ctx* c, struct zx_ps_Tag_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_Tag_s* zx_DEEP_CLONE_ps_Tag(struct zx_ctx* c, struct zx_ps_Tag_s* x, int dup_strs);
void zx_DUP_STRS_ps_Tag(struct zx_ctx* c, struct zx_ps_Tag_s* x);
int zx_WALK_SO_ps_Tag(struct zx_ctx* c, struct zx_ps_Tag_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_Tag(struct zx_ctx* c, struct zx_ps_Tag_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_Tag(struct zx_ctx* c, struct zx_ps_Tag_s* x);
int zx_LEN_WO_ps_Tag(struct zx_ctx* c, struct zx_ps_Tag_s* x);
char* zx_ENC_SO_ps_Tag(struct zx_ctx* c, struct zx_ps_Tag_s* x, char* p);
char* zx_ENC_WO_ps_Tag(struct zx_ctx* c, struct zx_ps_Tag_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_Tag(struct zx_ctx* c, struct zx_ps_Tag_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_Tag(struct zx_ctx* c, struct zx_ps_Tag_s* x);

struct zx_ps_Tag_s {
  ZX_ELEM_EXT
  zx_ps_Tag_EXT
  struct zx_str* Ref;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_Tag_GET_Ref(struct zx_ps_Tag_s* x);





void zx_ps_Tag_PUT_Ref(struct zx_ps_Tag_s* x, struct zx_str* y);





#endif
/* -------------------------- ps_TestMembershipRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_TestMembershipRequest_EXT
#define zx_ps_TestMembershipRequest_EXT
#endif

struct zx_ps_TestMembershipRequest_s* zx_DEC_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_TestMembershipRequest_s* zx_NEW_ps_TestMembershipRequest(struct zx_ctx* c);
void zx_FREE_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ps_TestMembershipRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_TestMembershipRequest_s* zx_DEEP_CLONE_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ps_TestMembershipRequest_s* x, int dup_strs);
void zx_DUP_STRS_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ps_TestMembershipRequest_s* x);
int zx_WALK_SO_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ps_TestMembershipRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ps_TestMembershipRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ps_TestMembershipRequest_s* x);
int zx_LEN_WO_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ps_TestMembershipRequest_s* x);
char* zx_ENC_SO_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ps_TestMembershipRequest_s* x, char* p);
char* zx_ENC_WO_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ps_TestMembershipRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ps_TestMembershipRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_TestMembershipRequest(struct zx_ctx* c, struct zx_ps_TestMembershipRequest_s* x);

struct zx_ps_TestMembershipRequest_s {
  ZX_ELEM_EXT
  zx_ps_TestMembershipRequest_EXT
  struct zx_elem_s* TargetObjectID;	/* {0,1} xs:anyURI */
  struct zx_sec_Token_s* Token;	/* {1,1} nada */
  struct zx_ps_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_TestMembershipRequest_GET_id(struct zx_ps_TestMembershipRequest_s* x);

struct zx_elem_s* zx_ps_TestMembershipRequest_GET_TargetObjectID(struct zx_ps_TestMembershipRequest_s* x, int n);
struct zx_sec_Token_s* zx_ps_TestMembershipRequest_GET_Token(struct zx_ps_TestMembershipRequest_s* x, int n);
struct zx_ps_Subscription_s* zx_ps_TestMembershipRequest_GET_Subscription(struct zx_ps_TestMembershipRequest_s* x, int n);

int zx_ps_TestMembershipRequest_NUM_TargetObjectID(struct zx_ps_TestMembershipRequest_s* x);
int zx_ps_TestMembershipRequest_NUM_Token(struct zx_ps_TestMembershipRequest_s* x);
int zx_ps_TestMembershipRequest_NUM_Subscription(struct zx_ps_TestMembershipRequest_s* x);

struct zx_elem_s* zx_ps_TestMembershipRequest_POP_TargetObjectID(struct zx_ps_TestMembershipRequest_s* x);
struct zx_sec_Token_s* zx_ps_TestMembershipRequest_POP_Token(struct zx_ps_TestMembershipRequest_s* x);
struct zx_ps_Subscription_s* zx_ps_TestMembershipRequest_POP_Subscription(struct zx_ps_TestMembershipRequest_s* x);

void zx_ps_TestMembershipRequest_PUSH_TargetObjectID(struct zx_ps_TestMembershipRequest_s* x, struct zx_elem_s* y);
void zx_ps_TestMembershipRequest_PUSH_Token(struct zx_ps_TestMembershipRequest_s* x, struct zx_sec_Token_s* y);
void zx_ps_TestMembershipRequest_PUSH_Subscription(struct zx_ps_TestMembershipRequest_s* x, struct zx_ps_Subscription_s* y);

void zx_ps_TestMembershipRequest_PUT_id(struct zx_ps_TestMembershipRequest_s* x, struct zx_str* y);

void zx_ps_TestMembershipRequest_PUT_TargetObjectID(struct zx_ps_TestMembershipRequest_s* x, int n, struct zx_elem_s* y);
void zx_ps_TestMembershipRequest_PUT_Token(struct zx_ps_TestMembershipRequest_s* x, int n, struct zx_sec_Token_s* y);
void zx_ps_TestMembershipRequest_PUT_Subscription(struct zx_ps_TestMembershipRequest_s* x, int n, struct zx_ps_Subscription_s* y);

void zx_ps_TestMembershipRequest_ADD_TargetObjectID(struct zx_ps_TestMembershipRequest_s* x, int n, struct zx_elem_s* z);
void zx_ps_TestMembershipRequest_ADD_Token(struct zx_ps_TestMembershipRequest_s* x, int n, struct zx_sec_Token_s* z);
void zx_ps_TestMembershipRequest_ADD_Subscription(struct zx_ps_TestMembershipRequest_s* x, int n, struct zx_ps_Subscription_s* z);

void zx_ps_TestMembershipRequest_DEL_TargetObjectID(struct zx_ps_TestMembershipRequest_s* x, int n);
void zx_ps_TestMembershipRequest_DEL_Token(struct zx_ps_TestMembershipRequest_s* x, int n);
void zx_ps_TestMembershipRequest_DEL_Subscription(struct zx_ps_TestMembershipRequest_s* x, int n);

void zx_ps_TestMembershipRequest_REV_TargetObjectID(struct zx_ps_TestMembershipRequest_s* x);
void zx_ps_TestMembershipRequest_REV_Token(struct zx_ps_TestMembershipRequest_s* x);
void zx_ps_TestMembershipRequest_REV_Subscription(struct zx_ps_TestMembershipRequest_s* x);

#endif
/* -------------------------- ps_TestMembershipResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_ps_TestMembershipResponse_EXT
#define zx_ps_TestMembershipResponse_EXT
#endif

struct zx_ps_TestMembershipResponse_s* zx_DEC_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_ps_TestMembershipResponse_s* zx_NEW_ps_TestMembershipResponse(struct zx_ctx* c);
void zx_FREE_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ps_TestMembershipResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_ps_TestMembershipResponse_s* zx_DEEP_CLONE_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ps_TestMembershipResponse_s* x, int dup_strs);
void zx_DUP_STRS_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ps_TestMembershipResponse_s* x);
int zx_WALK_SO_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ps_TestMembershipResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ps_TestMembershipResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ps_TestMembershipResponse_s* x);
int zx_LEN_WO_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ps_TestMembershipResponse_s* x);
char* zx_ENC_SO_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ps_TestMembershipResponse_s* x, char* p);
char* zx_ENC_WO_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ps_TestMembershipResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ps_TestMembershipResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_ps_TestMembershipResponse(struct zx_ctx* c, struct zx_ps_TestMembershipResponse_s* x);

struct zx_ps_TestMembershipResponse_s {
  ZX_ELEM_EXT
  zx_ps_TestMembershipResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_elem_s* Result;	/* {0,1} xs:boolean */
  struct zx_str* TimeStamp;	/* {1,1} attribute mm7:relativeOrAbsoluteDateType */
  struct zx_str* id;	/* {1,1} attribute xs:ID */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_ps_TestMembershipResponse_GET_TimeStamp(struct zx_ps_TestMembershipResponse_s* x);
struct zx_str* zx_ps_TestMembershipResponse_GET_id(struct zx_ps_TestMembershipResponse_s* x);

struct zx_lu_Status_s* zx_ps_TestMembershipResponse_GET_Status(struct zx_ps_TestMembershipResponse_s* x, int n);
struct zx_elem_s* zx_ps_TestMembershipResponse_GET_Result(struct zx_ps_TestMembershipResponse_s* x, int n);

int zx_ps_TestMembershipResponse_NUM_Status(struct zx_ps_TestMembershipResponse_s* x);
int zx_ps_TestMembershipResponse_NUM_Result(struct zx_ps_TestMembershipResponse_s* x);

struct zx_lu_Status_s* zx_ps_TestMembershipResponse_POP_Status(struct zx_ps_TestMembershipResponse_s* x);
struct zx_elem_s* zx_ps_TestMembershipResponse_POP_Result(struct zx_ps_TestMembershipResponse_s* x);

void zx_ps_TestMembershipResponse_PUSH_Status(struct zx_ps_TestMembershipResponse_s* x, struct zx_lu_Status_s* y);
void zx_ps_TestMembershipResponse_PUSH_Result(struct zx_ps_TestMembershipResponse_s* x, struct zx_elem_s* y);

void zx_ps_TestMembershipResponse_PUT_TimeStamp(struct zx_ps_TestMembershipResponse_s* x, struct zx_str* y);
void zx_ps_TestMembershipResponse_PUT_id(struct zx_ps_TestMembershipResponse_s* x, struct zx_str* y);

void zx_ps_TestMembershipResponse_PUT_Status(struct zx_ps_TestMembershipResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_ps_TestMembershipResponse_PUT_Result(struct zx_ps_TestMembershipResponse_s* x, int n, struct zx_elem_s* y);

void zx_ps_TestMembershipResponse_ADD_Status(struct zx_ps_TestMembershipResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_ps_TestMembershipResponse_ADD_Result(struct zx_ps_TestMembershipResponse_s* x, int n, struct zx_elem_s* z);

void zx_ps_TestMembershipResponse_DEL_Status(struct zx_ps_TestMembershipResponse_s* x, int n);
void zx_ps_TestMembershipResponse_DEL_Result(struct zx_ps_TestMembershipResponse_s* x, int n);

void zx_ps_TestMembershipResponse_REV_Status(struct zx_ps_TestMembershipResponse_s* x);
void zx_ps_TestMembershipResponse_REV_Result(struct zx_ps_TestMembershipResponse_s* x);

#endif

#endif
