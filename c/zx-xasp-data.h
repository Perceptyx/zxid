/* c/zx-xasp-data.h - WARNING: This header was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Datastructure design, topography, and layout
 * Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for
 * terms and conditions of use. Element and attributes names as well
 * as some topography are derived from schema descriptions that were used as
 * input and may be subject to their own copright. */

#ifndef _c_zx_xasp_data_h
#define _c_zx_xasp_data_h

#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"

#ifndef ZX_ELEM_EXT
#define ZX_ELEM_EXT  /* This extension point should be defined by who includes this file. */
#endif

/* -------------------------- xasp_XACMLAuthzDecisionQuery -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_xasp_XACMLAuthzDecisionQuery_EXT
#define zx_xasp_XACMLAuthzDecisionQuery_EXT
#endif

struct zx_xasp_XACMLAuthzDecisionQuery_s* zx_DEC_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xasp_XACMLAuthzDecisionQuery_s* zx_NEW_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c);
void zx_FREE_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xasp_XACMLAuthzDecisionQuery_s* zx_DEEP_CLONE_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int dup_strs);
void zx_DUP_STRS_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
int zx_WALK_SO_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_xasp_XACMLAuthzDecisionQuery_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_xasp_XACMLAuthzDecisionQuery_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
int zx_LEN_WO_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
char* zx_ENC_SO_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_xasp_XACMLAuthzDecisionQuery_s* x, char* p);
char* zx_ENC_WO_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_xasp_XACMLAuthzDecisionQuery_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
struct zx_str* zx_EASY_ENC_WO_xasp_XACMLAuthzDecisionQuery(struct zx_ctx* c, struct zx_xasp_XACMLAuthzDecisionQuery_s* x);

struct zx_xasp_XACMLAuthzDecisionQuery_s {
  ZX_ELEM_EXT
  zx_xasp_XACMLAuthzDecisionQuery_EXT
  struct zx_sa_Issuer_s* Issuer;	/* {0,1} nada */
  struct zx_ds_Signature_s* Signature;	/* {0,1} nada */
  struct zx_sp_Extensions_s* Extensions;	/* {0,1}  */
  struct zx_xac_Request_s* Request;	/* {1,1} nada */
  struct zx_str* Consent;	/* {0,1} attribute xs:anyURI */
  struct zx_str* Destination;	/* {0,1} attribute xs:anyURI */
  struct zx_str* ID;	/* {1,1} attribute xs:anyURI */
  struct zx_str* InputContextOnly;	/* {0,1} attribute boolean */
  struct zx_str* IssueInstant;	/* {1,1} attribute xs:dateTime */
  struct zx_str* ReturnContext;	/* {0,1} attribute boolean */
  struct zx_str* Version;	/* {1,1} attribute xa:VersionType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xasp_XACMLAuthzDecisionQuery_GET_Consent(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
struct zx_str* zx_xasp_XACMLAuthzDecisionQuery_GET_Destination(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
struct zx_str* zx_xasp_XACMLAuthzDecisionQuery_GET_ID(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
struct zx_str* zx_xasp_XACMLAuthzDecisionQuery_GET_InputContextOnly(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
struct zx_str* zx_xasp_XACMLAuthzDecisionQuery_GET_IssueInstant(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
struct zx_str* zx_xasp_XACMLAuthzDecisionQuery_GET_ReturnContext(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
struct zx_str* zx_xasp_XACMLAuthzDecisionQuery_GET_Version(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);

struct zx_sa_Issuer_s* zx_xasp_XACMLAuthzDecisionQuery_GET_Issuer(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n);
struct zx_ds_Signature_s* zx_xasp_XACMLAuthzDecisionQuery_GET_Signature(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n);
struct zx_sp_Extensions_s* zx_xasp_XACMLAuthzDecisionQuery_GET_Extensions(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n);
struct zx_xac_Request_s* zx_xasp_XACMLAuthzDecisionQuery_GET_Request(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n);

int zx_xasp_XACMLAuthzDecisionQuery_NUM_Issuer(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
int zx_xasp_XACMLAuthzDecisionQuery_NUM_Signature(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
int zx_xasp_XACMLAuthzDecisionQuery_NUM_Extensions(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
int zx_xasp_XACMLAuthzDecisionQuery_NUM_Request(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);

struct zx_sa_Issuer_s* zx_xasp_XACMLAuthzDecisionQuery_POP_Issuer(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
struct zx_ds_Signature_s* zx_xasp_XACMLAuthzDecisionQuery_POP_Signature(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
struct zx_sp_Extensions_s* zx_xasp_XACMLAuthzDecisionQuery_POP_Extensions(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
struct zx_xac_Request_s* zx_xasp_XACMLAuthzDecisionQuery_POP_Request(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);

void zx_xasp_XACMLAuthzDecisionQuery_PUSH_Issuer(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, struct zx_sa_Issuer_s* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUSH_Signature(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, struct zx_ds_Signature_s* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUSH_Extensions(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, struct zx_sp_Extensions_s* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUSH_Request(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, struct zx_xac_Request_s* y);

void zx_xasp_XACMLAuthzDecisionQuery_PUT_Consent(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, struct zx_str* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUT_Destination(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, struct zx_str* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUT_ID(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, struct zx_str* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUT_InputContextOnly(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, struct zx_str* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUT_IssueInstant(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, struct zx_str* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUT_ReturnContext(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, struct zx_str* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUT_Version(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, struct zx_str* y);

void zx_xasp_XACMLAuthzDecisionQuery_PUT_Issuer(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n, struct zx_sa_Issuer_s* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUT_Signature(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n, struct zx_ds_Signature_s* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUT_Extensions(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n, struct zx_sp_Extensions_s* y);
void zx_xasp_XACMLAuthzDecisionQuery_PUT_Request(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n, struct zx_xac_Request_s* y);

void zx_xasp_XACMLAuthzDecisionQuery_ADD_Issuer(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n, struct zx_sa_Issuer_s* z);
void zx_xasp_XACMLAuthzDecisionQuery_ADD_Signature(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n, struct zx_ds_Signature_s* z);
void zx_xasp_XACMLAuthzDecisionQuery_ADD_Extensions(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n, struct zx_sp_Extensions_s* z);
void zx_xasp_XACMLAuthzDecisionQuery_ADD_Request(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n, struct zx_xac_Request_s* z);

void zx_xasp_XACMLAuthzDecisionQuery_DEL_Issuer(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n);
void zx_xasp_XACMLAuthzDecisionQuery_DEL_Signature(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n);
void zx_xasp_XACMLAuthzDecisionQuery_DEL_Extensions(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n);
void zx_xasp_XACMLAuthzDecisionQuery_DEL_Request(struct zx_xasp_XACMLAuthzDecisionQuery_s* x, int n);

void zx_xasp_XACMLAuthzDecisionQuery_REV_Issuer(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
void zx_xasp_XACMLAuthzDecisionQuery_REV_Signature(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
void zx_xasp_XACMLAuthzDecisionQuery_REV_Extensions(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);
void zx_xasp_XACMLAuthzDecisionQuery_REV_Request(struct zx_xasp_XACMLAuthzDecisionQuery_s* x);

#endif
/* -------------------------- xasp_XACMLPolicyQuery -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_xasp_XACMLPolicyQuery_EXT
#define zx_xasp_XACMLPolicyQuery_EXT
#endif

struct zx_xasp_XACMLPolicyQuery_s* zx_DEC_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xasp_XACMLPolicyQuery_s* zx_NEW_xasp_XACMLPolicyQuery(struct zx_ctx* c);
void zx_FREE_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_xasp_XACMLPolicyQuery_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xasp_XACMLPolicyQuery_s* zx_DEEP_CLONE_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_xasp_XACMLPolicyQuery_s* x, int dup_strs);
void zx_DUP_STRS_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_xasp_XACMLPolicyQuery_s* x);
int zx_WALK_SO_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_xasp_XACMLPolicyQuery_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_xasp_XACMLPolicyQuery_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_xasp_XACMLPolicyQuery_s* x);
int zx_LEN_WO_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_xasp_XACMLPolicyQuery_s* x);
char* zx_ENC_SO_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_xasp_XACMLPolicyQuery_s* x, char* p);
char* zx_ENC_WO_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_xasp_XACMLPolicyQuery_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_xasp_XACMLPolicyQuery_s* x);
struct zx_str* zx_EASY_ENC_WO_xasp_XACMLPolicyQuery(struct zx_ctx* c, struct zx_xasp_XACMLPolicyQuery_s* x);

struct zx_xasp_XACMLPolicyQuery_s {
  ZX_ELEM_EXT
  zx_xasp_XACMLPolicyQuery_EXT
  struct zx_sa_Issuer_s* Issuer;	/* {0,1} nada */
  struct zx_ds_Signature_s* Signature;	/* {0,1} nada */
  struct zx_sp_Extensions_s* Extensions;	/* {0,1}  */
  struct zx_xac_Request_s* Request;	/* {0,1} nada */
  struct zx_xa_Target_s* Target;	/* {0,1} nada */
  struct zx_xa_PolicySetIdReference_s* PolicySetIdReference;	/* {0,1} nada */
  struct zx_xa_PolicyIdReference_s* PolicyIdReference;	/* {0,1} nada */
  struct zx_str* Consent;	/* {0,1} attribute xs:anyURI */
  struct zx_str* Destination;	/* {0,1} attribute xs:anyURI */
  struct zx_str* ID;	/* {1,1} attribute xs:anyURI */
  struct zx_str* IssueInstant;	/* {1,1} attribute xs:dateTime */
  struct zx_str* Version;	/* {1,1} attribute xa:VersionType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xasp_XACMLPolicyQuery_GET_Consent(struct zx_xasp_XACMLPolicyQuery_s* x);
struct zx_str* zx_xasp_XACMLPolicyQuery_GET_Destination(struct zx_xasp_XACMLPolicyQuery_s* x);
struct zx_str* zx_xasp_XACMLPolicyQuery_GET_ID(struct zx_xasp_XACMLPolicyQuery_s* x);
struct zx_str* zx_xasp_XACMLPolicyQuery_GET_IssueInstant(struct zx_xasp_XACMLPolicyQuery_s* x);
struct zx_str* zx_xasp_XACMLPolicyQuery_GET_Version(struct zx_xasp_XACMLPolicyQuery_s* x);

struct zx_sa_Issuer_s* zx_xasp_XACMLPolicyQuery_GET_Issuer(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
struct zx_ds_Signature_s* zx_xasp_XACMLPolicyQuery_GET_Signature(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
struct zx_sp_Extensions_s* zx_xasp_XACMLPolicyQuery_GET_Extensions(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
struct zx_xac_Request_s* zx_xasp_XACMLPolicyQuery_GET_Request(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
struct zx_xa_Target_s* zx_xasp_XACMLPolicyQuery_GET_Target(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
struct zx_xa_PolicySetIdReference_s* zx_xasp_XACMLPolicyQuery_GET_PolicySetIdReference(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
struct zx_xa_PolicyIdReference_s* zx_xasp_XACMLPolicyQuery_GET_PolicyIdReference(struct zx_xasp_XACMLPolicyQuery_s* x, int n);

int zx_xasp_XACMLPolicyQuery_NUM_Issuer(struct zx_xasp_XACMLPolicyQuery_s* x);
int zx_xasp_XACMLPolicyQuery_NUM_Signature(struct zx_xasp_XACMLPolicyQuery_s* x);
int zx_xasp_XACMLPolicyQuery_NUM_Extensions(struct zx_xasp_XACMLPolicyQuery_s* x);
int zx_xasp_XACMLPolicyQuery_NUM_Request(struct zx_xasp_XACMLPolicyQuery_s* x);
int zx_xasp_XACMLPolicyQuery_NUM_Target(struct zx_xasp_XACMLPolicyQuery_s* x);
int zx_xasp_XACMLPolicyQuery_NUM_PolicySetIdReference(struct zx_xasp_XACMLPolicyQuery_s* x);
int zx_xasp_XACMLPolicyQuery_NUM_PolicyIdReference(struct zx_xasp_XACMLPolicyQuery_s* x);

struct zx_sa_Issuer_s* zx_xasp_XACMLPolicyQuery_POP_Issuer(struct zx_xasp_XACMLPolicyQuery_s* x);
struct zx_ds_Signature_s* zx_xasp_XACMLPolicyQuery_POP_Signature(struct zx_xasp_XACMLPolicyQuery_s* x);
struct zx_sp_Extensions_s* zx_xasp_XACMLPolicyQuery_POP_Extensions(struct zx_xasp_XACMLPolicyQuery_s* x);
struct zx_xac_Request_s* zx_xasp_XACMLPolicyQuery_POP_Request(struct zx_xasp_XACMLPolicyQuery_s* x);
struct zx_xa_Target_s* zx_xasp_XACMLPolicyQuery_POP_Target(struct zx_xasp_XACMLPolicyQuery_s* x);
struct zx_xa_PolicySetIdReference_s* zx_xasp_XACMLPolicyQuery_POP_PolicySetIdReference(struct zx_xasp_XACMLPolicyQuery_s* x);
struct zx_xa_PolicyIdReference_s* zx_xasp_XACMLPolicyQuery_POP_PolicyIdReference(struct zx_xasp_XACMLPolicyQuery_s* x);

void zx_xasp_XACMLPolicyQuery_PUSH_Issuer(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_sa_Issuer_s* y);
void zx_xasp_XACMLPolicyQuery_PUSH_Signature(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_ds_Signature_s* y);
void zx_xasp_XACMLPolicyQuery_PUSH_Extensions(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_sp_Extensions_s* y);
void zx_xasp_XACMLPolicyQuery_PUSH_Request(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_xac_Request_s* y);
void zx_xasp_XACMLPolicyQuery_PUSH_Target(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_xa_Target_s* y);
void zx_xasp_XACMLPolicyQuery_PUSH_PolicySetIdReference(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_xa_PolicySetIdReference_s* y);
void zx_xasp_XACMLPolicyQuery_PUSH_PolicyIdReference(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_xa_PolicyIdReference_s* y);

void zx_xasp_XACMLPolicyQuery_PUT_Consent(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_str* y);
void zx_xasp_XACMLPolicyQuery_PUT_Destination(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_str* y);
void zx_xasp_XACMLPolicyQuery_PUT_ID(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_str* y);
void zx_xasp_XACMLPolicyQuery_PUT_IssueInstant(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_str* y);
void zx_xasp_XACMLPolicyQuery_PUT_Version(struct zx_xasp_XACMLPolicyQuery_s* x, struct zx_str* y);

void zx_xasp_XACMLPolicyQuery_PUT_Issuer(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_sa_Issuer_s* y);
void zx_xasp_XACMLPolicyQuery_PUT_Signature(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_ds_Signature_s* y);
void zx_xasp_XACMLPolicyQuery_PUT_Extensions(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_sp_Extensions_s* y);
void zx_xasp_XACMLPolicyQuery_PUT_Request(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_xac_Request_s* y);
void zx_xasp_XACMLPolicyQuery_PUT_Target(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_xa_Target_s* y);
void zx_xasp_XACMLPolicyQuery_PUT_PolicySetIdReference(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_xa_PolicySetIdReference_s* y);
void zx_xasp_XACMLPolicyQuery_PUT_PolicyIdReference(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_xa_PolicyIdReference_s* y);

void zx_xasp_XACMLPolicyQuery_ADD_Issuer(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_sa_Issuer_s* z);
void zx_xasp_XACMLPolicyQuery_ADD_Signature(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_ds_Signature_s* z);
void zx_xasp_XACMLPolicyQuery_ADD_Extensions(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_sp_Extensions_s* z);
void zx_xasp_XACMLPolicyQuery_ADD_Request(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_xac_Request_s* z);
void zx_xasp_XACMLPolicyQuery_ADD_Target(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_xa_Target_s* z);
void zx_xasp_XACMLPolicyQuery_ADD_PolicySetIdReference(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_xa_PolicySetIdReference_s* z);
void zx_xasp_XACMLPolicyQuery_ADD_PolicyIdReference(struct zx_xasp_XACMLPolicyQuery_s* x, int n, struct zx_xa_PolicyIdReference_s* z);

void zx_xasp_XACMLPolicyQuery_DEL_Issuer(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
void zx_xasp_XACMLPolicyQuery_DEL_Signature(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
void zx_xasp_XACMLPolicyQuery_DEL_Extensions(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
void zx_xasp_XACMLPolicyQuery_DEL_Request(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
void zx_xasp_XACMLPolicyQuery_DEL_Target(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
void zx_xasp_XACMLPolicyQuery_DEL_PolicySetIdReference(struct zx_xasp_XACMLPolicyQuery_s* x, int n);
void zx_xasp_XACMLPolicyQuery_DEL_PolicyIdReference(struct zx_xasp_XACMLPolicyQuery_s* x, int n);

void zx_xasp_XACMLPolicyQuery_REV_Issuer(struct zx_xasp_XACMLPolicyQuery_s* x);
void zx_xasp_XACMLPolicyQuery_REV_Signature(struct zx_xasp_XACMLPolicyQuery_s* x);
void zx_xasp_XACMLPolicyQuery_REV_Extensions(struct zx_xasp_XACMLPolicyQuery_s* x);
void zx_xasp_XACMLPolicyQuery_REV_Request(struct zx_xasp_XACMLPolicyQuery_s* x);
void zx_xasp_XACMLPolicyQuery_REV_Target(struct zx_xasp_XACMLPolicyQuery_s* x);
void zx_xasp_XACMLPolicyQuery_REV_PolicySetIdReference(struct zx_xasp_XACMLPolicyQuery_s* x);
void zx_xasp_XACMLPolicyQuery_REV_PolicyIdReference(struct zx_xasp_XACMLPolicyQuery_s* x);

#endif

#endif
