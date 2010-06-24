/* c/zx-xasa-data.h - WARNING: This header was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Datastructure design, topography, and layout
 * Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for
 * terms and conditions of use. Element and attributes names as well
 * as some topography are derived from schema descriptions that were used as
 * input and may be subject to their own copright. */

#ifndef _c_zx_xasa_data_h
#define _c_zx_xasa_data_h

#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"

#ifndef ZX_ELEM_EXT
#define ZX_ELEM_EXT  /* This extension point should be defined by who includes this file. */
#endif

/* -------------------------- xasa_XACMLAuthzDecisionStatement -------------------------- */
/* refby( zx_sa11_Assertion_s zx_sa_Assertion_s zx_ff12_Assertion_s ) */
#ifndef zx_xasa_XACMLAuthzDecisionStatement_EXT
#define zx_xasa_XACMLAuthzDecisionStatement_EXT
#endif

struct zx_xasa_XACMLAuthzDecisionStatement_s* zx_DEC_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xasa_XACMLAuthzDecisionStatement_s* zx_NEW_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c);
void zx_FREE_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_xasa_XACMLAuthzDecisionStatement_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xasa_XACMLAuthzDecisionStatement_s* zx_DEEP_CLONE_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_xasa_XACMLAuthzDecisionStatement_s* x, int dup_strs);
void zx_DUP_STRS_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_xasa_XACMLAuthzDecisionStatement_s* x);
int zx_WALK_SO_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_xasa_XACMLAuthzDecisionStatement_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_xasa_XACMLAuthzDecisionStatement_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_xasa_XACMLAuthzDecisionStatement_s* x);
int zx_LEN_WO_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_xasa_XACMLAuthzDecisionStatement_s* x);
char* zx_ENC_SO_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_xasa_XACMLAuthzDecisionStatement_s* x, char* p);
char* zx_ENC_WO_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_xasa_XACMLAuthzDecisionStatement_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_xasa_XACMLAuthzDecisionStatement_s* x);
struct zx_str* zx_EASY_ENC_WO_xasa_XACMLAuthzDecisionStatement(struct zx_ctx* c, struct zx_xasa_XACMLAuthzDecisionStatement_s* x);

struct zx_xasa_XACMLAuthzDecisionStatement_s {
  ZX_ELEM_EXT
  zx_xasa_XACMLAuthzDecisionStatement_EXT
  struct zx_xac_Response_s* Response;	/* {0,1}  */
  struct zx_xac_Request_s* Request;	/* {0,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_xac_Response_s* zx_xasa_XACMLAuthzDecisionStatement_GET_Response(struct zx_xasa_XACMLAuthzDecisionStatement_s* x, int n);
struct zx_xac_Request_s* zx_xasa_XACMLAuthzDecisionStatement_GET_Request(struct zx_xasa_XACMLAuthzDecisionStatement_s* x, int n);

int zx_xasa_XACMLAuthzDecisionStatement_NUM_Response(struct zx_xasa_XACMLAuthzDecisionStatement_s* x);
int zx_xasa_XACMLAuthzDecisionStatement_NUM_Request(struct zx_xasa_XACMLAuthzDecisionStatement_s* x);

struct zx_xac_Response_s* zx_xasa_XACMLAuthzDecisionStatement_POP_Response(struct zx_xasa_XACMLAuthzDecisionStatement_s* x);
struct zx_xac_Request_s* zx_xasa_XACMLAuthzDecisionStatement_POP_Request(struct zx_xasa_XACMLAuthzDecisionStatement_s* x);

void zx_xasa_XACMLAuthzDecisionStatement_PUSH_Response(struct zx_xasa_XACMLAuthzDecisionStatement_s* x, struct zx_xac_Response_s* y);
void zx_xasa_XACMLAuthzDecisionStatement_PUSH_Request(struct zx_xasa_XACMLAuthzDecisionStatement_s* x, struct zx_xac_Request_s* y);


void zx_xasa_XACMLAuthzDecisionStatement_PUT_Response(struct zx_xasa_XACMLAuthzDecisionStatement_s* x, int n, struct zx_xac_Response_s* y);
void zx_xasa_XACMLAuthzDecisionStatement_PUT_Request(struct zx_xasa_XACMLAuthzDecisionStatement_s* x, int n, struct zx_xac_Request_s* y);

void zx_xasa_XACMLAuthzDecisionStatement_ADD_Response(struct zx_xasa_XACMLAuthzDecisionStatement_s* x, int n, struct zx_xac_Response_s* z);
void zx_xasa_XACMLAuthzDecisionStatement_ADD_Request(struct zx_xasa_XACMLAuthzDecisionStatement_s* x, int n, struct zx_xac_Request_s* z);

void zx_xasa_XACMLAuthzDecisionStatement_DEL_Response(struct zx_xasa_XACMLAuthzDecisionStatement_s* x, int n);
void zx_xasa_XACMLAuthzDecisionStatement_DEL_Request(struct zx_xasa_XACMLAuthzDecisionStatement_s* x, int n);

void zx_xasa_XACMLAuthzDecisionStatement_REV_Response(struct zx_xasa_XACMLAuthzDecisionStatement_s* x);
void zx_xasa_XACMLAuthzDecisionStatement_REV_Request(struct zx_xasa_XACMLAuthzDecisionStatement_s* x);

#endif
/* -------------------------- xasa_XACMLPolicyStatement -------------------------- */
/* refby( zx_sa11_Assertion_s zx_sa_Assertion_s zx_ff12_Assertion_s ) */
#ifndef zx_xasa_XACMLPolicyStatement_EXT
#define zx_xasa_XACMLPolicyStatement_EXT
#endif

struct zx_xasa_XACMLPolicyStatement_s* zx_DEC_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xasa_XACMLPolicyStatement_s* zx_NEW_xasa_XACMLPolicyStatement(struct zx_ctx* c);
void zx_FREE_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_xasa_XACMLPolicyStatement_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xasa_XACMLPolicyStatement_s* zx_DEEP_CLONE_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_xasa_XACMLPolicyStatement_s* x, int dup_strs);
void zx_DUP_STRS_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_xasa_XACMLPolicyStatement_s* x);
int zx_WALK_SO_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_xasa_XACMLPolicyStatement_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_xasa_XACMLPolicyStatement_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_xasa_XACMLPolicyStatement_s* x);
int zx_LEN_WO_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_xasa_XACMLPolicyStatement_s* x);
char* zx_ENC_SO_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_xasa_XACMLPolicyStatement_s* x, char* p);
char* zx_ENC_WO_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_xasa_XACMLPolicyStatement_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_xasa_XACMLPolicyStatement_s* x);
struct zx_str* zx_EASY_ENC_WO_xasa_XACMLPolicyStatement(struct zx_ctx* c, struct zx_xasa_XACMLPolicyStatement_s* x);

struct zx_xasa_XACMLPolicyStatement_s {
  ZX_ELEM_EXT
  zx_xasa_XACMLPolicyStatement_EXT
  struct zx_xa_Policy_s* Policy;	/* {0,1} nada */
  struct zx_xa_PolicySet_s* PolicySet;	/* {0,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_Policy_s* zx_xasa_XACMLPolicyStatement_GET_Policy(struct zx_xasa_XACMLPolicyStatement_s* x, int n);
struct zx_xa_PolicySet_s* zx_xasa_XACMLPolicyStatement_GET_PolicySet(struct zx_xasa_XACMLPolicyStatement_s* x, int n);

int zx_xasa_XACMLPolicyStatement_NUM_Policy(struct zx_xasa_XACMLPolicyStatement_s* x);
int zx_xasa_XACMLPolicyStatement_NUM_PolicySet(struct zx_xasa_XACMLPolicyStatement_s* x);

struct zx_xa_Policy_s* zx_xasa_XACMLPolicyStatement_POP_Policy(struct zx_xasa_XACMLPolicyStatement_s* x);
struct zx_xa_PolicySet_s* zx_xasa_XACMLPolicyStatement_POP_PolicySet(struct zx_xasa_XACMLPolicyStatement_s* x);

void zx_xasa_XACMLPolicyStatement_PUSH_Policy(struct zx_xasa_XACMLPolicyStatement_s* x, struct zx_xa_Policy_s* y);
void zx_xasa_XACMLPolicyStatement_PUSH_PolicySet(struct zx_xasa_XACMLPolicyStatement_s* x, struct zx_xa_PolicySet_s* y);


void zx_xasa_XACMLPolicyStatement_PUT_Policy(struct zx_xasa_XACMLPolicyStatement_s* x, int n, struct zx_xa_Policy_s* y);
void zx_xasa_XACMLPolicyStatement_PUT_PolicySet(struct zx_xasa_XACMLPolicyStatement_s* x, int n, struct zx_xa_PolicySet_s* y);

void zx_xasa_XACMLPolicyStatement_ADD_Policy(struct zx_xasa_XACMLPolicyStatement_s* x, int n, struct zx_xa_Policy_s* z);
void zx_xasa_XACMLPolicyStatement_ADD_PolicySet(struct zx_xasa_XACMLPolicyStatement_s* x, int n, struct zx_xa_PolicySet_s* z);

void zx_xasa_XACMLPolicyStatement_DEL_Policy(struct zx_xasa_XACMLPolicyStatement_s* x, int n);
void zx_xasa_XACMLPolicyStatement_DEL_PolicySet(struct zx_xasa_XACMLPolicyStatement_s* x, int n);

void zx_xasa_XACMLPolicyStatement_REV_Policy(struct zx_xasa_XACMLPolicyStatement_s* x);
void zx_xasa_XACMLPolicyStatement_REV_PolicySet(struct zx_xasa_XACMLPolicyStatement_s* x);

#endif

#endif
