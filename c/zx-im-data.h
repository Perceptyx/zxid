/* c/zx-im-data.h - WARNING: This header was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Datastructure design, topography, and layout
 * Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for
 * terms and conditions of use. Element and attributes names as well
 * as some topography are derived from schema descriptions that were used as
 * input and may be subject to their own copright. */

#ifndef _c_zx_im_data_h
#define _c_zx_im_data_h

#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"

#ifndef ZX_ELEM_EXT
#define ZX_ELEM_EXT  /* This extension point should be defined by who includes this file. */
#endif

/* -------------------------- im_IdentityMappingRequest -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_im_IdentityMappingRequest_EXT
#define zx_im_IdentityMappingRequest_EXT
#endif

struct zx_im_IdentityMappingRequest_s* zx_DEC_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_im_IdentityMappingRequest_s* zx_NEW_im_IdentityMappingRequest(struct zx_ctx* c);
void zx_FREE_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_im_IdentityMappingRequest_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_im_IdentityMappingRequest_s* zx_DEEP_CLONE_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_im_IdentityMappingRequest_s* x, int dup_strs);
void zx_DUP_STRS_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_im_IdentityMappingRequest_s* x);
int zx_WALK_SO_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_im_IdentityMappingRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_im_IdentityMappingRequest_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_im_IdentityMappingRequest_s* x);
int zx_LEN_WO_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_im_IdentityMappingRequest_s* x);
char* zx_ENC_SO_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_im_IdentityMappingRequest_s* x, char* p);
char* zx_ENC_WO_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_im_IdentityMappingRequest_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_im_IdentityMappingRequest_s* x);
struct zx_str* zx_EASY_ENC_WO_im_IdentityMappingRequest(struct zx_ctx* c, struct zx_im_IdentityMappingRequest_s* x);

struct zx_im_IdentityMappingRequest_s {
  ZX_ELEM_EXT
  zx_im_IdentityMappingRequest_EXT
  struct zx_im_MappingInput_s* MappingInput;	/* {1,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_im_MappingInput_s* zx_im_IdentityMappingRequest_GET_MappingInput(struct zx_im_IdentityMappingRequest_s* x, int n);

int zx_im_IdentityMappingRequest_NUM_MappingInput(struct zx_im_IdentityMappingRequest_s* x);

struct zx_im_MappingInput_s* zx_im_IdentityMappingRequest_POP_MappingInput(struct zx_im_IdentityMappingRequest_s* x);

void zx_im_IdentityMappingRequest_PUSH_MappingInput(struct zx_im_IdentityMappingRequest_s* x, struct zx_im_MappingInput_s* y);


void zx_im_IdentityMappingRequest_PUT_MappingInput(struct zx_im_IdentityMappingRequest_s* x, int n, struct zx_im_MappingInput_s* y);

void zx_im_IdentityMappingRequest_ADD_MappingInput(struct zx_im_IdentityMappingRequest_s* x, int n, struct zx_im_MappingInput_s* z);

void zx_im_IdentityMappingRequest_DEL_MappingInput(struct zx_im_IdentityMappingRequest_s* x, int n);

void zx_im_IdentityMappingRequest_REV_MappingInput(struct zx_im_IdentityMappingRequest_s* x);

#endif
/* -------------------------- im_IdentityMappingResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_im_IdentityMappingResponse_EXT
#define zx_im_IdentityMappingResponse_EXT
#endif

struct zx_im_IdentityMappingResponse_s* zx_DEC_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_im_IdentityMappingResponse_s* zx_NEW_im_IdentityMappingResponse(struct zx_ctx* c);
void zx_FREE_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_im_IdentityMappingResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_im_IdentityMappingResponse_s* zx_DEEP_CLONE_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_im_IdentityMappingResponse_s* x, int dup_strs);
void zx_DUP_STRS_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_im_IdentityMappingResponse_s* x);
int zx_WALK_SO_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_im_IdentityMappingResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_im_IdentityMappingResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_im_IdentityMappingResponse_s* x);
int zx_LEN_WO_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_im_IdentityMappingResponse_s* x);
char* zx_ENC_SO_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_im_IdentityMappingResponse_s* x, char* p);
char* zx_ENC_WO_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_im_IdentityMappingResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_im_IdentityMappingResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_im_IdentityMappingResponse(struct zx_ctx* c, struct zx_im_IdentityMappingResponse_s* x);

struct zx_im_IdentityMappingResponse_s {
  ZX_ELEM_EXT
  zx_im_IdentityMappingResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_im_MappingOutput_s* MappingOutput;	/* {0,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_lu_Status_s* zx_im_IdentityMappingResponse_GET_Status(struct zx_im_IdentityMappingResponse_s* x, int n);
struct zx_im_MappingOutput_s* zx_im_IdentityMappingResponse_GET_MappingOutput(struct zx_im_IdentityMappingResponse_s* x, int n);

int zx_im_IdentityMappingResponse_NUM_Status(struct zx_im_IdentityMappingResponse_s* x);
int zx_im_IdentityMappingResponse_NUM_MappingOutput(struct zx_im_IdentityMappingResponse_s* x);

struct zx_lu_Status_s* zx_im_IdentityMappingResponse_POP_Status(struct zx_im_IdentityMappingResponse_s* x);
struct zx_im_MappingOutput_s* zx_im_IdentityMappingResponse_POP_MappingOutput(struct zx_im_IdentityMappingResponse_s* x);

void zx_im_IdentityMappingResponse_PUSH_Status(struct zx_im_IdentityMappingResponse_s* x, struct zx_lu_Status_s* y);
void zx_im_IdentityMappingResponse_PUSH_MappingOutput(struct zx_im_IdentityMappingResponse_s* x, struct zx_im_MappingOutput_s* y);


void zx_im_IdentityMappingResponse_PUT_Status(struct zx_im_IdentityMappingResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_im_IdentityMappingResponse_PUT_MappingOutput(struct zx_im_IdentityMappingResponse_s* x, int n, struct zx_im_MappingOutput_s* y);

void zx_im_IdentityMappingResponse_ADD_Status(struct zx_im_IdentityMappingResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_im_IdentityMappingResponse_ADD_MappingOutput(struct zx_im_IdentityMappingResponse_s* x, int n, struct zx_im_MappingOutput_s* z);

void zx_im_IdentityMappingResponse_DEL_Status(struct zx_im_IdentityMappingResponse_s* x, int n);
void zx_im_IdentityMappingResponse_DEL_MappingOutput(struct zx_im_IdentityMappingResponse_s* x, int n);

void zx_im_IdentityMappingResponse_REV_Status(struct zx_im_IdentityMappingResponse_s* x);
void zx_im_IdentityMappingResponse_REV_MappingOutput(struct zx_im_IdentityMappingResponse_s* x);

#endif
/* -------------------------- im_MappingInput -------------------------- */
/* refby( zx_im_IdentityMappingRequest_s ) */
#ifndef zx_im_MappingInput_EXT
#define zx_im_MappingInput_EXT
#endif

struct zx_im_MappingInput_s* zx_DEC_im_MappingInput(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_im_MappingInput_s* zx_NEW_im_MappingInput(struct zx_ctx* c);
void zx_FREE_im_MappingInput(struct zx_ctx* c, struct zx_im_MappingInput_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_im_MappingInput_s* zx_DEEP_CLONE_im_MappingInput(struct zx_ctx* c, struct zx_im_MappingInput_s* x, int dup_strs);
void zx_DUP_STRS_im_MappingInput(struct zx_ctx* c, struct zx_im_MappingInput_s* x);
int zx_WALK_SO_im_MappingInput(struct zx_ctx* c, struct zx_im_MappingInput_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_im_MappingInput(struct zx_ctx* c, struct zx_im_MappingInput_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_im_MappingInput(struct zx_ctx* c, struct zx_im_MappingInput_s* x);
int zx_LEN_WO_im_MappingInput(struct zx_ctx* c, struct zx_im_MappingInput_s* x);
char* zx_ENC_SO_im_MappingInput(struct zx_ctx* c, struct zx_im_MappingInput_s* x, char* p);
char* zx_ENC_WO_im_MappingInput(struct zx_ctx* c, struct zx_im_MappingInput_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_im_MappingInput(struct zx_ctx* c, struct zx_im_MappingInput_s* x);
struct zx_str* zx_EASY_ENC_WO_im_MappingInput(struct zx_ctx* c, struct zx_im_MappingInput_s* x);

struct zx_im_MappingInput_s {
  ZX_ELEM_EXT
  zx_im_MappingInput_EXT
  struct zx_sec_TokenPolicy_s* TokenPolicy;	/* {0,1} nada */
  struct zx_sec_Token_s* Token;	/* {0,1} nada */
  struct zx_str* reqID;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_im_MappingInput_GET_reqID(struct zx_im_MappingInput_s* x);

struct zx_sec_TokenPolicy_s* zx_im_MappingInput_GET_TokenPolicy(struct zx_im_MappingInput_s* x, int n);
struct zx_sec_Token_s* zx_im_MappingInput_GET_Token(struct zx_im_MappingInput_s* x, int n);

int zx_im_MappingInput_NUM_TokenPolicy(struct zx_im_MappingInput_s* x);
int zx_im_MappingInput_NUM_Token(struct zx_im_MappingInput_s* x);

struct zx_sec_TokenPolicy_s* zx_im_MappingInput_POP_TokenPolicy(struct zx_im_MappingInput_s* x);
struct zx_sec_Token_s* zx_im_MappingInput_POP_Token(struct zx_im_MappingInput_s* x);

void zx_im_MappingInput_PUSH_TokenPolicy(struct zx_im_MappingInput_s* x, struct zx_sec_TokenPolicy_s* y);
void zx_im_MappingInput_PUSH_Token(struct zx_im_MappingInput_s* x, struct zx_sec_Token_s* y);

void zx_im_MappingInput_PUT_reqID(struct zx_im_MappingInput_s* x, struct zx_str* y);

void zx_im_MappingInput_PUT_TokenPolicy(struct zx_im_MappingInput_s* x, int n, struct zx_sec_TokenPolicy_s* y);
void zx_im_MappingInput_PUT_Token(struct zx_im_MappingInput_s* x, int n, struct zx_sec_Token_s* y);

void zx_im_MappingInput_ADD_TokenPolicy(struct zx_im_MappingInput_s* x, int n, struct zx_sec_TokenPolicy_s* z);
void zx_im_MappingInput_ADD_Token(struct zx_im_MappingInput_s* x, int n, struct zx_sec_Token_s* z);

void zx_im_MappingInput_DEL_TokenPolicy(struct zx_im_MappingInput_s* x, int n);
void zx_im_MappingInput_DEL_Token(struct zx_im_MappingInput_s* x, int n);

void zx_im_MappingInput_REV_TokenPolicy(struct zx_im_MappingInput_s* x);
void zx_im_MappingInput_REV_Token(struct zx_im_MappingInput_s* x);

#endif
/* -------------------------- im_MappingOutput -------------------------- */
/* refby( zx_im_IdentityMappingResponse_s ) */
#ifndef zx_im_MappingOutput_EXT
#define zx_im_MappingOutput_EXT
#endif

struct zx_im_MappingOutput_s* zx_DEC_im_MappingOutput(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_im_MappingOutput_s* zx_NEW_im_MappingOutput(struct zx_ctx* c);
void zx_FREE_im_MappingOutput(struct zx_ctx* c, struct zx_im_MappingOutput_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_im_MappingOutput_s* zx_DEEP_CLONE_im_MappingOutput(struct zx_ctx* c, struct zx_im_MappingOutput_s* x, int dup_strs);
void zx_DUP_STRS_im_MappingOutput(struct zx_ctx* c, struct zx_im_MappingOutput_s* x);
int zx_WALK_SO_im_MappingOutput(struct zx_ctx* c, struct zx_im_MappingOutput_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_im_MappingOutput(struct zx_ctx* c, struct zx_im_MappingOutput_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_im_MappingOutput(struct zx_ctx* c, struct zx_im_MappingOutput_s* x);
int zx_LEN_WO_im_MappingOutput(struct zx_ctx* c, struct zx_im_MappingOutput_s* x);
char* zx_ENC_SO_im_MappingOutput(struct zx_ctx* c, struct zx_im_MappingOutput_s* x, char* p);
char* zx_ENC_WO_im_MappingOutput(struct zx_ctx* c, struct zx_im_MappingOutput_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_im_MappingOutput(struct zx_ctx* c, struct zx_im_MappingOutput_s* x);
struct zx_str* zx_EASY_ENC_WO_im_MappingOutput(struct zx_ctx* c, struct zx_im_MappingOutput_s* x);

struct zx_im_MappingOutput_s {
  ZX_ELEM_EXT
  zx_im_MappingOutput_EXT
  struct zx_sec_Token_s* Token;	/* {1,1} nada */
  struct zx_str* reqRef;	/* {0,1} attribute lu:IDReferenceType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_im_MappingOutput_GET_reqRef(struct zx_im_MappingOutput_s* x);

struct zx_sec_Token_s* zx_im_MappingOutput_GET_Token(struct zx_im_MappingOutput_s* x, int n);

int zx_im_MappingOutput_NUM_Token(struct zx_im_MappingOutput_s* x);

struct zx_sec_Token_s* zx_im_MappingOutput_POP_Token(struct zx_im_MappingOutput_s* x);

void zx_im_MappingOutput_PUSH_Token(struct zx_im_MappingOutput_s* x, struct zx_sec_Token_s* y);

void zx_im_MappingOutput_PUT_reqRef(struct zx_im_MappingOutput_s* x, struct zx_str* y);

void zx_im_MappingOutput_PUT_Token(struct zx_im_MappingOutput_s* x, int n, struct zx_sec_Token_s* y);

void zx_im_MappingOutput_ADD_Token(struct zx_im_MappingOutput_s* x, int n, struct zx_sec_Token_s* z);

void zx_im_MappingOutput_DEL_Token(struct zx_im_MappingOutput_s* x, int n);

void zx_im_MappingOutput_REV_Token(struct zx_im_MappingOutput_s* x);

#endif

#endif
