/* c/zx-di-data.h - WARNING: This header was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Datastructure design, topography, and layout
 * Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for
 * terms and conditions of use. Element and attributes names as well
 * as some topography are derived from schema descriptions that were used as
 * input and may be subject to their own copright. */

#ifndef _c_zx_di_data_h
#define _c_zx_di_data_h

#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"

#ifndef ZX_ELEM_EXT
#define ZX_ELEM_EXT  /* This extension point should be defined by who includes this file. */
#endif

/* -------------------------- di_EndpointContext -------------------------- */
/* refby( zx_di_ServiceContext_s ) */
#ifndef zx_di_EndpointContext_EXT
#define zx_di_EndpointContext_EXT
#endif

struct zx_di_EndpointContext_s* zx_DEC_di_EndpointContext(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_EndpointContext_s* zx_NEW_di_EndpointContext(struct zx_ctx* c);
void zx_FREE_di_EndpointContext(struct zx_ctx* c, struct zx_di_EndpointContext_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_EndpointContext_s* zx_DEEP_CLONE_di_EndpointContext(struct zx_ctx* c, struct zx_di_EndpointContext_s* x, int dup_strs);
void zx_DUP_STRS_di_EndpointContext(struct zx_ctx* c, struct zx_di_EndpointContext_s* x);
int zx_WALK_SO_di_EndpointContext(struct zx_ctx* c, struct zx_di_EndpointContext_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_EndpointContext(struct zx_ctx* c, struct zx_di_EndpointContext_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_EndpointContext(struct zx_ctx* c, struct zx_di_EndpointContext_s* x);
int zx_LEN_WO_di_EndpointContext(struct zx_ctx* c, struct zx_di_EndpointContext_s* x);
char* zx_ENC_SO_di_EndpointContext(struct zx_ctx* c, struct zx_di_EndpointContext_s* x, char* p);
char* zx_ENC_WO_di_EndpointContext(struct zx_ctx* c, struct zx_di_EndpointContext_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_EndpointContext(struct zx_ctx* c, struct zx_di_EndpointContext_s* x);
struct zx_str* zx_EASY_ENC_WO_di_EndpointContext(struct zx_ctx* c, struct zx_di_EndpointContext_s* x);

struct zx_di_EndpointContext_s {
  ZX_ELEM_EXT
  zx_di_EndpointContext_EXT
  struct zx_elem_s* Address;	/* {1,-1} xs:anyURI */
  struct zx_sbf_Framework_s* Framework;	/* {1,-1} nada */
  struct zx_elem_s* SecurityMechID;	/* {1,-1} xs:anyURI */
  struct zx_elem_s* Action;	/* {0,-1} xs:anyURI */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_di_EndpointContext_GET_Address(struct zx_di_EndpointContext_s* x, int n);
struct zx_sbf_Framework_s* zx_di_EndpointContext_GET_Framework(struct zx_di_EndpointContext_s* x, int n);
struct zx_elem_s* zx_di_EndpointContext_GET_SecurityMechID(struct zx_di_EndpointContext_s* x, int n);
struct zx_elem_s* zx_di_EndpointContext_GET_Action(struct zx_di_EndpointContext_s* x, int n);

int zx_di_EndpointContext_NUM_Address(struct zx_di_EndpointContext_s* x);
int zx_di_EndpointContext_NUM_Framework(struct zx_di_EndpointContext_s* x);
int zx_di_EndpointContext_NUM_SecurityMechID(struct zx_di_EndpointContext_s* x);
int zx_di_EndpointContext_NUM_Action(struct zx_di_EndpointContext_s* x);

struct zx_elem_s* zx_di_EndpointContext_POP_Address(struct zx_di_EndpointContext_s* x);
struct zx_sbf_Framework_s* zx_di_EndpointContext_POP_Framework(struct zx_di_EndpointContext_s* x);
struct zx_elem_s* zx_di_EndpointContext_POP_SecurityMechID(struct zx_di_EndpointContext_s* x);
struct zx_elem_s* zx_di_EndpointContext_POP_Action(struct zx_di_EndpointContext_s* x);

void zx_di_EndpointContext_PUSH_Address(struct zx_di_EndpointContext_s* x, struct zx_elem_s* y);
void zx_di_EndpointContext_PUSH_Framework(struct zx_di_EndpointContext_s* x, struct zx_sbf_Framework_s* y);
void zx_di_EndpointContext_PUSH_SecurityMechID(struct zx_di_EndpointContext_s* x, struct zx_elem_s* y);
void zx_di_EndpointContext_PUSH_Action(struct zx_di_EndpointContext_s* x, struct zx_elem_s* y);


void zx_di_EndpointContext_PUT_Address(struct zx_di_EndpointContext_s* x, int n, struct zx_elem_s* y);
void zx_di_EndpointContext_PUT_Framework(struct zx_di_EndpointContext_s* x, int n, struct zx_sbf_Framework_s* y);
void zx_di_EndpointContext_PUT_SecurityMechID(struct zx_di_EndpointContext_s* x, int n, struct zx_elem_s* y);
void zx_di_EndpointContext_PUT_Action(struct zx_di_EndpointContext_s* x, int n, struct zx_elem_s* y);

void zx_di_EndpointContext_ADD_Address(struct zx_di_EndpointContext_s* x, int n, struct zx_elem_s* z);
void zx_di_EndpointContext_ADD_Framework(struct zx_di_EndpointContext_s* x, int n, struct zx_sbf_Framework_s* z);
void zx_di_EndpointContext_ADD_SecurityMechID(struct zx_di_EndpointContext_s* x, int n, struct zx_elem_s* z);
void zx_di_EndpointContext_ADD_Action(struct zx_di_EndpointContext_s* x, int n, struct zx_elem_s* z);

void zx_di_EndpointContext_DEL_Address(struct zx_di_EndpointContext_s* x, int n);
void zx_di_EndpointContext_DEL_Framework(struct zx_di_EndpointContext_s* x, int n);
void zx_di_EndpointContext_DEL_SecurityMechID(struct zx_di_EndpointContext_s* x, int n);
void zx_di_EndpointContext_DEL_Action(struct zx_di_EndpointContext_s* x, int n);

void zx_di_EndpointContext_REV_Address(struct zx_di_EndpointContext_s* x);
void zx_di_EndpointContext_REV_Framework(struct zx_di_EndpointContext_s* x);
void zx_di_EndpointContext_REV_SecurityMechID(struct zx_di_EndpointContext_s* x);
void zx_di_EndpointContext_REV_Action(struct zx_di_EndpointContext_s* x);

#endif
/* -------------------------- di_Framework -------------------------- */
/* refby( zx_di_RequestedService_s ) */
#ifndef zx_di_Framework_EXT
#define zx_di_Framework_EXT
#endif

struct zx_di_Framework_s* zx_DEC_di_Framework(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_Framework_s* zx_NEW_di_Framework(struct zx_ctx* c);
void zx_FREE_di_Framework(struct zx_ctx* c, struct zx_di_Framework_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_Framework_s* zx_DEEP_CLONE_di_Framework(struct zx_ctx* c, struct zx_di_Framework_s* x, int dup_strs);
void zx_DUP_STRS_di_Framework(struct zx_ctx* c, struct zx_di_Framework_s* x);
int zx_WALK_SO_di_Framework(struct zx_ctx* c, struct zx_di_Framework_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_Framework(struct zx_ctx* c, struct zx_di_Framework_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_Framework(struct zx_ctx* c, struct zx_di_Framework_s* x);
int zx_LEN_WO_di_Framework(struct zx_ctx* c, struct zx_di_Framework_s* x);
char* zx_ENC_SO_di_Framework(struct zx_ctx* c, struct zx_di_Framework_s* x, char* p);
char* zx_ENC_WO_di_Framework(struct zx_ctx* c, struct zx_di_Framework_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_Framework(struct zx_ctx* c, struct zx_di_Framework_s* x);
struct zx_str* zx_EASY_ENC_WO_di_Framework(struct zx_ctx* c, struct zx_di_Framework_s* x);

struct zx_di_Framework_s {
  ZX_ELEM_EXT
  zx_di_Framework_EXT
  struct zx_str* version;	/* {1,1} attribute xsd:string */
  struct zx_str* Id;	/* {0,1} attribute xs:ID */
  struct zx_str* actor;	/* {0,1} attribute xs:anyURI */
  struct zx_str* mustUnderstand;	/* {0,1} attribute xs:boolean */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_di_Framework_GET_version(struct zx_di_Framework_s* x);
struct zx_str* zx_di_Framework_GET_Id(struct zx_di_Framework_s* x);
struct zx_str* zx_di_Framework_GET_actor(struct zx_di_Framework_s* x);
struct zx_str* zx_di_Framework_GET_mustUnderstand(struct zx_di_Framework_s* x);





void zx_di_Framework_PUT_version(struct zx_di_Framework_s* x, struct zx_str* y);
void zx_di_Framework_PUT_Id(struct zx_di_Framework_s* x, struct zx_str* y);
void zx_di_Framework_PUT_actor(struct zx_di_Framework_s* x, struct zx_str* y);
void zx_di_Framework_PUT_mustUnderstand(struct zx_di_Framework_s* x, struct zx_str* y);





#endif
/* -------------------------- di_Keys -------------------------- */
/* refby( zx_di_SvcMDRegisterResponse_s ) */
#ifndef zx_di_Keys_EXT
#define zx_di_Keys_EXT
#endif

struct zx_di_Keys_s* zx_DEC_di_Keys(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_Keys_s* zx_NEW_di_Keys(struct zx_ctx* c);
void zx_FREE_di_Keys(struct zx_ctx* c, struct zx_di_Keys_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_Keys_s* zx_DEEP_CLONE_di_Keys(struct zx_ctx* c, struct zx_di_Keys_s* x, int dup_strs);
void zx_DUP_STRS_di_Keys(struct zx_ctx* c, struct zx_di_Keys_s* x);
int zx_WALK_SO_di_Keys(struct zx_ctx* c, struct zx_di_Keys_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_Keys(struct zx_ctx* c, struct zx_di_Keys_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_Keys(struct zx_ctx* c, struct zx_di_Keys_s* x);
int zx_LEN_WO_di_Keys(struct zx_ctx* c, struct zx_di_Keys_s* x);
char* zx_ENC_SO_di_Keys(struct zx_ctx* c, struct zx_di_Keys_s* x, char* p);
char* zx_ENC_WO_di_Keys(struct zx_ctx* c, struct zx_di_Keys_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_Keys(struct zx_ctx* c, struct zx_di_Keys_s* x);
struct zx_str* zx_EASY_ENC_WO_di_Keys(struct zx_ctx* c, struct zx_di_Keys_s* x);

struct zx_di_Keys_s {
  ZX_ELEM_EXT
  zx_di_Keys_EXT
  struct zx_md_KeyDescriptor_s* KeyDescriptor;	/* {1,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_md_KeyDescriptor_s* zx_di_Keys_GET_KeyDescriptor(struct zx_di_Keys_s* x, int n);

int zx_di_Keys_NUM_KeyDescriptor(struct zx_di_Keys_s* x);

struct zx_md_KeyDescriptor_s* zx_di_Keys_POP_KeyDescriptor(struct zx_di_Keys_s* x);

void zx_di_Keys_PUSH_KeyDescriptor(struct zx_di_Keys_s* x, struct zx_md_KeyDescriptor_s* y);


void zx_di_Keys_PUT_KeyDescriptor(struct zx_di_Keys_s* x, int n, struct zx_md_KeyDescriptor_s* y);

void zx_di_Keys_ADD_KeyDescriptor(struct zx_di_Keys_s* x, int n, struct zx_md_KeyDescriptor_s* z);

void zx_di_Keys_DEL_KeyDescriptor(struct zx_di_Keys_s* x, int n);

void zx_di_Keys_REV_KeyDescriptor(struct zx_di_Keys_s* x);

#endif
/* -------------------------- di_Options -------------------------- */
/* refby( zx_di_ServiceContext_s zx_di_RequestedService_s ) */
#ifndef zx_di_Options_EXT
#define zx_di_Options_EXT
#endif

struct zx_di_Options_s* zx_DEC_di_Options(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_Options_s* zx_NEW_di_Options(struct zx_ctx* c);
void zx_FREE_di_Options(struct zx_ctx* c, struct zx_di_Options_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_Options_s* zx_DEEP_CLONE_di_Options(struct zx_ctx* c, struct zx_di_Options_s* x, int dup_strs);
void zx_DUP_STRS_di_Options(struct zx_ctx* c, struct zx_di_Options_s* x);
int zx_WALK_SO_di_Options(struct zx_ctx* c, struct zx_di_Options_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_Options(struct zx_ctx* c, struct zx_di_Options_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_Options(struct zx_ctx* c, struct zx_di_Options_s* x);
int zx_LEN_WO_di_Options(struct zx_ctx* c, struct zx_di_Options_s* x);
char* zx_ENC_SO_di_Options(struct zx_ctx* c, struct zx_di_Options_s* x, char* p);
char* zx_ENC_WO_di_Options(struct zx_ctx* c, struct zx_di_Options_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_Options(struct zx_ctx* c, struct zx_di_Options_s* x);
struct zx_str* zx_EASY_ENC_WO_di_Options(struct zx_ctx* c, struct zx_di_Options_s* x);

struct zx_di_Options_s {
  ZX_ELEM_EXT
  zx_di_Options_EXT
  struct zx_elem_s* Option;	/* {0,-1} xs:anyURI */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_di_Options_GET_Option(struct zx_di_Options_s* x, int n);

int zx_di_Options_NUM_Option(struct zx_di_Options_s* x);

struct zx_elem_s* zx_di_Options_POP_Option(struct zx_di_Options_s* x);

void zx_di_Options_PUSH_Option(struct zx_di_Options_s* x, struct zx_elem_s* y);


void zx_di_Options_PUT_Option(struct zx_di_Options_s* x, int n, struct zx_elem_s* y);

void zx_di_Options_ADD_Option(struct zx_di_Options_s* x, int n, struct zx_elem_s* z);

void zx_di_Options_DEL_Option(struct zx_di_Options_s* x, int n);

void zx_di_Options_REV_Option(struct zx_di_Options_s* x);

#endif
/* -------------------------- di_Query -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_Query_EXT
#define zx_di_Query_EXT
#endif

struct zx_di_Query_s* zx_DEC_di_Query(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_Query_s* zx_NEW_di_Query(struct zx_ctx* c);
void zx_FREE_di_Query(struct zx_ctx* c, struct zx_di_Query_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_Query_s* zx_DEEP_CLONE_di_Query(struct zx_ctx* c, struct zx_di_Query_s* x, int dup_strs);
void zx_DUP_STRS_di_Query(struct zx_ctx* c, struct zx_di_Query_s* x);
int zx_WALK_SO_di_Query(struct zx_ctx* c, struct zx_di_Query_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_Query(struct zx_ctx* c, struct zx_di_Query_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_Query(struct zx_ctx* c, struct zx_di_Query_s* x);
int zx_LEN_WO_di_Query(struct zx_ctx* c, struct zx_di_Query_s* x);
char* zx_ENC_SO_di_Query(struct zx_ctx* c, struct zx_di_Query_s* x, char* p);
char* zx_ENC_WO_di_Query(struct zx_ctx* c, struct zx_di_Query_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_Query(struct zx_ctx* c, struct zx_di_Query_s* x);
struct zx_str* zx_EASY_ENC_WO_di_Query(struct zx_ctx* c, struct zx_di_Query_s* x);

struct zx_di_Query_s {
  ZX_ELEM_EXT
  zx_di_Query_EXT
  struct zx_di_RequestedService_s* RequestedService;	/* {0,-1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_di_RequestedService_s* zx_di_Query_GET_RequestedService(struct zx_di_Query_s* x, int n);

int zx_di_Query_NUM_RequestedService(struct zx_di_Query_s* x);

struct zx_di_RequestedService_s* zx_di_Query_POP_RequestedService(struct zx_di_Query_s* x);

void zx_di_Query_PUSH_RequestedService(struct zx_di_Query_s* x, struct zx_di_RequestedService_s* y);


void zx_di_Query_PUT_RequestedService(struct zx_di_Query_s* x, int n, struct zx_di_RequestedService_s* y);

void zx_di_Query_ADD_RequestedService(struct zx_di_Query_s* x, int n, struct zx_di_RequestedService_s* z);

void zx_di_Query_DEL_RequestedService(struct zx_di_Query_s* x, int n);

void zx_di_Query_REV_RequestedService(struct zx_di_Query_s* x);

#endif
/* -------------------------- di_QueryResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_QueryResponse_EXT
#define zx_di_QueryResponse_EXT
#endif

struct zx_di_QueryResponse_s* zx_DEC_di_QueryResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_QueryResponse_s* zx_NEW_di_QueryResponse(struct zx_ctx* c);
void zx_FREE_di_QueryResponse(struct zx_ctx* c, struct zx_di_QueryResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_QueryResponse_s* zx_DEEP_CLONE_di_QueryResponse(struct zx_ctx* c, struct zx_di_QueryResponse_s* x, int dup_strs);
void zx_DUP_STRS_di_QueryResponse(struct zx_ctx* c, struct zx_di_QueryResponse_s* x);
int zx_WALK_SO_di_QueryResponse(struct zx_ctx* c, struct zx_di_QueryResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_QueryResponse(struct zx_ctx* c, struct zx_di_QueryResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_QueryResponse(struct zx_ctx* c, struct zx_di_QueryResponse_s* x);
int zx_LEN_WO_di_QueryResponse(struct zx_ctx* c, struct zx_di_QueryResponse_s* x);
char* zx_ENC_SO_di_QueryResponse(struct zx_ctx* c, struct zx_di_QueryResponse_s* x, char* p);
char* zx_ENC_WO_di_QueryResponse(struct zx_ctx* c, struct zx_di_QueryResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_QueryResponse(struct zx_ctx* c, struct zx_di_QueryResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_di_QueryResponse(struct zx_ctx* c, struct zx_di_QueryResponse_s* x);

struct zx_di_QueryResponse_s {
  ZX_ELEM_EXT
  zx_di_QueryResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_a_EndpointReference_s* EndpointReference;	/* {0,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_lu_Status_s* zx_di_QueryResponse_GET_Status(struct zx_di_QueryResponse_s* x, int n);
struct zx_a_EndpointReference_s* zx_di_QueryResponse_GET_EndpointReference(struct zx_di_QueryResponse_s* x, int n);

int zx_di_QueryResponse_NUM_Status(struct zx_di_QueryResponse_s* x);
int zx_di_QueryResponse_NUM_EndpointReference(struct zx_di_QueryResponse_s* x);

struct zx_lu_Status_s* zx_di_QueryResponse_POP_Status(struct zx_di_QueryResponse_s* x);
struct zx_a_EndpointReference_s* zx_di_QueryResponse_POP_EndpointReference(struct zx_di_QueryResponse_s* x);

void zx_di_QueryResponse_PUSH_Status(struct zx_di_QueryResponse_s* x, struct zx_lu_Status_s* y);
void zx_di_QueryResponse_PUSH_EndpointReference(struct zx_di_QueryResponse_s* x, struct zx_a_EndpointReference_s* y);


void zx_di_QueryResponse_PUT_Status(struct zx_di_QueryResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_di_QueryResponse_PUT_EndpointReference(struct zx_di_QueryResponse_s* x, int n, struct zx_a_EndpointReference_s* y);

void zx_di_QueryResponse_ADD_Status(struct zx_di_QueryResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_di_QueryResponse_ADD_EndpointReference(struct zx_di_QueryResponse_s* x, int n, struct zx_a_EndpointReference_s* z);

void zx_di_QueryResponse_DEL_Status(struct zx_di_QueryResponse_s* x, int n);
void zx_di_QueryResponse_DEL_EndpointReference(struct zx_di_QueryResponse_s* x, int n);

void zx_di_QueryResponse_REV_Status(struct zx_di_QueryResponse_s* x);
void zx_di_QueryResponse_REV_EndpointReference(struct zx_di_QueryResponse_s* x);

#endif
/* -------------------------- di_RequestedService -------------------------- */
/* refby( zx_shps_Query_s zx_di_Query_s ) */
#ifndef zx_di_RequestedService_EXT
#define zx_di_RequestedService_EXT
#endif

struct zx_di_RequestedService_s* zx_DEC_di_RequestedService(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_RequestedService_s* zx_NEW_di_RequestedService(struct zx_ctx* c);
void zx_FREE_di_RequestedService(struct zx_ctx* c, struct zx_di_RequestedService_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_RequestedService_s* zx_DEEP_CLONE_di_RequestedService(struct zx_ctx* c, struct zx_di_RequestedService_s* x, int dup_strs);
void zx_DUP_STRS_di_RequestedService(struct zx_ctx* c, struct zx_di_RequestedService_s* x);
int zx_WALK_SO_di_RequestedService(struct zx_ctx* c, struct zx_di_RequestedService_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_RequestedService(struct zx_ctx* c, struct zx_di_RequestedService_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_RequestedService(struct zx_ctx* c, struct zx_di_RequestedService_s* x);
int zx_LEN_WO_di_RequestedService(struct zx_ctx* c, struct zx_di_RequestedService_s* x);
char* zx_ENC_SO_di_RequestedService(struct zx_ctx* c, struct zx_di_RequestedService_s* x, char* p);
char* zx_ENC_WO_di_RequestedService(struct zx_ctx* c, struct zx_di_RequestedService_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_RequestedService(struct zx_ctx* c, struct zx_di_RequestedService_s* x);
struct zx_str* zx_EASY_ENC_WO_di_RequestedService(struct zx_ctx* c, struct zx_di_RequestedService_s* x);

struct zx_di_RequestedService_s {
  ZX_ELEM_EXT
  zx_di_RequestedService_EXT
  struct zx_elem_s* ServiceType;	/* {0,-1} xs:anyURI */
  struct zx_elem_s* ProviderID;	/* {0,-1} xs:anyURI */
  struct zx_di_Options_s* Options;	/* {0,-1}  */
  struct zx_elem_s* SecurityMechID;	/* {0,-1} xs:anyURI */
  struct zx_di_Framework_s* Framework;	/* {0,-1} nada */
  struct zx_elem_s* Action;	/* {0,-1} xs:anyURI */
  struct zx_str* reqID;	/* {0,1} attribute xs:string */
  struct zx_str* resultsType;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_di_RequestedService_GET_reqID(struct zx_di_RequestedService_s* x);
struct zx_str* zx_di_RequestedService_GET_resultsType(struct zx_di_RequestedService_s* x);

struct zx_elem_s* zx_di_RequestedService_GET_ServiceType(struct zx_di_RequestedService_s* x, int n);
struct zx_elem_s* zx_di_RequestedService_GET_ProviderID(struct zx_di_RequestedService_s* x, int n);
struct zx_di_Options_s* zx_di_RequestedService_GET_Options(struct zx_di_RequestedService_s* x, int n);
struct zx_elem_s* zx_di_RequestedService_GET_SecurityMechID(struct zx_di_RequestedService_s* x, int n);
struct zx_di_Framework_s* zx_di_RequestedService_GET_Framework(struct zx_di_RequestedService_s* x, int n);
struct zx_elem_s* zx_di_RequestedService_GET_Action(struct zx_di_RequestedService_s* x, int n);

int zx_di_RequestedService_NUM_ServiceType(struct zx_di_RequestedService_s* x);
int zx_di_RequestedService_NUM_ProviderID(struct zx_di_RequestedService_s* x);
int zx_di_RequestedService_NUM_Options(struct zx_di_RequestedService_s* x);
int zx_di_RequestedService_NUM_SecurityMechID(struct zx_di_RequestedService_s* x);
int zx_di_RequestedService_NUM_Framework(struct zx_di_RequestedService_s* x);
int zx_di_RequestedService_NUM_Action(struct zx_di_RequestedService_s* x);

struct zx_elem_s* zx_di_RequestedService_POP_ServiceType(struct zx_di_RequestedService_s* x);
struct zx_elem_s* zx_di_RequestedService_POP_ProviderID(struct zx_di_RequestedService_s* x);
struct zx_di_Options_s* zx_di_RequestedService_POP_Options(struct zx_di_RequestedService_s* x);
struct zx_elem_s* zx_di_RequestedService_POP_SecurityMechID(struct zx_di_RequestedService_s* x);
struct zx_di_Framework_s* zx_di_RequestedService_POP_Framework(struct zx_di_RequestedService_s* x);
struct zx_elem_s* zx_di_RequestedService_POP_Action(struct zx_di_RequestedService_s* x);

void zx_di_RequestedService_PUSH_ServiceType(struct zx_di_RequestedService_s* x, struct zx_elem_s* y);
void zx_di_RequestedService_PUSH_ProviderID(struct zx_di_RequestedService_s* x, struct zx_elem_s* y);
void zx_di_RequestedService_PUSH_Options(struct zx_di_RequestedService_s* x, struct zx_di_Options_s* y);
void zx_di_RequestedService_PUSH_SecurityMechID(struct zx_di_RequestedService_s* x, struct zx_elem_s* y);
void zx_di_RequestedService_PUSH_Framework(struct zx_di_RequestedService_s* x, struct zx_di_Framework_s* y);
void zx_di_RequestedService_PUSH_Action(struct zx_di_RequestedService_s* x, struct zx_elem_s* y);

void zx_di_RequestedService_PUT_reqID(struct zx_di_RequestedService_s* x, struct zx_str* y);
void zx_di_RequestedService_PUT_resultsType(struct zx_di_RequestedService_s* x, struct zx_str* y);

void zx_di_RequestedService_PUT_ServiceType(struct zx_di_RequestedService_s* x, int n, struct zx_elem_s* y);
void zx_di_RequestedService_PUT_ProviderID(struct zx_di_RequestedService_s* x, int n, struct zx_elem_s* y);
void zx_di_RequestedService_PUT_Options(struct zx_di_RequestedService_s* x, int n, struct zx_di_Options_s* y);
void zx_di_RequestedService_PUT_SecurityMechID(struct zx_di_RequestedService_s* x, int n, struct zx_elem_s* y);
void zx_di_RequestedService_PUT_Framework(struct zx_di_RequestedService_s* x, int n, struct zx_di_Framework_s* y);
void zx_di_RequestedService_PUT_Action(struct zx_di_RequestedService_s* x, int n, struct zx_elem_s* y);

void zx_di_RequestedService_ADD_ServiceType(struct zx_di_RequestedService_s* x, int n, struct zx_elem_s* z);
void zx_di_RequestedService_ADD_ProviderID(struct zx_di_RequestedService_s* x, int n, struct zx_elem_s* z);
void zx_di_RequestedService_ADD_Options(struct zx_di_RequestedService_s* x, int n, struct zx_di_Options_s* z);
void zx_di_RequestedService_ADD_SecurityMechID(struct zx_di_RequestedService_s* x, int n, struct zx_elem_s* z);
void zx_di_RequestedService_ADD_Framework(struct zx_di_RequestedService_s* x, int n, struct zx_di_Framework_s* z);
void zx_di_RequestedService_ADD_Action(struct zx_di_RequestedService_s* x, int n, struct zx_elem_s* z);

void zx_di_RequestedService_DEL_ServiceType(struct zx_di_RequestedService_s* x, int n);
void zx_di_RequestedService_DEL_ProviderID(struct zx_di_RequestedService_s* x, int n);
void zx_di_RequestedService_DEL_Options(struct zx_di_RequestedService_s* x, int n);
void zx_di_RequestedService_DEL_SecurityMechID(struct zx_di_RequestedService_s* x, int n);
void zx_di_RequestedService_DEL_Framework(struct zx_di_RequestedService_s* x, int n);
void zx_di_RequestedService_DEL_Action(struct zx_di_RequestedService_s* x, int n);

void zx_di_RequestedService_REV_ServiceType(struct zx_di_RequestedService_s* x);
void zx_di_RequestedService_REV_ProviderID(struct zx_di_RequestedService_s* x);
void zx_di_RequestedService_REV_Options(struct zx_di_RequestedService_s* x);
void zx_di_RequestedService_REV_SecurityMechID(struct zx_di_RequestedService_s* x);
void zx_di_RequestedService_REV_Framework(struct zx_di_RequestedService_s* x);
void zx_di_RequestedService_REV_Action(struct zx_di_RequestedService_s* x);

#endif
/* -------------------------- di_SecurityContext -------------------------- */
/* refby( zx_a_Metadata_s ) */
#ifndef zx_di_SecurityContext_EXT
#define zx_di_SecurityContext_EXT
#endif

struct zx_di_SecurityContext_s* zx_DEC_di_SecurityContext(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SecurityContext_s* zx_NEW_di_SecurityContext(struct zx_ctx* c);
void zx_FREE_di_SecurityContext(struct zx_ctx* c, struct zx_di_SecurityContext_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SecurityContext_s* zx_DEEP_CLONE_di_SecurityContext(struct zx_ctx* c, struct zx_di_SecurityContext_s* x, int dup_strs);
void zx_DUP_STRS_di_SecurityContext(struct zx_ctx* c, struct zx_di_SecurityContext_s* x);
int zx_WALK_SO_di_SecurityContext(struct zx_ctx* c, struct zx_di_SecurityContext_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SecurityContext(struct zx_ctx* c, struct zx_di_SecurityContext_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SecurityContext(struct zx_ctx* c, struct zx_di_SecurityContext_s* x);
int zx_LEN_WO_di_SecurityContext(struct zx_ctx* c, struct zx_di_SecurityContext_s* x);
char* zx_ENC_SO_di_SecurityContext(struct zx_ctx* c, struct zx_di_SecurityContext_s* x, char* p);
char* zx_ENC_WO_di_SecurityContext(struct zx_ctx* c, struct zx_di_SecurityContext_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SecurityContext(struct zx_ctx* c, struct zx_di_SecurityContext_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SecurityContext(struct zx_ctx* c, struct zx_di_SecurityContext_s* x);

struct zx_di_SecurityContext_s {
  ZX_ELEM_EXT
  zx_di_SecurityContext_EXT
  struct zx_elem_s* SecurityMechID;	/* {1,-1} xs:anyURI */
  struct zx_sec_Token_s* Token;	/* {0,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_di_SecurityContext_GET_SecurityMechID(struct zx_di_SecurityContext_s* x, int n);
struct zx_sec_Token_s* zx_di_SecurityContext_GET_Token(struct zx_di_SecurityContext_s* x, int n);

int zx_di_SecurityContext_NUM_SecurityMechID(struct zx_di_SecurityContext_s* x);
int zx_di_SecurityContext_NUM_Token(struct zx_di_SecurityContext_s* x);

struct zx_elem_s* zx_di_SecurityContext_POP_SecurityMechID(struct zx_di_SecurityContext_s* x);
struct zx_sec_Token_s* zx_di_SecurityContext_POP_Token(struct zx_di_SecurityContext_s* x);

void zx_di_SecurityContext_PUSH_SecurityMechID(struct zx_di_SecurityContext_s* x, struct zx_elem_s* y);
void zx_di_SecurityContext_PUSH_Token(struct zx_di_SecurityContext_s* x, struct zx_sec_Token_s* y);


void zx_di_SecurityContext_PUT_SecurityMechID(struct zx_di_SecurityContext_s* x, int n, struct zx_elem_s* y);
void zx_di_SecurityContext_PUT_Token(struct zx_di_SecurityContext_s* x, int n, struct zx_sec_Token_s* y);

void zx_di_SecurityContext_ADD_SecurityMechID(struct zx_di_SecurityContext_s* x, int n, struct zx_elem_s* z);
void zx_di_SecurityContext_ADD_Token(struct zx_di_SecurityContext_s* x, int n, struct zx_sec_Token_s* z);

void zx_di_SecurityContext_DEL_SecurityMechID(struct zx_di_SecurityContext_s* x, int n);
void zx_di_SecurityContext_DEL_Token(struct zx_di_SecurityContext_s* x, int n);

void zx_di_SecurityContext_REV_SecurityMechID(struct zx_di_SecurityContext_s* x);
void zx_di_SecurityContext_REV_Token(struct zx_di_SecurityContext_s* x);

#endif
/* -------------------------- di_ServiceContext -------------------------- */
/* refby( zx_di_SvcMD_s ) */
#ifndef zx_di_ServiceContext_EXT
#define zx_di_ServiceContext_EXT
#endif

struct zx_di_ServiceContext_s* zx_DEC_di_ServiceContext(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_ServiceContext_s* zx_NEW_di_ServiceContext(struct zx_ctx* c);
void zx_FREE_di_ServiceContext(struct zx_ctx* c, struct zx_di_ServiceContext_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_ServiceContext_s* zx_DEEP_CLONE_di_ServiceContext(struct zx_ctx* c, struct zx_di_ServiceContext_s* x, int dup_strs);
void zx_DUP_STRS_di_ServiceContext(struct zx_ctx* c, struct zx_di_ServiceContext_s* x);
int zx_WALK_SO_di_ServiceContext(struct zx_ctx* c, struct zx_di_ServiceContext_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_ServiceContext(struct zx_ctx* c, struct zx_di_ServiceContext_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_ServiceContext(struct zx_ctx* c, struct zx_di_ServiceContext_s* x);
int zx_LEN_WO_di_ServiceContext(struct zx_ctx* c, struct zx_di_ServiceContext_s* x);
char* zx_ENC_SO_di_ServiceContext(struct zx_ctx* c, struct zx_di_ServiceContext_s* x, char* p);
char* zx_ENC_WO_di_ServiceContext(struct zx_ctx* c, struct zx_di_ServiceContext_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_ServiceContext(struct zx_ctx* c, struct zx_di_ServiceContext_s* x);
struct zx_str* zx_EASY_ENC_WO_di_ServiceContext(struct zx_ctx* c, struct zx_di_ServiceContext_s* x);

struct zx_di_ServiceContext_s {
  ZX_ELEM_EXT
  zx_di_ServiceContext_EXT
  struct zx_elem_s* ServiceType;	/* {1,-1} xs:anyURI */
  struct zx_di_Options_s* Options;	/* {0,-1}  */
  struct zx_di_EndpointContext_s* EndpointContext;	/* {1,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_di_ServiceContext_GET_ServiceType(struct zx_di_ServiceContext_s* x, int n);
struct zx_di_Options_s* zx_di_ServiceContext_GET_Options(struct zx_di_ServiceContext_s* x, int n);
struct zx_di_EndpointContext_s* zx_di_ServiceContext_GET_EndpointContext(struct zx_di_ServiceContext_s* x, int n);

int zx_di_ServiceContext_NUM_ServiceType(struct zx_di_ServiceContext_s* x);
int zx_di_ServiceContext_NUM_Options(struct zx_di_ServiceContext_s* x);
int zx_di_ServiceContext_NUM_EndpointContext(struct zx_di_ServiceContext_s* x);

struct zx_elem_s* zx_di_ServiceContext_POP_ServiceType(struct zx_di_ServiceContext_s* x);
struct zx_di_Options_s* zx_di_ServiceContext_POP_Options(struct zx_di_ServiceContext_s* x);
struct zx_di_EndpointContext_s* zx_di_ServiceContext_POP_EndpointContext(struct zx_di_ServiceContext_s* x);

void zx_di_ServiceContext_PUSH_ServiceType(struct zx_di_ServiceContext_s* x, struct zx_elem_s* y);
void zx_di_ServiceContext_PUSH_Options(struct zx_di_ServiceContext_s* x, struct zx_di_Options_s* y);
void zx_di_ServiceContext_PUSH_EndpointContext(struct zx_di_ServiceContext_s* x, struct zx_di_EndpointContext_s* y);


void zx_di_ServiceContext_PUT_ServiceType(struct zx_di_ServiceContext_s* x, int n, struct zx_elem_s* y);
void zx_di_ServiceContext_PUT_Options(struct zx_di_ServiceContext_s* x, int n, struct zx_di_Options_s* y);
void zx_di_ServiceContext_PUT_EndpointContext(struct zx_di_ServiceContext_s* x, int n, struct zx_di_EndpointContext_s* y);

void zx_di_ServiceContext_ADD_ServiceType(struct zx_di_ServiceContext_s* x, int n, struct zx_elem_s* z);
void zx_di_ServiceContext_ADD_Options(struct zx_di_ServiceContext_s* x, int n, struct zx_di_Options_s* z);
void zx_di_ServiceContext_ADD_EndpointContext(struct zx_di_ServiceContext_s* x, int n, struct zx_di_EndpointContext_s* z);

void zx_di_ServiceContext_DEL_ServiceType(struct zx_di_ServiceContext_s* x, int n);
void zx_di_ServiceContext_DEL_Options(struct zx_di_ServiceContext_s* x, int n);
void zx_di_ServiceContext_DEL_EndpointContext(struct zx_di_ServiceContext_s* x, int n);

void zx_di_ServiceContext_REV_ServiceType(struct zx_di_ServiceContext_s* x);
void zx_di_ServiceContext_REV_Options(struct zx_di_ServiceContext_s* x);
void zx_di_ServiceContext_REV_EndpointContext(struct zx_di_ServiceContext_s* x);

#endif
/* -------------------------- di_SvcMD -------------------------- */
/* refby( zx_di_SvcMDQueryResponse_s zx_di_SvcMDReplace_s zx_di_SvcMDRegister_s ) */
#ifndef zx_di_SvcMD_EXT
#define zx_di_SvcMD_EXT
#endif

struct zx_di_SvcMD_s* zx_DEC_di_SvcMD(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMD_s* zx_NEW_di_SvcMD(struct zx_ctx* c);
void zx_FREE_di_SvcMD(struct zx_ctx* c, struct zx_di_SvcMD_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMD_s* zx_DEEP_CLONE_di_SvcMD(struct zx_ctx* c, struct zx_di_SvcMD_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMD(struct zx_ctx* c, struct zx_di_SvcMD_s* x);
int zx_WALK_SO_di_SvcMD(struct zx_ctx* c, struct zx_di_SvcMD_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMD(struct zx_ctx* c, struct zx_di_SvcMD_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMD(struct zx_ctx* c, struct zx_di_SvcMD_s* x);
int zx_LEN_WO_di_SvcMD(struct zx_ctx* c, struct zx_di_SvcMD_s* x);
char* zx_ENC_SO_di_SvcMD(struct zx_ctx* c, struct zx_di_SvcMD_s* x, char* p);
char* zx_ENC_WO_di_SvcMD(struct zx_ctx* c, struct zx_di_SvcMD_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMD(struct zx_ctx* c, struct zx_di_SvcMD_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMD(struct zx_ctx* c, struct zx_di_SvcMD_s* x);

struct zx_di_SvcMD_s {
  ZX_ELEM_EXT
  zx_di_SvcMD_EXT
  struct zx_elem_s* Abstract;	/* {1,1} xs:string */
  struct zx_elem_s* ProviderID;	/* {1,1} xs:anyURI */
  struct zx_di_ServiceContext_s* ServiceContext;	/* {1,-1} nada */
  struct zx_str* svcMDID;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_di_SvcMD_GET_svcMDID(struct zx_di_SvcMD_s* x);

struct zx_elem_s* zx_di_SvcMD_GET_Abstract(struct zx_di_SvcMD_s* x, int n);
struct zx_elem_s* zx_di_SvcMD_GET_ProviderID(struct zx_di_SvcMD_s* x, int n);
struct zx_di_ServiceContext_s* zx_di_SvcMD_GET_ServiceContext(struct zx_di_SvcMD_s* x, int n);

int zx_di_SvcMD_NUM_Abstract(struct zx_di_SvcMD_s* x);
int zx_di_SvcMD_NUM_ProviderID(struct zx_di_SvcMD_s* x);
int zx_di_SvcMD_NUM_ServiceContext(struct zx_di_SvcMD_s* x);

struct zx_elem_s* zx_di_SvcMD_POP_Abstract(struct zx_di_SvcMD_s* x);
struct zx_elem_s* zx_di_SvcMD_POP_ProviderID(struct zx_di_SvcMD_s* x);
struct zx_di_ServiceContext_s* zx_di_SvcMD_POP_ServiceContext(struct zx_di_SvcMD_s* x);

void zx_di_SvcMD_PUSH_Abstract(struct zx_di_SvcMD_s* x, struct zx_elem_s* y);
void zx_di_SvcMD_PUSH_ProviderID(struct zx_di_SvcMD_s* x, struct zx_elem_s* y);
void zx_di_SvcMD_PUSH_ServiceContext(struct zx_di_SvcMD_s* x, struct zx_di_ServiceContext_s* y);

void zx_di_SvcMD_PUT_svcMDID(struct zx_di_SvcMD_s* x, struct zx_str* y);

void zx_di_SvcMD_PUT_Abstract(struct zx_di_SvcMD_s* x, int n, struct zx_elem_s* y);
void zx_di_SvcMD_PUT_ProviderID(struct zx_di_SvcMD_s* x, int n, struct zx_elem_s* y);
void zx_di_SvcMD_PUT_ServiceContext(struct zx_di_SvcMD_s* x, int n, struct zx_di_ServiceContext_s* y);

void zx_di_SvcMD_ADD_Abstract(struct zx_di_SvcMD_s* x, int n, struct zx_elem_s* z);
void zx_di_SvcMD_ADD_ProviderID(struct zx_di_SvcMD_s* x, int n, struct zx_elem_s* z);
void zx_di_SvcMD_ADD_ServiceContext(struct zx_di_SvcMD_s* x, int n, struct zx_di_ServiceContext_s* z);

void zx_di_SvcMD_DEL_Abstract(struct zx_di_SvcMD_s* x, int n);
void zx_di_SvcMD_DEL_ProviderID(struct zx_di_SvcMD_s* x, int n);
void zx_di_SvcMD_DEL_ServiceContext(struct zx_di_SvcMD_s* x, int n);

void zx_di_SvcMD_REV_Abstract(struct zx_di_SvcMD_s* x);
void zx_di_SvcMD_REV_ProviderID(struct zx_di_SvcMD_s* x);
void zx_di_SvcMD_REV_ServiceContext(struct zx_di_SvcMD_s* x);

#endif
/* -------------------------- di_SvcMDAssociationAdd -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDAssociationAdd_EXT
#define zx_di_SvcMDAssociationAdd_EXT
#endif

struct zx_di_SvcMDAssociationAdd_s* zx_DEC_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDAssociationAdd_s* zx_NEW_di_SvcMDAssociationAdd(struct zx_ctx* c);
void zx_FREE_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_di_SvcMDAssociationAdd_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDAssociationAdd_s* zx_DEEP_CLONE_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_di_SvcMDAssociationAdd_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_di_SvcMDAssociationAdd_s* x);
int zx_WALK_SO_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_di_SvcMDAssociationAdd_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_di_SvcMDAssociationAdd_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_di_SvcMDAssociationAdd_s* x);
int zx_LEN_WO_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_di_SvcMDAssociationAdd_s* x);
char* zx_ENC_SO_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_di_SvcMDAssociationAdd_s* x, char* p);
char* zx_ENC_WO_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_di_SvcMDAssociationAdd_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_di_SvcMDAssociationAdd_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDAssociationAdd(struct zx_ctx* c, struct zx_di_SvcMDAssociationAdd_s* x);

struct zx_di_SvcMDAssociationAdd_s {
  ZX_ELEM_EXT
  zx_di_SvcMDAssociationAdd_EXT
  struct zx_elem_s* SvcMDID;	/* {1,-1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_di_SvcMDAssociationAdd_GET_SvcMDID(struct zx_di_SvcMDAssociationAdd_s* x, int n);

int zx_di_SvcMDAssociationAdd_NUM_SvcMDID(struct zx_di_SvcMDAssociationAdd_s* x);

struct zx_elem_s* zx_di_SvcMDAssociationAdd_POP_SvcMDID(struct zx_di_SvcMDAssociationAdd_s* x);

void zx_di_SvcMDAssociationAdd_PUSH_SvcMDID(struct zx_di_SvcMDAssociationAdd_s* x, struct zx_elem_s* y);


void zx_di_SvcMDAssociationAdd_PUT_SvcMDID(struct zx_di_SvcMDAssociationAdd_s* x, int n, struct zx_elem_s* y);

void zx_di_SvcMDAssociationAdd_ADD_SvcMDID(struct zx_di_SvcMDAssociationAdd_s* x, int n, struct zx_elem_s* z);

void zx_di_SvcMDAssociationAdd_DEL_SvcMDID(struct zx_di_SvcMDAssociationAdd_s* x, int n);

void zx_di_SvcMDAssociationAdd_REV_SvcMDID(struct zx_di_SvcMDAssociationAdd_s* x);

#endif
/* -------------------------- di_SvcMDAssociationAddResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDAssociationAddResponse_EXT
#define zx_di_SvcMDAssociationAddResponse_EXT
#endif

struct zx_di_SvcMDAssociationAddResponse_s* zx_DEC_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDAssociationAddResponse_s* zx_NEW_di_SvcMDAssociationAddResponse(struct zx_ctx* c);
void zx_FREE_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationAddResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDAssociationAddResponse_s* zx_DEEP_CLONE_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationAddResponse_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationAddResponse_s* x);
int zx_WALK_SO_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationAddResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationAddResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationAddResponse_s* x);
int zx_LEN_WO_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationAddResponse_s* x);
char* zx_ENC_SO_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationAddResponse_s* x, char* p);
char* zx_ENC_WO_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationAddResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationAddResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDAssociationAddResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationAddResponse_s* x);

struct zx_di_SvcMDAssociationAddResponse_s {
  ZX_ELEM_EXT
  zx_di_SvcMDAssociationAddResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_lu_Status_s* zx_di_SvcMDAssociationAddResponse_GET_Status(struct zx_di_SvcMDAssociationAddResponse_s* x, int n);

int zx_di_SvcMDAssociationAddResponse_NUM_Status(struct zx_di_SvcMDAssociationAddResponse_s* x);

struct zx_lu_Status_s* zx_di_SvcMDAssociationAddResponse_POP_Status(struct zx_di_SvcMDAssociationAddResponse_s* x);

void zx_di_SvcMDAssociationAddResponse_PUSH_Status(struct zx_di_SvcMDAssociationAddResponse_s* x, struct zx_lu_Status_s* y);


void zx_di_SvcMDAssociationAddResponse_PUT_Status(struct zx_di_SvcMDAssociationAddResponse_s* x, int n, struct zx_lu_Status_s* y);

void zx_di_SvcMDAssociationAddResponse_ADD_Status(struct zx_di_SvcMDAssociationAddResponse_s* x, int n, struct zx_lu_Status_s* z);

void zx_di_SvcMDAssociationAddResponse_DEL_Status(struct zx_di_SvcMDAssociationAddResponse_s* x, int n);

void zx_di_SvcMDAssociationAddResponse_REV_Status(struct zx_di_SvcMDAssociationAddResponse_s* x);

#endif
/* -------------------------- di_SvcMDAssociationDelete -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDAssociationDelete_EXT
#define zx_di_SvcMDAssociationDelete_EXT
#endif

struct zx_di_SvcMDAssociationDelete_s* zx_DEC_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDAssociationDelete_s* zx_NEW_di_SvcMDAssociationDelete(struct zx_ctx* c);
void zx_FREE_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_di_SvcMDAssociationDelete_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDAssociationDelete_s* zx_DEEP_CLONE_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_di_SvcMDAssociationDelete_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_di_SvcMDAssociationDelete_s* x);
int zx_WALK_SO_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_di_SvcMDAssociationDelete_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_di_SvcMDAssociationDelete_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_di_SvcMDAssociationDelete_s* x);
int zx_LEN_WO_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_di_SvcMDAssociationDelete_s* x);
char* zx_ENC_SO_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_di_SvcMDAssociationDelete_s* x, char* p);
char* zx_ENC_WO_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_di_SvcMDAssociationDelete_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_di_SvcMDAssociationDelete_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDAssociationDelete(struct zx_ctx* c, struct zx_di_SvcMDAssociationDelete_s* x);

struct zx_di_SvcMDAssociationDelete_s {
  ZX_ELEM_EXT
  zx_di_SvcMDAssociationDelete_EXT
  struct zx_elem_s* SvcMDID;	/* {1,-1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_di_SvcMDAssociationDelete_GET_SvcMDID(struct zx_di_SvcMDAssociationDelete_s* x, int n);

int zx_di_SvcMDAssociationDelete_NUM_SvcMDID(struct zx_di_SvcMDAssociationDelete_s* x);

struct zx_elem_s* zx_di_SvcMDAssociationDelete_POP_SvcMDID(struct zx_di_SvcMDAssociationDelete_s* x);

void zx_di_SvcMDAssociationDelete_PUSH_SvcMDID(struct zx_di_SvcMDAssociationDelete_s* x, struct zx_elem_s* y);


void zx_di_SvcMDAssociationDelete_PUT_SvcMDID(struct zx_di_SvcMDAssociationDelete_s* x, int n, struct zx_elem_s* y);

void zx_di_SvcMDAssociationDelete_ADD_SvcMDID(struct zx_di_SvcMDAssociationDelete_s* x, int n, struct zx_elem_s* z);

void zx_di_SvcMDAssociationDelete_DEL_SvcMDID(struct zx_di_SvcMDAssociationDelete_s* x, int n);

void zx_di_SvcMDAssociationDelete_REV_SvcMDID(struct zx_di_SvcMDAssociationDelete_s* x);

#endif
/* -------------------------- di_SvcMDAssociationDeleteResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDAssociationDeleteResponse_EXT
#define zx_di_SvcMDAssociationDeleteResponse_EXT
#endif

struct zx_di_SvcMDAssociationDeleteResponse_s* zx_DEC_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDAssociationDeleteResponse_s* zx_NEW_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c);
void zx_FREE_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationDeleteResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDAssociationDeleteResponse_s* zx_DEEP_CLONE_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationDeleteResponse_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationDeleteResponse_s* x);
int zx_WALK_SO_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationDeleteResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationDeleteResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationDeleteResponse_s* x);
int zx_LEN_WO_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationDeleteResponse_s* x);
char* zx_ENC_SO_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationDeleteResponse_s* x, char* p);
char* zx_ENC_WO_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationDeleteResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationDeleteResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDAssociationDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationDeleteResponse_s* x);

struct zx_di_SvcMDAssociationDeleteResponse_s {
  ZX_ELEM_EXT
  zx_di_SvcMDAssociationDeleteResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_lu_Status_s* zx_di_SvcMDAssociationDeleteResponse_GET_Status(struct zx_di_SvcMDAssociationDeleteResponse_s* x, int n);

int zx_di_SvcMDAssociationDeleteResponse_NUM_Status(struct zx_di_SvcMDAssociationDeleteResponse_s* x);

struct zx_lu_Status_s* zx_di_SvcMDAssociationDeleteResponse_POP_Status(struct zx_di_SvcMDAssociationDeleteResponse_s* x);

void zx_di_SvcMDAssociationDeleteResponse_PUSH_Status(struct zx_di_SvcMDAssociationDeleteResponse_s* x, struct zx_lu_Status_s* y);


void zx_di_SvcMDAssociationDeleteResponse_PUT_Status(struct zx_di_SvcMDAssociationDeleteResponse_s* x, int n, struct zx_lu_Status_s* y);

void zx_di_SvcMDAssociationDeleteResponse_ADD_Status(struct zx_di_SvcMDAssociationDeleteResponse_s* x, int n, struct zx_lu_Status_s* z);

void zx_di_SvcMDAssociationDeleteResponse_DEL_Status(struct zx_di_SvcMDAssociationDeleteResponse_s* x, int n);

void zx_di_SvcMDAssociationDeleteResponse_REV_Status(struct zx_di_SvcMDAssociationDeleteResponse_s* x);

#endif
/* -------------------------- di_SvcMDAssociationQuery -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDAssociationQuery_EXT
#define zx_di_SvcMDAssociationQuery_EXT
#endif

struct zx_di_SvcMDAssociationQuery_s* zx_DEC_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDAssociationQuery_s* zx_NEW_di_SvcMDAssociationQuery(struct zx_ctx* c);
void zx_FREE_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_di_SvcMDAssociationQuery_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDAssociationQuery_s* zx_DEEP_CLONE_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_di_SvcMDAssociationQuery_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_di_SvcMDAssociationQuery_s* x);
int zx_WALK_SO_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_di_SvcMDAssociationQuery_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_di_SvcMDAssociationQuery_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_di_SvcMDAssociationQuery_s* x);
int zx_LEN_WO_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_di_SvcMDAssociationQuery_s* x);
char* zx_ENC_SO_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_di_SvcMDAssociationQuery_s* x, char* p);
char* zx_ENC_WO_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_di_SvcMDAssociationQuery_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_di_SvcMDAssociationQuery_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDAssociationQuery(struct zx_ctx* c, struct zx_di_SvcMDAssociationQuery_s* x);

struct zx_di_SvcMDAssociationQuery_s {
  ZX_ELEM_EXT
  zx_di_SvcMDAssociationQuery_EXT
  struct zx_elem_s* SvcMDID;	/* {0,-1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_di_SvcMDAssociationQuery_GET_SvcMDID(struct zx_di_SvcMDAssociationQuery_s* x, int n);

int zx_di_SvcMDAssociationQuery_NUM_SvcMDID(struct zx_di_SvcMDAssociationQuery_s* x);

struct zx_elem_s* zx_di_SvcMDAssociationQuery_POP_SvcMDID(struct zx_di_SvcMDAssociationQuery_s* x);

void zx_di_SvcMDAssociationQuery_PUSH_SvcMDID(struct zx_di_SvcMDAssociationQuery_s* x, struct zx_elem_s* y);


void zx_di_SvcMDAssociationQuery_PUT_SvcMDID(struct zx_di_SvcMDAssociationQuery_s* x, int n, struct zx_elem_s* y);

void zx_di_SvcMDAssociationQuery_ADD_SvcMDID(struct zx_di_SvcMDAssociationQuery_s* x, int n, struct zx_elem_s* z);

void zx_di_SvcMDAssociationQuery_DEL_SvcMDID(struct zx_di_SvcMDAssociationQuery_s* x, int n);

void zx_di_SvcMDAssociationQuery_REV_SvcMDID(struct zx_di_SvcMDAssociationQuery_s* x);

#endif
/* -------------------------- di_SvcMDAssociationQueryResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDAssociationQueryResponse_EXT
#define zx_di_SvcMDAssociationQueryResponse_EXT
#endif

struct zx_di_SvcMDAssociationQueryResponse_s* zx_DEC_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDAssociationQueryResponse_s* zx_NEW_di_SvcMDAssociationQueryResponse(struct zx_ctx* c);
void zx_FREE_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationQueryResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDAssociationQueryResponse_s* zx_DEEP_CLONE_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationQueryResponse_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationQueryResponse_s* x);
int zx_WALK_SO_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationQueryResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationQueryResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationQueryResponse_s* x);
int zx_LEN_WO_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationQueryResponse_s* x);
char* zx_ENC_SO_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationQueryResponse_s* x, char* p);
char* zx_ENC_WO_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationQueryResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationQueryResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDAssociationQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDAssociationQueryResponse_s* x);

struct zx_di_SvcMDAssociationQueryResponse_s {
  ZX_ELEM_EXT
  zx_di_SvcMDAssociationQueryResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_elem_s* SvcMDID;	/* {0,-1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_lu_Status_s* zx_di_SvcMDAssociationQueryResponse_GET_Status(struct zx_di_SvcMDAssociationQueryResponse_s* x, int n);
struct zx_elem_s* zx_di_SvcMDAssociationQueryResponse_GET_SvcMDID(struct zx_di_SvcMDAssociationQueryResponse_s* x, int n);

int zx_di_SvcMDAssociationQueryResponse_NUM_Status(struct zx_di_SvcMDAssociationQueryResponse_s* x);
int zx_di_SvcMDAssociationQueryResponse_NUM_SvcMDID(struct zx_di_SvcMDAssociationQueryResponse_s* x);

struct zx_lu_Status_s* zx_di_SvcMDAssociationQueryResponse_POP_Status(struct zx_di_SvcMDAssociationQueryResponse_s* x);
struct zx_elem_s* zx_di_SvcMDAssociationQueryResponse_POP_SvcMDID(struct zx_di_SvcMDAssociationQueryResponse_s* x);

void zx_di_SvcMDAssociationQueryResponse_PUSH_Status(struct zx_di_SvcMDAssociationQueryResponse_s* x, struct zx_lu_Status_s* y);
void zx_di_SvcMDAssociationQueryResponse_PUSH_SvcMDID(struct zx_di_SvcMDAssociationQueryResponse_s* x, struct zx_elem_s* y);


void zx_di_SvcMDAssociationQueryResponse_PUT_Status(struct zx_di_SvcMDAssociationQueryResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_di_SvcMDAssociationQueryResponse_PUT_SvcMDID(struct zx_di_SvcMDAssociationQueryResponse_s* x, int n, struct zx_elem_s* y);

void zx_di_SvcMDAssociationQueryResponse_ADD_Status(struct zx_di_SvcMDAssociationQueryResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_di_SvcMDAssociationQueryResponse_ADD_SvcMDID(struct zx_di_SvcMDAssociationQueryResponse_s* x, int n, struct zx_elem_s* z);

void zx_di_SvcMDAssociationQueryResponse_DEL_Status(struct zx_di_SvcMDAssociationQueryResponse_s* x, int n);
void zx_di_SvcMDAssociationQueryResponse_DEL_SvcMDID(struct zx_di_SvcMDAssociationQueryResponse_s* x, int n);

void zx_di_SvcMDAssociationQueryResponse_REV_Status(struct zx_di_SvcMDAssociationQueryResponse_s* x);
void zx_di_SvcMDAssociationQueryResponse_REV_SvcMDID(struct zx_di_SvcMDAssociationQueryResponse_s* x);

#endif
/* -------------------------- di_SvcMDDelete -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDDelete_EXT
#define zx_di_SvcMDDelete_EXT
#endif

struct zx_di_SvcMDDelete_s* zx_DEC_di_SvcMDDelete(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDDelete_s* zx_NEW_di_SvcMDDelete(struct zx_ctx* c);
void zx_FREE_di_SvcMDDelete(struct zx_ctx* c, struct zx_di_SvcMDDelete_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDDelete_s* zx_DEEP_CLONE_di_SvcMDDelete(struct zx_ctx* c, struct zx_di_SvcMDDelete_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDDelete(struct zx_ctx* c, struct zx_di_SvcMDDelete_s* x);
int zx_WALK_SO_di_SvcMDDelete(struct zx_ctx* c, struct zx_di_SvcMDDelete_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDDelete(struct zx_ctx* c, struct zx_di_SvcMDDelete_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDDelete(struct zx_ctx* c, struct zx_di_SvcMDDelete_s* x);
int zx_LEN_WO_di_SvcMDDelete(struct zx_ctx* c, struct zx_di_SvcMDDelete_s* x);
char* zx_ENC_SO_di_SvcMDDelete(struct zx_ctx* c, struct zx_di_SvcMDDelete_s* x, char* p);
char* zx_ENC_WO_di_SvcMDDelete(struct zx_ctx* c, struct zx_di_SvcMDDelete_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDDelete(struct zx_ctx* c, struct zx_di_SvcMDDelete_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDDelete(struct zx_ctx* c, struct zx_di_SvcMDDelete_s* x);

struct zx_di_SvcMDDelete_s {
  ZX_ELEM_EXT
  zx_di_SvcMDDelete_EXT
  struct zx_elem_s* SvcMDID;	/* {1,-1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_di_SvcMDDelete_GET_SvcMDID(struct zx_di_SvcMDDelete_s* x, int n);

int zx_di_SvcMDDelete_NUM_SvcMDID(struct zx_di_SvcMDDelete_s* x);

struct zx_elem_s* zx_di_SvcMDDelete_POP_SvcMDID(struct zx_di_SvcMDDelete_s* x);

void zx_di_SvcMDDelete_PUSH_SvcMDID(struct zx_di_SvcMDDelete_s* x, struct zx_elem_s* y);


void zx_di_SvcMDDelete_PUT_SvcMDID(struct zx_di_SvcMDDelete_s* x, int n, struct zx_elem_s* y);

void zx_di_SvcMDDelete_ADD_SvcMDID(struct zx_di_SvcMDDelete_s* x, int n, struct zx_elem_s* z);

void zx_di_SvcMDDelete_DEL_SvcMDID(struct zx_di_SvcMDDelete_s* x, int n);

void zx_di_SvcMDDelete_REV_SvcMDID(struct zx_di_SvcMDDelete_s* x);

#endif
/* -------------------------- di_SvcMDDeleteResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDDeleteResponse_EXT
#define zx_di_SvcMDDeleteResponse_EXT
#endif

struct zx_di_SvcMDDeleteResponse_s* zx_DEC_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDDeleteResponse_s* zx_NEW_di_SvcMDDeleteResponse(struct zx_ctx* c);
void zx_FREE_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDDeleteResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDDeleteResponse_s* zx_DEEP_CLONE_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDDeleteResponse_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDDeleteResponse_s* x);
int zx_WALK_SO_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDDeleteResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDDeleteResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDDeleteResponse_s* x);
int zx_LEN_WO_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDDeleteResponse_s* x);
char* zx_ENC_SO_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDDeleteResponse_s* x, char* p);
char* zx_ENC_WO_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDDeleteResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDDeleteResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDDeleteResponse(struct zx_ctx* c, struct zx_di_SvcMDDeleteResponse_s* x);

struct zx_di_SvcMDDeleteResponse_s {
  ZX_ELEM_EXT
  zx_di_SvcMDDeleteResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_lu_Status_s* zx_di_SvcMDDeleteResponse_GET_Status(struct zx_di_SvcMDDeleteResponse_s* x, int n);

int zx_di_SvcMDDeleteResponse_NUM_Status(struct zx_di_SvcMDDeleteResponse_s* x);

struct zx_lu_Status_s* zx_di_SvcMDDeleteResponse_POP_Status(struct zx_di_SvcMDDeleteResponse_s* x);

void zx_di_SvcMDDeleteResponse_PUSH_Status(struct zx_di_SvcMDDeleteResponse_s* x, struct zx_lu_Status_s* y);


void zx_di_SvcMDDeleteResponse_PUT_Status(struct zx_di_SvcMDDeleteResponse_s* x, int n, struct zx_lu_Status_s* y);

void zx_di_SvcMDDeleteResponse_ADD_Status(struct zx_di_SvcMDDeleteResponse_s* x, int n, struct zx_lu_Status_s* z);

void zx_di_SvcMDDeleteResponse_DEL_Status(struct zx_di_SvcMDDeleteResponse_s* x, int n);

void zx_di_SvcMDDeleteResponse_REV_Status(struct zx_di_SvcMDDeleteResponse_s* x);

#endif
/* -------------------------- di_SvcMDQuery -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDQuery_EXT
#define zx_di_SvcMDQuery_EXT
#endif

struct zx_di_SvcMDQuery_s* zx_DEC_di_SvcMDQuery(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDQuery_s* zx_NEW_di_SvcMDQuery(struct zx_ctx* c);
void zx_FREE_di_SvcMDQuery(struct zx_ctx* c, struct zx_di_SvcMDQuery_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDQuery_s* zx_DEEP_CLONE_di_SvcMDQuery(struct zx_ctx* c, struct zx_di_SvcMDQuery_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDQuery(struct zx_ctx* c, struct zx_di_SvcMDQuery_s* x);
int zx_WALK_SO_di_SvcMDQuery(struct zx_ctx* c, struct zx_di_SvcMDQuery_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDQuery(struct zx_ctx* c, struct zx_di_SvcMDQuery_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDQuery(struct zx_ctx* c, struct zx_di_SvcMDQuery_s* x);
int zx_LEN_WO_di_SvcMDQuery(struct zx_ctx* c, struct zx_di_SvcMDQuery_s* x);
char* zx_ENC_SO_di_SvcMDQuery(struct zx_ctx* c, struct zx_di_SvcMDQuery_s* x, char* p);
char* zx_ENC_WO_di_SvcMDQuery(struct zx_ctx* c, struct zx_di_SvcMDQuery_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDQuery(struct zx_ctx* c, struct zx_di_SvcMDQuery_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDQuery(struct zx_ctx* c, struct zx_di_SvcMDQuery_s* x);

struct zx_di_SvcMDQuery_s {
  ZX_ELEM_EXT
  zx_di_SvcMDQuery_EXT
  struct zx_elem_s* SvcMDID;	/* {0,-1} xs:string */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_di_SvcMDQuery_GET_SvcMDID(struct zx_di_SvcMDQuery_s* x, int n);

int zx_di_SvcMDQuery_NUM_SvcMDID(struct zx_di_SvcMDQuery_s* x);

struct zx_elem_s* zx_di_SvcMDQuery_POP_SvcMDID(struct zx_di_SvcMDQuery_s* x);

void zx_di_SvcMDQuery_PUSH_SvcMDID(struct zx_di_SvcMDQuery_s* x, struct zx_elem_s* y);


void zx_di_SvcMDQuery_PUT_SvcMDID(struct zx_di_SvcMDQuery_s* x, int n, struct zx_elem_s* y);

void zx_di_SvcMDQuery_ADD_SvcMDID(struct zx_di_SvcMDQuery_s* x, int n, struct zx_elem_s* z);

void zx_di_SvcMDQuery_DEL_SvcMDID(struct zx_di_SvcMDQuery_s* x, int n);

void zx_di_SvcMDQuery_REV_SvcMDID(struct zx_di_SvcMDQuery_s* x);

#endif
/* -------------------------- di_SvcMDQueryResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDQueryResponse_EXT
#define zx_di_SvcMDQueryResponse_EXT
#endif

struct zx_di_SvcMDQueryResponse_s* zx_DEC_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDQueryResponse_s* zx_NEW_di_SvcMDQueryResponse(struct zx_ctx* c);
void zx_FREE_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDQueryResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDQueryResponse_s* zx_DEEP_CLONE_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDQueryResponse_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDQueryResponse_s* x);
int zx_WALK_SO_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDQueryResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDQueryResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDQueryResponse_s* x);
int zx_LEN_WO_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDQueryResponse_s* x);
char* zx_ENC_SO_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDQueryResponse_s* x, char* p);
char* zx_ENC_WO_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDQueryResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDQueryResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDQueryResponse(struct zx_ctx* c, struct zx_di_SvcMDQueryResponse_s* x);

struct zx_di_SvcMDQueryResponse_s {
  ZX_ELEM_EXT
  zx_di_SvcMDQueryResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_di_SvcMD_s* SvcMD;	/* {0,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_lu_Status_s* zx_di_SvcMDQueryResponse_GET_Status(struct zx_di_SvcMDQueryResponse_s* x, int n);
struct zx_di_SvcMD_s* zx_di_SvcMDQueryResponse_GET_SvcMD(struct zx_di_SvcMDQueryResponse_s* x, int n);

int zx_di_SvcMDQueryResponse_NUM_Status(struct zx_di_SvcMDQueryResponse_s* x);
int zx_di_SvcMDQueryResponse_NUM_SvcMD(struct zx_di_SvcMDQueryResponse_s* x);

struct zx_lu_Status_s* zx_di_SvcMDQueryResponse_POP_Status(struct zx_di_SvcMDQueryResponse_s* x);
struct zx_di_SvcMD_s* zx_di_SvcMDQueryResponse_POP_SvcMD(struct zx_di_SvcMDQueryResponse_s* x);

void zx_di_SvcMDQueryResponse_PUSH_Status(struct zx_di_SvcMDQueryResponse_s* x, struct zx_lu_Status_s* y);
void zx_di_SvcMDQueryResponse_PUSH_SvcMD(struct zx_di_SvcMDQueryResponse_s* x, struct zx_di_SvcMD_s* y);


void zx_di_SvcMDQueryResponse_PUT_Status(struct zx_di_SvcMDQueryResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_di_SvcMDQueryResponse_PUT_SvcMD(struct zx_di_SvcMDQueryResponse_s* x, int n, struct zx_di_SvcMD_s* y);

void zx_di_SvcMDQueryResponse_ADD_Status(struct zx_di_SvcMDQueryResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_di_SvcMDQueryResponse_ADD_SvcMD(struct zx_di_SvcMDQueryResponse_s* x, int n, struct zx_di_SvcMD_s* z);

void zx_di_SvcMDQueryResponse_DEL_Status(struct zx_di_SvcMDQueryResponse_s* x, int n);
void zx_di_SvcMDQueryResponse_DEL_SvcMD(struct zx_di_SvcMDQueryResponse_s* x, int n);

void zx_di_SvcMDQueryResponse_REV_Status(struct zx_di_SvcMDQueryResponse_s* x);
void zx_di_SvcMDQueryResponse_REV_SvcMD(struct zx_di_SvcMDQueryResponse_s* x);

#endif
/* -------------------------- di_SvcMDRegister -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDRegister_EXT
#define zx_di_SvcMDRegister_EXT
#endif

struct zx_di_SvcMDRegister_s* zx_DEC_di_SvcMDRegister(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDRegister_s* zx_NEW_di_SvcMDRegister(struct zx_ctx* c);
void zx_FREE_di_SvcMDRegister(struct zx_ctx* c, struct zx_di_SvcMDRegister_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDRegister_s* zx_DEEP_CLONE_di_SvcMDRegister(struct zx_ctx* c, struct zx_di_SvcMDRegister_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDRegister(struct zx_ctx* c, struct zx_di_SvcMDRegister_s* x);
int zx_WALK_SO_di_SvcMDRegister(struct zx_ctx* c, struct zx_di_SvcMDRegister_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDRegister(struct zx_ctx* c, struct zx_di_SvcMDRegister_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDRegister(struct zx_ctx* c, struct zx_di_SvcMDRegister_s* x);
int zx_LEN_WO_di_SvcMDRegister(struct zx_ctx* c, struct zx_di_SvcMDRegister_s* x);
char* zx_ENC_SO_di_SvcMDRegister(struct zx_ctx* c, struct zx_di_SvcMDRegister_s* x, char* p);
char* zx_ENC_WO_di_SvcMDRegister(struct zx_ctx* c, struct zx_di_SvcMDRegister_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDRegister(struct zx_ctx* c, struct zx_di_SvcMDRegister_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDRegister(struct zx_ctx* c, struct zx_di_SvcMDRegister_s* x);

struct zx_di_SvcMDRegister_s {
  ZX_ELEM_EXT
  zx_di_SvcMDRegister_EXT
  struct zx_di_SvcMD_s* SvcMD;	/* {1,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_di_SvcMD_s* zx_di_SvcMDRegister_GET_SvcMD(struct zx_di_SvcMDRegister_s* x, int n);

int zx_di_SvcMDRegister_NUM_SvcMD(struct zx_di_SvcMDRegister_s* x);

struct zx_di_SvcMD_s* zx_di_SvcMDRegister_POP_SvcMD(struct zx_di_SvcMDRegister_s* x);

void zx_di_SvcMDRegister_PUSH_SvcMD(struct zx_di_SvcMDRegister_s* x, struct zx_di_SvcMD_s* y);


void zx_di_SvcMDRegister_PUT_SvcMD(struct zx_di_SvcMDRegister_s* x, int n, struct zx_di_SvcMD_s* y);

void zx_di_SvcMDRegister_ADD_SvcMD(struct zx_di_SvcMDRegister_s* x, int n, struct zx_di_SvcMD_s* z);

void zx_di_SvcMDRegister_DEL_SvcMD(struct zx_di_SvcMDRegister_s* x, int n);

void zx_di_SvcMDRegister_REV_SvcMD(struct zx_di_SvcMDRegister_s* x);

#endif
/* -------------------------- di_SvcMDRegisterResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDRegisterResponse_EXT
#define zx_di_SvcMDRegisterResponse_EXT
#endif

struct zx_di_SvcMDRegisterResponse_s* zx_DEC_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDRegisterResponse_s* zx_NEW_di_SvcMDRegisterResponse(struct zx_ctx* c);
void zx_FREE_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_di_SvcMDRegisterResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDRegisterResponse_s* zx_DEEP_CLONE_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_di_SvcMDRegisterResponse_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_di_SvcMDRegisterResponse_s* x);
int zx_WALK_SO_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_di_SvcMDRegisterResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_di_SvcMDRegisterResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_di_SvcMDRegisterResponse_s* x);
int zx_LEN_WO_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_di_SvcMDRegisterResponse_s* x);
char* zx_ENC_SO_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_di_SvcMDRegisterResponse_s* x, char* p);
char* zx_ENC_WO_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_di_SvcMDRegisterResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_di_SvcMDRegisterResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDRegisterResponse(struct zx_ctx* c, struct zx_di_SvcMDRegisterResponse_s* x);

struct zx_di_SvcMDRegisterResponse_s {
  ZX_ELEM_EXT
  zx_di_SvcMDRegisterResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_elem_s* SvcMDID;	/* {0,-1} xs:string */
  struct zx_di_Keys_s* Keys;	/* {0,-1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_lu_Status_s* zx_di_SvcMDRegisterResponse_GET_Status(struct zx_di_SvcMDRegisterResponse_s* x, int n);
struct zx_elem_s* zx_di_SvcMDRegisterResponse_GET_SvcMDID(struct zx_di_SvcMDRegisterResponse_s* x, int n);
struct zx_di_Keys_s* zx_di_SvcMDRegisterResponse_GET_Keys(struct zx_di_SvcMDRegisterResponse_s* x, int n);

int zx_di_SvcMDRegisterResponse_NUM_Status(struct zx_di_SvcMDRegisterResponse_s* x);
int zx_di_SvcMDRegisterResponse_NUM_SvcMDID(struct zx_di_SvcMDRegisterResponse_s* x);
int zx_di_SvcMDRegisterResponse_NUM_Keys(struct zx_di_SvcMDRegisterResponse_s* x);

struct zx_lu_Status_s* zx_di_SvcMDRegisterResponse_POP_Status(struct zx_di_SvcMDRegisterResponse_s* x);
struct zx_elem_s* zx_di_SvcMDRegisterResponse_POP_SvcMDID(struct zx_di_SvcMDRegisterResponse_s* x);
struct zx_di_Keys_s* zx_di_SvcMDRegisterResponse_POP_Keys(struct zx_di_SvcMDRegisterResponse_s* x);

void zx_di_SvcMDRegisterResponse_PUSH_Status(struct zx_di_SvcMDRegisterResponse_s* x, struct zx_lu_Status_s* y);
void zx_di_SvcMDRegisterResponse_PUSH_SvcMDID(struct zx_di_SvcMDRegisterResponse_s* x, struct zx_elem_s* y);
void zx_di_SvcMDRegisterResponse_PUSH_Keys(struct zx_di_SvcMDRegisterResponse_s* x, struct zx_di_Keys_s* y);


void zx_di_SvcMDRegisterResponse_PUT_Status(struct zx_di_SvcMDRegisterResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_di_SvcMDRegisterResponse_PUT_SvcMDID(struct zx_di_SvcMDRegisterResponse_s* x, int n, struct zx_elem_s* y);
void zx_di_SvcMDRegisterResponse_PUT_Keys(struct zx_di_SvcMDRegisterResponse_s* x, int n, struct zx_di_Keys_s* y);

void zx_di_SvcMDRegisterResponse_ADD_Status(struct zx_di_SvcMDRegisterResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_di_SvcMDRegisterResponse_ADD_SvcMDID(struct zx_di_SvcMDRegisterResponse_s* x, int n, struct zx_elem_s* z);
void zx_di_SvcMDRegisterResponse_ADD_Keys(struct zx_di_SvcMDRegisterResponse_s* x, int n, struct zx_di_Keys_s* z);

void zx_di_SvcMDRegisterResponse_DEL_Status(struct zx_di_SvcMDRegisterResponse_s* x, int n);
void zx_di_SvcMDRegisterResponse_DEL_SvcMDID(struct zx_di_SvcMDRegisterResponse_s* x, int n);
void zx_di_SvcMDRegisterResponse_DEL_Keys(struct zx_di_SvcMDRegisterResponse_s* x, int n);

void zx_di_SvcMDRegisterResponse_REV_Status(struct zx_di_SvcMDRegisterResponse_s* x);
void zx_di_SvcMDRegisterResponse_REV_SvcMDID(struct zx_di_SvcMDRegisterResponse_s* x);
void zx_di_SvcMDRegisterResponse_REV_Keys(struct zx_di_SvcMDRegisterResponse_s* x);

#endif
/* -------------------------- di_SvcMDReplace -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDReplace_EXT
#define zx_di_SvcMDReplace_EXT
#endif

struct zx_di_SvcMDReplace_s* zx_DEC_di_SvcMDReplace(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDReplace_s* zx_NEW_di_SvcMDReplace(struct zx_ctx* c);
void zx_FREE_di_SvcMDReplace(struct zx_ctx* c, struct zx_di_SvcMDReplace_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDReplace_s* zx_DEEP_CLONE_di_SvcMDReplace(struct zx_ctx* c, struct zx_di_SvcMDReplace_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDReplace(struct zx_ctx* c, struct zx_di_SvcMDReplace_s* x);
int zx_WALK_SO_di_SvcMDReplace(struct zx_ctx* c, struct zx_di_SvcMDReplace_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDReplace(struct zx_ctx* c, struct zx_di_SvcMDReplace_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDReplace(struct zx_ctx* c, struct zx_di_SvcMDReplace_s* x);
int zx_LEN_WO_di_SvcMDReplace(struct zx_ctx* c, struct zx_di_SvcMDReplace_s* x);
char* zx_ENC_SO_di_SvcMDReplace(struct zx_ctx* c, struct zx_di_SvcMDReplace_s* x, char* p);
char* zx_ENC_WO_di_SvcMDReplace(struct zx_ctx* c, struct zx_di_SvcMDReplace_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDReplace(struct zx_ctx* c, struct zx_di_SvcMDReplace_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDReplace(struct zx_ctx* c, struct zx_di_SvcMDReplace_s* x);

struct zx_di_SvcMDReplace_s {
  ZX_ELEM_EXT
  zx_di_SvcMDReplace_EXT
  struct zx_di_SvcMD_s* SvcMD;	/* {1,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_di_SvcMD_s* zx_di_SvcMDReplace_GET_SvcMD(struct zx_di_SvcMDReplace_s* x, int n);

int zx_di_SvcMDReplace_NUM_SvcMD(struct zx_di_SvcMDReplace_s* x);

struct zx_di_SvcMD_s* zx_di_SvcMDReplace_POP_SvcMD(struct zx_di_SvcMDReplace_s* x);

void zx_di_SvcMDReplace_PUSH_SvcMD(struct zx_di_SvcMDReplace_s* x, struct zx_di_SvcMD_s* y);


void zx_di_SvcMDReplace_PUT_SvcMD(struct zx_di_SvcMDReplace_s* x, int n, struct zx_di_SvcMD_s* y);

void zx_di_SvcMDReplace_ADD_SvcMD(struct zx_di_SvcMDReplace_s* x, int n, struct zx_di_SvcMD_s* z);

void zx_di_SvcMDReplace_DEL_SvcMD(struct zx_di_SvcMDReplace_s* x, int n);

void zx_di_SvcMDReplace_REV_SvcMD(struct zx_di_SvcMDReplace_s* x);

#endif
/* -------------------------- di_SvcMDReplaceResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_di_SvcMDReplaceResponse_EXT
#define zx_di_SvcMDReplaceResponse_EXT
#endif

struct zx_di_SvcMDReplaceResponse_s* zx_DEC_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_di_SvcMDReplaceResponse_s* zx_NEW_di_SvcMDReplaceResponse(struct zx_ctx* c);
void zx_FREE_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_di_SvcMDReplaceResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_di_SvcMDReplaceResponse_s* zx_DEEP_CLONE_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_di_SvcMDReplaceResponse_s* x, int dup_strs);
void zx_DUP_STRS_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_di_SvcMDReplaceResponse_s* x);
int zx_WALK_SO_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_di_SvcMDReplaceResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_di_SvcMDReplaceResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_di_SvcMDReplaceResponse_s* x);
int zx_LEN_WO_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_di_SvcMDReplaceResponse_s* x);
char* zx_ENC_SO_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_di_SvcMDReplaceResponse_s* x, char* p);
char* zx_ENC_WO_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_di_SvcMDReplaceResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_di_SvcMDReplaceResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_di_SvcMDReplaceResponse(struct zx_ctx* c, struct zx_di_SvcMDReplaceResponse_s* x);

struct zx_di_SvcMDReplaceResponse_s {
  ZX_ELEM_EXT
  zx_di_SvcMDReplaceResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_lu_Status_s* zx_di_SvcMDReplaceResponse_GET_Status(struct zx_di_SvcMDReplaceResponse_s* x, int n);

int zx_di_SvcMDReplaceResponse_NUM_Status(struct zx_di_SvcMDReplaceResponse_s* x);

struct zx_lu_Status_s* zx_di_SvcMDReplaceResponse_POP_Status(struct zx_di_SvcMDReplaceResponse_s* x);

void zx_di_SvcMDReplaceResponse_PUSH_Status(struct zx_di_SvcMDReplaceResponse_s* x, struct zx_lu_Status_s* y);


void zx_di_SvcMDReplaceResponse_PUT_Status(struct zx_di_SvcMDReplaceResponse_s* x, int n, struct zx_lu_Status_s* y);

void zx_di_SvcMDReplaceResponse_ADD_Status(struct zx_di_SvcMDReplaceResponse_s* x, int n, struct zx_lu_Status_s* z);

void zx_di_SvcMDReplaceResponse_DEL_Status(struct zx_di_SvcMDReplaceResponse_s* x, int n);

void zx_di_SvcMDReplaceResponse_REV_Status(struct zx_di_SvcMDReplaceResponse_s* x);

#endif

#endif
