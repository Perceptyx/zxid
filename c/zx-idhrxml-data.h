/* c/zx-idhrxml-data.h - WARNING: This header was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Datastructure design, topography, and layout
 * Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for
 * terms and conditions of use. Element and attributes names as well
 * as some topography are derived from schema descriptions that were used as
 * input and may be subject to their own copright. */

#ifndef _c_zx_idhrxml_data_h
#define _c_zx_idhrxml_data_h

#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"

#ifndef ZX_ELEM_EXT
#define ZX_ELEM_EXT  /* This extension point should be defined by who includes this file. */
#endif

/* -------------------------- idhrxml_Create -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_idhrxml_Create_EXT
#define zx_idhrxml_Create_EXT
#endif

struct zx_idhrxml_Create_s* zx_DEC_idhrxml_Create(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_Create_s* zx_NEW_idhrxml_Create(struct zx_ctx* c);
void zx_FREE_idhrxml_Create(struct zx_ctx* c, struct zx_idhrxml_Create_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_Create_s* zx_DEEP_CLONE_idhrxml_Create(struct zx_ctx* c, struct zx_idhrxml_Create_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_Create(struct zx_ctx* c, struct zx_idhrxml_Create_s* x);
int zx_WALK_SO_idhrxml_Create(struct zx_ctx* c, struct zx_idhrxml_Create_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_Create(struct zx_ctx* c, struct zx_idhrxml_Create_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_Create(struct zx_ctx* c, struct zx_idhrxml_Create_s* x);
int zx_LEN_WO_idhrxml_Create(struct zx_ctx* c, struct zx_idhrxml_Create_s* x);
char* zx_ENC_SO_idhrxml_Create(struct zx_ctx* c, struct zx_idhrxml_Create_s* x, char* p);
char* zx_ENC_WO_idhrxml_Create(struct zx_ctx* c, struct zx_idhrxml_Create_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_Create(struct zx_ctx* c, struct zx_idhrxml_Create_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_Create(struct zx_ctx* c, struct zx_idhrxml_Create_s* x);

struct zx_idhrxml_Create_s {
  ZX_ELEM_EXT
  zx_idhrxml_Create_EXT
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_idhrxml_Subscription_s* Subscription;	/* {0,-1} nada */
  struct zx_idhrxml_CreateItem_s* CreateItem;	/* {1,-1} nada */
  struct zx_idhrxml_ResultQuery_s* ResultQuery;	/* {0,-1} nada */
  struct zx_str* itemID;	/* {0,1} attribute lu:IDType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_Create_GET_itemID(struct zx_idhrxml_Create_s* x);

struct zx_lu_Extension_s* zx_idhrxml_Create_GET_Extension(struct zx_idhrxml_Create_s* x, int n);
struct zx_idhrxml_Subscription_s* zx_idhrxml_Create_GET_Subscription(struct zx_idhrxml_Create_s* x, int n);
struct zx_idhrxml_CreateItem_s* zx_idhrxml_Create_GET_CreateItem(struct zx_idhrxml_Create_s* x, int n);
struct zx_idhrxml_ResultQuery_s* zx_idhrxml_Create_GET_ResultQuery(struct zx_idhrxml_Create_s* x, int n);

int zx_idhrxml_Create_NUM_Extension(struct zx_idhrxml_Create_s* x);
int zx_idhrxml_Create_NUM_Subscription(struct zx_idhrxml_Create_s* x);
int zx_idhrxml_Create_NUM_CreateItem(struct zx_idhrxml_Create_s* x);
int zx_idhrxml_Create_NUM_ResultQuery(struct zx_idhrxml_Create_s* x);

struct zx_lu_Extension_s* zx_idhrxml_Create_POP_Extension(struct zx_idhrxml_Create_s* x);
struct zx_idhrxml_Subscription_s* zx_idhrxml_Create_POP_Subscription(struct zx_idhrxml_Create_s* x);
struct zx_idhrxml_CreateItem_s* zx_idhrxml_Create_POP_CreateItem(struct zx_idhrxml_Create_s* x);
struct zx_idhrxml_ResultQuery_s* zx_idhrxml_Create_POP_ResultQuery(struct zx_idhrxml_Create_s* x);

void zx_idhrxml_Create_PUSH_Extension(struct zx_idhrxml_Create_s* x, struct zx_lu_Extension_s* y);
void zx_idhrxml_Create_PUSH_Subscription(struct zx_idhrxml_Create_s* x, struct zx_idhrxml_Subscription_s* y);
void zx_idhrxml_Create_PUSH_CreateItem(struct zx_idhrxml_Create_s* x, struct zx_idhrxml_CreateItem_s* y);
void zx_idhrxml_Create_PUSH_ResultQuery(struct zx_idhrxml_Create_s* x, struct zx_idhrxml_ResultQuery_s* y);

void zx_idhrxml_Create_PUT_itemID(struct zx_idhrxml_Create_s* x, struct zx_str* y);

void zx_idhrxml_Create_PUT_Extension(struct zx_idhrxml_Create_s* x, int n, struct zx_lu_Extension_s* y);
void zx_idhrxml_Create_PUT_Subscription(struct zx_idhrxml_Create_s* x, int n, struct zx_idhrxml_Subscription_s* y);
void zx_idhrxml_Create_PUT_CreateItem(struct zx_idhrxml_Create_s* x, int n, struct zx_idhrxml_CreateItem_s* y);
void zx_idhrxml_Create_PUT_ResultQuery(struct zx_idhrxml_Create_s* x, int n, struct zx_idhrxml_ResultQuery_s* y);

void zx_idhrxml_Create_ADD_Extension(struct zx_idhrxml_Create_s* x, int n, struct zx_lu_Extension_s* z);
void zx_idhrxml_Create_ADD_Subscription(struct zx_idhrxml_Create_s* x, int n, struct zx_idhrxml_Subscription_s* z);
void zx_idhrxml_Create_ADD_CreateItem(struct zx_idhrxml_Create_s* x, int n, struct zx_idhrxml_CreateItem_s* z);
void zx_idhrxml_Create_ADD_ResultQuery(struct zx_idhrxml_Create_s* x, int n, struct zx_idhrxml_ResultQuery_s* z);

void zx_idhrxml_Create_DEL_Extension(struct zx_idhrxml_Create_s* x, int n);
void zx_idhrxml_Create_DEL_Subscription(struct zx_idhrxml_Create_s* x, int n);
void zx_idhrxml_Create_DEL_CreateItem(struct zx_idhrxml_Create_s* x, int n);
void zx_idhrxml_Create_DEL_ResultQuery(struct zx_idhrxml_Create_s* x, int n);

void zx_idhrxml_Create_REV_Extension(struct zx_idhrxml_Create_s* x);
void zx_idhrxml_Create_REV_Subscription(struct zx_idhrxml_Create_s* x);
void zx_idhrxml_Create_REV_CreateItem(struct zx_idhrxml_Create_s* x);
void zx_idhrxml_Create_REV_ResultQuery(struct zx_idhrxml_Create_s* x);

#endif
/* -------------------------- idhrxml_CreateItem -------------------------- */
/* refby( zx_idhrxml_Create_s ) */
#ifndef zx_idhrxml_CreateItem_EXT
#define zx_idhrxml_CreateItem_EXT
#endif

struct zx_idhrxml_CreateItem_s* zx_DEC_idhrxml_CreateItem(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_CreateItem_s* zx_NEW_idhrxml_CreateItem(struct zx_ctx* c);
void zx_FREE_idhrxml_CreateItem(struct zx_ctx* c, struct zx_idhrxml_CreateItem_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_CreateItem_s* zx_DEEP_CLONE_idhrxml_CreateItem(struct zx_ctx* c, struct zx_idhrxml_CreateItem_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_CreateItem(struct zx_ctx* c, struct zx_idhrxml_CreateItem_s* x);
int zx_WALK_SO_idhrxml_CreateItem(struct zx_ctx* c, struct zx_idhrxml_CreateItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_CreateItem(struct zx_ctx* c, struct zx_idhrxml_CreateItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_CreateItem(struct zx_ctx* c, struct zx_idhrxml_CreateItem_s* x);
int zx_LEN_WO_idhrxml_CreateItem(struct zx_ctx* c, struct zx_idhrxml_CreateItem_s* x);
char* zx_ENC_SO_idhrxml_CreateItem(struct zx_ctx* c, struct zx_idhrxml_CreateItem_s* x, char* p);
char* zx_ENC_WO_idhrxml_CreateItem(struct zx_ctx* c, struct zx_idhrxml_CreateItem_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_CreateItem(struct zx_ctx* c, struct zx_idhrxml_CreateItem_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_CreateItem(struct zx_ctx* c, struct zx_idhrxml_CreateItem_s* x);

struct zx_idhrxml_CreateItem_s {
  ZX_ELEM_EXT
  zx_idhrxml_CreateItem_EXT
  struct zx_idhrxml_NewData_s* NewData;	/* {0,1} nada */
  struct zx_str* id;	/* {0,1} attribute xs:ID */
  struct zx_str* itemID;	/* {0,1} attribute lu:IDType */
  struct zx_str* objectType;	/* {0,1} attribute xs:NCName */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_CreateItem_GET_id(struct zx_idhrxml_CreateItem_s* x);
struct zx_str* zx_idhrxml_CreateItem_GET_itemID(struct zx_idhrxml_CreateItem_s* x);
struct zx_str* zx_idhrxml_CreateItem_GET_objectType(struct zx_idhrxml_CreateItem_s* x);

struct zx_idhrxml_NewData_s* zx_idhrxml_CreateItem_GET_NewData(struct zx_idhrxml_CreateItem_s* x, int n);

int zx_idhrxml_CreateItem_NUM_NewData(struct zx_idhrxml_CreateItem_s* x);

struct zx_idhrxml_NewData_s* zx_idhrxml_CreateItem_POP_NewData(struct zx_idhrxml_CreateItem_s* x);

void zx_idhrxml_CreateItem_PUSH_NewData(struct zx_idhrxml_CreateItem_s* x, struct zx_idhrxml_NewData_s* y);

void zx_idhrxml_CreateItem_PUT_id(struct zx_idhrxml_CreateItem_s* x, struct zx_str* y);
void zx_idhrxml_CreateItem_PUT_itemID(struct zx_idhrxml_CreateItem_s* x, struct zx_str* y);
void zx_idhrxml_CreateItem_PUT_objectType(struct zx_idhrxml_CreateItem_s* x, struct zx_str* y);

void zx_idhrxml_CreateItem_PUT_NewData(struct zx_idhrxml_CreateItem_s* x, int n, struct zx_idhrxml_NewData_s* y);

void zx_idhrxml_CreateItem_ADD_NewData(struct zx_idhrxml_CreateItem_s* x, int n, struct zx_idhrxml_NewData_s* z);

void zx_idhrxml_CreateItem_DEL_NewData(struct zx_idhrxml_CreateItem_s* x, int n);

void zx_idhrxml_CreateItem_REV_NewData(struct zx_idhrxml_CreateItem_s* x);

#endif
/* -------------------------- idhrxml_CreateResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_idhrxml_CreateResponse_EXT
#define zx_idhrxml_CreateResponse_EXT
#endif

struct zx_idhrxml_CreateResponse_s* zx_DEC_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_CreateResponse_s* zx_NEW_idhrxml_CreateResponse(struct zx_ctx* c);
void zx_FREE_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_idhrxml_CreateResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_CreateResponse_s* zx_DEEP_CLONE_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_idhrxml_CreateResponse_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_idhrxml_CreateResponse_s* x);
int zx_WALK_SO_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_idhrxml_CreateResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_idhrxml_CreateResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_idhrxml_CreateResponse_s* x);
int zx_LEN_WO_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_idhrxml_CreateResponse_s* x);
char* zx_ENC_SO_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_idhrxml_CreateResponse_s* x, char* p);
char* zx_ENC_WO_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_idhrxml_CreateResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_idhrxml_CreateResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_CreateResponse(struct zx_ctx* c, struct zx_idhrxml_CreateResponse_s* x);

struct zx_idhrxml_CreateResponse_s {
  ZX_ELEM_EXT
  zx_idhrxml_CreateResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_idhrxml_ItemData_s* ItemData;	/* {0,-1} nada */
  struct zx_str* timeStamp;	/* {0,1} attribute xs:dateTime */
  struct zx_str* itemIDRef;	/* {0,1} attribute lu:IDReferenceType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_CreateResponse_GET_timeStamp(struct zx_idhrxml_CreateResponse_s* x);
struct zx_str* zx_idhrxml_CreateResponse_GET_itemIDRef(struct zx_idhrxml_CreateResponse_s* x);

struct zx_lu_Status_s* zx_idhrxml_CreateResponse_GET_Status(struct zx_idhrxml_CreateResponse_s* x, int n);
struct zx_lu_Extension_s* zx_idhrxml_CreateResponse_GET_Extension(struct zx_idhrxml_CreateResponse_s* x, int n);
struct zx_idhrxml_ItemData_s* zx_idhrxml_CreateResponse_GET_ItemData(struct zx_idhrxml_CreateResponse_s* x, int n);

int zx_idhrxml_CreateResponse_NUM_Status(struct zx_idhrxml_CreateResponse_s* x);
int zx_idhrxml_CreateResponse_NUM_Extension(struct zx_idhrxml_CreateResponse_s* x);
int zx_idhrxml_CreateResponse_NUM_ItemData(struct zx_idhrxml_CreateResponse_s* x);

struct zx_lu_Status_s* zx_idhrxml_CreateResponse_POP_Status(struct zx_idhrxml_CreateResponse_s* x);
struct zx_lu_Extension_s* zx_idhrxml_CreateResponse_POP_Extension(struct zx_idhrxml_CreateResponse_s* x);
struct zx_idhrxml_ItemData_s* zx_idhrxml_CreateResponse_POP_ItemData(struct zx_idhrxml_CreateResponse_s* x);

void zx_idhrxml_CreateResponse_PUSH_Status(struct zx_idhrxml_CreateResponse_s* x, struct zx_lu_Status_s* y);
void zx_idhrxml_CreateResponse_PUSH_Extension(struct zx_idhrxml_CreateResponse_s* x, struct zx_lu_Extension_s* y);
void zx_idhrxml_CreateResponse_PUSH_ItemData(struct zx_idhrxml_CreateResponse_s* x, struct zx_idhrxml_ItemData_s* y);

void zx_idhrxml_CreateResponse_PUT_timeStamp(struct zx_idhrxml_CreateResponse_s* x, struct zx_str* y);
void zx_idhrxml_CreateResponse_PUT_itemIDRef(struct zx_idhrxml_CreateResponse_s* x, struct zx_str* y);

void zx_idhrxml_CreateResponse_PUT_Status(struct zx_idhrxml_CreateResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_idhrxml_CreateResponse_PUT_Extension(struct zx_idhrxml_CreateResponse_s* x, int n, struct zx_lu_Extension_s* y);
void zx_idhrxml_CreateResponse_PUT_ItemData(struct zx_idhrxml_CreateResponse_s* x, int n, struct zx_idhrxml_ItemData_s* y);

void zx_idhrxml_CreateResponse_ADD_Status(struct zx_idhrxml_CreateResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_idhrxml_CreateResponse_ADD_Extension(struct zx_idhrxml_CreateResponse_s* x, int n, struct zx_lu_Extension_s* z);
void zx_idhrxml_CreateResponse_ADD_ItemData(struct zx_idhrxml_CreateResponse_s* x, int n, struct zx_idhrxml_ItemData_s* z);

void zx_idhrxml_CreateResponse_DEL_Status(struct zx_idhrxml_CreateResponse_s* x, int n);
void zx_idhrxml_CreateResponse_DEL_Extension(struct zx_idhrxml_CreateResponse_s* x, int n);
void zx_idhrxml_CreateResponse_DEL_ItemData(struct zx_idhrxml_CreateResponse_s* x, int n);

void zx_idhrxml_CreateResponse_REV_Status(struct zx_idhrxml_CreateResponse_s* x);
void zx_idhrxml_CreateResponse_REV_Extension(struct zx_idhrxml_CreateResponse_s* x);
void zx_idhrxml_CreateResponse_REV_ItemData(struct zx_idhrxml_CreateResponse_s* x);

#endif
/* -------------------------- idhrxml_Data -------------------------- */
/* refby( zx_idhrxml_QueryResponse_s ) */
#ifndef zx_idhrxml_Data_EXT
#define zx_idhrxml_Data_EXT
#endif

struct zx_idhrxml_Data_s* zx_DEC_idhrxml_Data(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_Data_s* zx_NEW_idhrxml_Data(struct zx_ctx* c);
void zx_FREE_idhrxml_Data(struct zx_ctx* c, struct zx_idhrxml_Data_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_Data_s* zx_DEEP_CLONE_idhrxml_Data(struct zx_ctx* c, struct zx_idhrxml_Data_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_Data(struct zx_ctx* c, struct zx_idhrxml_Data_s* x);
int zx_WALK_SO_idhrxml_Data(struct zx_ctx* c, struct zx_idhrxml_Data_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_Data(struct zx_ctx* c, struct zx_idhrxml_Data_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_Data(struct zx_ctx* c, struct zx_idhrxml_Data_s* x);
int zx_LEN_WO_idhrxml_Data(struct zx_ctx* c, struct zx_idhrxml_Data_s* x);
char* zx_ENC_SO_idhrxml_Data(struct zx_ctx* c, struct zx_idhrxml_Data_s* x, char* p);
char* zx_ENC_WO_idhrxml_Data(struct zx_ctx* c, struct zx_idhrxml_Data_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_Data(struct zx_ctx* c, struct zx_idhrxml_Data_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_Data(struct zx_ctx* c, struct zx_idhrxml_Data_s* x);

struct zx_idhrxml_Data_s {
  ZX_ELEM_EXT
  zx_idhrxml_Data_EXT
  struct zx_hrxml_Candidate_s* Candidate;	/* {0,1} nada */
  struct zx_idhrxml_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_str* nextOffset;	/* {0,1} attribute xs:nonNegativeInteger */
  struct zx_str* notSorted;	/* {0,1} attribute Now */
  struct zx_str* remaining;	/* {0,1} attribute xs:integer */
  struct zx_str* setID;	/* {0,1} attribute xs:string */
  struct zx_str* changeFormat;	/* {0,1} attribute ChangedElements */
  struct zx_str* itemIDRef;	/* {0,1} attribute lu:IDReferenceType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_Data_GET_nextOffset(struct zx_idhrxml_Data_s* x);
struct zx_str* zx_idhrxml_Data_GET_notSorted(struct zx_idhrxml_Data_s* x);
struct zx_str* zx_idhrxml_Data_GET_remaining(struct zx_idhrxml_Data_s* x);
struct zx_str* zx_idhrxml_Data_GET_setID(struct zx_idhrxml_Data_s* x);
struct zx_str* zx_idhrxml_Data_GET_changeFormat(struct zx_idhrxml_Data_s* x);
struct zx_str* zx_idhrxml_Data_GET_itemIDRef(struct zx_idhrxml_Data_s* x);

struct zx_hrxml_Candidate_s* zx_idhrxml_Data_GET_Candidate(struct zx_idhrxml_Data_s* x, int n);
struct zx_idhrxml_Subscription_s* zx_idhrxml_Data_GET_Subscription(struct zx_idhrxml_Data_s* x, int n);

int zx_idhrxml_Data_NUM_Candidate(struct zx_idhrxml_Data_s* x);
int zx_idhrxml_Data_NUM_Subscription(struct zx_idhrxml_Data_s* x);

struct zx_hrxml_Candidate_s* zx_idhrxml_Data_POP_Candidate(struct zx_idhrxml_Data_s* x);
struct zx_idhrxml_Subscription_s* zx_idhrxml_Data_POP_Subscription(struct zx_idhrxml_Data_s* x);

void zx_idhrxml_Data_PUSH_Candidate(struct zx_idhrxml_Data_s* x, struct zx_hrxml_Candidate_s* y);
void zx_idhrxml_Data_PUSH_Subscription(struct zx_idhrxml_Data_s* x, struct zx_idhrxml_Subscription_s* y);

void zx_idhrxml_Data_PUT_nextOffset(struct zx_idhrxml_Data_s* x, struct zx_str* y);
void zx_idhrxml_Data_PUT_notSorted(struct zx_idhrxml_Data_s* x, struct zx_str* y);
void zx_idhrxml_Data_PUT_remaining(struct zx_idhrxml_Data_s* x, struct zx_str* y);
void zx_idhrxml_Data_PUT_setID(struct zx_idhrxml_Data_s* x, struct zx_str* y);
void zx_idhrxml_Data_PUT_changeFormat(struct zx_idhrxml_Data_s* x, struct zx_str* y);
void zx_idhrxml_Data_PUT_itemIDRef(struct zx_idhrxml_Data_s* x, struct zx_str* y);

void zx_idhrxml_Data_PUT_Candidate(struct zx_idhrxml_Data_s* x, int n, struct zx_hrxml_Candidate_s* y);
void zx_idhrxml_Data_PUT_Subscription(struct zx_idhrxml_Data_s* x, int n, struct zx_idhrxml_Subscription_s* y);

void zx_idhrxml_Data_ADD_Candidate(struct zx_idhrxml_Data_s* x, int n, struct zx_hrxml_Candidate_s* z);
void zx_idhrxml_Data_ADD_Subscription(struct zx_idhrxml_Data_s* x, int n, struct zx_idhrxml_Subscription_s* z);

void zx_idhrxml_Data_DEL_Candidate(struct zx_idhrxml_Data_s* x, int n);
void zx_idhrxml_Data_DEL_Subscription(struct zx_idhrxml_Data_s* x, int n);

void zx_idhrxml_Data_REV_Candidate(struct zx_idhrxml_Data_s* x);
void zx_idhrxml_Data_REV_Subscription(struct zx_idhrxml_Data_s* x);

#endif
/* -------------------------- idhrxml_Delete -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_idhrxml_Delete_EXT
#define zx_idhrxml_Delete_EXT
#endif

struct zx_idhrxml_Delete_s* zx_DEC_idhrxml_Delete(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_Delete_s* zx_NEW_idhrxml_Delete(struct zx_ctx* c);
void zx_FREE_idhrxml_Delete(struct zx_ctx* c, struct zx_idhrxml_Delete_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_Delete_s* zx_DEEP_CLONE_idhrxml_Delete(struct zx_ctx* c, struct zx_idhrxml_Delete_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_Delete(struct zx_ctx* c, struct zx_idhrxml_Delete_s* x);
int zx_WALK_SO_idhrxml_Delete(struct zx_ctx* c, struct zx_idhrxml_Delete_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_Delete(struct zx_ctx* c, struct zx_idhrxml_Delete_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_Delete(struct zx_ctx* c, struct zx_idhrxml_Delete_s* x);
int zx_LEN_WO_idhrxml_Delete(struct zx_ctx* c, struct zx_idhrxml_Delete_s* x);
char* zx_ENC_SO_idhrxml_Delete(struct zx_ctx* c, struct zx_idhrxml_Delete_s* x, char* p);
char* zx_ENC_WO_idhrxml_Delete(struct zx_ctx* c, struct zx_idhrxml_Delete_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_Delete(struct zx_ctx* c, struct zx_idhrxml_Delete_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_Delete(struct zx_ctx* c, struct zx_idhrxml_Delete_s* x);

struct zx_idhrxml_Delete_s {
  ZX_ELEM_EXT
  zx_idhrxml_Delete_EXT
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_idhrxml_DeleteItem_s* DeleteItem;	/* {1,-1} nada */
  struct zx_str* itemID;	/* {0,1} attribute lu:IDType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_Delete_GET_itemID(struct zx_idhrxml_Delete_s* x);

struct zx_lu_Extension_s* zx_idhrxml_Delete_GET_Extension(struct zx_idhrxml_Delete_s* x, int n);
struct zx_idhrxml_DeleteItem_s* zx_idhrxml_Delete_GET_DeleteItem(struct zx_idhrxml_Delete_s* x, int n);

int zx_idhrxml_Delete_NUM_Extension(struct zx_idhrxml_Delete_s* x);
int zx_idhrxml_Delete_NUM_DeleteItem(struct zx_idhrxml_Delete_s* x);

struct zx_lu_Extension_s* zx_idhrxml_Delete_POP_Extension(struct zx_idhrxml_Delete_s* x);
struct zx_idhrxml_DeleteItem_s* zx_idhrxml_Delete_POP_DeleteItem(struct zx_idhrxml_Delete_s* x);

void zx_idhrxml_Delete_PUSH_Extension(struct zx_idhrxml_Delete_s* x, struct zx_lu_Extension_s* y);
void zx_idhrxml_Delete_PUSH_DeleteItem(struct zx_idhrxml_Delete_s* x, struct zx_idhrxml_DeleteItem_s* y);

void zx_idhrxml_Delete_PUT_itemID(struct zx_idhrxml_Delete_s* x, struct zx_str* y);

void zx_idhrxml_Delete_PUT_Extension(struct zx_idhrxml_Delete_s* x, int n, struct zx_lu_Extension_s* y);
void zx_idhrxml_Delete_PUT_DeleteItem(struct zx_idhrxml_Delete_s* x, int n, struct zx_idhrxml_DeleteItem_s* y);

void zx_idhrxml_Delete_ADD_Extension(struct zx_idhrxml_Delete_s* x, int n, struct zx_lu_Extension_s* z);
void zx_idhrxml_Delete_ADD_DeleteItem(struct zx_idhrxml_Delete_s* x, int n, struct zx_idhrxml_DeleteItem_s* z);

void zx_idhrxml_Delete_DEL_Extension(struct zx_idhrxml_Delete_s* x, int n);
void zx_idhrxml_Delete_DEL_DeleteItem(struct zx_idhrxml_Delete_s* x, int n);

void zx_idhrxml_Delete_REV_Extension(struct zx_idhrxml_Delete_s* x);
void zx_idhrxml_Delete_REV_DeleteItem(struct zx_idhrxml_Delete_s* x);

#endif
/* -------------------------- idhrxml_DeleteItem -------------------------- */
/* refby( zx_idhrxml_Delete_s ) */
#ifndef zx_idhrxml_DeleteItem_EXT
#define zx_idhrxml_DeleteItem_EXT
#endif

struct zx_idhrxml_DeleteItem_s* zx_DEC_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_DeleteItem_s* zx_NEW_idhrxml_DeleteItem(struct zx_ctx* c);
void zx_FREE_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_idhrxml_DeleteItem_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_DeleteItem_s* zx_DEEP_CLONE_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_idhrxml_DeleteItem_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_idhrxml_DeleteItem_s* x);
int zx_WALK_SO_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_idhrxml_DeleteItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_idhrxml_DeleteItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_idhrxml_DeleteItem_s* x);
int zx_LEN_WO_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_idhrxml_DeleteItem_s* x);
char* zx_ENC_SO_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_idhrxml_DeleteItem_s* x, char* p);
char* zx_ENC_WO_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_idhrxml_DeleteItem_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_idhrxml_DeleteItem_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_DeleteItem(struct zx_ctx* c, struct zx_idhrxml_DeleteItem_s* x);

struct zx_idhrxml_DeleteItem_s {
  ZX_ELEM_EXT
  zx_idhrxml_DeleteItem_EXT
  struct zx_elem_s* Select;	/* {0,1} xs:string */
  struct zx_str* id;	/* {0,1} attribute xs:ID */
  struct zx_str* notChangedSince;	/* {0,1} attribute xs:dateTime */
  struct zx_str* itemID;	/* {0,1} attribute lu:IDType */
  struct zx_str* objectType;	/* {0,1} attribute xs:NCName */
  struct zx_str* predefined;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_DeleteItem_GET_id(struct zx_idhrxml_DeleteItem_s* x);
struct zx_str* zx_idhrxml_DeleteItem_GET_notChangedSince(struct zx_idhrxml_DeleteItem_s* x);
struct zx_str* zx_idhrxml_DeleteItem_GET_itemID(struct zx_idhrxml_DeleteItem_s* x);
struct zx_str* zx_idhrxml_DeleteItem_GET_objectType(struct zx_idhrxml_DeleteItem_s* x);
struct zx_str* zx_idhrxml_DeleteItem_GET_predefined(struct zx_idhrxml_DeleteItem_s* x);

struct zx_elem_s* zx_idhrxml_DeleteItem_GET_Select(struct zx_idhrxml_DeleteItem_s* x, int n);

int zx_idhrxml_DeleteItem_NUM_Select(struct zx_idhrxml_DeleteItem_s* x);

struct zx_elem_s* zx_idhrxml_DeleteItem_POP_Select(struct zx_idhrxml_DeleteItem_s* x);

void zx_idhrxml_DeleteItem_PUSH_Select(struct zx_idhrxml_DeleteItem_s* x, struct zx_elem_s* y);

void zx_idhrxml_DeleteItem_PUT_id(struct zx_idhrxml_DeleteItem_s* x, struct zx_str* y);
void zx_idhrxml_DeleteItem_PUT_notChangedSince(struct zx_idhrxml_DeleteItem_s* x, struct zx_str* y);
void zx_idhrxml_DeleteItem_PUT_itemID(struct zx_idhrxml_DeleteItem_s* x, struct zx_str* y);
void zx_idhrxml_DeleteItem_PUT_objectType(struct zx_idhrxml_DeleteItem_s* x, struct zx_str* y);
void zx_idhrxml_DeleteItem_PUT_predefined(struct zx_idhrxml_DeleteItem_s* x, struct zx_str* y);

void zx_idhrxml_DeleteItem_PUT_Select(struct zx_idhrxml_DeleteItem_s* x, int n, struct zx_elem_s* y);

void zx_idhrxml_DeleteItem_ADD_Select(struct zx_idhrxml_DeleteItem_s* x, int n, struct zx_elem_s* z);

void zx_idhrxml_DeleteItem_DEL_Select(struct zx_idhrxml_DeleteItem_s* x, int n);

void zx_idhrxml_DeleteItem_REV_Select(struct zx_idhrxml_DeleteItem_s* x);

#endif
/* -------------------------- idhrxml_DeleteResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_idhrxml_DeleteResponse_EXT
#define zx_idhrxml_DeleteResponse_EXT
#endif

struct zx_idhrxml_DeleteResponse_s* zx_DEC_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_DeleteResponse_s* zx_NEW_idhrxml_DeleteResponse(struct zx_ctx* c);
void zx_FREE_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_idhrxml_DeleteResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_DeleteResponse_s* zx_DEEP_CLONE_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_idhrxml_DeleteResponse_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_idhrxml_DeleteResponse_s* x);
int zx_WALK_SO_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_idhrxml_DeleteResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_idhrxml_DeleteResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_idhrxml_DeleteResponse_s* x);
int zx_LEN_WO_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_idhrxml_DeleteResponse_s* x);
char* zx_ENC_SO_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_idhrxml_DeleteResponse_s* x, char* p);
char* zx_ENC_WO_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_idhrxml_DeleteResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_idhrxml_DeleteResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_DeleteResponse(struct zx_ctx* c, struct zx_idhrxml_DeleteResponse_s* x);

struct zx_idhrxml_DeleteResponse_s {
  ZX_ELEM_EXT
  zx_idhrxml_DeleteResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_str* itemIDRef;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_DeleteResponse_GET_itemIDRef(struct zx_idhrxml_DeleteResponse_s* x);

struct zx_lu_Status_s* zx_idhrxml_DeleteResponse_GET_Status(struct zx_idhrxml_DeleteResponse_s* x, int n);
struct zx_lu_Extension_s* zx_idhrxml_DeleteResponse_GET_Extension(struct zx_idhrxml_DeleteResponse_s* x, int n);

int zx_idhrxml_DeleteResponse_NUM_Status(struct zx_idhrxml_DeleteResponse_s* x);
int zx_idhrxml_DeleteResponse_NUM_Extension(struct zx_idhrxml_DeleteResponse_s* x);

struct zx_lu_Status_s* zx_idhrxml_DeleteResponse_POP_Status(struct zx_idhrxml_DeleteResponse_s* x);
struct zx_lu_Extension_s* zx_idhrxml_DeleteResponse_POP_Extension(struct zx_idhrxml_DeleteResponse_s* x);

void zx_idhrxml_DeleteResponse_PUSH_Status(struct zx_idhrxml_DeleteResponse_s* x, struct zx_lu_Status_s* y);
void zx_idhrxml_DeleteResponse_PUSH_Extension(struct zx_idhrxml_DeleteResponse_s* x, struct zx_lu_Extension_s* y);

void zx_idhrxml_DeleteResponse_PUT_itemIDRef(struct zx_idhrxml_DeleteResponse_s* x, struct zx_str* y);

void zx_idhrxml_DeleteResponse_PUT_Status(struct zx_idhrxml_DeleteResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_idhrxml_DeleteResponse_PUT_Extension(struct zx_idhrxml_DeleteResponse_s* x, int n, struct zx_lu_Extension_s* y);

void zx_idhrxml_DeleteResponse_ADD_Status(struct zx_idhrxml_DeleteResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_idhrxml_DeleteResponse_ADD_Extension(struct zx_idhrxml_DeleteResponse_s* x, int n, struct zx_lu_Extension_s* z);

void zx_idhrxml_DeleteResponse_DEL_Status(struct zx_idhrxml_DeleteResponse_s* x, int n);
void zx_idhrxml_DeleteResponse_DEL_Extension(struct zx_idhrxml_DeleteResponse_s* x, int n);

void zx_idhrxml_DeleteResponse_REV_Status(struct zx_idhrxml_DeleteResponse_s* x);
void zx_idhrxml_DeleteResponse_REV_Extension(struct zx_idhrxml_DeleteResponse_s* x);

#endif
/* -------------------------- idhrxml_ItemData -------------------------- */
/* refby( zx_idhrxml_Notification_s zx_idhrxml_ModifyResponse_s zx_idhrxml_CreateResponse_s ) */
#ifndef zx_idhrxml_ItemData_EXT
#define zx_idhrxml_ItemData_EXT
#endif

struct zx_idhrxml_ItemData_s* zx_DEC_idhrxml_ItemData(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_ItemData_s* zx_NEW_idhrxml_ItemData(struct zx_ctx* c);
void zx_FREE_idhrxml_ItemData(struct zx_ctx* c, struct zx_idhrxml_ItemData_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_ItemData_s* zx_DEEP_CLONE_idhrxml_ItemData(struct zx_ctx* c, struct zx_idhrxml_ItemData_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_ItemData(struct zx_ctx* c, struct zx_idhrxml_ItemData_s* x);
int zx_WALK_SO_idhrxml_ItemData(struct zx_ctx* c, struct zx_idhrxml_ItemData_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_ItemData(struct zx_ctx* c, struct zx_idhrxml_ItemData_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_ItemData(struct zx_ctx* c, struct zx_idhrxml_ItemData_s* x);
int zx_LEN_WO_idhrxml_ItemData(struct zx_ctx* c, struct zx_idhrxml_ItemData_s* x);
char* zx_ENC_SO_idhrxml_ItemData(struct zx_ctx* c, struct zx_idhrxml_ItemData_s* x, char* p);
char* zx_ENC_WO_idhrxml_ItemData(struct zx_ctx* c, struct zx_idhrxml_ItemData_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_ItemData(struct zx_ctx* c, struct zx_idhrxml_ItemData_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_ItemData(struct zx_ctx* c, struct zx_idhrxml_ItemData_s* x);

struct zx_idhrxml_ItemData_s {
  ZX_ELEM_EXT
  zx_idhrxml_ItemData_EXT
  struct zx_hrxml_Candidate_s* Candidate;	/* {0,1} nada */
  struct zx_idhrxml_Subscription_s* Subscription;	/* {0,1} nada */
  struct zx_str* notSorted;	/* {0,1} attribute Now */
  struct zx_str* changeFormat;	/* {0,1} attribute ChangedElements */
  struct zx_str* itemIDRef;	/* {0,1} attribute lu:IDReferenceType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_ItemData_GET_notSorted(struct zx_idhrxml_ItemData_s* x);
struct zx_str* zx_idhrxml_ItemData_GET_changeFormat(struct zx_idhrxml_ItemData_s* x);
struct zx_str* zx_idhrxml_ItemData_GET_itemIDRef(struct zx_idhrxml_ItemData_s* x);

struct zx_hrxml_Candidate_s* zx_idhrxml_ItemData_GET_Candidate(struct zx_idhrxml_ItemData_s* x, int n);
struct zx_idhrxml_Subscription_s* zx_idhrxml_ItemData_GET_Subscription(struct zx_idhrxml_ItemData_s* x, int n);

int zx_idhrxml_ItemData_NUM_Candidate(struct zx_idhrxml_ItemData_s* x);
int zx_idhrxml_ItemData_NUM_Subscription(struct zx_idhrxml_ItemData_s* x);

struct zx_hrxml_Candidate_s* zx_idhrxml_ItemData_POP_Candidate(struct zx_idhrxml_ItemData_s* x);
struct zx_idhrxml_Subscription_s* zx_idhrxml_ItemData_POP_Subscription(struct zx_idhrxml_ItemData_s* x);

void zx_idhrxml_ItemData_PUSH_Candidate(struct zx_idhrxml_ItemData_s* x, struct zx_hrxml_Candidate_s* y);
void zx_idhrxml_ItemData_PUSH_Subscription(struct zx_idhrxml_ItemData_s* x, struct zx_idhrxml_Subscription_s* y);

void zx_idhrxml_ItemData_PUT_notSorted(struct zx_idhrxml_ItemData_s* x, struct zx_str* y);
void zx_idhrxml_ItemData_PUT_changeFormat(struct zx_idhrxml_ItemData_s* x, struct zx_str* y);
void zx_idhrxml_ItemData_PUT_itemIDRef(struct zx_idhrxml_ItemData_s* x, struct zx_str* y);

void zx_idhrxml_ItemData_PUT_Candidate(struct zx_idhrxml_ItemData_s* x, int n, struct zx_hrxml_Candidate_s* y);
void zx_idhrxml_ItemData_PUT_Subscription(struct zx_idhrxml_ItemData_s* x, int n, struct zx_idhrxml_Subscription_s* y);

void zx_idhrxml_ItemData_ADD_Candidate(struct zx_idhrxml_ItemData_s* x, int n, struct zx_hrxml_Candidate_s* z);
void zx_idhrxml_ItemData_ADD_Subscription(struct zx_idhrxml_ItemData_s* x, int n, struct zx_idhrxml_Subscription_s* z);

void zx_idhrxml_ItemData_DEL_Candidate(struct zx_idhrxml_ItemData_s* x, int n);
void zx_idhrxml_ItemData_DEL_Subscription(struct zx_idhrxml_ItemData_s* x, int n);

void zx_idhrxml_ItemData_REV_Candidate(struct zx_idhrxml_ItemData_s* x);
void zx_idhrxml_ItemData_REV_Subscription(struct zx_idhrxml_ItemData_s* x);

#endif
/* -------------------------- idhrxml_Modify -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_idhrxml_Modify_EXT
#define zx_idhrxml_Modify_EXT
#endif

struct zx_idhrxml_Modify_s* zx_DEC_idhrxml_Modify(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_Modify_s* zx_NEW_idhrxml_Modify(struct zx_ctx* c);
void zx_FREE_idhrxml_Modify(struct zx_ctx* c, struct zx_idhrxml_Modify_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_Modify_s* zx_DEEP_CLONE_idhrxml_Modify(struct zx_ctx* c, struct zx_idhrxml_Modify_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_Modify(struct zx_ctx* c, struct zx_idhrxml_Modify_s* x);
int zx_WALK_SO_idhrxml_Modify(struct zx_ctx* c, struct zx_idhrxml_Modify_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_Modify(struct zx_ctx* c, struct zx_idhrxml_Modify_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_Modify(struct zx_ctx* c, struct zx_idhrxml_Modify_s* x);
int zx_LEN_WO_idhrxml_Modify(struct zx_ctx* c, struct zx_idhrxml_Modify_s* x);
char* zx_ENC_SO_idhrxml_Modify(struct zx_ctx* c, struct zx_idhrxml_Modify_s* x, char* p);
char* zx_ENC_WO_idhrxml_Modify(struct zx_ctx* c, struct zx_idhrxml_Modify_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_Modify(struct zx_ctx* c, struct zx_idhrxml_Modify_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_Modify(struct zx_ctx* c, struct zx_idhrxml_Modify_s* x);

struct zx_idhrxml_Modify_s {
  ZX_ELEM_EXT
  zx_idhrxml_Modify_EXT
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_idhrxml_Subscription_s* Subscription;	/* {0,-1} nada */
  struct zx_idhrxml_ModifyItem_s* ModifyItem;	/* {1,-1} nada */
  struct zx_idhrxml_ResultQuery_s* ResultQuery;	/* {0,-1} nada */
  struct zx_str* itemID;	/* {0,1} attribute lu:IDType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_Modify_GET_itemID(struct zx_idhrxml_Modify_s* x);

struct zx_lu_Extension_s* zx_idhrxml_Modify_GET_Extension(struct zx_idhrxml_Modify_s* x, int n);
struct zx_idhrxml_Subscription_s* zx_idhrxml_Modify_GET_Subscription(struct zx_idhrxml_Modify_s* x, int n);
struct zx_idhrxml_ModifyItem_s* zx_idhrxml_Modify_GET_ModifyItem(struct zx_idhrxml_Modify_s* x, int n);
struct zx_idhrxml_ResultQuery_s* zx_idhrxml_Modify_GET_ResultQuery(struct zx_idhrxml_Modify_s* x, int n);

int zx_idhrxml_Modify_NUM_Extension(struct zx_idhrxml_Modify_s* x);
int zx_idhrxml_Modify_NUM_Subscription(struct zx_idhrxml_Modify_s* x);
int zx_idhrxml_Modify_NUM_ModifyItem(struct zx_idhrxml_Modify_s* x);
int zx_idhrxml_Modify_NUM_ResultQuery(struct zx_idhrxml_Modify_s* x);

struct zx_lu_Extension_s* zx_idhrxml_Modify_POP_Extension(struct zx_idhrxml_Modify_s* x);
struct zx_idhrxml_Subscription_s* zx_idhrxml_Modify_POP_Subscription(struct zx_idhrxml_Modify_s* x);
struct zx_idhrxml_ModifyItem_s* zx_idhrxml_Modify_POP_ModifyItem(struct zx_idhrxml_Modify_s* x);
struct zx_idhrxml_ResultQuery_s* zx_idhrxml_Modify_POP_ResultQuery(struct zx_idhrxml_Modify_s* x);

void zx_idhrxml_Modify_PUSH_Extension(struct zx_idhrxml_Modify_s* x, struct zx_lu_Extension_s* y);
void zx_idhrxml_Modify_PUSH_Subscription(struct zx_idhrxml_Modify_s* x, struct zx_idhrxml_Subscription_s* y);
void zx_idhrxml_Modify_PUSH_ModifyItem(struct zx_idhrxml_Modify_s* x, struct zx_idhrxml_ModifyItem_s* y);
void zx_idhrxml_Modify_PUSH_ResultQuery(struct zx_idhrxml_Modify_s* x, struct zx_idhrxml_ResultQuery_s* y);

void zx_idhrxml_Modify_PUT_itemID(struct zx_idhrxml_Modify_s* x, struct zx_str* y);

void zx_idhrxml_Modify_PUT_Extension(struct zx_idhrxml_Modify_s* x, int n, struct zx_lu_Extension_s* y);
void zx_idhrxml_Modify_PUT_Subscription(struct zx_idhrxml_Modify_s* x, int n, struct zx_idhrxml_Subscription_s* y);
void zx_idhrxml_Modify_PUT_ModifyItem(struct zx_idhrxml_Modify_s* x, int n, struct zx_idhrxml_ModifyItem_s* y);
void zx_idhrxml_Modify_PUT_ResultQuery(struct zx_idhrxml_Modify_s* x, int n, struct zx_idhrxml_ResultQuery_s* y);

void zx_idhrxml_Modify_ADD_Extension(struct zx_idhrxml_Modify_s* x, int n, struct zx_lu_Extension_s* z);
void zx_idhrxml_Modify_ADD_Subscription(struct zx_idhrxml_Modify_s* x, int n, struct zx_idhrxml_Subscription_s* z);
void zx_idhrxml_Modify_ADD_ModifyItem(struct zx_idhrxml_Modify_s* x, int n, struct zx_idhrxml_ModifyItem_s* z);
void zx_idhrxml_Modify_ADD_ResultQuery(struct zx_idhrxml_Modify_s* x, int n, struct zx_idhrxml_ResultQuery_s* z);

void zx_idhrxml_Modify_DEL_Extension(struct zx_idhrxml_Modify_s* x, int n);
void zx_idhrxml_Modify_DEL_Subscription(struct zx_idhrxml_Modify_s* x, int n);
void zx_idhrxml_Modify_DEL_ModifyItem(struct zx_idhrxml_Modify_s* x, int n);
void zx_idhrxml_Modify_DEL_ResultQuery(struct zx_idhrxml_Modify_s* x, int n);

void zx_idhrxml_Modify_REV_Extension(struct zx_idhrxml_Modify_s* x);
void zx_idhrxml_Modify_REV_Subscription(struct zx_idhrxml_Modify_s* x);
void zx_idhrxml_Modify_REV_ModifyItem(struct zx_idhrxml_Modify_s* x);
void zx_idhrxml_Modify_REV_ResultQuery(struct zx_idhrxml_Modify_s* x);

#endif
/* -------------------------- idhrxml_ModifyItem -------------------------- */
/* refby( zx_idhrxml_Modify_s ) */
#ifndef zx_idhrxml_ModifyItem_EXT
#define zx_idhrxml_ModifyItem_EXT
#endif

struct zx_idhrxml_ModifyItem_s* zx_DEC_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_ModifyItem_s* zx_NEW_idhrxml_ModifyItem(struct zx_ctx* c);
void zx_FREE_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_idhrxml_ModifyItem_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_ModifyItem_s* zx_DEEP_CLONE_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_idhrxml_ModifyItem_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_idhrxml_ModifyItem_s* x);
int zx_WALK_SO_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_idhrxml_ModifyItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_idhrxml_ModifyItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_idhrxml_ModifyItem_s* x);
int zx_LEN_WO_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_idhrxml_ModifyItem_s* x);
char* zx_ENC_SO_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_idhrxml_ModifyItem_s* x, char* p);
char* zx_ENC_WO_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_idhrxml_ModifyItem_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_idhrxml_ModifyItem_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_ModifyItem(struct zx_ctx* c, struct zx_idhrxml_ModifyItem_s* x);

struct zx_idhrxml_ModifyItem_s {
  ZX_ELEM_EXT
  zx_idhrxml_ModifyItem_EXT
  struct zx_elem_s* Select;	/* {0,1} xs:string */
  struct zx_idhrxml_NewData_s* NewData;	/* {0,1} nada */
  struct zx_str* id;	/* {0,1} attribute xs:ID */
  struct zx_str* notChangedSince;	/* {0,1} attribute xs:dateTime */
  struct zx_str* overrideAllowed;	/* {0,1} attribute xs:boolean */
  struct zx_str* itemID;	/* {0,1} attribute lu:IDType */
  struct zx_str* objectType;	/* {0,1} attribute xs:NCName */
  struct zx_str* predefined;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_ModifyItem_GET_id(struct zx_idhrxml_ModifyItem_s* x);
struct zx_str* zx_idhrxml_ModifyItem_GET_notChangedSince(struct zx_idhrxml_ModifyItem_s* x);
struct zx_str* zx_idhrxml_ModifyItem_GET_overrideAllowed(struct zx_idhrxml_ModifyItem_s* x);
struct zx_str* zx_idhrxml_ModifyItem_GET_itemID(struct zx_idhrxml_ModifyItem_s* x);
struct zx_str* zx_idhrxml_ModifyItem_GET_objectType(struct zx_idhrxml_ModifyItem_s* x);
struct zx_str* zx_idhrxml_ModifyItem_GET_predefined(struct zx_idhrxml_ModifyItem_s* x);

struct zx_elem_s* zx_idhrxml_ModifyItem_GET_Select(struct zx_idhrxml_ModifyItem_s* x, int n);
struct zx_idhrxml_NewData_s* zx_idhrxml_ModifyItem_GET_NewData(struct zx_idhrxml_ModifyItem_s* x, int n);

int zx_idhrxml_ModifyItem_NUM_Select(struct zx_idhrxml_ModifyItem_s* x);
int zx_idhrxml_ModifyItem_NUM_NewData(struct zx_idhrxml_ModifyItem_s* x);

struct zx_elem_s* zx_idhrxml_ModifyItem_POP_Select(struct zx_idhrxml_ModifyItem_s* x);
struct zx_idhrxml_NewData_s* zx_idhrxml_ModifyItem_POP_NewData(struct zx_idhrxml_ModifyItem_s* x);

void zx_idhrxml_ModifyItem_PUSH_Select(struct zx_idhrxml_ModifyItem_s* x, struct zx_elem_s* y);
void zx_idhrxml_ModifyItem_PUSH_NewData(struct zx_idhrxml_ModifyItem_s* x, struct zx_idhrxml_NewData_s* y);

void zx_idhrxml_ModifyItem_PUT_id(struct zx_idhrxml_ModifyItem_s* x, struct zx_str* y);
void zx_idhrxml_ModifyItem_PUT_notChangedSince(struct zx_idhrxml_ModifyItem_s* x, struct zx_str* y);
void zx_idhrxml_ModifyItem_PUT_overrideAllowed(struct zx_idhrxml_ModifyItem_s* x, struct zx_str* y);
void zx_idhrxml_ModifyItem_PUT_itemID(struct zx_idhrxml_ModifyItem_s* x, struct zx_str* y);
void zx_idhrxml_ModifyItem_PUT_objectType(struct zx_idhrxml_ModifyItem_s* x, struct zx_str* y);
void zx_idhrxml_ModifyItem_PUT_predefined(struct zx_idhrxml_ModifyItem_s* x, struct zx_str* y);

void zx_idhrxml_ModifyItem_PUT_Select(struct zx_idhrxml_ModifyItem_s* x, int n, struct zx_elem_s* y);
void zx_idhrxml_ModifyItem_PUT_NewData(struct zx_idhrxml_ModifyItem_s* x, int n, struct zx_idhrxml_NewData_s* y);

void zx_idhrxml_ModifyItem_ADD_Select(struct zx_idhrxml_ModifyItem_s* x, int n, struct zx_elem_s* z);
void zx_idhrxml_ModifyItem_ADD_NewData(struct zx_idhrxml_ModifyItem_s* x, int n, struct zx_idhrxml_NewData_s* z);

void zx_idhrxml_ModifyItem_DEL_Select(struct zx_idhrxml_ModifyItem_s* x, int n);
void zx_idhrxml_ModifyItem_DEL_NewData(struct zx_idhrxml_ModifyItem_s* x, int n);

void zx_idhrxml_ModifyItem_REV_Select(struct zx_idhrxml_ModifyItem_s* x);
void zx_idhrxml_ModifyItem_REV_NewData(struct zx_idhrxml_ModifyItem_s* x);

#endif
/* -------------------------- idhrxml_ModifyResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_idhrxml_ModifyResponse_EXT
#define zx_idhrxml_ModifyResponse_EXT
#endif

struct zx_idhrxml_ModifyResponse_s* zx_DEC_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_ModifyResponse_s* zx_NEW_idhrxml_ModifyResponse(struct zx_ctx* c);
void zx_FREE_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_idhrxml_ModifyResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_ModifyResponse_s* zx_DEEP_CLONE_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_idhrxml_ModifyResponse_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_idhrxml_ModifyResponse_s* x);
int zx_WALK_SO_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_idhrxml_ModifyResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_idhrxml_ModifyResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_idhrxml_ModifyResponse_s* x);
int zx_LEN_WO_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_idhrxml_ModifyResponse_s* x);
char* zx_ENC_SO_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_idhrxml_ModifyResponse_s* x, char* p);
char* zx_ENC_WO_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_idhrxml_ModifyResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_idhrxml_ModifyResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_ModifyResponse(struct zx_ctx* c, struct zx_idhrxml_ModifyResponse_s* x);

struct zx_idhrxml_ModifyResponse_s {
  ZX_ELEM_EXT
  zx_idhrxml_ModifyResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_idhrxml_ItemData_s* ItemData;	/* {0,-1} nada */
  struct zx_str* timeStamp;	/* {0,1} attribute xs:dateTime */
  struct zx_str* itemIDRef;	/* {0,1} attribute lu:IDReferenceType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_ModifyResponse_GET_timeStamp(struct zx_idhrxml_ModifyResponse_s* x);
struct zx_str* zx_idhrxml_ModifyResponse_GET_itemIDRef(struct zx_idhrxml_ModifyResponse_s* x);

struct zx_lu_Status_s* zx_idhrxml_ModifyResponse_GET_Status(struct zx_idhrxml_ModifyResponse_s* x, int n);
struct zx_lu_Extension_s* zx_idhrxml_ModifyResponse_GET_Extension(struct zx_idhrxml_ModifyResponse_s* x, int n);
struct zx_idhrxml_ItemData_s* zx_idhrxml_ModifyResponse_GET_ItemData(struct zx_idhrxml_ModifyResponse_s* x, int n);

int zx_idhrxml_ModifyResponse_NUM_Status(struct zx_idhrxml_ModifyResponse_s* x);
int zx_idhrxml_ModifyResponse_NUM_Extension(struct zx_idhrxml_ModifyResponse_s* x);
int zx_idhrxml_ModifyResponse_NUM_ItemData(struct zx_idhrxml_ModifyResponse_s* x);

struct zx_lu_Status_s* zx_idhrxml_ModifyResponse_POP_Status(struct zx_idhrxml_ModifyResponse_s* x);
struct zx_lu_Extension_s* zx_idhrxml_ModifyResponse_POP_Extension(struct zx_idhrxml_ModifyResponse_s* x);
struct zx_idhrxml_ItemData_s* zx_idhrxml_ModifyResponse_POP_ItemData(struct zx_idhrxml_ModifyResponse_s* x);

void zx_idhrxml_ModifyResponse_PUSH_Status(struct zx_idhrxml_ModifyResponse_s* x, struct zx_lu_Status_s* y);
void zx_idhrxml_ModifyResponse_PUSH_Extension(struct zx_idhrxml_ModifyResponse_s* x, struct zx_lu_Extension_s* y);
void zx_idhrxml_ModifyResponse_PUSH_ItemData(struct zx_idhrxml_ModifyResponse_s* x, struct zx_idhrxml_ItemData_s* y);

void zx_idhrxml_ModifyResponse_PUT_timeStamp(struct zx_idhrxml_ModifyResponse_s* x, struct zx_str* y);
void zx_idhrxml_ModifyResponse_PUT_itemIDRef(struct zx_idhrxml_ModifyResponse_s* x, struct zx_str* y);

void zx_idhrxml_ModifyResponse_PUT_Status(struct zx_idhrxml_ModifyResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_idhrxml_ModifyResponse_PUT_Extension(struct zx_idhrxml_ModifyResponse_s* x, int n, struct zx_lu_Extension_s* y);
void zx_idhrxml_ModifyResponse_PUT_ItemData(struct zx_idhrxml_ModifyResponse_s* x, int n, struct zx_idhrxml_ItemData_s* y);

void zx_idhrxml_ModifyResponse_ADD_Status(struct zx_idhrxml_ModifyResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_idhrxml_ModifyResponse_ADD_Extension(struct zx_idhrxml_ModifyResponse_s* x, int n, struct zx_lu_Extension_s* z);
void zx_idhrxml_ModifyResponse_ADD_ItemData(struct zx_idhrxml_ModifyResponse_s* x, int n, struct zx_idhrxml_ItemData_s* z);

void zx_idhrxml_ModifyResponse_DEL_Status(struct zx_idhrxml_ModifyResponse_s* x, int n);
void zx_idhrxml_ModifyResponse_DEL_Extension(struct zx_idhrxml_ModifyResponse_s* x, int n);
void zx_idhrxml_ModifyResponse_DEL_ItemData(struct zx_idhrxml_ModifyResponse_s* x, int n);

void zx_idhrxml_ModifyResponse_REV_Status(struct zx_idhrxml_ModifyResponse_s* x);
void zx_idhrxml_ModifyResponse_REV_Extension(struct zx_idhrxml_ModifyResponse_s* x);
void zx_idhrxml_ModifyResponse_REV_ItemData(struct zx_idhrxml_ModifyResponse_s* x);

#endif
/* -------------------------- idhrxml_NewData -------------------------- */
/* refby( zx_idhrxml_CreateItem_s zx_idhrxml_ModifyItem_s ) */
#ifndef zx_idhrxml_NewData_EXT
#define zx_idhrxml_NewData_EXT
#endif

struct zx_idhrxml_NewData_s* zx_DEC_idhrxml_NewData(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_NewData_s* zx_NEW_idhrxml_NewData(struct zx_ctx* c);
void zx_FREE_idhrxml_NewData(struct zx_ctx* c, struct zx_idhrxml_NewData_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_NewData_s* zx_DEEP_CLONE_idhrxml_NewData(struct zx_ctx* c, struct zx_idhrxml_NewData_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_NewData(struct zx_ctx* c, struct zx_idhrxml_NewData_s* x);
int zx_WALK_SO_idhrxml_NewData(struct zx_ctx* c, struct zx_idhrxml_NewData_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_NewData(struct zx_ctx* c, struct zx_idhrxml_NewData_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_NewData(struct zx_ctx* c, struct zx_idhrxml_NewData_s* x);
int zx_LEN_WO_idhrxml_NewData(struct zx_ctx* c, struct zx_idhrxml_NewData_s* x);
char* zx_ENC_SO_idhrxml_NewData(struct zx_ctx* c, struct zx_idhrxml_NewData_s* x, char* p);
char* zx_ENC_WO_idhrxml_NewData(struct zx_ctx* c, struct zx_idhrxml_NewData_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_NewData(struct zx_ctx* c, struct zx_idhrxml_NewData_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_NewData(struct zx_ctx* c, struct zx_idhrxml_NewData_s* x);

struct zx_idhrxml_NewData_s {
  ZX_ELEM_EXT
  zx_idhrxml_NewData_EXT
  struct zx_hrxml_Candidate_s* Candidate;	/* {0,1} nada */
  struct zx_idhrxml_Subscription_s* Subscription;	/* {0,1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_hrxml_Candidate_s* zx_idhrxml_NewData_GET_Candidate(struct zx_idhrxml_NewData_s* x, int n);
struct zx_idhrxml_Subscription_s* zx_idhrxml_NewData_GET_Subscription(struct zx_idhrxml_NewData_s* x, int n);

int zx_idhrxml_NewData_NUM_Candidate(struct zx_idhrxml_NewData_s* x);
int zx_idhrxml_NewData_NUM_Subscription(struct zx_idhrxml_NewData_s* x);

struct zx_hrxml_Candidate_s* zx_idhrxml_NewData_POP_Candidate(struct zx_idhrxml_NewData_s* x);
struct zx_idhrxml_Subscription_s* zx_idhrxml_NewData_POP_Subscription(struct zx_idhrxml_NewData_s* x);

void zx_idhrxml_NewData_PUSH_Candidate(struct zx_idhrxml_NewData_s* x, struct zx_hrxml_Candidate_s* y);
void zx_idhrxml_NewData_PUSH_Subscription(struct zx_idhrxml_NewData_s* x, struct zx_idhrxml_Subscription_s* y);


void zx_idhrxml_NewData_PUT_Candidate(struct zx_idhrxml_NewData_s* x, int n, struct zx_hrxml_Candidate_s* y);
void zx_idhrxml_NewData_PUT_Subscription(struct zx_idhrxml_NewData_s* x, int n, struct zx_idhrxml_Subscription_s* y);

void zx_idhrxml_NewData_ADD_Candidate(struct zx_idhrxml_NewData_s* x, int n, struct zx_hrxml_Candidate_s* z);
void zx_idhrxml_NewData_ADD_Subscription(struct zx_idhrxml_NewData_s* x, int n, struct zx_idhrxml_Subscription_s* z);

void zx_idhrxml_NewData_DEL_Candidate(struct zx_idhrxml_NewData_s* x, int n);
void zx_idhrxml_NewData_DEL_Subscription(struct zx_idhrxml_NewData_s* x, int n);

void zx_idhrxml_NewData_REV_Candidate(struct zx_idhrxml_NewData_s* x);
void zx_idhrxml_NewData_REV_Subscription(struct zx_idhrxml_NewData_s* x);

#endif
/* -------------------------- idhrxml_Notification -------------------------- */
/* refby( zx_idhrxml_Notify_s ) */
#ifndef zx_idhrxml_Notification_EXT
#define zx_idhrxml_Notification_EXT
#endif

struct zx_idhrxml_Notification_s* zx_DEC_idhrxml_Notification(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_Notification_s* zx_NEW_idhrxml_Notification(struct zx_ctx* c);
void zx_FREE_idhrxml_Notification(struct zx_ctx* c, struct zx_idhrxml_Notification_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_Notification_s* zx_DEEP_CLONE_idhrxml_Notification(struct zx_ctx* c, struct zx_idhrxml_Notification_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_Notification(struct zx_ctx* c, struct zx_idhrxml_Notification_s* x);
int zx_WALK_SO_idhrxml_Notification(struct zx_ctx* c, struct zx_idhrxml_Notification_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_Notification(struct zx_ctx* c, struct zx_idhrxml_Notification_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_Notification(struct zx_ctx* c, struct zx_idhrxml_Notification_s* x);
int zx_LEN_WO_idhrxml_Notification(struct zx_ctx* c, struct zx_idhrxml_Notification_s* x);
char* zx_ENC_SO_idhrxml_Notification(struct zx_ctx* c, struct zx_idhrxml_Notification_s* x, char* p);
char* zx_ENC_WO_idhrxml_Notification(struct zx_ctx* c, struct zx_idhrxml_Notification_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_Notification(struct zx_ctx* c, struct zx_idhrxml_Notification_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_Notification(struct zx_ctx* c, struct zx_idhrxml_Notification_s* x);

struct zx_idhrxml_Notification_s {
  ZX_ELEM_EXT
  zx_idhrxml_Notification_EXT
  struct zx_lu_TestResult_s* TestResult;	/* {0,-1} nada */
  struct zx_idhrxml_ItemData_s* ItemData;	/* {0,-1} nada */
  struct zx_str* endReason;	/* {0,1} attribute xs:anyURI */
  struct zx_str* expires;	/* {0,1} attribute xs:dateTime */
  struct zx_str* id;	/* {0,1} attribute xs:ID */
  struct zx_str* subscriptionID;	/* {1,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_Notification_GET_endReason(struct zx_idhrxml_Notification_s* x);
struct zx_str* zx_idhrxml_Notification_GET_expires(struct zx_idhrxml_Notification_s* x);
struct zx_str* zx_idhrxml_Notification_GET_id(struct zx_idhrxml_Notification_s* x);
struct zx_str* zx_idhrxml_Notification_GET_subscriptionID(struct zx_idhrxml_Notification_s* x);

struct zx_lu_TestResult_s* zx_idhrxml_Notification_GET_TestResult(struct zx_idhrxml_Notification_s* x, int n);
struct zx_idhrxml_ItemData_s* zx_idhrxml_Notification_GET_ItemData(struct zx_idhrxml_Notification_s* x, int n);

int zx_idhrxml_Notification_NUM_TestResult(struct zx_idhrxml_Notification_s* x);
int zx_idhrxml_Notification_NUM_ItemData(struct zx_idhrxml_Notification_s* x);

struct zx_lu_TestResult_s* zx_idhrxml_Notification_POP_TestResult(struct zx_idhrxml_Notification_s* x);
struct zx_idhrxml_ItemData_s* zx_idhrxml_Notification_POP_ItemData(struct zx_idhrxml_Notification_s* x);

void zx_idhrxml_Notification_PUSH_TestResult(struct zx_idhrxml_Notification_s* x, struct zx_lu_TestResult_s* y);
void zx_idhrxml_Notification_PUSH_ItemData(struct zx_idhrxml_Notification_s* x, struct zx_idhrxml_ItemData_s* y);

void zx_idhrxml_Notification_PUT_endReason(struct zx_idhrxml_Notification_s* x, struct zx_str* y);
void zx_idhrxml_Notification_PUT_expires(struct zx_idhrxml_Notification_s* x, struct zx_str* y);
void zx_idhrxml_Notification_PUT_id(struct zx_idhrxml_Notification_s* x, struct zx_str* y);
void zx_idhrxml_Notification_PUT_subscriptionID(struct zx_idhrxml_Notification_s* x, struct zx_str* y);

void zx_idhrxml_Notification_PUT_TestResult(struct zx_idhrxml_Notification_s* x, int n, struct zx_lu_TestResult_s* y);
void zx_idhrxml_Notification_PUT_ItemData(struct zx_idhrxml_Notification_s* x, int n, struct zx_idhrxml_ItemData_s* y);

void zx_idhrxml_Notification_ADD_TestResult(struct zx_idhrxml_Notification_s* x, int n, struct zx_lu_TestResult_s* z);
void zx_idhrxml_Notification_ADD_ItemData(struct zx_idhrxml_Notification_s* x, int n, struct zx_idhrxml_ItemData_s* z);

void zx_idhrxml_Notification_DEL_TestResult(struct zx_idhrxml_Notification_s* x, int n);
void zx_idhrxml_Notification_DEL_ItemData(struct zx_idhrxml_Notification_s* x, int n);

void zx_idhrxml_Notification_REV_TestResult(struct zx_idhrxml_Notification_s* x);
void zx_idhrxml_Notification_REV_ItemData(struct zx_idhrxml_Notification_s* x);

#endif
/* -------------------------- idhrxml_Notify -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_idhrxml_Notify_EXT
#define zx_idhrxml_Notify_EXT
#endif

struct zx_idhrxml_Notify_s* zx_DEC_idhrxml_Notify(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_Notify_s* zx_NEW_idhrxml_Notify(struct zx_ctx* c);
void zx_FREE_idhrxml_Notify(struct zx_ctx* c, struct zx_idhrxml_Notify_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_Notify_s* zx_DEEP_CLONE_idhrxml_Notify(struct zx_ctx* c, struct zx_idhrxml_Notify_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_Notify(struct zx_ctx* c, struct zx_idhrxml_Notify_s* x);
int zx_WALK_SO_idhrxml_Notify(struct zx_ctx* c, struct zx_idhrxml_Notify_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_Notify(struct zx_ctx* c, struct zx_idhrxml_Notify_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_Notify(struct zx_ctx* c, struct zx_idhrxml_Notify_s* x);
int zx_LEN_WO_idhrxml_Notify(struct zx_ctx* c, struct zx_idhrxml_Notify_s* x);
char* zx_ENC_SO_idhrxml_Notify(struct zx_ctx* c, struct zx_idhrxml_Notify_s* x, char* p);
char* zx_ENC_WO_idhrxml_Notify(struct zx_ctx* c, struct zx_idhrxml_Notify_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_Notify(struct zx_ctx* c, struct zx_idhrxml_Notify_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_Notify(struct zx_ctx* c, struct zx_idhrxml_Notify_s* x);

struct zx_idhrxml_Notify_s {
  ZX_ELEM_EXT
  zx_idhrxml_Notify_EXT
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_idhrxml_Notification_s* Notification;	/* {0,-1} nada */
  struct zx_str* timeStamp;	/* {0,1} attribute xs:dateTime */
  struct zx_str* itemID;	/* {0,1} attribute lu:IDType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_Notify_GET_timeStamp(struct zx_idhrxml_Notify_s* x);
struct zx_str* zx_idhrxml_Notify_GET_itemID(struct zx_idhrxml_Notify_s* x);

struct zx_lu_Extension_s* zx_idhrxml_Notify_GET_Extension(struct zx_idhrxml_Notify_s* x, int n);
struct zx_idhrxml_Notification_s* zx_idhrxml_Notify_GET_Notification(struct zx_idhrxml_Notify_s* x, int n);

int zx_idhrxml_Notify_NUM_Extension(struct zx_idhrxml_Notify_s* x);
int zx_idhrxml_Notify_NUM_Notification(struct zx_idhrxml_Notify_s* x);

struct zx_lu_Extension_s* zx_idhrxml_Notify_POP_Extension(struct zx_idhrxml_Notify_s* x);
struct zx_idhrxml_Notification_s* zx_idhrxml_Notify_POP_Notification(struct zx_idhrxml_Notify_s* x);

void zx_idhrxml_Notify_PUSH_Extension(struct zx_idhrxml_Notify_s* x, struct zx_lu_Extension_s* y);
void zx_idhrxml_Notify_PUSH_Notification(struct zx_idhrxml_Notify_s* x, struct zx_idhrxml_Notification_s* y);

void zx_idhrxml_Notify_PUT_timeStamp(struct zx_idhrxml_Notify_s* x, struct zx_str* y);
void zx_idhrxml_Notify_PUT_itemID(struct zx_idhrxml_Notify_s* x, struct zx_str* y);

void zx_idhrxml_Notify_PUT_Extension(struct zx_idhrxml_Notify_s* x, int n, struct zx_lu_Extension_s* y);
void zx_idhrxml_Notify_PUT_Notification(struct zx_idhrxml_Notify_s* x, int n, struct zx_idhrxml_Notification_s* y);

void zx_idhrxml_Notify_ADD_Extension(struct zx_idhrxml_Notify_s* x, int n, struct zx_lu_Extension_s* z);
void zx_idhrxml_Notify_ADD_Notification(struct zx_idhrxml_Notify_s* x, int n, struct zx_idhrxml_Notification_s* z);

void zx_idhrxml_Notify_DEL_Extension(struct zx_idhrxml_Notify_s* x, int n);
void zx_idhrxml_Notify_DEL_Notification(struct zx_idhrxml_Notify_s* x, int n);

void zx_idhrxml_Notify_REV_Extension(struct zx_idhrxml_Notify_s* x);
void zx_idhrxml_Notify_REV_Notification(struct zx_idhrxml_Notify_s* x);

#endif
/* -------------------------- idhrxml_NotifyResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_idhrxml_NotifyResponse_EXT
#define zx_idhrxml_NotifyResponse_EXT
#endif

struct zx_idhrxml_NotifyResponse_s* zx_DEC_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_NotifyResponse_s* zx_NEW_idhrxml_NotifyResponse(struct zx_ctx* c);
void zx_FREE_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_idhrxml_NotifyResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_NotifyResponse_s* zx_DEEP_CLONE_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_idhrxml_NotifyResponse_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_idhrxml_NotifyResponse_s* x);
int zx_WALK_SO_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_idhrxml_NotifyResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_idhrxml_NotifyResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_idhrxml_NotifyResponse_s* x);
int zx_LEN_WO_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_idhrxml_NotifyResponse_s* x);
char* zx_ENC_SO_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_idhrxml_NotifyResponse_s* x, char* p);
char* zx_ENC_WO_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_idhrxml_NotifyResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_idhrxml_NotifyResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_NotifyResponse(struct zx_ctx* c, struct zx_idhrxml_NotifyResponse_s* x);

struct zx_idhrxml_NotifyResponse_s {
  ZX_ELEM_EXT
  zx_idhrxml_NotifyResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_str* itemIDRef;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_NotifyResponse_GET_itemIDRef(struct zx_idhrxml_NotifyResponse_s* x);

struct zx_lu_Status_s* zx_idhrxml_NotifyResponse_GET_Status(struct zx_idhrxml_NotifyResponse_s* x, int n);
struct zx_lu_Extension_s* zx_idhrxml_NotifyResponse_GET_Extension(struct zx_idhrxml_NotifyResponse_s* x, int n);

int zx_idhrxml_NotifyResponse_NUM_Status(struct zx_idhrxml_NotifyResponse_s* x);
int zx_idhrxml_NotifyResponse_NUM_Extension(struct zx_idhrxml_NotifyResponse_s* x);

struct zx_lu_Status_s* zx_idhrxml_NotifyResponse_POP_Status(struct zx_idhrxml_NotifyResponse_s* x);
struct zx_lu_Extension_s* zx_idhrxml_NotifyResponse_POP_Extension(struct zx_idhrxml_NotifyResponse_s* x);

void zx_idhrxml_NotifyResponse_PUSH_Status(struct zx_idhrxml_NotifyResponse_s* x, struct zx_lu_Status_s* y);
void zx_idhrxml_NotifyResponse_PUSH_Extension(struct zx_idhrxml_NotifyResponse_s* x, struct zx_lu_Extension_s* y);

void zx_idhrxml_NotifyResponse_PUT_itemIDRef(struct zx_idhrxml_NotifyResponse_s* x, struct zx_str* y);

void zx_idhrxml_NotifyResponse_PUT_Status(struct zx_idhrxml_NotifyResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_idhrxml_NotifyResponse_PUT_Extension(struct zx_idhrxml_NotifyResponse_s* x, int n, struct zx_lu_Extension_s* y);

void zx_idhrxml_NotifyResponse_ADD_Status(struct zx_idhrxml_NotifyResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_idhrxml_NotifyResponse_ADD_Extension(struct zx_idhrxml_NotifyResponse_s* x, int n, struct zx_lu_Extension_s* z);

void zx_idhrxml_NotifyResponse_DEL_Status(struct zx_idhrxml_NotifyResponse_s* x, int n);
void zx_idhrxml_NotifyResponse_DEL_Extension(struct zx_idhrxml_NotifyResponse_s* x, int n);

void zx_idhrxml_NotifyResponse_REV_Status(struct zx_idhrxml_NotifyResponse_s* x);
void zx_idhrxml_NotifyResponse_REV_Extension(struct zx_idhrxml_NotifyResponse_s* x);

#endif
/* -------------------------- idhrxml_Query -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_idhrxml_Query_EXT
#define zx_idhrxml_Query_EXT
#endif

struct zx_idhrxml_Query_s* zx_DEC_idhrxml_Query(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_Query_s* zx_NEW_idhrxml_Query(struct zx_ctx* c);
void zx_FREE_idhrxml_Query(struct zx_ctx* c, struct zx_idhrxml_Query_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_Query_s* zx_DEEP_CLONE_idhrxml_Query(struct zx_ctx* c, struct zx_idhrxml_Query_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_Query(struct zx_ctx* c, struct zx_idhrxml_Query_s* x);
int zx_WALK_SO_idhrxml_Query(struct zx_ctx* c, struct zx_idhrxml_Query_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_Query(struct zx_ctx* c, struct zx_idhrxml_Query_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_Query(struct zx_ctx* c, struct zx_idhrxml_Query_s* x);
int zx_LEN_WO_idhrxml_Query(struct zx_ctx* c, struct zx_idhrxml_Query_s* x);
char* zx_ENC_SO_idhrxml_Query(struct zx_ctx* c, struct zx_idhrxml_Query_s* x, char* p);
char* zx_ENC_WO_idhrxml_Query(struct zx_ctx* c, struct zx_idhrxml_Query_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_Query(struct zx_ctx* c, struct zx_idhrxml_Query_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_Query(struct zx_ctx* c, struct zx_idhrxml_Query_s* x);

struct zx_idhrxml_Query_s {
  ZX_ELEM_EXT
  zx_idhrxml_Query_EXT
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_idhrxml_TestItem_s* TestItem;	/* {0,-1} nada */
  struct zx_idhrxml_QueryItem_s* QueryItem;	/* {0,-1} nada */
  struct zx_idhrxml_Subscription_s* Subscription;	/* {0,-1} nada */
  struct zx_str* itemID;	/* {0,1} attribute lu:IDType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_Query_GET_itemID(struct zx_idhrxml_Query_s* x);

struct zx_lu_Extension_s* zx_idhrxml_Query_GET_Extension(struct zx_idhrxml_Query_s* x, int n);
struct zx_idhrxml_TestItem_s* zx_idhrxml_Query_GET_TestItem(struct zx_idhrxml_Query_s* x, int n);
struct zx_idhrxml_QueryItem_s* zx_idhrxml_Query_GET_QueryItem(struct zx_idhrxml_Query_s* x, int n);
struct zx_idhrxml_Subscription_s* zx_idhrxml_Query_GET_Subscription(struct zx_idhrxml_Query_s* x, int n);

int zx_idhrxml_Query_NUM_Extension(struct zx_idhrxml_Query_s* x);
int zx_idhrxml_Query_NUM_TestItem(struct zx_idhrxml_Query_s* x);
int zx_idhrxml_Query_NUM_QueryItem(struct zx_idhrxml_Query_s* x);
int zx_idhrxml_Query_NUM_Subscription(struct zx_idhrxml_Query_s* x);

struct zx_lu_Extension_s* zx_idhrxml_Query_POP_Extension(struct zx_idhrxml_Query_s* x);
struct zx_idhrxml_TestItem_s* zx_idhrxml_Query_POP_TestItem(struct zx_idhrxml_Query_s* x);
struct zx_idhrxml_QueryItem_s* zx_idhrxml_Query_POP_QueryItem(struct zx_idhrxml_Query_s* x);
struct zx_idhrxml_Subscription_s* zx_idhrxml_Query_POP_Subscription(struct zx_idhrxml_Query_s* x);

void zx_idhrxml_Query_PUSH_Extension(struct zx_idhrxml_Query_s* x, struct zx_lu_Extension_s* y);
void zx_idhrxml_Query_PUSH_TestItem(struct zx_idhrxml_Query_s* x, struct zx_idhrxml_TestItem_s* y);
void zx_idhrxml_Query_PUSH_QueryItem(struct zx_idhrxml_Query_s* x, struct zx_idhrxml_QueryItem_s* y);
void zx_idhrxml_Query_PUSH_Subscription(struct zx_idhrxml_Query_s* x, struct zx_idhrxml_Subscription_s* y);

void zx_idhrxml_Query_PUT_itemID(struct zx_idhrxml_Query_s* x, struct zx_str* y);

void zx_idhrxml_Query_PUT_Extension(struct zx_idhrxml_Query_s* x, int n, struct zx_lu_Extension_s* y);
void zx_idhrxml_Query_PUT_TestItem(struct zx_idhrxml_Query_s* x, int n, struct zx_idhrxml_TestItem_s* y);
void zx_idhrxml_Query_PUT_QueryItem(struct zx_idhrxml_Query_s* x, int n, struct zx_idhrxml_QueryItem_s* y);
void zx_idhrxml_Query_PUT_Subscription(struct zx_idhrxml_Query_s* x, int n, struct zx_idhrxml_Subscription_s* y);

void zx_idhrxml_Query_ADD_Extension(struct zx_idhrxml_Query_s* x, int n, struct zx_lu_Extension_s* z);
void zx_idhrxml_Query_ADD_TestItem(struct zx_idhrxml_Query_s* x, int n, struct zx_idhrxml_TestItem_s* z);
void zx_idhrxml_Query_ADD_QueryItem(struct zx_idhrxml_Query_s* x, int n, struct zx_idhrxml_QueryItem_s* z);
void zx_idhrxml_Query_ADD_Subscription(struct zx_idhrxml_Query_s* x, int n, struct zx_idhrxml_Subscription_s* z);

void zx_idhrxml_Query_DEL_Extension(struct zx_idhrxml_Query_s* x, int n);
void zx_idhrxml_Query_DEL_TestItem(struct zx_idhrxml_Query_s* x, int n);
void zx_idhrxml_Query_DEL_QueryItem(struct zx_idhrxml_Query_s* x, int n);
void zx_idhrxml_Query_DEL_Subscription(struct zx_idhrxml_Query_s* x, int n);

void zx_idhrxml_Query_REV_Extension(struct zx_idhrxml_Query_s* x);
void zx_idhrxml_Query_REV_TestItem(struct zx_idhrxml_Query_s* x);
void zx_idhrxml_Query_REV_QueryItem(struct zx_idhrxml_Query_s* x);
void zx_idhrxml_Query_REV_Subscription(struct zx_idhrxml_Query_s* x);

#endif
/* -------------------------- idhrxml_QueryItem -------------------------- */
/* refby( zx_idhrxml_Query_s ) */
#ifndef zx_idhrxml_QueryItem_EXT
#define zx_idhrxml_QueryItem_EXT
#endif

struct zx_idhrxml_QueryItem_s* zx_DEC_idhrxml_QueryItem(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_QueryItem_s* zx_NEW_idhrxml_QueryItem(struct zx_ctx* c);
void zx_FREE_idhrxml_QueryItem(struct zx_ctx* c, struct zx_idhrxml_QueryItem_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_QueryItem_s* zx_DEEP_CLONE_idhrxml_QueryItem(struct zx_ctx* c, struct zx_idhrxml_QueryItem_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_QueryItem(struct zx_ctx* c, struct zx_idhrxml_QueryItem_s* x);
int zx_WALK_SO_idhrxml_QueryItem(struct zx_ctx* c, struct zx_idhrxml_QueryItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_QueryItem(struct zx_ctx* c, struct zx_idhrxml_QueryItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_QueryItem(struct zx_ctx* c, struct zx_idhrxml_QueryItem_s* x);
int zx_LEN_WO_idhrxml_QueryItem(struct zx_ctx* c, struct zx_idhrxml_QueryItem_s* x);
char* zx_ENC_SO_idhrxml_QueryItem(struct zx_ctx* c, struct zx_idhrxml_QueryItem_s* x, char* p);
char* zx_ENC_WO_idhrxml_QueryItem(struct zx_ctx* c, struct zx_idhrxml_QueryItem_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_QueryItem(struct zx_ctx* c, struct zx_idhrxml_QueryItem_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_QueryItem(struct zx_ctx* c, struct zx_idhrxml_QueryItem_s* x);

struct zx_idhrxml_QueryItem_s {
  ZX_ELEM_EXT
  zx_idhrxml_QueryItem_EXT
  struct zx_elem_s* ChangeFormat;	/* {0,2} xs:string */
  struct zx_elem_s* Select;	/* {0,1} xs:string */
  struct zx_elem_s* Sort;	/* {0,1} xs:string */
  struct zx_str* changedSince;	/* {0,1} attribute xs:dateTime */
  struct zx_str* contingency;	/* {0,1} attribute xs:boolean */
  struct zx_str* count;	/* {0,1} attribute xs:nonNegativeInteger */
  struct zx_str* includeCommonAttributes;	/* {0,1} attribute xs:boolean */
  struct zx_str* offset;	/* {0,1} attribute xs:integer */
  struct zx_str* setID;	/* {0,1} attribute xs:string */
  struct zx_str* setReq;	/* {0,1} attribute Static */
  struct zx_str* itemID;	/* {0,1} attribute lu:IDType */
  struct zx_str* itemIDRef;	/* {0,1} attribute lu:IDReferenceType */
  struct zx_str* objectType;	/* {0,1} attribute xs:NCName */
  struct zx_str* predefined;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_QueryItem_GET_changedSince(struct zx_idhrxml_QueryItem_s* x);
struct zx_str* zx_idhrxml_QueryItem_GET_contingency(struct zx_idhrxml_QueryItem_s* x);
struct zx_str* zx_idhrxml_QueryItem_GET_count(struct zx_idhrxml_QueryItem_s* x);
struct zx_str* zx_idhrxml_QueryItem_GET_includeCommonAttributes(struct zx_idhrxml_QueryItem_s* x);
struct zx_str* zx_idhrxml_QueryItem_GET_offset(struct zx_idhrxml_QueryItem_s* x);
struct zx_str* zx_idhrxml_QueryItem_GET_setID(struct zx_idhrxml_QueryItem_s* x);
struct zx_str* zx_idhrxml_QueryItem_GET_setReq(struct zx_idhrxml_QueryItem_s* x);
struct zx_str* zx_idhrxml_QueryItem_GET_itemID(struct zx_idhrxml_QueryItem_s* x);
struct zx_str* zx_idhrxml_QueryItem_GET_itemIDRef(struct zx_idhrxml_QueryItem_s* x);
struct zx_str* zx_idhrxml_QueryItem_GET_objectType(struct zx_idhrxml_QueryItem_s* x);
struct zx_str* zx_idhrxml_QueryItem_GET_predefined(struct zx_idhrxml_QueryItem_s* x);

struct zx_elem_s* zx_idhrxml_QueryItem_GET_ChangeFormat(struct zx_idhrxml_QueryItem_s* x, int n);
struct zx_elem_s* zx_idhrxml_QueryItem_GET_Select(struct zx_idhrxml_QueryItem_s* x, int n);
struct zx_elem_s* zx_idhrxml_QueryItem_GET_Sort(struct zx_idhrxml_QueryItem_s* x, int n);

int zx_idhrxml_QueryItem_NUM_ChangeFormat(struct zx_idhrxml_QueryItem_s* x);
int zx_idhrxml_QueryItem_NUM_Select(struct zx_idhrxml_QueryItem_s* x);
int zx_idhrxml_QueryItem_NUM_Sort(struct zx_idhrxml_QueryItem_s* x);

struct zx_elem_s* zx_idhrxml_QueryItem_POP_ChangeFormat(struct zx_idhrxml_QueryItem_s* x);
struct zx_elem_s* zx_idhrxml_QueryItem_POP_Select(struct zx_idhrxml_QueryItem_s* x);
struct zx_elem_s* zx_idhrxml_QueryItem_POP_Sort(struct zx_idhrxml_QueryItem_s* x);

void zx_idhrxml_QueryItem_PUSH_ChangeFormat(struct zx_idhrxml_QueryItem_s* x, struct zx_elem_s* y);
void zx_idhrxml_QueryItem_PUSH_Select(struct zx_idhrxml_QueryItem_s* x, struct zx_elem_s* y);
void zx_idhrxml_QueryItem_PUSH_Sort(struct zx_idhrxml_QueryItem_s* x, struct zx_elem_s* y);

void zx_idhrxml_QueryItem_PUT_changedSince(struct zx_idhrxml_QueryItem_s* x, struct zx_str* y);
void zx_idhrxml_QueryItem_PUT_contingency(struct zx_idhrxml_QueryItem_s* x, struct zx_str* y);
void zx_idhrxml_QueryItem_PUT_count(struct zx_idhrxml_QueryItem_s* x, struct zx_str* y);
void zx_idhrxml_QueryItem_PUT_includeCommonAttributes(struct zx_idhrxml_QueryItem_s* x, struct zx_str* y);
void zx_idhrxml_QueryItem_PUT_offset(struct zx_idhrxml_QueryItem_s* x, struct zx_str* y);
void zx_idhrxml_QueryItem_PUT_setID(struct zx_idhrxml_QueryItem_s* x, struct zx_str* y);
void zx_idhrxml_QueryItem_PUT_setReq(struct zx_idhrxml_QueryItem_s* x, struct zx_str* y);
void zx_idhrxml_QueryItem_PUT_itemID(struct zx_idhrxml_QueryItem_s* x, struct zx_str* y);
void zx_idhrxml_QueryItem_PUT_itemIDRef(struct zx_idhrxml_QueryItem_s* x, struct zx_str* y);
void zx_idhrxml_QueryItem_PUT_objectType(struct zx_idhrxml_QueryItem_s* x, struct zx_str* y);
void zx_idhrxml_QueryItem_PUT_predefined(struct zx_idhrxml_QueryItem_s* x, struct zx_str* y);

void zx_idhrxml_QueryItem_PUT_ChangeFormat(struct zx_idhrxml_QueryItem_s* x, int n, struct zx_elem_s* y);
void zx_idhrxml_QueryItem_PUT_Select(struct zx_idhrxml_QueryItem_s* x, int n, struct zx_elem_s* y);
void zx_idhrxml_QueryItem_PUT_Sort(struct zx_idhrxml_QueryItem_s* x, int n, struct zx_elem_s* y);

void zx_idhrxml_QueryItem_ADD_ChangeFormat(struct zx_idhrxml_QueryItem_s* x, int n, struct zx_elem_s* z);
void zx_idhrxml_QueryItem_ADD_Select(struct zx_idhrxml_QueryItem_s* x, int n, struct zx_elem_s* z);
void zx_idhrxml_QueryItem_ADD_Sort(struct zx_idhrxml_QueryItem_s* x, int n, struct zx_elem_s* z);

void zx_idhrxml_QueryItem_DEL_ChangeFormat(struct zx_idhrxml_QueryItem_s* x, int n);
void zx_idhrxml_QueryItem_DEL_Select(struct zx_idhrxml_QueryItem_s* x, int n);
void zx_idhrxml_QueryItem_DEL_Sort(struct zx_idhrxml_QueryItem_s* x, int n);

void zx_idhrxml_QueryItem_REV_ChangeFormat(struct zx_idhrxml_QueryItem_s* x);
void zx_idhrxml_QueryItem_REV_Select(struct zx_idhrxml_QueryItem_s* x);
void zx_idhrxml_QueryItem_REV_Sort(struct zx_idhrxml_QueryItem_s* x);

#endif
/* -------------------------- idhrxml_QueryResponse -------------------------- */
/* refby( zx_e_Body_s ) */
#ifndef zx_idhrxml_QueryResponse_EXT
#define zx_idhrxml_QueryResponse_EXT
#endif

struct zx_idhrxml_QueryResponse_s* zx_DEC_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_QueryResponse_s* zx_NEW_idhrxml_QueryResponse(struct zx_ctx* c);
void zx_FREE_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_idhrxml_QueryResponse_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_QueryResponse_s* zx_DEEP_CLONE_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_idhrxml_QueryResponse_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_idhrxml_QueryResponse_s* x);
int zx_WALK_SO_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_idhrxml_QueryResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_idhrxml_QueryResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_idhrxml_QueryResponse_s* x);
int zx_LEN_WO_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_idhrxml_QueryResponse_s* x);
char* zx_ENC_SO_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_idhrxml_QueryResponse_s* x, char* p);
char* zx_ENC_WO_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_idhrxml_QueryResponse_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_idhrxml_QueryResponse_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_QueryResponse(struct zx_ctx* c, struct zx_idhrxml_QueryResponse_s* x);

struct zx_idhrxml_QueryResponse_s {
  ZX_ELEM_EXT
  zx_idhrxml_QueryResponse_EXT
  struct zx_lu_Status_s* Status;	/* {1,1} nada */
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_dst_TestResult_s* TestResult;	/* {0,-1} nada */
  struct zx_idhrxml_Data_s* Data;	/* {0,-1} nada */
  struct zx_str* timeStamp;	/* {0,1} attribute xs:dateTime */
  struct zx_str* itemIDRef;	/* {0,1} attribute lu:IDReferenceType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_QueryResponse_GET_timeStamp(struct zx_idhrxml_QueryResponse_s* x);
struct zx_str* zx_idhrxml_QueryResponse_GET_itemIDRef(struct zx_idhrxml_QueryResponse_s* x);

struct zx_lu_Status_s* zx_idhrxml_QueryResponse_GET_Status(struct zx_idhrxml_QueryResponse_s* x, int n);
struct zx_lu_Extension_s* zx_idhrxml_QueryResponse_GET_Extension(struct zx_idhrxml_QueryResponse_s* x, int n);
struct zx_dst_TestResult_s* zx_idhrxml_QueryResponse_GET_TestResult(struct zx_idhrxml_QueryResponse_s* x, int n);
struct zx_idhrxml_Data_s* zx_idhrxml_QueryResponse_GET_Data(struct zx_idhrxml_QueryResponse_s* x, int n);

int zx_idhrxml_QueryResponse_NUM_Status(struct zx_idhrxml_QueryResponse_s* x);
int zx_idhrxml_QueryResponse_NUM_Extension(struct zx_idhrxml_QueryResponse_s* x);
int zx_idhrxml_QueryResponse_NUM_TestResult(struct zx_idhrxml_QueryResponse_s* x);
int zx_idhrxml_QueryResponse_NUM_Data(struct zx_idhrxml_QueryResponse_s* x);

struct zx_lu_Status_s* zx_idhrxml_QueryResponse_POP_Status(struct zx_idhrxml_QueryResponse_s* x);
struct zx_lu_Extension_s* zx_idhrxml_QueryResponse_POP_Extension(struct zx_idhrxml_QueryResponse_s* x);
struct zx_dst_TestResult_s* zx_idhrxml_QueryResponse_POP_TestResult(struct zx_idhrxml_QueryResponse_s* x);
struct zx_idhrxml_Data_s* zx_idhrxml_QueryResponse_POP_Data(struct zx_idhrxml_QueryResponse_s* x);

void zx_idhrxml_QueryResponse_PUSH_Status(struct zx_idhrxml_QueryResponse_s* x, struct zx_lu_Status_s* y);
void zx_idhrxml_QueryResponse_PUSH_Extension(struct zx_idhrxml_QueryResponse_s* x, struct zx_lu_Extension_s* y);
void zx_idhrxml_QueryResponse_PUSH_TestResult(struct zx_idhrxml_QueryResponse_s* x, struct zx_dst_TestResult_s* y);
void zx_idhrxml_QueryResponse_PUSH_Data(struct zx_idhrxml_QueryResponse_s* x, struct zx_idhrxml_Data_s* y);

void zx_idhrxml_QueryResponse_PUT_timeStamp(struct zx_idhrxml_QueryResponse_s* x, struct zx_str* y);
void zx_idhrxml_QueryResponse_PUT_itemIDRef(struct zx_idhrxml_QueryResponse_s* x, struct zx_str* y);

void zx_idhrxml_QueryResponse_PUT_Status(struct zx_idhrxml_QueryResponse_s* x, int n, struct zx_lu_Status_s* y);
void zx_idhrxml_QueryResponse_PUT_Extension(struct zx_idhrxml_QueryResponse_s* x, int n, struct zx_lu_Extension_s* y);
void zx_idhrxml_QueryResponse_PUT_TestResult(struct zx_idhrxml_QueryResponse_s* x, int n, struct zx_dst_TestResult_s* y);
void zx_idhrxml_QueryResponse_PUT_Data(struct zx_idhrxml_QueryResponse_s* x, int n, struct zx_idhrxml_Data_s* y);

void zx_idhrxml_QueryResponse_ADD_Status(struct zx_idhrxml_QueryResponse_s* x, int n, struct zx_lu_Status_s* z);
void zx_idhrxml_QueryResponse_ADD_Extension(struct zx_idhrxml_QueryResponse_s* x, int n, struct zx_lu_Extension_s* z);
void zx_idhrxml_QueryResponse_ADD_TestResult(struct zx_idhrxml_QueryResponse_s* x, int n, struct zx_dst_TestResult_s* z);
void zx_idhrxml_QueryResponse_ADD_Data(struct zx_idhrxml_QueryResponse_s* x, int n, struct zx_idhrxml_Data_s* z);

void zx_idhrxml_QueryResponse_DEL_Status(struct zx_idhrxml_QueryResponse_s* x, int n);
void zx_idhrxml_QueryResponse_DEL_Extension(struct zx_idhrxml_QueryResponse_s* x, int n);
void zx_idhrxml_QueryResponse_DEL_TestResult(struct zx_idhrxml_QueryResponse_s* x, int n);
void zx_idhrxml_QueryResponse_DEL_Data(struct zx_idhrxml_QueryResponse_s* x, int n);

void zx_idhrxml_QueryResponse_REV_Status(struct zx_idhrxml_QueryResponse_s* x);
void zx_idhrxml_QueryResponse_REV_Extension(struct zx_idhrxml_QueryResponse_s* x);
void zx_idhrxml_QueryResponse_REV_TestResult(struct zx_idhrxml_QueryResponse_s* x);
void zx_idhrxml_QueryResponse_REV_Data(struct zx_idhrxml_QueryResponse_s* x);

#endif
/* -------------------------- idhrxml_ResultQuery -------------------------- */
/* refby( zx_idhrxml_Create_s zx_idhrxml_Modify_s zx_idhrxml_Subscription_s ) */
#ifndef zx_idhrxml_ResultQuery_EXT
#define zx_idhrxml_ResultQuery_EXT
#endif

struct zx_idhrxml_ResultQuery_s* zx_DEC_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_ResultQuery_s* zx_NEW_idhrxml_ResultQuery(struct zx_ctx* c);
void zx_FREE_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_idhrxml_ResultQuery_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_ResultQuery_s* zx_DEEP_CLONE_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_idhrxml_ResultQuery_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_idhrxml_ResultQuery_s* x);
int zx_WALK_SO_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_idhrxml_ResultQuery_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_idhrxml_ResultQuery_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_idhrxml_ResultQuery_s* x);
int zx_LEN_WO_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_idhrxml_ResultQuery_s* x);
char* zx_ENC_SO_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_idhrxml_ResultQuery_s* x, char* p);
char* zx_ENC_WO_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_idhrxml_ResultQuery_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_idhrxml_ResultQuery_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_ResultQuery(struct zx_ctx* c, struct zx_idhrxml_ResultQuery_s* x);

struct zx_idhrxml_ResultQuery_s {
  ZX_ELEM_EXT
  zx_idhrxml_ResultQuery_EXT
  struct zx_elem_s* ChangeFormat;	/* {0,2} xs:string */
  struct zx_elem_s* Select;	/* {0,1} xs:string */
  struct zx_elem_s* Sort;	/* {0,1} xs:string */
  struct zx_str* changedSince;	/* {0,1} attribute xs:dateTime */
  struct zx_str* contingency;	/* {0,1} attribute xs:boolean */
  struct zx_str* includeCommonAttributes;	/* {0,1} attribute xs:boolean */
  struct zx_str* itemID;	/* {0,1} attribute lu:IDType */
  struct zx_str* itemIDRef;	/* {0,1} attribute lu:IDReferenceType */
  struct zx_str* objectType;	/* {0,1} attribute xs:NCName */
  struct zx_str* predefined;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_ResultQuery_GET_changedSince(struct zx_idhrxml_ResultQuery_s* x);
struct zx_str* zx_idhrxml_ResultQuery_GET_contingency(struct zx_idhrxml_ResultQuery_s* x);
struct zx_str* zx_idhrxml_ResultQuery_GET_includeCommonAttributes(struct zx_idhrxml_ResultQuery_s* x);
struct zx_str* zx_idhrxml_ResultQuery_GET_itemID(struct zx_idhrxml_ResultQuery_s* x);
struct zx_str* zx_idhrxml_ResultQuery_GET_itemIDRef(struct zx_idhrxml_ResultQuery_s* x);
struct zx_str* zx_idhrxml_ResultQuery_GET_objectType(struct zx_idhrxml_ResultQuery_s* x);
struct zx_str* zx_idhrxml_ResultQuery_GET_predefined(struct zx_idhrxml_ResultQuery_s* x);

struct zx_elem_s* zx_idhrxml_ResultQuery_GET_ChangeFormat(struct zx_idhrxml_ResultQuery_s* x, int n);
struct zx_elem_s* zx_idhrxml_ResultQuery_GET_Select(struct zx_idhrxml_ResultQuery_s* x, int n);
struct zx_elem_s* zx_idhrxml_ResultQuery_GET_Sort(struct zx_idhrxml_ResultQuery_s* x, int n);

int zx_idhrxml_ResultQuery_NUM_ChangeFormat(struct zx_idhrxml_ResultQuery_s* x);
int zx_idhrxml_ResultQuery_NUM_Select(struct zx_idhrxml_ResultQuery_s* x);
int zx_idhrxml_ResultQuery_NUM_Sort(struct zx_idhrxml_ResultQuery_s* x);

struct zx_elem_s* zx_idhrxml_ResultQuery_POP_ChangeFormat(struct zx_idhrxml_ResultQuery_s* x);
struct zx_elem_s* zx_idhrxml_ResultQuery_POP_Select(struct zx_idhrxml_ResultQuery_s* x);
struct zx_elem_s* zx_idhrxml_ResultQuery_POP_Sort(struct zx_idhrxml_ResultQuery_s* x);

void zx_idhrxml_ResultQuery_PUSH_ChangeFormat(struct zx_idhrxml_ResultQuery_s* x, struct zx_elem_s* y);
void zx_idhrxml_ResultQuery_PUSH_Select(struct zx_idhrxml_ResultQuery_s* x, struct zx_elem_s* y);
void zx_idhrxml_ResultQuery_PUSH_Sort(struct zx_idhrxml_ResultQuery_s* x, struct zx_elem_s* y);

void zx_idhrxml_ResultQuery_PUT_changedSince(struct zx_idhrxml_ResultQuery_s* x, struct zx_str* y);
void zx_idhrxml_ResultQuery_PUT_contingency(struct zx_idhrxml_ResultQuery_s* x, struct zx_str* y);
void zx_idhrxml_ResultQuery_PUT_includeCommonAttributes(struct zx_idhrxml_ResultQuery_s* x, struct zx_str* y);
void zx_idhrxml_ResultQuery_PUT_itemID(struct zx_idhrxml_ResultQuery_s* x, struct zx_str* y);
void zx_idhrxml_ResultQuery_PUT_itemIDRef(struct zx_idhrxml_ResultQuery_s* x, struct zx_str* y);
void zx_idhrxml_ResultQuery_PUT_objectType(struct zx_idhrxml_ResultQuery_s* x, struct zx_str* y);
void zx_idhrxml_ResultQuery_PUT_predefined(struct zx_idhrxml_ResultQuery_s* x, struct zx_str* y);

void zx_idhrxml_ResultQuery_PUT_ChangeFormat(struct zx_idhrxml_ResultQuery_s* x, int n, struct zx_elem_s* y);
void zx_idhrxml_ResultQuery_PUT_Select(struct zx_idhrxml_ResultQuery_s* x, int n, struct zx_elem_s* y);
void zx_idhrxml_ResultQuery_PUT_Sort(struct zx_idhrxml_ResultQuery_s* x, int n, struct zx_elem_s* y);

void zx_idhrxml_ResultQuery_ADD_ChangeFormat(struct zx_idhrxml_ResultQuery_s* x, int n, struct zx_elem_s* z);
void zx_idhrxml_ResultQuery_ADD_Select(struct zx_idhrxml_ResultQuery_s* x, int n, struct zx_elem_s* z);
void zx_idhrxml_ResultQuery_ADD_Sort(struct zx_idhrxml_ResultQuery_s* x, int n, struct zx_elem_s* z);

void zx_idhrxml_ResultQuery_DEL_ChangeFormat(struct zx_idhrxml_ResultQuery_s* x, int n);
void zx_idhrxml_ResultQuery_DEL_Select(struct zx_idhrxml_ResultQuery_s* x, int n);
void zx_idhrxml_ResultQuery_DEL_Sort(struct zx_idhrxml_ResultQuery_s* x, int n);

void zx_idhrxml_ResultQuery_REV_ChangeFormat(struct zx_idhrxml_ResultQuery_s* x);
void zx_idhrxml_ResultQuery_REV_Select(struct zx_idhrxml_ResultQuery_s* x);
void zx_idhrxml_ResultQuery_REV_Sort(struct zx_idhrxml_ResultQuery_s* x);

#endif
/* -------------------------- idhrxml_Subscription -------------------------- */
/* refby( zx_idhrxml_Data_s zx_idhrxml_ItemData_s zx_idhrxml_Create_s zx_idhrxml_NewData_s zx_idhrxml_Query_s zx_idhrxml_Modify_s ) */
#ifndef zx_idhrxml_Subscription_EXT
#define zx_idhrxml_Subscription_EXT
#endif

struct zx_idhrxml_Subscription_s* zx_DEC_idhrxml_Subscription(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_Subscription_s* zx_NEW_idhrxml_Subscription(struct zx_ctx* c);
void zx_FREE_idhrxml_Subscription(struct zx_ctx* c, struct zx_idhrxml_Subscription_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_Subscription_s* zx_DEEP_CLONE_idhrxml_Subscription(struct zx_ctx* c, struct zx_idhrxml_Subscription_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_Subscription(struct zx_ctx* c, struct zx_idhrxml_Subscription_s* x);
int zx_WALK_SO_idhrxml_Subscription(struct zx_ctx* c, struct zx_idhrxml_Subscription_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_Subscription(struct zx_ctx* c, struct zx_idhrxml_Subscription_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_Subscription(struct zx_ctx* c, struct zx_idhrxml_Subscription_s* x);
int zx_LEN_WO_idhrxml_Subscription(struct zx_ctx* c, struct zx_idhrxml_Subscription_s* x);
char* zx_ENC_SO_idhrxml_Subscription(struct zx_ctx* c, struct zx_idhrxml_Subscription_s* x, char* p);
char* zx_ENC_WO_idhrxml_Subscription(struct zx_ctx* c, struct zx_idhrxml_Subscription_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_Subscription(struct zx_ctx* c, struct zx_idhrxml_Subscription_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_Subscription(struct zx_ctx* c, struct zx_idhrxml_Subscription_s* x);

struct zx_idhrxml_Subscription_s {
  ZX_ELEM_EXT
  zx_idhrxml_Subscription_EXT
  struct zx_subs_RefItem_s* RefItem;	/* {0,-1} nada */
  struct zx_lu_Extension_s* Extension;	/* {0,-1}  */
  struct zx_idhrxml_ResultQuery_s* ResultQuery;	/* {0,-1} nada */
  struct zx_elem_s* Aggregation;	/* {0,1} xs:string */
  struct zx_elem_s* Trigger;	/* {0,1} xs:string */
  struct zx_str* adminNotifyToRef;	/* {0,1} attribute xs:anyURI */
  struct zx_str* expires;	/* {0,1} attribute xs:dateTime */
  struct zx_str* id;	/* {0,1} attribute xs:ID */
  struct zx_str* includeData;	/* {0,1} attribute Yes */
  struct zx_str* notifyToRef;	/* {1,1} attribute xs:anyURI */
  struct zx_str* starts;	/* {0,1} attribute xs:dateTime */
  struct zx_str* subscriptionID;	/* {1,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_Subscription_GET_adminNotifyToRef(struct zx_idhrxml_Subscription_s* x);
struct zx_str* zx_idhrxml_Subscription_GET_expires(struct zx_idhrxml_Subscription_s* x);
struct zx_str* zx_idhrxml_Subscription_GET_id(struct zx_idhrxml_Subscription_s* x);
struct zx_str* zx_idhrxml_Subscription_GET_includeData(struct zx_idhrxml_Subscription_s* x);
struct zx_str* zx_idhrxml_Subscription_GET_notifyToRef(struct zx_idhrxml_Subscription_s* x);
struct zx_str* zx_idhrxml_Subscription_GET_starts(struct zx_idhrxml_Subscription_s* x);
struct zx_str* zx_idhrxml_Subscription_GET_subscriptionID(struct zx_idhrxml_Subscription_s* x);

struct zx_subs_RefItem_s* zx_idhrxml_Subscription_GET_RefItem(struct zx_idhrxml_Subscription_s* x, int n);
struct zx_lu_Extension_s* zx_idhrxml_Subscription_GET_Extension(struct zx_idhrxml_Subscription_s* x, int n);
struct zx_idhrxml_ResultQuery_s* zx_idhrxml_Subscription_GET_ResultQuery(struct zx_idhrxml_Subscription_s* x, int n);
struct zx_elem_s* zx_idhrxml_Subscription_GET_Aggregation(struct zx_idhrxml_Subscription_s* x, int n);
struct zx_elem_s* zx_idhrxml_Subscription_GET_Trigger(struct zx_idhrxml_Subscription_s* x, int n);

int zx_idhrxml_Subscription_NUM_RefItem(struct zx_idhrxml_Subscription_s* x);
int zx_idhrxml_Subscription_NUM_Extension(struct zx_idhrxml_Subscription_s* x);
int zx_idhrxml_Subscription_NUM_ResultQuery(struct zx_idhrxml_Subscription_s* x);
int zx_idhrxml_Subscription_NUM_Aggregation(struct zx_idhrxml_Subscription_s* x);
int zx_idhrxml_Subscription_NUM_Trigger(struct zx_idhrxml_Subscription_s* x);

struct zx_subs_RefItem_s* zx_idhrxml_Subscription_POP_RefItem(struct zx_idhrxml_Subscription_s* x);
struct zx_lu_Extension_s* zx_idhrxml_Subscription_POP_Extension(struct zx_idhrxml_Subscription_s* x);
struct zx_idhrxml_ResultQuery_s* zx_idhrxml_Subscription_POP_ResultQuery(struct zx_idhrxml_Subscription_s* x);
struct zx_elem_s* zx_idhrxml_Subscription_POP_Aggregation(struct zx_idhrxml_Subscription_s* x);
struct zx_elem_s* zx_idhrxml_Subscription_POP_Trigger(struct zx_idhrxml_Subscription_s* x);

void zx_idhrxml_Subscription_PUSH_RefItem(struct zx_idhrxml_Subscription_s* x, struct zx_subs_RefItem_s* y);
void zx_idhrxml_Subscription_PUSH_Extension(struct zx_idhrxml_Subscription_s* x, struct zx_lu_Extension_s* y);
void zx_idhrxml_Subscription_PUSH_ResultQuery(struct zx_idhrxml_Subscription_s* x, struct zx_idhrxml_ResultQuery_s* y);
void zx_idhrxml_Subscription_PUSH_Aggregation(struct zx_idhrxml_Subscription_s* x, struct zx_elem_s* y);
void zx_idhrxml_Subscription_PUSH_Trigger(struct zx_idhrxml_Subscription_s* x, struct zx_elem_s* y);

void zx_idhrxml_Subscription_PUT_adminNotifyToRef(struct zx_idhrxml_Subscription_s* x, struct zx_str* y);
void zx_idhrxml_Subscription_PUT_expires(struct zx_idhrxml_Subscription_s* x, struct zx_str* y);
void zx_idhrxml_Subscription_PUT_id(struct zx_idhrxml_Subscription_s* x, struct zx_str* y);
void zx_idhrxml_Subscription_PUT_includeData(struct zx_idhrxml_Subscription_s* x, struct zx_str* y);
void zx_idhrxml_Subscription_PUT_notifyToRef(struct zx_idhrxml_Subscription_s* x, struct zx_str* y);
void zx_idhrxml_Subscription_PUT_starts(struct zx_idhrxml_Subscription_s* x, struct zx_str* y);
void zx_idhrxml_Subscription_PUT_subscriptionID(struct zx_idhrxml_Subscription_s* x, struct zx_str* y);

void zx_idhrxml_Subscription_PUT_RefItem(struct zx_idhrxml_Subscription_s* x, int n, struct zx_subs_RefItem_s* y);
void zx_idhrxml_Subscription_PUT_Extension(struct zx_idhrxml_Subscription_s* x, int n, struct zx_lu_Extension_s* y);
void zx_idhrxml_Subscription_PUT_ResultQuery(struct zx_idhrxml_Subscription_s* x, int n, struct zx_idhrxml_ResultQuery_s* y);
void zx_idhrxml_Subscription_PUT_Aggregation(struct zx_idhrxml_Subscription_s* x, int n, struct zx_elem_s* y);
void zx_idhrxml_Subscription_PUT_Trigger(struct zx_idhrxml_Subscription_s* x, int n, struct zx_elem_s* y);

void zx_idhrxml_Subscription_ADD_RefItem(struct zx_idhrxml_Subscription_s* x, int n, struct zx_subs_RefItem_s* z);
void zx_idhrxml_Subscription_ADD_Extension(struct zx_idhrxml_Subscription_s* x, int n, struct zx_lu_Extension_s* z);
void zx_idhrxml_Subscription_ADD_ResultQuery(struct zx_idhrxml_Subscription_s* x, int n, struct zx_idhrxml_ResultQuery_s* z);
void zx_idhrxml_Subscription_ADD_Aggregation(struct zx_idhrxml_Subscription_s* x, int n, struct zx_elem_s* z);
void zx_idhrxml_Subscription_ADD_Trigger(struct zx_idhrxml_Subscription_s* x, int n, struct zx_elem_s* z);

void zx_idhrxml_Subscription_DEL_RefItem(struct zx_idhrxml_Subscription_s* x, int n);
void zx_idhrxml_Subscription_DEL_Extension(struct zx_idhrxml_Subscription_s* x, int n);
void zx_idhrxml_Subscription_DEL_ResultQuery(struct zx_idhrxml_Subscription_s* x, int n);
void zx_idhrxml_Subscription_DEL_Aggregation(struct zx_idhrxml_Subscription_s* x, int n);
void zx_idhrxml_Subscription_DEL_Trigger(struct zx_idhrxml_Subscription_s* x, int n);

void zx_idhrxml_Subscription_REV_RefItem(struct zx_idhrxml_Subscription_s* x);
void zx_idhrxml_Subscription_REV_Extension(struct zx_idhrxml_Subscription_s* x);
void zx_idhrxml_Subscription_REV_ResultQuery(struct zx_idhrxml_Subscription_s* x);
void zx_idhrxml_Subscription_REV_Aggregation(struct zx_idhrxml_Subscription_s* x);
void zx_idhrxml_Subscription_REV_Trigger(struct zx_idhrxml_Subscription_s* x);

#endif
/* -------------------------- idhrxml_TestItem -------------------------- */
/* refby( zx_idhrxml_Query_s ) */
#ifndef zx_idhrxml_TestItem_EXT
#define zx_idhrxml_TestItem_EXT
#endif

struct zx_idhrxml_TestItem_s* zx_DEC_idhrxml_TestItem(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_idhrxml_TestItem_s* zx_NEW_idhrxml_TestItem(struct zx_ctx* c);
void zx_FREE_idhrxml_TestItem(struct zx_ctx* c, struct zx_idhrxml_TestItem_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_idhrxml_TestItem_s* zx_DEEP_CLONE_idhrxml_TestItem(struct zx_ctx* c, struct zx_idhrxml_TestItem_s* x, int dup_strs);
void zx_DUP_STRS_idhrxml_TestItem(struct zx_ctx* c, struct zx_idhrxml_TestItem_s* x);
int zx_WALK_SO_idhrxml_TestItem(struct zx_ctx* c, struct zx_idhrxml_TestItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_idhrxml_TestItem(struct zx_ctx* c, struct zx_idhrxml_TestItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_idhrxml_TestItem(struct zx_ctx* c, struct zx_idhrxml_TestItem_s* x);
int zx_LEN_WO_idhrxml_TestItem(struct zx_ctx* c, struct zx_idhrxml_TestItem_s* x);
char* zx_ENC_SO_idhrxml_TestItem(struct zx_ctx* c, struct zx_idhrxml_TestItem_s* x, char* p);
char* zx_ENC_WO_idhrxml_TestItem(struct zx_ctx* c, struct zx_idhrxml_TestItem_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_idhrxml_TestItem(struct zx_ctx* c, struct zx_idhrxml_TestItem_s* x);
struct zx_str* zx_EASY_ENC_WO_idhrxml_TestItem(struct zx_ctx* c, struct zx_idhrxml_TestItem_s* x);

struct zx_idhrxml_TestItem_s {
  ZX_ELEM_EXT
  zx_idhrxml_TestItem_EXT
  struct zx_elem_s* TestOp;	/* {0,1} xs:string */
  struct zx_str* id;	/* {0,1} attribute xs:ID */
  struct zx_str* itemID;	/* {0,1} attribute lu:IDType */
  struct zx_str* objectType;	/* {0,1} attribute xs:NCName */
  struct zx_str* predefined;	/* {0,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_idhrxml_TestItem_GET_id(struct zx_idhrxml_TestItem_s* x);
struct zx_str* zx_idhrxml_TestItem_GET_itemID(struct zx_idhrxml_TestItem_s* x);
struct zx_str* zx_idhrxml_TestItem_GET_objectType(struct zx_idhrxml_TestItem_s* x);
struct zx_str* zx_idhrxml_TestItem_GET_predefined(struct zx_idhrxml_TestItem_s* x);

struct zx_elem_s* zx_idhrxml_TestItem_GET_TestOp(struct zx_idhrxml_TestItem_s* x, int n);

int zx_idhrxml_TestItem_NUM_TestOp(struct zx_idhrxml_TestItem_s* x);

struct zx_elem_s* zx_idhrxml_TestItem_POP_TestOp(struct zx_idhrxml_TestItem_s* x);

void zx_idhrxml_TestItem_PUSH_TestOp(struct zx_idhrxml_TestItem_s* x, struct zx_elem_s* y);

void zx_idhrxml_TestItem_PUT_id(struct zx_idhrxml_TestItem_s* x, struct zx_str* y);
void zx_idhrxml_TestItem_PUT_itemID(struct zx_idhrxml_TestItem_s* x, struct zx_str* y);
void zx_idhrxml_TestItem_PUT_objectType(struct zx_idhrxml_TestItem_s* x, struct zx_str* y);
void zx_idhrxml_TestItem_PUT_predefined(struct zx_idhrxml_TestItem_s* x, struct zx_str* y);

void zx_idhrxml_TestItem_PUT_TestOp(struct zx_idhrxml_TestItem_s* x, int n, struct zx_elem_s* y);

void zx_idhrxml_TestItem_ADD_TestOp(struct zx_idhrxml_TestItem_s* x, int n, struct zx_elem_s* z);

void zx_idhrxml_TestItem_DEL_TestOp(struct zx_idhrxml_TestItem_s* x, int n);

void zx_idhrxml_TestItem_REV_TestOp(struct zx_idhrxml_TestItem_s* x);

#endif

#endif
