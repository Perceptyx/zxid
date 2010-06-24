/* c/zx-xa-data.h - WARNING: This header was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Datastructure design, topography, and layout
 * Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for
 * terms and conditions of use. Element and attributes names as well
 * as some topography are derived from schema descriptions that were used as
 * input and may be subject to their own copright. */

#ifndef _c_zx_xa_data_h
#define _c_zx_xa_data_h

#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"

#ifndef ZX_ELEM_EXT
#define ZX_ELEM_EXT  /* This extension point should be defined by who includes this file. */
#endif

/* -------------------------- xa_Action -------------------------- */
/* refby( zx_xa_Actions_s ) */
#ifndef zx_xa_Action_EXT
#define zx_xa_Action_EXT
#endif

struct zx_xa_Action_s* zx_DEC_xa_Action(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Action_s* zx_NEW_xa_Action(struct zx_ctx* c);
void zx_FREE_xa_Action(struct zx_ctx* c, struct zx_xa_Action_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Action_s* zx_DEEP_CLONE_xa_Action(struct zx_ctx* c, struct zx_xa_Action_s* x, int dup_strs);
void zx_DUP_STRS_xa_Action(struct zx_ctx* c, struct zx_xa_Action_s* x);
int zx_WALK_SO_xa_Action(struct zx_ctx* c, struct zx_xa_Action_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Action(struct zx_ctx* c, struct zx_xa_Action_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Action(struct zx_ctx* c, struct zx_xa_Action_s* x);
int zx_LEN_WO_xa_Action(struct zx_ctx* c, struct zx_xa_Action_s* x);
char* zx_ENC_SO_xa_Action(struct zx_ctx* c, struct zx_xa_Action_s* x, char* p);
char* zx_ENC_WO_xa_Action(struct zx_ctx* c, struct zx_xa_Action_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Action(struct zx_ctx* c, struct zx_xa_Action_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Action(struct zx_ctx* c, struct zx_xa_Action_s* x);

struct zx_xa_Action_s {
  ZX_ELEM_EXT
  zx_xa_Action_EXT
  struct zx_xa_ActionMatch_s* ActionMatch;	/* {1,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_ActionMatch_s* zx_xa_Action_GET_ActionMatch(struct zx_xa_Action_s* x, int n);

int zx_xa_Action_NUM_ActionMatch(struct zx_xa_Action_s* x);

struct zx_xa_ActionMatch_s* zx_xa_Action_POP_ActionMatch(struct zx_xa_Action_s* x);

void zx_xa_Action_PUSH_ActionMatch(struct zx_xa_Action_s* x, struct zx_xa_ActionMatch_s* y);


void zx_xa_Action_PUT_ActionMatch(struct zx_xa_Action_s* x, int n, struct zx_xa_ActionMatch_s* y);

void zx_xa_Action_ADD_ActionMatch(struct zx_xa_Action_s* x, int n, struct zx_xa_ActionMatch_s* z);

void zx_xa_Action_DEL_ActionMatch(struct zx_xa_Action_s* x, int n);

void zx_xa_Action_REV_ActionMatch(struct zx_xa_Action_s* x);

#endif
/* -------------------------- xa_ActionAttributeDesignator -------------------------- */
/* refby( zx_xa_ActionMatch_s ) */
#ifndef zx_xa_ActionAttributeDesignator_EXT
#define zx_xa_ActionAttributeDesignator_EXT
#endif

struct zx_xa_ActionAttributeDesignator_s* zx_DEC_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_ActionAttributeDesignator_s* zx_NEW_xa_ActionAttributeDesignator(struct zx_ctx* c);
void zx_FREE_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_xa_ActionAttributeDesignator_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_ActionAttributeDesignator_s* zx_DEEP_CLONE_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_xa_ActionAttributeDesignator_s* x, int dup_strs);
void zx_DUP_STRS_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_xa_ActionAttributeDesignator_s* x);
int zx_WALK_SO_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_xa_ActionAttributeDesignator_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_xa_ActionAttributeDesignator_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_xa_ActionAttributeDesignator_s* x);
int zx_LEN_WO_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_xa_ActionAttributeDesignator_s* x);
char* zx_ENC_SO_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_xa_ActionAttributeDesignator_s* x, char* p);
char* zx_ENC_WO_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_xa_ActionAttributeDesignator_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_xa_ActionAttributeDesignator_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_ActionAttributeDesignator(struct zx_ctx* c, struct zx_xa_ActionAttributeDesignator_s* x);

struct zx_xa_ActionAttributeDesignator_s {
  ZX_ELEM_EXT
  zx_xa_ActionAttributeDesignator_EXT
  struct zx_str* AttributeId;	/* {1,1} attribute xs:anyURI */
  struct zx_str* DataType;	/* {1,1} attribute xs:anyURI */
  struct zx_str* Issuer;	/* {0,1} attribute xs:string */
  struct zx_str* MustBePresent;	/* {0,1} attribute xs:boolean */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_ActionAttributeDesignator_GET_AttributeId(struct zx_xa_ActionAttributeDesignator_s* x);
struct zx_str* zx_xa_ActionAttributeDesignator_GET_DataType(struct zx_xa_ActionAttributeDesignator_s* x);
struct zx_str* zx_xa_ActionAttributeDesignator_GET_Issuer(struct zx_xa_ActionAttributeDesignator_s* x);
struct zx_str* zx_xa_ActionAttributeDesignator_GET_MustBePresent(struct zx_xa_ActionAttributeDesignator_s* x);





void zx_xa_ActionAttributeDesignator_PUT_AttributeId(struct zx_xa_ActionAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_ActionAttributeDesignator_PUT_DataType(struct zx_xa_ActionAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_ActionAttributeDesignator_PUT_Issuer(struct zx_xa_ActionAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_ActionAttributeDesignator_PUT_MustBePresent(struct zx_xa_ActionAttributeDesignator_s* x, struct zx_str* y);





#endif
/* -------------------------- xa_ActionMatch -------------------------- */
/* refby( zx_xa_Action_s ) */
#ifndef zx_xa_ActionMatch_EXT
#define zx_xa_ActionMatch_EXT
#endif

struct zx_xa_ActionMatch_s* zx_DEC_xa_ActionMatch(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_ActionMatch_s* zx_NEW_xa_ActionMatch(struct zx_ctx* c);
void zx_FREE_xa_ActionMatch(struct zx_ctx* c, struct zx_xa_ActionMatch_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_ActionMatch_s* zx_DEEP_CLONE_xa_ActionMatch(struct zx_ctx* c, struct zx_xa_ActionMatch_s* x, int dup_strs);
void zx_DUP_STRS_xa_ActionMatch(struct zx_ctx* c, struct zx_xa_ActionMatch_s* x);
int zx_WALK_SO_xa_ActionMatch(struct zx_ctx* c, struct zx_xa_ActionMatch_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_ActionMatch(struct zx_ctx* c, struct zx_xa_ActionMatch_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_ActionMatch(struct zx_ctx* c, struct zx_xa_ActionMatch_s* x);
int zx_LEN_WO_xa_ActionMatch(struct zx_ctx* c, struct zx_xa_ActionMatch_s* x);
char* zx_ENC_SO_xa_ActionMatch(struct zx_ctx* c, struct zx_xa_ActionMatch_s* x, char* p);
char* zx_ENC_WO_xa_ActionMatch(struct zx_ctx* c, struct zx_xa_ActionMatch_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_ActionMatch(struct zx_ctx* c, struct zx_xa_ActionMatch_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_ActionMatch(struct zx_ctx* c, struct zx_xa_ActionMatch_s* x);

struct zx_xa_ActionMatch_s {
  ZX_ELEM_EXT
  zx_xa_ActionMatch_EXT
  struct zx_xa_AttributeValue_s* AttributeValue;	/* {1,1} nada */
  struct zx_xa_ActionAttributeDesignator_s* ActionAttributeDesignator;	/* {0,1} nada */
  struct zx_xa_AttributeSelector_s* AttributeSelector;	/* {0,1} nada */
  struct zx_str* MatchId;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_ActionMatch_GET_MatchId(struct zx_xa_ActionMatch_s* x);

struct zx_xa_AttributeValue_s* zx_xa_ActionMatch_GET_AttributeValue(struct zx_xa_ActionMatch_s* x, int n);
struct zx_xa_ActionAttributeDesignator_s* zx_xa_ActionMatch_GET_ActionAttributeDesignator(struct zx_xa_ActionMatch_s* x, int n);
struct zx_xa_AttributeSelector_s* zx_xa_ActionMatch_GET_AttributeSelector(struct zx_xa_ActionMatch_s* x, int n);

int zx_xa_ActionMatch_NUM_AttributeValue(struct zx_xa_ActionMatch_s* x);
int zx_xa_ActionMatch_NUM_ActionAttributeDesignator(struct zx_xa_ActionMatch_s* x);
int zx_xa_ActionMatch_NUM_AttributeSelector(struct zx_xa_ActionMatch_s* x);

struct zx_xa_AttributeValue_s* zx_xa_ActionMatch_POP_AttributeValue(struct zx_xa_ActionMatch_s* x);
struct zx_xa_ActionAttributeDesignator_s* zx_xa_ActionMatch_POP_ActionAttributeDesignator(struct zx_xa_ActionMatch_s* x);
struct zx_xa_AttributeSelector_s* zx_xa_ActionMatch_POP_AttributeSelector(struct zx_xa_ActionMatch_s* x);

void zx_xa_ActionMatch_PUSH_AttributeValue(struct zx_xa_ActionMatch_s* x, struct zx_xa_AttributeValue_s* y);
void zx_xa_ActionMatch_PUSH_ActionAttributeDesignator(struct zx_xa_ActionMatch_s* x, struct zx_xa_ActionAttributeDesignator_s* y);
void zx_xa_ActionMatch_PUSH_AttributeSelector(struct zx_xa_ActionMatch_s* x, struct zx_xa_AttributeSelector_s* y);

void zx_xa_ActionMatch_PUT_MatchId(struct zx_xa_ActionMatch_s* x, struct zx_str* y);

void zx_xa_ActionMatch_PUT_AttributeValue(struct zx_xa_ActionMatch_s* x, int n, struct zx_xa_AttributeValue_s* y);
void zx_xa_ActionMatch_PUT_ActionAttributeDesignator(struct zx_xa_ActionMatch_s* x, int n, struct zx_xa_ActionAttributeDesignator_s* y);
void zx_xa_ActionMatch_PUT_AttributeSelector(struct zx_xa_ActionMatch_s* x, int n, struct zx_xa_AttributeSelector_s* y);

void zx_xa_ActionMatch_ADD_AttributeValue(struct zx_xa_ActionMatch_s* x, int n, struct zx_xa_AttributeValue_s* z);
void zx_xa_ActionMatch_ADD_ActionAttributeDesignator(struct zx_xa_ActionMatch_s* x, int n, struct zx_xa_ActionAttributeDesignator_s* z);
void zx_xa_ActionMatch_ADD_AttributeSelector(struct zx_xa_ActionMatch_s* x, int n, struct zx_xa_AttributeSelector_s* z);

void zx_xa_ActionMatch_DEL_AttributeValue(struct zx_xa_ActionMatch_s* x, int n);
void zx_xa_ActionMatch_DEL_ActionAttributeDesignator(struct zx_xa_ActionMatch_s* x, int n);
void zx_xa_ActionMatch_DEL_AttributeSelector(struct zx_xa_ActionMatch_s* x, int n);

void zx_xa_ActionMatch_REV_AttributeValue(struct zx_xa_ActionMatch_s* x);
void zx_xa_ActionMatch_REV_ActionAttributeDesignator(struct zx_xa_ActionMatch_s* x);
void zx_xa_ActionMatch_REV_AttributeSelector(struct zx_xa_ActionMatch_s* x);

#endif
/* -------------------------- xa_Actions -------------------------- */
/* refby( zx_xa_Target_s ) */
#ifndef zx_xa_Actions_EXT
#define zx_xa_Actions_EXT
#endif

struct zx_xa_Actions_s* zx_DEC_xa_Actions(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Actions_s* zx_NEW_xa_Actions(struct zx_ctx* c);
void zx_FREE_xa_Actions(struct zx_ctx* c, struct zx_xa_Actions_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Actions_s* zx_DEEP_CLONE_xa_Actions(struct zx_ctx* c, struct zx_xa_Actions_s* x, int dup_strs);
void zx_DUP_STRS_xa_Actions(struct zx_ctx* c, struct zx_xa_Actions_s* x);
int zx_WALK_SO_xa_Actions(struct zx_ctx* c, struct zx_xa_Actions_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Actions(struct zx_ctx* c, struct zx_xa_Actions_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Actions(struct zx_ctx* c, struct zx_xa_Actions_s* x);
int zx_LEN_WO_xa_Actions(struct zx_ctx* c, struct zx_xa_Actions_s* x);
char* zx_ENC_SO_xa_Actions(struct zx_ctx* c, struct zx_xa_Actions_s* x, char* p);
char* zx_ENC_WO_xa_Actions(struct zx_ctx* c, struct zx_xa_Actions_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Actions(struct zx_ctx* c, struct zx_xa_Actions_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Actions(struct zx_ctx* c, struct zx_xa_Actions_s* x);

struct zx_xa_Actions_s {
  ZX_ELEM_EXT
  zx_xa_Actions_EXT
  struct zx_xa_Action_s* Action;	/* {1,-1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_Action_s* zx_xa_Actions_GET_Action(struct zx_xa_Actions_s* x, int n);

int zx_xa_Actions_NUM_Action(struct zx_xa_Actions_s* x);

struct zx_xa_Action_s* zx_xa_Actions_POP_Action(struct zx_xa_Actions_s* x);

void zx_xa_Actions_PUSH_Action(struct zx_xa_Actions_s* x, struct zx_xa_Action_s* y);


void zx_xa_Actions_PUT_Action(struct zx_xa_Actions_s* x, int n, struct zx_xa_Action_s* y);

void zx_xa_Actions_ADD_Action(struct zx_xa_Actions_s* x, int n, struct zx_xa_Action_s* z);

void zx_xa_Actions_DEL_Action(struct zx_xa_Actions_s* x, int n);

void zx_xa_Actions_REV_Action(struct zx_xa_Actions_s* x);

#endif
/* -------------------------- xa_Apply -------------------------- */
/* refby( ) */
#ifndef zx_xa_Apply_EXT
#define zx_xa_Apply_EXT
#endif

struct zx_xa_Apply_s* zx_DEC_xa_Apply(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Apply_s* zx_NEW_xa_Apply(struct zx_ctx* c);
void zx_FREE_xa_Apply(struct zx_ctx* c, struct zx_xa_Apply_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Apply_s* zx_DEEP_CLONE_xa_Apply(struct zx_ctx* c, struct zx_xa_Apply_s* x, int dup_strs);
void zx_DUP_STRS_xa_Apply(struct zx_ctx* c, struct zx_xa_Apply_s* x);
int zx_WALK_SO_xa_Apply(struct zx_ctx* c, struct zx_xa_Apply_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Apply(struct zx_ctx* c, struct zx_xa_Apply_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Apply(struct zx_ctx* c, struct zx_xa_Apply_s* x);
int zx_LEN_WO_xa_Apply(struct zx_ctx* c, struct zx_xa_Apply_s* x);
char* zx_ENC_SO_xa_Apply(struct zx_ctx* c, struct zx_xa_Apply_s* x, char* p);
char* zx_ENC_WO_xa_Apply(struct zx_ctx* c, struct zx_xa_Apply_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Apply(struct zx_ctx* c, struct zx_xa_Apply_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Apply(struct zx_ctx* c, struct zx_xa_Apply_s* x);

struct zx_xa_Apply_s {
  ZX_ELEM_EXT
  zx_xa_Apply_EXT
  struct zx_elem_s* Expression;	/* {0,-1} xa:ExpressionType */
  struct zx_str* FunctionId;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_Apply_GET_FunctionId(struct zx_xa_Apply_s* x);

struct zx_elem_s* zx_xa_Apply_GET_Expression(struct zx_xa_Apply_s* x, int n);

int zx_xa_Apply_NUM_Expression(struct zx_xa_Apply_s* x);

struct zx_elem_s* zx_xa_Apply_POP_Expression(struct zx_xa_Apply_s* x);

void zx_xa_Apply_PUSH_Expression(struct zx_xa_Apply_s* x, struct zx_elem_s* y);

void zx_xa_Apply_PUT_FunctionId(struct zx_xa_Apply_s* x, struct zx_str* y);

void zx_xa_Apply_PUT_Expression(struct zx_xa_Apply_s* x, int n, struct zx_elem_s* y);

void zx_xa_Apply_ADD_Expression(struct zx_xa_Apply_s* x, int n, struct zx_elem_s* z);

void zx_xa_Apply_DEL_Expression(struct zx_xa_Apply_s* x, int n);

void zx_xa_Apply_REV_Expression(struct zx_xa_Apply_s* x);

#endif
/* -------------------------- xa_AttributeAssignment -------------------------- */
/* refby( zx_xa_Obligation_s ) */
#ifndef zx_xa_AttributeAssignment_EXT
#define zx_xa_AttributeAssignment_EXT
#endif

struct zx_xa_AttributeAssignment_s* zx_DEC_xa_AttributeAssignment(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_AttributeAssignment_s* zx_NEW_xa_AttributeAssignment(struct zx_ctx* c);
void zx_FREE_xa_AttributeAssignment(struct zx_ctx* c, struct zx_xa_AttributeAssignment_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_AttributeAssignment_s* zx_DEEP_CLONE_xa_AttributeAssignment(struct zx_ctx* c, struct zx_xa_AttributeAssignment_s* x, int dup_strs);
void zx_DUP_STRS_xa_AttributeAssignment(struct zx_ctx* c, struct zx_xa_AttributeAssignment_s* x);
int zx_WALK_SO_xa_AttributeAssignment(struct zx_ctx* c, struct zx_xa_AttributeAssignment_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_AttributeAssignment(struct zx_ctx* c, struct zx_xa_AttributeAssignment_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_AttributeAssignment(struct zx_ctx* c, struct zx_xa_AttributeAssignment_s* x);
int zx_LEN_WO_xa_AttributeAssignment(struct zx_ctx* c, struct zx_xa_AttributeAssignment_s* x);
char* zx_ENC_SO_xa_AttributeAssignment(struct zx_ctx* c, struct zx_xa_AttributeAssignment_s* x, char* p);
char* zx_ENC_WO_xa_AttributeAssignment(struct zx_ctx* c, struct zx_xa_AttributeAssignment_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_AttributeAssignment(struct zx_ctx* c, struct zx_xa_AttributeAssignment_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_AttributeAssignment(struct zx_ctx* c, struct zx_xa_AttributeAssignment_s* x);

struct zx_xa_AttributeAssignment_s {
  ZX_ELEM_EXT
  zx_xa_AttributeAssignment_EXT
  struct zx_str* AttributeId;	/* {1,1} attribute xs:anyURI */
  struct zx_str* DataType;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_AttributeAssignment_GET_AttributeId(struct zx_xa_AttributeAssignment_s* x);
struct zx_str* zx_xa_AttributeAssignment_GET_DataType(struct zx_xa_AttributeAssignment_s* x);





void zx_xa_AttributeAssignment_PUT_AttributeId(struct zx_xa_AttributeAssignment_s* x, struct zx_str* y);
void zx_xa_AttributeAssignment_PUT_DataType(struct zx_xa_AttributeAssignment_s* x, struct zx_str* y);





#endif
/* -------------------------- xa_AttributeSelector -------------------------- */
/* refby( zx_xa_ResourceMatch_s zx_xa_ActionMatch_s zx_xa_EnvironmentMatch_s zx_xa_SubjectMatch_s ) */
#ifndef zx_xa_AttributeSelector_EXT
#define zx_xa_AttributeSelector_EXT
#endif

struct zx_xa_AttributeSelector_s* zx_DEC_xa_AttributeSelector(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_AttributeSelector_s* zx_NEW_xa_AttributeSelector(struct zx_ctx* c);
void zx_FREE_xa_AttributeSelector(struct zx_ctx* c, struct zx_xa_AttributeSelector_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_AttributeSelector_s* zx_DEEP_CLONE_xa_AttributeSelector(struct zx_ctx* c, struct zx_xa_AttributeSelector_s* x, int dup_strs);
void zx_DUP_STRS_xa_AttributeSelector(struct zx_ctx* c, struct zx_xa_AttributeSelector_s* x);
int zx_WALK_SO_xa_AttributeSelector(struct zx_ctx* c, struct zx_xa_AttributeSelector_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_AttributeSelector(struct zx_ctx* c, struct zx_xa_AttributeSelector_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_AttributeSelector(struct zx_ctx* c, struct zx_xa_AttributeSelector_s* x);
int zx_LEN_WO_xa_AttributeSelector(struct zx_ctx* c, struct zx_xa_AttributeSelector_s* x);
char* zx_ENC_SO_xa_AttributeSelector(struct zx_ctx* c, struct zx_xa_AttributeSelector_s* x, char* p);
char* zx_ENC_WO_xa_AttributeSelector(struct zx_ctx* c, struct zx_xa_AttributeSelector_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_AttributeSelector(struct zx_ctx* c, struct zx_xa_AttributeSelector_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_AttributeSelector(struct zx_ctx* c, struct zx_xa_AttributeSelector_s* x);

struct zx_xa_AttributeSelector_s {
  ZX_ELEM_EXT
  zx_xa_AttributeSelector_EXT
  struct zx_str* DataType;	/* {1,1} attribute xs:anyURI */
  struct zx_str* MustBePresent;	/* {0,1} attribute xs:boolean */
  struct zx_str* RequestContextPath;	/* {1,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_AttributeSelector_GET_DataType(struct zx_xa_AttributeSelector_s* x);
struct zx_str* zx_xa_AttributeSelector_GET_MustBePresent(struct zx_xa_AttributeSelector_s* x);
struct zx_str* zx_xa_AttributeSelector_GET_RequestContextPath(struct zx_xa_AttributeSelector_s* x);





void zx_xa_AttributeSelector_PUT_DataType(struct zx_xa_AttributeSelector_s* x, struct zx_str* y);
void zx_xa_AttributeSelector_PUT_MustBePresent(struct zx_xa_AttributeSelector_s* x, struct zx_str* y);
void zx_xa_AttributeSelector_PUT_RequestContextPath(struct zx_xa_AttributeSelector_s* x, struct zx_str* y);





#endif
/* -------------------------- xa_AttributeValue -------------------------- */
/* refby( zx_xa_CombinerParameter_s zx_xa_ResourceMatch_s zx_xa_ActionMatch_s zx_xa_EnvironmentMatch_s zx_xa_SubjectMatch_s ) */
#ifndef zx_xa_AttributeValue_EXT
#define zx_xa_AttributeValue_EXT
#endif

struct zx_xa_AttributeValue_s* zx_DEC_xa_AttributeValue(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_AttributeValue_s* zx_NEW_xa_AttributeValue(struct zx_ctx* c);
void zx_FREE_xa_AttributeValue(struct zx_ctx* c, struct zx_xa_AttributeValue_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_AttributeValue_s* zx_DEEP_CLONE_xa_AttributeValue(struct zx_ctx* c, struct zx_xa_AttributeValue_s* x, int dup_strs);
void zx_DUP_STRS_xa_AttributeValue(struct zx_ctx* c, struct zx_xa_AttributeValue_s* x);
int zx_WALK_SO_xa_AttributeValue(struct zx_ctx* c, struct zx_xa_AttributeValue_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_AttributeValue(struct zx_ctx* c, struct zx_xa_AttributeValue_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_AttributeValue(struct zx_ctx* c, struct zx_xa_AttributeValue_s* x);
int zx_LEN_WO_xa_AttributeValue(struct zx_ctx* c, struct zx_xa_AttributeValue_s* x);
char* zx_ENC_SO_xa_AttributeValue(struct zx_ctx* c, struct zx_xa_AttributeValue_s* x, char* p);
char* zx_ENC_WO_xa_AttributeValue(struct zx_ctx* c, struct zx_xa_AttributeValue_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_AttributeValue(struct zx_ctx* c, struct zx_xa_AttributeValue_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_AttributeValue(struct zx_ctx* c, struct zx_xa_AttributeValue_s* x);

struct zx_xa_AttributeValue_s {
  ZX_ELEM_EXT
  zx_xa_AttributeValue_EXT
  struct zx_str* DataType;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_AttributeValue_GET_DataType(struct zx_xa_AttributeValue_s* x);





void zx_xa_AttributeValue_PUT_DataType(struct zx_xa_AttributeValue_s* x, struct zx_str* y);





#endif
/* -------------------------- xa_CombinerParameter -------------------------- */
/* refby( zx_xa_PolicyCombinerParameters_s zx_xa_CombinerParameters_s zx_xa_PolicySetCombinerParameters_s zx_xa_RuleCombinerParameters_s ) */
#ifndef zx_xa_CombinerParameter_EXT
#define zx_xa_CombinerParameter_EXT
#endif

struct zx_xa_CombinerParameter_s* zx_DEC_xa_CombinerParameter(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_CombinerParameter_s* zx_NEW_xa_CombinerParameter(struct zx_ctx* c);
void zx_FREE_xa_CombinerParameter(struct zx_ctx* c, struct zx_xa_CombinerParameter_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_CombinerParameter_s* zx_DEEP_CLONE_xa_CombinerParameter(struct zx_ctx* c, struct zx_xa_CombinerParameter_s* x, int dup_strs);
void zx_DUP_STRS_xa_CombinerParameter(struct zx_ctx* c, struct zx_xa_CombinerParameter_s* x);
int zx_WALK_SO_xa_CombinerParameter(struct zx_ctx* c, struct zx_xa_CombinerParameter_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_CombinerParameter(struct zx_ctx* c, struct zx_xa_CombinerParameter_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_CombinerParameter(struct zx_ctx* c, struct zx_xa_CombinerParameter_s* x);
int zx_LEN_WO_xa_CombinerParameter(struct zx_ctx* c, struct zx_xa_CombinerParameter_s* x);
char* zx_ENC_SO_xa_CombinerParameter(struct zx_ctx* c, struct zx_xa_CombinerParameter_s* x, char* p);
char* zx_ENC_WO_xa_CombinerParameter(struct zx_ctx* c, struct zx_xa_CombinerParameter_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_CombinerParameter(struct zx_ctx* c, struct zx_xa_CombinerParameter_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_CombinerParameter(struct zx_ctx* c, struct zx_xa_CombinerParameter_s* x);

struct zx_xa_CombinerParameter_s {
  ZX_ELEM_EXT
  zx_xa_CombinerParameter_EXT
  struct zx_xa_AttributeValue_s* AttributeValue;	/* {1,1} nada */
  struct zx_str* ParameterName;	/* {1,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_CombinerParameter_GET_ParameterName(struct zx_xa_CombinerParameter_s* x);

struct zx_xa_AttributeValue_s* zx_xa_CombinerParameter_GET_AttributeValue(struct zx_xa_CombinerParameter_s* x, int n);

int zx_xa_CombinerParameter_NUM_AttributeValue(struct zx_xa_CombinerParameter_s* x);

struct zx_xa_AttributeValue_s* zx_xa_CombinerParameter_POP_AttributeValue(struct zx_xa_CombinerParameter_s* x);

void zx_xa_CombinerParameter_PUSH_AttributeValue(struct zx_xa_CombinerParameter_s* x, struct zx_xa_AttributeValue_s* y);

void zx_xa_CombinerParameter_PUT_ParameterName(struct zx_xa_CombinerParameter_s* x, struct zx_str* y);

void zx_xa_CombinerParameter_PUT_AttributeValue(struct zx_xa_CombinerParameter_s* x, int n, struct zx_xa_AttributeValue_s* y);

void zx_xa_CombinerParameter_ADD_AttributeValue(struct zx_xa_CombinerParameter_s* x, int n, struct zx_xa_AttributeValue_s* z);

void zx_xa_CombinerParameter_DEL_AttributeValue(struct zx_xa_CombinerParameter_s* x, int n);

void zx_xa_CombinerParameter_REV_AttributeValue(struct zx_xa_CombinerParameter_s* x);

#endif
/* -------------------------- xa_CombinerParameters -------------------------- */
/* refby( zx_xa_Policy_s zx_xa_PolicySet_s ) */
#ifndef zx_xa_CombinerParameters_EXT
#define zx_xa_CombinerParameters_EXT
#endif

struct zx_xa_CombinerParameters_s* zx_DEC_xa_CombinerParameters(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_CombinerParameters_s* zx_NEW_xa_CombinerParameters(struct zx_ctx* c);
void zx_FREE_xa_CombinerParameters(struct zx_ctx* c, struct zx_xa_CombinerParameters_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_CombinerParameters_s* zx_DEEP_CLONE_xa_CombinerParameters(struct zx_ctx* c, struct zx_xa_CombinerParameters_s* x, int dup_strs);
void zx_DUP_STRS_xa_CombinerParameters(struct zx_ctx* c, struct zx_xa_CombinerParameters_s* x);
int zx_WALK_SO_xa_CombinerParameters(struct zx_ctx* c, struct zx_xa_CombinerParameters_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_CombinerParameters(struct zx_ctx* c, struct zx_xa_CombinerParameters_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_CombinerParameters(struct zx_ctx* c, struct zx_xa_CombinerParameters_s* x);
int zx_LEN_WO_xa_CombinerParameters(struct zx_ctx* c, struct zx_xa_CombinerParameters_s* x);
char* zx_ENC_SO_xa_CombinerParameters(struct zx_ctx* c, struct zx_xa_CombinerParameters_s* x, char* p);
char* zx_ENC_WO_xa_CombinerParameters(struct zx_ctx* c, struct zx_xa_CombinerParameters_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_CombinerParameters(struct zx_ctx* c, struct zx_xa_CombinerParameters_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_CombinerParameters(struct zx_ctx* c, struct zx_xa_CombinerParameters_s* x);

struct zx_xa_CombinerParameters_s {
  ZX_ELEM_EXT
  zx_xa_CombinerParameters_EXT
  struct zx_xa_CombinerParameter_s* CombinerParameter;	/* {0,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_CombinerParameter_s* zx_xa_CombinerParameters_GET_CombinerParameter(struct zx_xa_CombinerParameters_s* x, int n);

int zx_xa_CombinerParameters_NUM_CombinerParameter(struct zx_xa_CombinerParameters_s* x);

struct zx_xa_CombinerParameter_s* zx_xa_CombinerParameters_POP_CombinerParameter(struct zx_xa_CombinerParameters_s* x);

void zx_xa_CombinerParameters_PUSH_CombinerParameter(struct zx_xa_CombinerParameters_s* x, struct zx_xa_CombinerParameter_s* y);


void zx_xa_CombinerParameters_PUT_CombinerParameter(struct zx_xa_CombinerParameters_s* x, int n, struct zx_xa_CombinerParameter_s* y);

void zx_xa_CombinerParameters_ADD_CombinerParameter(struct zx_xa_CombinerParameters_s* x, int n, struct zx_xa_CombinerParameter_s* z);

void zx_xa_CombinerParameters_DEL_CombinerParameter(struct zx_xa_CombinerParameters_s* x, int n);

void zx_xa_CombinerParameters_REV_CombinerParameter(struct zx_xa_CombinerParameters_s* x);

#endif
/* -------------------------- xa_Condition -------------------------- */
/* refby( zx_xa_Rule_s ) */
#ifndef zx_xa_Condition_EXT
#define zx_xa_Condition_EXT
#endif

struct zx_xa_Condition_s* zx_DEC_xa_Condition(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Condition_s* zx_NEW_xa_Condition(struct zx_ctx* c);
void zx_FREE_xa_Condition(struct zx_ctx* c, struct zx_xa_Condition_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Condition_s* zx_DEEP_CLONE_xa_Condition(struct zx_ctx* c, struct zx_xa_Condition_s* x, int dup_strs);
void zx_DUP_STRS_xa_Condition(struct zx_ctx* c, struct zx_xa_Condition_s* x);
int zx_WALK_SO_xa_Condition(struct zx_ctx* c, struct zx_xa_Condition_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Condition(struct zx_ctx* c, struct zx_xa_Condition_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Condition(struct zx_ctx* c, struct zx_xa_Condition_s* x);
int zx_LEN_WO_xa_Condition(struct zx_ctx* c, struct zx_xa_Condition_s* x);
char* zx_ENC_SO_xa_Condition(struct zx_ctx* c, struct zx_xa_Condition_s* x, char* p);
char* zx_ENC_WO_xa_Condition(struct zx_ctx* c, struct zx_xa_Condition_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Condition(struct zx_ctx* c, struct zx_xa_Condition_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Condition(struct zx_ctx* c, struct zx_xa_Condition_s* x);

struct zx_xa_Condition_s {
  ZX_ELEM_EXT
  zx_xa_Condition_EXT
  struct zx_elem_s* Expression;	/* {1,1} xa:ExpressionType */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_xa_Condition_GET_Expression(struct zx_xa_Condition_s* x, int n);

int zx_xa_Condition_NUM_Expression(struct zx_xa_Condition_s* x);

struct zx_elem_s* zx_xa_Condition_POP_Expression(struct zx_xa_Condition_s* x);

void zx_xa_Condition_PUSH_Expression(struct zx_xa_Condition_s* x, struct zx_elem_s* y);


void zx_xa_Condition_PUT_Expression(struct zx_xa_Condition_s* x, int n, struct zx_elem_s* y);

void zx_xa_Condition_ADD_Expression(struct zx_xa_Condition_s* x, int n, struct zx_elem_s* z);

void zx_xa_Condition_DEL_Expression(struct zx_xa_Condition_s* x, int n);

void zx_xa_Condition_REV_Expression(struct zx_xa_Condition_s* x);

#endif
/* -------------------------- xa_Environment -------------------------- */
/* refby( zx_xa_Environments_s ) */
#ifndef zx_xa_Environment_EXT
#define zx_xa_Environment_EXT
#endif

struct zx_xa_Environment_s* zx_DEC_xa_Environment(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Environment_s* zx_NEW_xa_Environment(struct zx_ctx* c);
void zx_FREE_xa_Environment(struct zx_ctx* c, struct zx_xa_Environment_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Environment_s* zx_DEEP_CLONE_xa_Environment(struct zx_ctx* c, struct zx_xa_Environment_s* x, int dup_strs);
void zx_DUP_STRS_xa_Environment(struct zx_ctx* c, struct zx_xa_Environment_s* x);
int zx_WALK_SO_xa_Environment(struct zx_ctx* c, struct zx_xa_Environment_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Environment(struct zx_ctx* c, struct zx_xa_Environment_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Environment(struct zx_ctx* c, struct zx_xa_Environment_s* x);
int zx_LEN_WO_xa_Environment(struct zx_ctx* c, struct zx_xa_Environment_s* x);
char* zx_ENC_SO_xa_Environment(struct zx_ctx* c, struct zx_xa_Environment_s* x, char* p);
char* zx_ENC_WO_xa_Environment(struct zx_ctx* c, struct zx_xa_Environment_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Environment(struct zx_ctx* c, struct zx_xa_Environment_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Environment(struct zx_ctx* c, struct zx_xa_Environment_s* x);

struct zx_xa_Environment_s {
  ZX_ELEM_EXT
  zx_xa_Environment_EXT
  struct zx_xa_EnvironmentMatch_s* EnvironmentMatch;	/* {1,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_EnvironmentMatch_s* zx_xa_Environment_GET_EnvironmentMatch(struct zx_xa_Environment_s* x, int n);

int zx_xa_Environment_NUM_EnvironmentMatch(struct zx_xa_Environment_s* x);

struct zx_xa_EnvironmentMatch_s* zx_xa_Environment_POP_EnvironmentMatch(struct zx_xa_Environment_s* x);

void zx_xa_Environment_PUSH_EnvironmentMatch(struct zx_xa_Environment_s* x, struct zx_xa_EnvironmentMatch_s* y);


void zx_xa_Environment_PUT_EnvironmentMatch(struct zx_xa_Environment_s* x, int n, struct zx_xa_EnvironmentMatch_s* y);

void zx_xa_Environment_ADD_EnvironmentMatch(struct zx_xa_Environment_s* x, int n, struct zx_xa_EnvironmentMatch_s* z);

void zx_xa_Environment_DEL_EnvironmentMatch(struct zx_xa_Environment_s* x, int n);

void zx_xa_Environment_REV_EnvironmentMatch(struct zx_xa_Environment_s* x);

#endif
/* -------------------------- xa_EnvironmentAttributeDesignator -------------------------- */
/* refby( zx_xa_EnvironmentMatch_s ) */
#ifndef zx_xa_EnvironmentAttributeDesignator_EXT
#define zx_xa_EnvironmentAttributeDesignator_EXT
#endif

struct zx_xa_EnvironmentAttributeDesignator_s* zx_DEC_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_EnvironmentAttributeDesignator_s* zx_NEW_xa_EnvironmentAttributeDesignator(struct zx_ctx* c);
void zx_FREE_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_xa_EnvironmentAttributeDesignator_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_EnvironmentAttributeDesignator_s* zx_DEEP_CLONE_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_xa_EnvironmentAttributeDesignator_s* x, int dup_strs);
void zx_DUP_STRS_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_xa_EnvironmentAttributeDesignator_s* x);
int zx_WALK_SO_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_xa_EnvironmentAttributeDesignator_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_xa_EnvironmentAttributeDesignator_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_xa_EnvironmentAttributeDesignator_s* x);
int zx_LEN_WO_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_xa_EnvironmentAttributeDesignator_s* x);
char* zx_ENC_SO_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_xa_EnvironmentAttributeDesignator_s* x, char* p);
char* zx_ENC_WO_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_xa_EnvironmentAttributeDesignator_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_xa_EnvironmentAttributeDesignator_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_EnvironmentAttributeDesignator(struct zx_ctx* c, struct zx_xa_EnvironmentAttributeDesignator_s* x);

struct zx_xa_EnvironmentAttributeDesignator_s {
  ZX_ELEM_EXT
  zx_xa_EnvironmentAttributeDesignator_EXT
  struct zx_str* AttributeId;	/* {1,1} attribute xs:anyURI */
  struct zx_str* DataType;	/* {1,1} attribute xs:anyURI */
  struct zx_str* Issuer;	/* {0,1} attribute xs:string */
  struct zx_str* MustBePresent;	/* {0,1} attribute xs:boolean */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_EnvironmentAttributeDesignator_GET_AttributeId(struct zx_xa_EnvironmentAttributeDesignator_s* x);
struct zx_str* zx_xa_EnvironmentAttributeDesignator_GET_DataType(struct zx_xa_EnvironmentAttributeDesignator_s* x);
struct zx_str* zx_xa_EnvironmentAttributeDesignator_GET_Issuer(struct zx_xa_EnvironmentAttributeDesignator_s* x);
struct zx_str* zx_xa_EnvironmentAttributeDesignator_GET_MustBePresent(struct zx_xa_EnvironmentAttributeDesignator_s* x);





void zx_xa_EnvironmentAttributeDesignator_PUT_AttributeId(struct zx_xa_EnvironmentAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_EnvironmentAttributeDesignator_PUT_DataType(struct zx_xa_EnvironmentAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_EnvironmentAttributeDesignator_PUT_Issuer(struct zx_xa_EnvironmentAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_EnvironmentAttributeDesignator_PUT_MustBePresent(struct zx_xa_EnvironmentAttributeDesignator_s* x, struct zx_str* y);





#endif
/* -------------------------- xa_EnvironmentMatch -------------------------- */
/* refby( zx_xa_Environment_s ) */
#ifndef zx_xa_EnvironmentMatch_EXT
#define zx_xa_EnvironmentMatch_EXT
#endif

struct zx_xa_EnvironmentMatch_s* zx_DEC_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_EnvironmentMatch_s* zx_NEW_xa_EnvironmentMatch(struct zx_ctx* c);
void zx_FREE_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_xa_EnvironmentMatch_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_EnvironmentMatch_s* zx_DEEP_CLONE_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_xa_EnvironmentMatch_s* x, int dup_strs);
void zx_DUP_STRS_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_xa_EnvironmentMatch_s* x);
int zx_WALK_SO_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_xa_EnvironmentMatch_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_xa_EnvironmentMatch_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_xa_EnvironmentMatch_s* x);
int zx_LEN_WO_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_xa_EnvironmentMatch_s* x);
char* zx_ENC_SO_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_xa_EnvironmentMatch_s* x, char* p);
char* zx_ENC_WO_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_xa_EnvironmentMatch_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_xa_EnvironmentMatch_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_EnvironmentMatch(struct zx_ctx* c, struct zx_xa_EnvironmentMatch_s* x);

struct zx_xa_EnvironmentMatch_s {
  ZX_ELEM_EXT
  zx_xa_EnvironmentMatch_EXT
  struct zx_xa_AttributeValue_s* AttributeValue;	/* {1,1} nada */
  struct zx_xa_EnvironmentAttributeDesignator_s* EnvironmentAttributeDesignator;	/* {0,1} nada */
  struct zx_xa_AttributeSelector_s* AttributeSelector;	/* {0,1} nada */
  struct zx_str* MatchId;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_EnvironmentMatch_GET_MatchId(struct zx_xa_EnvironmentMatch_s* x);

struct zx_xa_AttributeValue_s* zx_xa_EnvironmentMatch_GET_AttributeValue(struct zx_xa_EnvironmentMatch_s* x, int n);
struct zx_xa_EnvironmentAttributeDesignator_s* zx_xa_EnvironmentMatch_GET_EnvironmentAttributeDesignator(struct zx_xa_EnvironmentMatch_s* x, int n);
struct zx_xa_AttributeSelector_s* zx_xa_EnvironmentMatch_GET_AttributeSelector(struct zx_xa_EnvironmentMatch_s* x, int n);

int zx_xa_EnvironmentMatch_NUM_AttributeValue(struct zx_xa_EnvironmentMatch_s* x);
int zx_xa_EnvironmentMatch_NUM_EnvironmentAttributeDesignator(struct zx_xa_EnvironmentMatch_s* x);
int zx_xa_EnvironmentMatch_NUM_AttributeSelector(struct zx_xa_EnvironmentMatch_s* x);

struct zx_xa_AttributeValue_s* zx_xa_EnvironmentMatch_POP_AttributeValue(struct zx_xa_EnvironmentMatch_s* x);
struct zx_xa_EnvironmentAttributeDesignator_s* zx_xa_EnvironmentMatch_POP_EnvironmentAttributeDesignator(struct zx_xa_EnvironmentMatch_s* x);
struct zx_xa_AttributeSelector_s* zx_xa_EnvironmentMatch_POP_AttributeSelector(struct zx_xa_EnvironmentMatch_s* x);

void zx_xa_EnvironmentMatch_PUSH_AttributeValue(struct zx_xa_EnvironmentMatch_s* x, struct zx_xa_AttributeValue_s* y);
void zx_xa_EnvironmentMatch_PUSH_EnvironmentAttributeDesignator(struct zx_xa_EnvironmentMatch_s* x, struct zx_xa_EnvironmentAttributeDesignator_s* y);
void zx_xa_EnvironmentMatch_PUSH_AttributeSelector(struct zx_xa_EnvironmentMatch_s* x, struct zx_xa_AttributeSelector_s* y);

void zx_xa_EnvironmentMatch_PUT_MatchId(struct zx_xa_EnvironmentMatch_s* x, struct zx_str* y);

void zx_xa_EnvironmentMatch_PUT_AttributeValue(struct zx_xa_EnvironmentMatch_s* x, int n, struct zx_xa_AttributeValue_s* y);
void zx_xa_EnvironmentMatch_PUT_EnvironmentAttributeDesignator(struct zx_xa_EnvironmentMatch_s* x, int n, struct zx_xa_EnvironmentAttributeDesignator_s* y);
void zx_xa_EnvironmentMatch_PUT_AttributeSelector(struct zx_xa_EnvironmentMatch_s* x, int n, struct zx_xa_AttributeSelector_s* y);

void zx_xa_EnvironmentMatch_ADD_AttributeValue(struct zx_xa_EnvironmentMatch_s* x, int n, struct zx_xa_AttributeValue_s* z);
void zx_xa_EnvironmentMatch_ADD_EnvironmentAttributeDesignator(struct zx_xa_EnvironmentMatch_s* x, int n, struct zx_xa_EnvironmentAttributeDesignator_s* z);
void zx_xa_EnvironmentMatch_ADD_AttributeSelector(struct zx_xa_EnvironmentMatch_s* x, int n, struct zx_xa_AttributeSelector_s* z);

void zx_xa_EnvironmentMatch_DEL_AttributeValue(struct zx_xa_EnvironmentMatch_s* x, int n);
void zx_xa_EnvironmentMatch_DEL_EnvironmentAttributeDesignator(struct zx_xa_EnvironmentMatch_s* x, int n);
void zx_xa_EnvironmentMatch_DEL_AttributeSelector(struct zx_xa_EnvironmentMatch_s* x, int n);

void zx_xa_EnvironmentMatch_REV_AttributeValue(struct zx_xa_EnvironmentMatch_s* x);
void zx_xa_EnvironmentMatch_REV_EnvironmentAttributeDesignator(struct zx_xa_EnvironmentMatch_s* x);
void zx_xa_EnvironmentMatch_REV_AttributeSelector(struct zx_xa_EnvironmentMatch_s* x);

#endif
/* -------------------------- xa_Environments -------------------------- */
/* refby( zx_xa_Target_s ) */
#ifndef zx_xa_Environments_EXT
#define zx_xa_Environments_EXT
#endif

struct zx_xa_Environments_s* zx_DEC_xa_Environments(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Environments_s* zx_NEW_xa_Environments(struct zx_ctx* c);
void zx_FREE_xa_Environments(struct zx_ctx* c, struct zx_xa_Environments_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Environments_s* zx_DEEP_CLONE_xa_Environments(struct zx_ctx* c, struct zx_xa_Environments_s* x, int dup_strs);
void zx_DUP_STRS_xa_Environments(struct zx_ctx* c, struct zx_xa_Environments_s* x);
int zx_WALK_SO_xa_Environments(struct zx_ctx* c, struct zx_xa_Environments_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Environments(struct zx_ctx* c, struct zx_xa_Environments_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Environments(struct zx_ctx* c, struct zx_xa_Environments_s* x);
int zx_LEN_WO_xa_Environments(struct zx_ctx* c, struct zx_xa_Environments_s* x);
char* zx_ENC_SO_xa_Environments(struct zx_ctx* c, struct zx_xa_Environments_s* x, char* p);
char* zx_ENC_WO_xa_Environments(struct zx_ctx* c, struct zx_xa_Environments_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Environments(struct zx_ctx* c, struct zx_xa_Environments_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Environments(struct zx_ctx* c, struct zx_xa_Environments_s* x);

struct zx_xa_Environments_s {
  ZX_ELEM_EXT
  zx_xa_Environments_EXT
  struct zx_xa_Environment_s* Environment;	/* {1,-1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_Environment_s* zx_xa_Environments_GET_Environment(struct zx_xa_Environments_s* x, int n);

int zx_xa_Environments_NUM_Environment(struct zx_xa_Environments_s* x);

struct zx_xa_Environment_s* zx_xa_Environments_POP_Environment(struct zx_xa_Environments_s* x);

void zx_xa_Environments_PUSH_Environment(struct zx_xa_Environments_s* x, struct zx_xa_Environment_s* y);


void zx_xa_Environments_PUT_Environment(struct zx_xa_Environments_s* x, int n, struct zx_xa_Environment_s* y);

void zx_xa_Environments_ADD_Environment(struct zx_xa_Environments_s* x, int n, struct zx_xa_Environment_s* z);

void zx_xa_Environments_DEL_Environment(struct zx_xa_Environments_s* x, int n);

void zx_xa_Environments_REV_Environment(struct zx_xa_Environments_s* x);

#endif
/* -------------------------- xa_Function -------------------------- */
/* refby( ) */
#ifndef zx_xa_Function_EXT
#define zx_xa_Function_EXT
#endif

struct zx_xa_Function_s* zx_DEC_xa_Function(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Function_s* zx_NEW_xa_Function(struct zx_ctx* c);
void zx_FREE_xa_Function(struct zx_ctx* c, struct zx_xa_Function_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Function_s* zx_DEEP_CLONE_xa_Function(struct zx_ctx* c, struct zx_xa_Function_s* x, int dup_strs);
void zx_DUP_STRS_xa_Function(struct zx_ctx* c, struct zx_xa_Function_s* x);
int zx_WALK_SO_xa_Function(struct zx_ctx* c, struct zx_xa_Function_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Function(struct zx_ctx* c, struct zx_xa_Function_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Function(struct zx_ctx* c, struct zx_xa_Function_s* x);
int zx_LEN_WO_xa_Function(struct zx_ctx* c, struct zx_xa_Function_s* x);
char* zx_ENC_SO_xa_Function(struct zx_ctx* c, struct zx_xa_Function_s* x, char* p);
char* zx_ENC_WO_xa_Function(struct zx_ctx* c, struct zx_xa_Function_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Function(struct zx_ctx* c, struct zx_xa_Function_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Function(struct zx_ctx* c, struct zx_xa_Function_s* x);

struct zx_xa_Function_s {
  ZX_ELEM_EXT
  zx_xa_Function_EXT
  struct zx_str* FunctionId;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_Function_GET_FunctionId(struct zx_xa_Function_s* x);





void zx_xa_Function_PUT_FunctionId(struct zx_xa_Function_s* x, struct zx_str* y);





#endif
/* -------------------------- xa_Obligation -------------------------- */
/* refby( zx_tas3_ESLApply_s zx_xa_Obligations_s zx_b_UsageDirective_s ) */
#ifndef zx_xa_Obligation_EXT
#define zx_xa_Obligation_EXT
#endif

struct zx_xa_Obligation_s* zx_DEC_xa_Obligation(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Obligation_s* zx_NEW_xa_Obligation(struct zx_ctx* c);
void zx_FREE_xa_Obligation(struct zx_ctx* c, struct zx_xa_Obligation_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Obligation_s* zx_DEEP_CLONE_xa_Obligation(struct zx_ctx* c, struct zx_xa_Obligation_s* x, int dup_strs);
void zx_DUP_STRS_xa_Obligation(struct zx_ctx* c, struct zx_xa_Obligation_s* x);
int zx_WALK_SO_xa_Obligation(struct zx_ctx* c, struct zx_xa_Obligation_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Obligation(struct zx_ctx* c, struct zx_xa_Obligation_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Obligation(struct zx_ctx* c, struct zx_xa_Obligation_s* x);
int zx_LEN_WO_xa_Obligation(struct zx_ctx* c, struct zx_xa_Obligation_s* x);
char* zx_ENC_SO_xa_Obligation(struct zx_ctx* c, struct zx_xa_Obligation_s* x, char* p);
char* zx_ENC_WO_xa_Obligation(struct zx_ctx* c, struct zx_xa_Obligation_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Obligation(struct zx_ctx* c, struct zx_xa_Obligation_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Obligation(struct zx_ctx* c, struct zx_xa_Obligation_s* x);

struct zx_xa_Obligation_s {
  ZX_ELEM_EXT
  zx_xa_Obligation_EXT
  struct zx_xa_AttributeAssignment_s* AttributeAssignment;	/* {0,-1} nada */
  struct zx_str* FulfillOn;	/* {1,1} attribute xa:EffectType */
  struct zx_str* ObligationId;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_Obligation_GET_FulfillOn(struct zx_xa_Obligation_s* x);
struct zx_str* zx_xa_Obligation_GET_ObligationId(struct zx_xa_Obligation_s* x);

struct zx_xa_AttributeAssignment_s* zx_xa_Obligation_GET_AttributeAssignment(struct zx_xa_Obligation_s* x, int n);

int zx_xa_Obligation_NUM_AttributeAssignment(struct zx_xa_Obligation_s* x);

struct zx_xa_AttributeAssignment_s* zx_xa_Obligation_POP_AttributeAssignment(struct zx_xa_Obligation_s* x);

void zx_xa_Obligation_PUSH_AttributeAssignment(struct zx_xa_Obligation_s* x, struct zx_xa_AttributeAssignment_s* y);

void zx_xa_Obligation_PUT_FulfillOn(struct zx_xa_Obligation_s* x, struct zx_str* y);
void zx_xa_Obligation_PUT_ObligationId(struct zx_xa_Obligation_s* x, struct zx_str* y);

void zx_xa_Obligation_PUT_AttributeAssignment(struct zx_xa_Obligation_s* x, int n, struct zx_xa_AttributeAssignment_s* y);

void zx_xa_Obligation_ADD_AttributeAssignment(struct zx_xa_Obligation_s* x, int n, struct zx_xa_AttributeAssignment_s* z);

void zx_xa_Obligation_DEL_AttributeAssignment(struct zx_xa_Obligation_s* x, int n);

void zx_xa_Obligation_REV_AttributeAssignment(struct zx_xa_Obligation_s* x);

#endif
/* -------------------------- xa_Obligations -------------------------- */
/* refby( zx_xac_Result_s zx_xa_Policy_s zx_xa_PolicySet_s ) */
#ifndef zx_xa_Obligations_EXT
#define zx_xa_Obligations_EXT
#endif

struct zx_xa_Obligations_s* zx_DEC_xa_Obligations(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Obligations_s* zx_NEW_xa_Obligations(struct zx_ctx* c);
void zx_FREE_xa_Obligations(struct zx_ctx* c, struct zx_xa_Obligations_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Obligations_s* zx_DEEP_CLONE_xa_Obligations(struct zx_ctx* c, struct zx_xa_Obligations_s* x, int dup_strs);
void zx_DUP_STRS_xa_Obligations(struct zx_ctx* c, struct zx_xa_Obligations_s* x);
int zx_WALK_SO_xa_Obligations(struct zx_ctx* c, struct zx_xa_Obligations_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Obligations(struct zx_ctx* c, struct zx_xa_Obligations_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Obligations(struct zx_ctx* c, struct zx_xa_Obligations_s* x);
int zx_LEN_WO_xa_Obligations(struct zx_ctx* c, struct zx_xa_Obligations_s* x);
char* zx_ENC_SO_xa_Obligations(struct zx_ctx* c, struct zx_xa_Obligations_s* x, char* p);
char* zx_ENC_WO_xa_Obligations(struct zx_ctx* c, struct zx_xa_Obligations_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Obligations(struct zx_ctx* c, struct zx_xa_Obligations_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Obligations(struct zx_ctx* c, struct zx_xa_Obligations_s* x);

struct zx_xa_Obligations_s {
  ZX_ELEM_EXT
  zx_xa_Obligations_EXT
  struct zx_xa_Obligation_s* Obligation;	/* {1,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_Obligation_s* zx_xa_Obligations_GET_Obligation(struct zx_xa_Obligations_s* x, int n);

int zx_xa_Obligations_NUM_Obligation(struct zx_xa_Obligations_s* x);

struct zx_xa_Obligation_s* zx_xa_Obligations_POP_Obligation(struct zx_xa_Obligations_s* x);

void zx_xa_Obligations_PUSH_Obligation(struct zx_xa_Obligations_s* x, struct zx_xa_Obligation_s* y);


void zx_xa_Obligations_PUT_Obligation(struct zx_xa_Obligations_s* x, int n, struct zx_xa_Obligation_s* y);

void zx_xa_Obligations_ADD_Obligation(struct zx_xa_Obligations_s* x, int n, struct zx_xa_Obligation_s* z);

void zx_xa_Obligations_DEL_Obligation(struct zx_xa_Obligations_s* x, int n);

void zx_xa_Obligations_REV_Obligation(struct zx_xa_Obligations_s* x);

#endif
/* -------------------------- xa_Policy -------------------------- */
/* refby( zx_xasacd1_ReferencedPolicies_s zx_xasacd1_XACMLPolicyStatement_s zx_xaspcd1_XACMLAuthzDecisionQuery_s zx_xasa_XACMLPolicyStatement_s zx_xa_PolicySet_s ) */
#ifndef zx_xa_Policy_EXT
#define zx_xa_Policy_EXT
#endif

struct zx_xa_Policy_s* zx_DEC_xa_Policy(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Policy_s* zx_NEW_xa_Policy(struct zx_ctx* c);
void zx_FREE_xa_Policy(struct zx_ctx* c, struct zx_xa_Policy_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Policy_s* zx_DEEP_CLONE_xa_Policy(struct zx_ctx* c, struct zx_xa_Policy_s* x, int dup_strs);
void zx_DUP_STRS_xa_Policy(struct zx_ctx* c, struct zx_xa_Policy_s* x);
int zx_WALK_SO_xa_Policy(struct zx_ctx* c, struct zx_xa_Policy_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Policy(struct zx_ctx* c, struct zx_xa_Policy_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Policy(struct zx_ctx* c, struct zx_xa_Policy_s* x);
int zx_LEN_WO_xa_Policy(struct zx_ctx* c, struct zx_xa_Policy_s* x);
char* zx_ENC_SO_xa_Policy(struct zx_ctx* c, struct zx_xa_Policy_s* x, char* p);
char* zx_ENC_WO_xa_Policy(struct zx_ctx* c, struct zx_xa_Policy_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Policy(struct zx_ctx* c, struct zx_xa_Policy_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Policy(struct zx_ctx* c, struct zx_xa_Policy_s* x);

struct zx_xa_Policy_s {
  ZX_ELEM_EXT
  zx_xa_Policy_EXT
  struct zx_elem_s* Description;	/* {0,1} xs:string */
  struct zx_xa_PolicyDefaults_s* PolicyDefaults;	/* {0,1}  */
  struct zx_xa_Target_s* Target;	/* {1,1} nada */
  struct zx_xa_CombinerParameters_s* CombinerParameters;	/* {0,1}  */
  struct zx_xa_RuleCombinerParameters_s* RuleCombinerParameters;	/* {0,1} nada */
  struct zx_xa_VariableDefinition_s* VariableDefinition;	/* {0,1} nada */
  struct zx_xa_Rule_s* Rule;	/* {0,1} nada */
  struct zx_xa_Obligations_s* Obligations;	/* {0,1}  */
  struct zx_str* PolicyId;	/* {1,1} attribute xs:anyURI */
  struct zx_str* RuleCombiningAlgId;	/* {1,1} attribute xs:anyURI */
  struct zx_str* Version;	/* {0,1} attribute xa:VersionType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_Policy_GET_PolicyId(struct zx_xa_Policy_s* x);
struct zx_str* zx_xa_Policy_GET_RuleCombiningAlgId(struct zx_xa_Policy_s* x);
struct zx_str* zx_xa_Policy_GET_Version(struct zx_xa_Policy_s* x);

struct zx_elem_s* zx_xa_Policy_GET_Description(struct zx_xa_Policy_s* x, int n);
struct zx_xa_PolicyDefaults_s* zx_xa_Policy_GET_PolicyDefaults(struct zx_xa_Policy_s* x, int n);
struct zx_xa_Target_s* zx_xa_Policy_GET_Target(struct zx_xa_Policy_s* x, int n);
struct zx_xa_CombinerParameters_s* zx_xa_Policy_GET_CombinerParameters(struct zx_xa_Policy_s* x, int n);
struct zx_xa_RuleCombinerParameters_s* zx_xa_Policy_GET_RuleCombinerParameters(struct zx_xa_Policy_s* x, int n);
struct zx_xa_VariableDefinition_s* zx_xa_Policy_GET_VariableDefinition(struct zx_xa_Policy_s* x, int n);
struct zx_xa_Rule_s* zx_xa_Policy_GET_Rule(struct zx_xa_Policy_s* x, int n);
struct zx_xa_Obligations_s* zx_xa_Policy_GET_Obligations(struct zx_xa_Policy_s* x, int n);

int zx_xa_Policy_NUM_Description(struct zx_xa_Policy_s* x);
int zx_xa_Policy_NUM_PolicyDefaults(struct zx_xa_Policy_s* x);
int zx_xa_Policy_NUM_Target(struct zx_xa_Policy_s* x);
int zx_xa_Policy_NUM_CombinerParameters(struct zx_xa_Policy_s* x);
int zx_xa_Policy_NUM_RuleCombinerParameters(struct zx_xa_Policy_s* x);
int zx_xa_Policy_NUM_VariableDefinition(struct zx_xa_Policy_s* x);
int zx_xa_Policy_NUM_Rule(struct zx_xa_Policy_s* x);
int zx_xa_Policy_NUM_Obligations(struct zx_xa_Policy_s* x);

struct zx_elem_s* zx_xa_Policy_POP_Description(struct zx_xa_Policy_s* x);
struct zx_xa_PolicyDefaults_s* zx_xa_Policy_POP_PolicyDefaults(struct zx_xa_Policy_s* x);
struct zx_xa_Target_s* zx_xa_Policy_POP_Target(struct zx_xa_Policy_s* x);
struct zx_xa_CombinerParameters_s* zx_xa_Policy_POP_CombinerParameters(struct zx_xa_Policy_s* x);
struct zx_xa_RuleCombinerParameters_s* zx_xa_Policy_POP_RuleCombinerParameters(struct zx_xa_Policy_s* x);
struct zx_xa_VariableDefinition_s* zx_xa_Policy_POP_VariableDefinition(struct zx_xa_Policy_s* x);
struct zx_xa_Rule_s* zx_xa_Policy_POP_Rule(struct zx_xa_Policy_s* x);
struct zx_xa_Obligations_s* zx_xa_Policy_POP_Obligations(struct zx_xa_Policy_s* x);

void zx_xa_Policy_PUSH_Description(struct zx_xa_Policy_s* x, struct zx_elem_s* y);
void zx_xa_Policy_PUSH_PolicyDefaults(struct zx_xa_Policy_s* x, struct zx_xa_PolicyDefaults_s* y);
void zx_xa_Policy_PUSH_Target(struct zx_xa_Policy_s* x, struct zx_xa_Target_s* y);
void zx_xa_Policy_PUSH_CombinerParameters(struct zx_xa_Policy_s* x, struct zx_xa_CombinerParameters_s* y);
void zx_xa_Policy_PUSH_RuleCombinerParameters(struct zx_xa_Policy_s* x, struct zx_xa_RuleCombinerParameters_s* y);
void zx_xa_Policy_PUSH_VariableDefinition(struct zx_xa_Policy_s* x, struct zx_xa_VariableDefinition_s* y);
void zx_xa_Policy_PUSH_Rule(struct zx_xa_Policy_s* x, struct zx_xa_Rule_s* y);
void zx_xa_Policy_PUSH_Obligations(struct zx_xa_Policy_s* x, struct zx_xa_Obligations_s* y);

void zx_xa_Policy_PUT_PolicyId(struct zx_xa_Policy_s* x, struct zx_str* y);
void zx_xa_Policy_PUT_RuleCombiningAlgId(struct zx_xa_Policy_s* x, struct zx_str* y);
void zx_xa_Policy_PUT_Version(struct zx_xa_Policy_s* x, struct zx_str* y);

void zx_xa_Policy_PUT_Description(struct zx_xa_Policy_s* x, int n, struct zx_elem_s* y);
void zx_xa_Policy_PUT_PolicyDefaults(struct zx_xa_Policy_s* x, int n, struct zx_xa_PolicyDefaults_s* y);
void zx_xa_Policy_PUT_Target(struct zx_xa_Policy_s* x, int n, struct zx_xa_Target_s* y);
void zx_xa_Policy_PUT_CombinerParameters(struct zx_xa_Policy_s* x, int n, struct zx_xa_CombinerParameters_s* y);
void zx_xa_Policy_PUT_RuleCombinerParameters(struct zx_xa_Policy_s* x, int n, struct zx_xa_RuleCombinerParameters_s* y);
void zx_xa_Policy_PUT_VariableDefinition(struct zx_xa_Policy_s* x, int n, struct zx_xa_VariableDefinition_s* y);
void zx_xa_Policy_PUT_Rule(struct zx_xa_Policy_s* x, int n, struct zx_xa_Rule_s* y);
void zx_xa_Policy_PUT_Obligations(struct zx_xa_Policy_s* x, int n, struct zx_xa_Obligations_s* y);

void zx_xa_Policy_ADD_Description(struct zx_xa_Policy_s* x, int n, struct zx_elem_s* z);
void zx_xa_Policy_ADD_PolicyDefaults(struct zx_xa_Policy_s* x, int n, struct zx_xa_PolicyDefaults_s* z);
void zx_xa_Policy_ADD_Target(struct zx_xa_Policy_s* x, int n, struct zx_xa_Target_s* z);
void zx_xa_Policy_ADD_CombinerParameters(struct zx_xa_Policy_s* x, int n, struct zx_xa_CombinerParameters_s* z);
void zx_xa_Policy_ADD_RuleCombinerParameters(struct zx_xa_Policy_s* x, int n, struct zx_xa_RuleCombinerParameters_s* z);
void zx_xa_Policy_ADD_VariableDefinition(struct zx_xa_Policy_s* x, int n, struct zx_xa_VariableDefinition_s* z);
void zx_xa_Policy_ADD_Rule(struct zx_xa_Policy_s* x, int n, struct zx_xa_Rule_s* z);
void zx_xa_Policy_ADD_Obligations(struct zx_xa_Policy_s* x, int n, struct zx_xa_Obligations_s* z);

void zx_xa_Policy_DEL_Description(struct zx_xa_Policy_s* x, int n);
void zx_xa_Policy_DEL_PolicyDefaults(struct zx_xa_Policy_s* x, int n);
void zx_xa_Policy_DEL_Target(struct zx_xa_Policy_s* x, int n);
void zx_xa_Policy_DEL_CombinerParameters(struct zx_xa_Policy_s* x, int n);
void zx_xa_Policy_DEL_RuleCombinerParameters(struct zx_xa_Policy_s* x, int n);
void zx_xa_Policy_DEL_VariableDefinition(struct zx_xa_Policy_s* x, int n);
void zx_xa_Policy_DEL_Rule(struct zx_xa_Policy_s* x, int n);
void zx_xa_Policy_DEL_Obligations(struct zx_xa_Policy_s* x, int n);

void zx_xa_Policy_REV_Description(struct zx_xa_Policy_s* x);
void zx_xa_Policy_REV_PolicyDefaults(struct zx_xa_Policy_s* x);
void zx_xa_Policy_REV_Target(struct zx_xa_Policy_s* x);
void zx_xa_Policy_REV_CombinerParameters(struct zx_xa_Policy_s* x);
void zx_xa_Policy_REV_RuleCombinerParameters(struct zx_xa_Policy_s* x);
void zx_xa_Policy_REV_VariableDefinition(struct zx_xa_Policy_s* x);
void zx_xa_Policy_REV_Rule(struct zx_xa_Policy_s* x);
void zx_xa_Policy_REV_Obligations(struct zx_xa_Policy_s* x);

#endif
/* -------------------------- xa_PolicyCombinerParameters -------------------------- */
/* refby( zx_xa_PolicySet_s ) */
#ifndef zx_xa_PolicyCombinerParameters_EXT
#define zx_xa_PolicyCombinerParameters_EXT
#endif

struct zx_xa_PolicyCombinerParameters_s* zx_DEC_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_PolicyCombinerParameters_s* zx_NEW_xa_PolicyCombinerParameters(struct zx_ctx* c);
void zx_FREE_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicyCombinerParameters_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_PolicyCombinerParameters_s* zx_DEEP_CLONE_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicyCombinerParameters_s* x, int dup_strs);
void zx_DUP_STRS_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicyCombinerParameters_s* x);
int zx_WALK_SO_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicyCombinerParameters_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicyCombinerParameters_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicyCombinerParameters_s* x);
int zx_LEN_WO_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicyCombinerParameters_s* x);
char* zx_ENC_SO_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicyCombinerParameters_s* x, char* p);
char* zx_ENC_WO_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicyCombinerParameters_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicyCombinerParameters_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_PolicyCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicyCombinerParameters_s* x);

struct zx_xa_PolicyCombinerParameters_s {
  ZX_ELEM_EXT
  zx_xa_PolicyCombinerParameters_EXT
  struct zx_xa_CombinerParameter_s* CombinerParameter;	/* {0,-1} nada */
  struct zx_str* PolicyIdRef;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_PolicyCombinerParameters_GET_PolicyIdRef(struct zx_xa_PolicyCombinerParameters_s* x);

struct zx_xa_CombinerParameter_s* zx_xa_PolicyCombinerParameters_GET_CombinerParameter(struct zx_xa_PolicyCombinerParameters_s* x, int n);

int zx_xa_PolicyCombinerParameters_NUM_CombinerParameter(struct zx_xa_PolicyCombinerParameters_s* x);

struct zx_xa_CombinerParameter_s* zx_xa_PolicyCombinerParameters_POP_CombinerParameter(struct zx_xa_PolicyCombinerParameters_s* x);

void zx_xa_PolicyCombinerParameters_PUSH_CombinerParameter(struct zx_xa_PolicyCombinerParameters_s* x, struct zx_xa_CombinerParameter_s* y);

void zx_xa_PolicyCombinerParameters_PUT_PolicyIdRef(struct zx_xa_PolicyCombinerParameters_s* x, struct zx_str* y);

void zx_xa_PolicyCombinerParameters_PUT_CombinerParameter(struct zx_xa_PolicyCombinerParameters_s* x, int n, struct zx_xa_CombinerParameter_s* y);

void zx_xa_PolicyCombinerParameters_ADD_CombinerParameter(struct zx_xa_PolicyCombinerParameters_s* x, int n, struct zx_xa_CombinerParameter_s* z);

void zx_xa_PolicyCombinerParameters_DEL_CombinerParameter(struct zx_xa_PolicyCombinerParameters_s* x, int n);

void zx_xa_PolicyCombinerParameters_REV_CombinerParameter(struct zx_xa_PolicyCombinerParameters_s* x);

#endif
/* -------------------------- xa_PolicyDefaults -------------------------- */
/* refby( zx_xa_Policy_s ) */
#ifndef zx_xa_PolicyDefaults_EXT
#define zx_xa_PolicyDefaults_EXT
#endif

struct zx_xa_PolicyDefaults_s* zx_DEC_xa_PolicyDefaults(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_PolicyDefaults_s* zx_NEW_xa_PolicyDefaults(struct zx_ctx* c);
void zx_FREE_xa_PolicyDefaults(struct zx_ctx* c, struct zx_xa_PolicyDefaults_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_PolicyDefaults_s* zx_DEEP_CLONE_xa_PolicyDefaults(struct zx_ctx* c, struct zx_xa_PolicyDefaults_s* x, int dup_strs);
void zx_DUP_STRS_xa_PolicyDefaults(struct zx_ctx* c, struct zx_xa_PolicyDefaults_s* x);
int zx_WALK_SO_xa_PolicyDefaults(struct zx_ctx* c, struct zx_xa_PolicyDefaults_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_PolicyDefaults(struct zx_ctx* c, struct zx_xa_PolicyDefaults_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_PolicyDefaults(struct zx_ctx* c, struct zx_xa_PolicyDefaults_s* x);
int zx_LEN_WO_xa_PolicyDefaults(struct zx_ctx* c, struct zx_xa_PolicyDefaults_s* x);
char* zx_ENC_SO_xa_PolicyDefaults(struct zx_ctx* c, struct zx_xa_PolicyDefaults_s* x, char* p);
char* zx_ENC_WO_xa_PolicyDefaults(struct zx_ctx* c, struct zx_xa_PolicyDefaults_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_PolicyDefaults(struct zx_ctx* c, struct zx_xa_PolicyDefaults_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_PolicyDefaults(struct zx_ctx* c, struct zx_xa_PolicyDefaults_s* x);

struct zx_xa_PolicyDefaults_s {
  ZX_ELEM_EXT
  zx_xa_PolicyDefaults_EXT
  struct zx_elem_s* XPathVersion;	/* {1,1} xs:anyURI */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_xa_PolicyDefaults_GET_XPathVersion(struct zx_xa_PolicyDefaults_s* x, int n);

int zx_xa_PolicyDefaults_NUM_XPathVersion(struct zx_xa_PolicyDefaults_s* x);

struct zx_elem_s* zx_xa_PolicyDefaults_POP_XPathVersion(struct zx_xa_PolicyDefaults_s* x);

void zx_xa_PolicyDefaults_PUSH_XPathVersion(struct zx_xa_PolicyDefaults_s* x, struct zx_elem_s* y);


void zx_xa_PolicyDefaults_PUT_XPathVersion(struct zx_xa_PolicyDefaults_s* x, int n, struct zx_elem_s* y);

void zx_xa_PolicyDefaults_ADD_XPathVersion(struct zx_xa_PolicyDefaults_s* x, int n, struct zx_elem_s* z);

void zx_xa_PolicyDefaults_DEL_XPathVersion(struct zx_xa_PolicyDefaults_s* x, int n);

void zx_xa_PolicyDefaults_REV_XPathVersion(struct zx_xa_PolicyDefaults_s* x);

#endif
/* -------------------------- xa_PolicyIdReference -------------------------- */
/* refby( zx_xaspcd1_XACMLPolicyQuery_s zx_xasp_XACMLPolicyQuery_s zx_xa_PolicySet_s ) */
#ifndef zx_xa_PolicyIdReference_EXT
#define zx_xa_PolicyIdReference_EXT
#endif

struct zx_xa_PolicyIdReference_s* zx_DEC_xa_PolicyIdReference(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_PolicyIdReference_s* zx_NEW_xa_PolicyIdReference(struct zx_ctx* c);
void zx_FREE_xa_PolicyIdReference(struct zx_ctx* c, struct zx_xa_PolicyIdReference_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_PolicyIdReference_s* zx_DEEP_CLONE_xa_PolicyIdReference(struct zx_ctx* c, struct zx_xa_PolicyIdReference_s* x, int dup_strs);
void zx_DUP_STRS_xa_PolicyIdReference(struct zx_ctx* c, struct zx_xa_PolicyIdReference_s* x);
int zx_WALK_SO_xa_PolicyIdReference(struct zx_ctx* c, struct zx_xa_PolicyIdReference_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_PolicyIdReference(struct zx_ctx* c, struct zx_xa_PolicyIdReference_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_PolicyIdReference(struct zx_ctx* c, struct zx_xa_PolicyIdReference_s* x);
int zx_LEN_WO_xa_PolicyIdReference(struct zx_ctx* c, struct zx_xa_PolicyIdReference_s* x);
char* zx_ENC_SO_xa_PolicyIdReference(struct zx_ctx* c, struct zx_xa_PolicyIdReference_s* x, char* p);
char* zx_ENC_WO_xa_PolicyIdReference(struct zx_ctx* c, struct zx_xa_PolicyIdReference_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_PolicyIdReference(struct zx_ctx* c, struct zx_xa_PolicyIdReference_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_PolicyIdReference(struct zx_ctx* c, struct zx_xa_PolicyIdReference_s* x);

struct zx_xa_PolicyIdReference_s {
  ZX_ELEM_EXT
  zx_xa_PolicyIdReference_EXT
  struct zx_str* EarliestVersion;	/* {0,1} attribute xa:VersionMatchType */
  struct zx_str* LatestVersion;	/* {0,1} attribute xa:VersionMatchType */
  struct zx_str* Version;	/* {0,1} attribute xa:VersionType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_PolicyIdReference_GET_EarliestVersion(struct zx_xa_PolicyIdReference_s* x);
struct zx_str* zx_xa_PolicyIdReference_GET_LatestVersion(struct zx_xa_PolicyIdReference_s* x);
struct zx_str* zx_xa_PolicyIdReference_GET_Version(struct zx_xa_PolicyIdReference_s* x);





void zx_xa_PolicyIdReference_PUT_EarliestVersion(struct zx_xa_PolicyIdReference_s* x, struct zx_str* y);
void zx_xa_PolicyIdReference_PUT_LatestVersion(struct zx_xa_PolicyIdReference_s* x, struct zx_str* y);
void zx_xa_PolicyIdReference_PUT_Version(struct zx_xa_PolicyIdReference_s* x, struct zx_str* y);





#endif
/* -------------------------- xa_PolicySet -------------------------- */
/* refby( zx_xasacd1_ReferencedPolicies_s zx_xasacd1_XACMLPolicyStatement_s zx_xaspcd1_XACMLAuthzDecisionQuery_s zx_xasa_XACMLPolicyStatement_s zx_xa_PolicySet_s ) */
#ifndef zx_xa_PolicySet_EXT
#define zx_xa_PolicySet_EXT
#endif

struct zx_xa_PolicySet_s* zx_DEC_xa_PolicySet(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_PolicySet_s* zx_NEW_xa_PolicySet(struct zx_ctx* c);
void zx_FREE_xa_PolicySet(struct zx_ctx* c, struct zx_xa_PolicySet_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_PolicySet_s* zx_DEEP_CLONE_xa_PolicySet(struct zx_ctx* c, struct zx_xa_PolicySet_s* x, int dup_strs);
void zx_DUP_STRS_xa_PolicySet(struct zx_ctx* c, struct zx_xa_PolicySet_s* x);
int zx_WALK_SO_xa_PolicySet(struct zx_ctx* c, struct zx_xa_PolicySet_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_PolicySet(struct zx_ctx* c, struct zx_xa_PolicySet_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_PolicySet(struct zx_ctx* c, struct zx_xa_PolicySet_s* x);
int zx_LEN_WO_xa_PolicySet(struct zx_ctx* c, struct zx_xa_PolicySet_s* x);
char* zx_ENC_SO_xa_PolicySet(struct zx_ctx* c, struct zx_xa_PolicySet_s* x, char* p);
char* zx_ENC_WO_xa_PolicySet(struct zx_ctx* c, struct zx_xa_PolicySet_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_PolicySet(struct zx_ctx* c, struct zx_xa_PolicySet_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_PolicySet(struct zx_ctx* c, struct zx_xa_PolicySet_s* x);

struct zx_xa_PolicySet_s {
  ZX_ELEM_EXT
  zx_xa_PolicySet_EXT
  struct zx_elem_s* Description;	/* {0,1} xs:string */
  struct zx_xa_PolicySetDefaults_s* PolicySetDefaults;	/* {0,1}  */
  struct zx_xa_Target_s* Target;	/* {1,1} nada */
  struct zx_xa_PolicySet_s* PolicySet;	/* {0,1} nada */
  struct zx_xa_Policy_s* Policy;	/* {0,1} nada */
  struct zx_xa_PolicySetIdReference_s* PolicySetIdReference;	/* {0,1} nada */
  struct zx_xa_PolicyIdReference_s* PolicyIdReference;	/* {0,1} nada */
  struct zx_xa_CombinerParameters_s* CombinerParameters;	/* {0,1}  */
  struct zx_xa_PolicyCombinerParameters_s* PolicyCombinerParameters;	/* {0,1} nada */
  struct zx_xa_PolicySetCombinerParameters_s* PolicySetCombinerParameters;	/* {0,1} nada */
  struct zx_xa_Obligations_s* Obligations;	/* {0,1}  */
  struct zx_str* PolicyCombiningAlgId;	/* {1,1} attribute xs:anyURI */
  struct zx_str* PolicySetId;	/* {1,1} attribute xs:anyURI */
  struct zx_str* Version;	/* {0,1} attribute xa:VersionType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_PolicySet_GET_PolicyCombiningAlgId(struct zx_xa_PolicySet_s* x);
struct zx_str* zx_xa_PolicySet_GET_PolicySetId(struct zx_xa_PolicySet_s* x);
struct zx_str* zx_xa_PolicySet_GET_Version(struct zx_xa_PolicySet_s* x);

struct zx_elem_s* zx_xa_PolicySet_GET_Description(struct zx_xa_PolicySet_s* x, int n);
struct zx_xa_PolicySetDefaults_s* zx_xa_PolicySet_GET_PolicySetDefaults(struct zx_xa_PolicySet_s* x, int n);
struct zx_xa_Target_s* zx_xa_PolicySet_GET_Target(struct zx_xa_PolicySet_s* x, int n);
struct zx_xa_PolicySet_s* zx_xa_PolicySet_GET_PolicySet(struct zx_xa_PolicySet_s* x, int n);
struct zx_xa_Policy_s* zx_xa_PolicySet_GET_Policy(struct zx_xa_PolicySet_s* x, int n);
struct zx_xa_PolicySetIdReference_s* zx_xa_PolicySet_GET_PolicySetIdReference(struct zx_xa_PolicySet_s* x, int n);
struct zx_xa_PolicyIdReference_s* zx_xa_PolicySet_GET_PolicyIdReference(struct zx_xa_PolicySet_s* x, int n);
struct zx_xa_CombinerParameters_s* zx_xa_PolicySet_GET_CombinerParameters(struct zx_xa_PolicySet_s* x, int n);
struct zx_xa_PolicyCombinerParameters_s* zx_xa_PolicySet_GET_PolicyCombinerParameters(struct zx_xa_PolicySet_s* x, int n);
struct zx_xa_PolicySetCombinerParameters_s* zx_xa_PolicySet_GET_PolicySetCombinerParameters(struct zx_xa_PolicySet_s* x, int n);
struct zx_xa_Obligations_s* zx_xa_PolicySet_GET_Obligations(struct zx_xa_PolicySet_s* x, int n);

int zx_xa_PolicySet_NUM_Description(struct zx_xa_PolicySet_s* x);
int zx_xa_PolicySet_NUM_PolicySetDefaults(struct zx_xa_PolicySet_s* x);
int zx_xa_PolicySet_NUM_Target(struct zx_xa_PolicySet_s* x);
int zx_xa_PolicySet_NUM_PolicySet(struct zx_xa_PolicySet_s* x);
int zx_xa_PolicySet_NUM_Policy(struct zx_xa_PolicySet_s* x);
int zx_xa_PolicySet_NUM_PolicySetIdReference(struct zx_xa_PolicySet_s* x);
int zx_xa_PolicySet_NUM_PolicyIdReference(struct zx_xa_PolicySet_s* x);
int zx_xa_PolicySet_NUM_CombinerParameters(struct zx_xa_PolicySet_s* x);
int zx_xa_PolicySet_NUM_PolicyCombinerParameters(struct zx_xa_PolicySet_s* x);
int zx_xa_PolicySet_NUM_PolicySetCombinerParameters(struct zx_xa_PolicySet_s* x);
int zx_xa_PolicySet_NUM_Obligations(struct zx_xa_PolicySet_s* x);

struct zx_elem_s* zx_xa_PolicySet_POP_Description(struct zx_xa_PolicySet_s* x);
struct zx_xa_PolicySetDefaults_s* zx_xa_PolicySet_POP_PolicySetDefaults(struct zx_xa_PolicySet_s* x);
struct zx_xa_Target_s* zx_xa_PolicySet_POP_Target(struct zx_xa_PolicySet_s* x);
struct zx_xa_PolicySet_s* zx_xa_PolicySet_POP_PolicySet(struct zx_xa_PolicySet_s* x);
struct zx_xa_Policy_s* zx_xa_PolicySet_POP_Policy(struct zx_xa_PolicySet_s* x);
struct zx_xa_PolicySetIdReference_s* zx_xa_PolicySet_POP_PolicySetIdReference(struct zx_xa_PolicySet_s* x);
struct zx_xa_PolicyIdReference_s* zx_xa_PolicySet_POP_PolicyIdReference(struct zx_xa_PolicySet_s* x);
struct zx_xa_CombinerParameters_s* zx_xa_PolicySet_POP_CombinerParameters(struct zx_xa_PolicySet_s* x);
struct zx_xa_PolicyCombinerParameters_s* zx_xa_PolicySet_POP_PolicyCombinerParameters(struct zx_xa_PolicySet_s* x);
struct zx_xa_PolicySetCombinerParameters_s* zx_xa_PolicySet_POP_PolicySetCombinerParameters(struct zx_xa_PolicySet_s* x);
struct zx_xa_Obligations_s* zx_xa_PolicySet_POP_Obligations(struct zx_xa_PolicySet_s* x);

void zx_xa_PolicySet_PUSH_Description(struct zx_xa_PolicySet_s* x, struct zx_elem_s* y);
void zx_xa_PolicySet_PUSH_PolicySetDefaults(struct zx_xa_PolicySet_s* x, struct zx_xa_PolicySetDefaults_s* y);
void zx_xa_PolicySet_PUSH_Target(struct zx_xa_PolicySet_s* x, struct zx_xa_Target_s* y);
void zx_xa_PolicySet_PUSH_PolicySet(struct zx_xa_PolicySet_s* x, struct zx_xa_PolicySet_s* y);
void zx_xa_PolicySet_PUSH_Policy(struct zx_xa_PolicySet_s* x, struct zx_xa_Policy_s* y);
void zx_xa_PolicySet_PUSH_PolicySetIdReference(struct zx_xa_PolicySet_s* x, struct zx_xa_PolicySetIdReference_s* y);
void zx_xa_PolicySet_PUSH_PolicyIdReference(struct zx_xa_PolicySet_s* x, struct zx_xa_PolicyIdReference_s* y);
void zx_xa_PolicySet_PUSH_CombinerParameters(struct zx_xa_PolicySet_s* x, struct zx_xa_CombinerParameters_s* y);
void zx_xa_PolicySet_PUSH_PolicyCombinerParameters(struct zx_xa_PolicySet_s* x, struct zx_xa_PolicyCombinerParameters_s* y);
void zx_xa_PolicySet_PUSH_PolicySetCombinerParameters(struct zx_xa_PolicySet_s* x, struct zx_xa_PolicySetCombinerParameters_s* y);
void zx_xa_PolicySet_PUSH_Obligations(struct zx_xa_PolicySet_s* x, struct zx_xa_Obligations_s* y);

void zx_xa_PolicySet_PUT_PolicyCombiningAlgId(struct zx_xa_PolicySet_s* x, struct zx_str* y);
void zx_xa_PolicySet_PUT_PolicySetId(struct zx_xa_PolicySet_s* x, struct zx_str* y);
void zx_xa_PolicySet_PUT_Version(struct zx_xa_PolicySet_s* x, struct zx_str* y);

void zx_xa_PolicySet_PUT_Description(struct zx_xa_PolicySet_s* x, int n, struct zx_elem_s* y);
void zx_xa_PolicySet_PUT_PolicySetDefaults(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicySetDefaults_s* y);
void zx_xa_PolicySet_PUT_Target(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_Target_s* y);
void zx_xa_PolicySet_PUT_PolicySet(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicySet_s* y);
void zx_xa_PolicySet_PUT_Policy(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_Policy_s* y);
void zx_xa_PolicySet_PUT_PolicySetIdReference(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicySetIdReference_s* y);
void zx_xa_PolicySet_PUT_PolicyIdReference(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicyIdReference_s* y);
void zx_xa_PolicySet_PUT_CombinerParameters(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_CombinerParameters_s* y);
void zx_xa_PolicySet_PUT_PolicyCombinerParameters(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicyCombinerParameters_s* y);
void zx_xa_PolicySet_PUT_PolicySetCombinerParameters(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicySetCombinerParameters_s* y);
void zx_xa_PolicySet_PUT_Obligations(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_Obligations_s* y);

void zx_xa_PolicySet_ADD_Description(struct zx_xa_PolicySet_s* x, int n, struct zx_elem_s* z);
void zx_xa_PolicySet_ADD_PolicySetDefaults(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicySetDefaults_s* z);
void zx_xa_PolicySet_ADD_Target(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_Target_s* z);
void zx_xa_PolicySet_ADD_PolicySet(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicySet_s* z);
void zx_xa_PolicySet_ADD_Policy(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_Policy_s* z);
void zx_xa_PolicySet_ADD_PolicySetIdReference(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicySetIdReference_s* z);
void zx_xa_PolicySet_ADD_PolicyIdReference(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicyIdReference_s* z);
void zx_xa_PolicySet_ADD_CombinerParameters(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_CombinerParameters_s* z);
void zx_xa_PolicySet_ADD_PolicyCombinerParameters(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicyCombinerParameters_s* z);
void zx_xa_PolicySet_ADD_PolicySetCombinerParameters(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_PolicySetCombinerParameters_s* z);
void zx_xa_PolicySet_ADD_Obligations(struct zx_xa_PolicySet_s* x, int n, struct zx_xa_Obligations_s* z);

void zx_xa_PolicySet_DEL_Description(struct zx_xa_PolicySet_s* x, int n);
void zx_xa_PolicySet_DEL_PolicySetDefaults(struct zx_xa_PolicySet_s* x, int n);
void zx_xa_PolicySet_DEL_Target(struct zx_xa_PolicySet_s* x, int n);
void zx_xa_PolicySet_DEL_PolicySet(struct zx_xa_PolicySet_s* x, int n);
void zx_xa_PolicySet_DEL_Policy(struct zx_xa_PolicySet_s* x, int n);
void zx_xa_PolicySet_DEL_PolicySetIdReference(struct zx_xa_PolicySet_s* x, int n);
void zx_xa_PolicySet_DEL_PolicyIdReference(struct zx_xa_PolicySet_s* x, int n);
void zx_xa_PolicySet_DEL_CombinerParameters(struct zx_xa_PolicySet_s* x, int n);
void zx_xa_PolicySet_DEL_PolicyCombinerParameters(struct zx_xa_PolicySet_s* x, int n);
void zx_xa_PolicySet_DEL_PolicySetCombinerParameters(struct zx_xa_PolicySet_s* x, int n);
void zx_xa_PolicySet_DEL_Obligations(struct zx_xa_PolicySet_s* x, int n);

void zx_xa_PolicySet_REV_Description(struct zx_xa_PolicySet_s* x);
void zx_xa_PolicySet_REV_PolicySetDefaults(struct zx_xa_PolicySet_s* x);
void zx_xa_PolicySet_REV_Target(struct zx_xa_PolicySet_s* x);
void zx_xa_PolicySet_REV_PolicySet(struct zx_xa_PolicySet_s* x);
void zx_xa_PolicySet_REV_Policy(struct zx_xa_PolicySet_s* x);
void zx_xa_PolicySet_REV_PolicySetIdReference(struct zx_xa_PolicySet_s* x);
void zx_xa_PolicySet_REV_PolicyIdReference(struct zx_xa_PolicySet_s* x);
void zx_xa_PolicySet_REV_CombinerParameters(struct zx_xa_PolicySet_s* x);
void zx_xa_PolicySet_REV_PolicyCombinerParameters(struct zx_xa_PolicySet_s* x);
void zx_xa_PolicySet_REV_PolicySetCombinerParameters(struct zx_xa_PolicySet_s* x);
void zx_xa_PolicySet_REV_Obligations(struct zx_xa_PolicySet_s* x);

#endif
/* -------------------------- xa_PolicySetCombinerParameters -------------------------- */
/* refby( zx_xa_PolicySet_s ) */
#ifndef zx_xa_PolicySetCombinerParameters_EXT
#define zx_xa_PolicySetCombinerParameters_EXT
#endif

struct zx_xa_PolicySetCombinerParameters_s* zx_DEC_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_PolicySetCombinerParameters_s* zx_NEW_xa_PolicySetCombinerParameters(struct zx_ctx* c);
void zx_FREE_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicySetCombinerParameters_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_PolicySetCombinerParameters_s* zx_DEEP_CLONE_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicySetCombinerParameters_s* x, int dup_strs);
void zx_DUP_STRS_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicySetCombinerParameters_s* x);
int zx_WALK_SO_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicySetCombinerParameters_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicySetCombinerParameters_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicySetCombinerParameters_s* x);
int zx_LEN_WO_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicySetCombinerParameters_s* x);
char* zx_ENC_SO_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicySetCombinerParameters_s* x, char* p);
char* zx_ENC_WO_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicySetCombinerParameters_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicySetCombinerParameters_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_PolicySetCombinerParameters(struct zx_ctx* c, struct zx_xa_PolicySetCombinerParameters_s* x);

struct zx_xa_PolicySetCombinerParameters_s {
  ZX_ELEM_EXT
  zx_xa_PolicySetCombinerParameters_EXT
  struct zx_xa_CombinerParameter_s* CombinerParameter;	/* {0,-1} nada */
  struct zx_str* PolicySetIdRef;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_PolicySetCombinerParameters_GET_PolicySetIdRef(struct zx_xa_PolicySetCombinerParameters_s* x);

struct zx_xa_CombinerParameter_s* zx_xa_PolicySetCombinerParameters_GET_CombinerParameter(struct zx_xa_PolicySetCombinerParameters_s* x, int n);

int zx_xa_PolicySetCombinerParameters_NUM_CombinerParameter(struct zx_xa_PolicySetCombinerParameters_s* x);

struct zx_xa_CombinerParameter_s* zx_xa_PolicySetCombinerParameters_POP_CombinerParameter(struct zx_xa_PolicySetCombinerParameters_s* x);

void zx_xa_PolicySetCombinerParameters_PUSH_CombinerParameter(struct zx_xa_PolicySetCombinerParameters_s* x, struct zx_xa_CombinerParameter_s* y);

void zx_xa_PolicySetCombinerParameters_PUT_PolicySetIdRef(struct zx_xa_PolicySetCombinerParameters_s* x, struct zx_str* y);

void zx_xa_PolicySetCombinerParameters_PUT_CombinerParameter(struct zx_xa_PolicySetCombinerParameters_s* x, int n, struct zx_xa_CombinerParameter_s* y);

void zx_xa_PolicySetCombinerParameters_ADD_CombinerParameter(struct zx_xa_PolicySetCombinerParameters_s* x, int n, struct zx_xa_CombinerParameter_s* z);

void zx_xa_PolicySetCombinerParameters_DEL_CombinerParameter(struct zx_xa_PolicySetCombinerParameters_s* x, int n);

void zx_xa_PolicySetCombinerParameters_REV_CombinerParameter(struct zx_xa_PolicySetCombinerParameters_s* x);

#endif
/* -------------------------- xa_PolicySetDefaults -------------------------- */
/* refby( zx_xa_PolicySet_s ) */
#ifndef zx_xa_PolicySetDefaults_EXT
#define zx_xa_PolicySetDefaults_EXT
#endif

struct zx_xa_PolicySetDefaults_s* zx_DEC_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_PolicySetDefaults_s* zx_NEW_xa_PolicySetDefaults(struct zx_ctx* c);
void zx_FREE_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_xa_PolicySetDefaults_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_PolicySetDefaults_s* zx_DEEP_CLONE_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_xa_PolicySetDefaults_s* x, int dup_strs);
void zx_DUP_STRS_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_xa_PolicySetDefaults_s* x);
int zx_WALK_SO_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_xa_PolicySetDefaults_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_xa_PolicySetDefaults_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_xa_PolicySetDefaults_s* x);
int zx_LEN_WO_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_xa_PolicySetDefaults_s* x);
char* zx_ENC_SO_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_xa_PolicySetDefaults_s* x, char* p);
char* zx_ENC_WO_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_xa_PolicySetDefaults_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_xa_PolicySetDefaults_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_PolicySetDefaults(struct zx_ctx* c, struct zx_xa_PolicySetDefaults_s* x);

struct zx_xa_PolicySetDefaults_s {
  ZX_ELEM_EXT
  zx_xa_PolicySetDefaults_EXT
  struct zx_elem_s* XPathVersion;	/* {1,1} xs:anyURI */
};

#ifdef ZX_ENA_GETPUT

struct zx_elem_s* zx_xa_PolicySetDefaults_GET_XPathVersion(struct zx_xa_PolicySetDefaults_s* x, int n);

int zx_xa_PolicySetDefaults_NUM_XPathVersion(struct zx_xa_PolicySetDefaults_s* x);

struct zx_elem_s* zx_xa_PolicySetDefaults_POP_XPathVersion(struct zx_xa_PolicySetDefaults_s* x);

void zx_xa_PolicySetDefaults_PUSH_XPathVersion(struct zx_xa_PolicySetDefaults_s* x, struct zx_elem_s* y);


void zx_xa_PolicySetDefaults_PUT_XPathVersion(struct zx_xa_PolicySetDefaults_s* x, int n, struct zx_elem_s* y);

void zx_xa_PolicySetDefaults_ADD_XPathVersion(struct zx_xa_PolicySetDefaults_s* x, int n, struct zx_elem_s* z);

void zx_xa_PolicySetDefaults_DEL_XPathVersion(struct zx_xa_PolicySetDefaults_s* x, int n);

void zx_xa_PolicySetDefaults_REV_XPathVersion(struct zx_xa_PolicySetDefaults_s* x);

#endif
/* -------------------------- xa_PolicySetIdReference -------------------------- */
/* refby( zx_xaspcd1_XACMLPolicyQuery_s zx_xasp_XACMLPolicyQuery_s zx_xa_PolicySet_s ) */
#ifndef zx_xa_PolicySetIdReference_EXT
#define zx_xa_PolicySetIdReference_EXT
#endif

struct zx_xa_PolicySetIdReference_s* zx_DEC_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_PolicySetIdReference_s* zx_NEW_xa_PolicySetIdReference(struct zx_ctx* c);
void zx_FREE_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_xa_PolicySetIdReference_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_PolicySetIdReference_s* zx_DEEP_CLONE_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_xa_PolicySetIdReference_s* x, int dup_strs);
void zx_DUP_STRS_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_xa_PolicySetIdReference_s* x);
int zx_WALK_SO_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_xa_PolicySetIdReference_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_xa_PolicySetIdReference_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_xa_PolicySetIdReference_s* x);
int zx_LEN_WO_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_xa_PolicySetIdReference_s* x);
char* zx_ENC_SO_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_xa_PolicySetIdReference_s* x, char* p);
char* zx_ENC_WO_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_xa_PolicySetIdReference_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_xa_PolicySetIdReference_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_PolicySetIdReference(struct zx_ctx* c, struct zx_xa_PolicySetIdReference_s* x);

struct zx_xa_PolicySetIdReference_s {
  ZX_ELEM_EXT
  zx_xa_PolicySetIdReference_EXT
  struct zx_str* EarliestVersion;	/* {0,1} attribute xa:VersionMatchType */
  struct zx_str* LatestVersion;	/* {0,1} attribute xa:VersionMatchType */
  struct zx_str* Version;	/* {0,1} attribute xa:VersionType */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_PolicySetIdReference_GET_EarliestVersion(struct zx_xa_PolicySetIdReference_s* x);
struct zx_str* zx_xa_PolicySetIdReference_GET_LatestVersion(struct zx_xa_PolicySetIdReference_s* x);
struct zx_str* zx_xa_PolicySetIdReference_GET_Version(struct zx_xa_PolicySetIdReference_s* x);





void zx_xa_PolicySetIdReference_PUT_EarliestVersion(struct zx_xa_PolicySetIdReference_s* x, struct zx_str* y);
void zx_xa_PolicySetIdReference_PUT_LatestVersion(struct zx_xa_PolicySetIdReference_s* x, struct zx_str* y);
void zx_xa_PolicySetIdReference_PUT_Version(struct zx_xa_PolicySetIdReference_s* x, struct zx_str* y);





#endif
/* -------------------------- xa_Resource -------------------------- */
/* refby( zx_xa_Resources_s ) */
#ifndef zx_xa_Resource_EXT
#define zx_xa_Resource_EXT
#endif

struct zx_xa_Resource_s* zx_DEC_xa_Resource(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Resource_s* zx_NEW_xa_Resource(struct zx_ctx* c);
void zx_FREE_xa_Resource(struct zx_ctx* c, struct zx_xa_Resource_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Resource_s* zx_DEEP_CLONE_xa_Resource(struct zx_ctx* c, struct zx_xa_Resource_s* x, int dup_strs);
void zx_DUP_STRS_xa_Resource(struct zx_ctx* c, struct zx_xa_Resource_s* x);
int zx_WALK_SO_xa_Resource(struct zx_ctx* c, struct zx_xa_Resource_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Resource(struct zx_ctx* c, struct zx_xa_Resource_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Resource(struct zx_ctx* c, struct zx_xa_Resource_s* x);
int zx_LEN_WO_xa_Resource(struct zx_ctx* c, struct zx_xa_Resource_s* x);
char* zx_ENC_SO_xa_Resource(struct zx_ctx* c, struct zx_xa_Resource_s* x, char* p);
char* zx_ENC_WO_xa_Resource(struct zx_ctx* c, struct zx_xa_Resource_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Resource(struct zx_ctx* c, struct zx_xa_Resource_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Resource(struct zx_ctx* c, struct zx_xa_Resource_s* x);

struct zx_xa_Resource_s {
  ZX_ELEM_EXT
  zx_xa_Resource_EXT
  struct zx_xa_ResourceMatch_s* ResourceMatch;	/* {1,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_ResourceMatch_s* zx_xa_Resource_GET_ResourceMatch(struct zx_xa_Resource_s* x, int n);

int zx_xa_Resource_NUM_ResourceMatch(struct zx_xa_Resource_s* x);

struct zx_xa_ResourceMatch_s* zx_xa_Resource_POP_ResourceMatch(struct zx_xa_Resource_s* x);

void zx_xa_Resource_PUSH_ResourceMatch(struct zx_xa_Resource_s* x, struct zx_xa_ResourceMatch_s* y);


void zx_xa_Resource_PUT_ResourceMatch(struct zx_xa_Resource_s* x, int n, struct zx_xa_ResourceMatch_s* y);

void zx_xa_Resource_ADD_ResourceMatch(struct zx_xa_Resource_s* x, int n, struct zx_xa_ResourceMatch_s* z);

void zx_xa_Resource_DEL_ResourceMatch(struct zx_xa_Resource_s* x, int n);

void zx_xa_Resource_REV_ResourceMatch(struct zx_xa_Resource_s* x);

#endif
/* -------------------------- xa_ResourceAttributeDesignator -------------------------- */
/* refby( zx_xa_ResourceMatch_s ) */
#ifndef zx_xa_ResourceAttributeDesignator_EXT
#define zx_xa_ResourceAttributeDesignator_EXT
#endif

struct zx_xa_ResourceAttributeDesignator_s* zx_DEC_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_ResourceAttributeDesignator_s* zx_NEW_xa_ResourceAttributeDesignator(struct zx_ctx* c);
void zx_FREE_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_xa_ResourceAttributeDesignator_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_ResourceAttributeDesignator_s* zx_DEEP_CLONE_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_xa_ResourceAttributeDesignator_s* x, int dup_strs);
void zx_DUP_STRS_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_xa_ResourceAttributeDesignator_s* x);
int zx_WALK_SO_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_xa_ResourceAttributeDesignator_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_xa_ResourceAttributeDesignator_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_xa_ResourceAttributeDesignator_s* x);
int zx_LEN_WO_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_xa_ResourceAttributeDesignator_s* x);
char* zx_ENC_SO_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_xa_ResourceAttributeDesignator_s* x, char* p);
char* zx_ENC_WO_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_xa_ResourceAttributeDesignator_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_xa_ResourceAttributeDesignator_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_ResourceAttributeDesignator(struct zx_ctx* c, struct zx_xa_ResourceAttributeDesignator_s* x);

struct zx_xa_ResourceAttributeDesignator_s {
  ZX_ELEM_EXT
  zx_xa_ResourceAttributeDesignator_EXT
  struct zx_str* AttributeId;	/* {1,1} attribute xs:anyURI */
  struct zx_str* DataType;	/* {1,1} attribute xs:anyURI */
  struct zx_str* Issuer;	/* {0,1} attribute xs:string */
  struct zx_str* MustBePresent;	/* {0,1} attribute xs:boolean */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_ResourceAttributeDesignator_GET_AttributeId(struct zx_xa_ResourceAttributeDesignator_s* x);
struct zx_str* zx_xa_ResourceAttributeDesignator_GET_DataType(struct zx_xa_ResourceAttributeDesignator_s* x);
struct zx_str* zx_xa_ResourceAttributeDesignator_GET_Issuer(struct zx_xa_ResourceAttributeDesignator_s* x);
struct zx_str* zx_xa_ResourceAttributeDesignator_GET_MustBePresent(struct zx_xa_ResourceAttributeDesignator_s* x);





void zx_xa_ResourceAttributeDesignator_PUT_AttributeId(struct zx_xa_ResourceAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_ResourceAttributeDesignator_PUT_DataType(struct zx_xa_ResourceAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_ResourceAttributeDesignator_PUT_Issuer(struct zx_xa_ResourceAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_ResourceAttributeDesignator_PUT_MustBePresent(struct zx_xa_ResourceAttributeDesignator_s* x, struct zx_str* y);





#endif
/* -------------------------- xa_ResourceMatch -------------------------- */
/* refby( zx_xa_Resource_s ) */
#ifndef zx_xa_ResourceMatch_EXT
#define zx_xa_ResourceMatch_EXT
#endif

struct zx_xa_ResourceMatch_s* zx_DEC_xa_ResourceMatch(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_ResourceMatch_s* zx_NEW_xa_ResourceMatch(struct zx_ctx* c);
void zx_FREE_xa_ResourceMatch(struct zx_ctx* c, struct zx_xa_ResourceMatch_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_ResourceMatch_s* zx_DEEP_CLONE_xa_ResourceMatch(struct zx_ctx* c, struct zx_xa_ResourceMatch_s* x, int dup_strs);
void zx_DUP_STRS_xa_ResourceMatch(struct zx_ctx* c, struct zx_xa_ResourceMatch_s* x);
int zx_WALK_SO_xa_ResourceMatch(struct zx_ctx* c, struct zx_xa_ResourceMatch_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_ResourceMatch(struct zx_ctx* c, struct zx_xa_ResourceMatch_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_ResourceMatch(struct zx_ctx* c, struct zx_xa_ResourceMatch_s* x);
int zx_LEN_WO_xa_ResourceMatch(struct zx_ctx* c, struct zx_xa_ResourceMatch_s* x);
char* zx_ENC_SO_xa_ResourceMatch(struct zx_ctx* c, struct zx_xa_ResourceMatch_s* x, char* p);
char* zx_ENC_WO_xa_ResourceMatch(struct zx_ctx* c, struct zx_xa_ResourceMatch_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_ResourceMatch(struct zx_ctx* c, struct zx_xa_ResourceMatch_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_ResourceMatch(struct zx_ctx* c, struct zx_xa_ResourceMatch_s* x);

struct zx_xa_ResourceMatch_s {
  ZX_ELEM_EXT
  zx_xa_ResourceMatch_EXT
  struct zx_xa_AttributeValue_s* AttributeValue;	/* {1,1} nada */
  struct zx_xa_ResourceAttributeDesignator_s* ResourceAttributeDesignator;	/* {0,1} nada */
  struct zx_xa_AttributeSelector_s* AttributeSelector;	/* {0,1} nada */
  struct zx_str* MatchId;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_ResourceMatch_GET_MatchId(struct zx_xa_ResourceMatch_s* x);

struct zx_xa_AttributeValue_s* zx_xa_ResourceMatch_GET_AttributeValue(struct zx_xa_ResourceMatch_s* x, int n);
struct zx_xa_ResourceAttributeDesignator_s* zx_xa_ResourceMatch_GET_ResourceAttributeDesignator(struct zx_xa_ResourceMatch_s* x, int n);
struct zx_xa_AttributeSelector_s* zx_xa_ResourceMatch_GET_AttributeSelector(struct zx_xa_ResourceMatch_s* x, int n);

int zx_xa_ResourceMatch_NUM_AttributeValue(struct zx_xa_ResourceMatch_s* x);
int zx_xa_ResourceMatch_NUM_ResourceAttributeDesignator(struct zx_xa_ResourceMatch_s* x);
int zx_xa_ResourceMatch_NUM_AttributeSelector(struct zx_xa_ResourceMatch_s* x);

struct zx_xa_AttributeValue_s* zx_xa_ResourceMatch_POP_AttributeValue(struct zx_xa_ResourceMatch_s* x);
struct zx_xa_ResourceAttributeDesignator_s* zx_xa_ResourceMatch_POP_ResourceAttributeDesignator(struct zx_xa_ResourceMatch_s* x);
struct zx_xa_AttributeSelector_s* zx_xa_ResourceMatch_POP_AttributeSelector(struct zx_xa_ResourceMatch_s* x);

void zx_xa_ResourceMatch_PUSH_AttributeValue(struct zx_xa_ResourceMatch_s* x, struct zx_xa_AttributeValue_s* y);
void zx_xa_ResourceMatch_PUSH_ResourceAttributeDesignator(struct zx_xa_ResourceMatch_s* x, struct zx_xa_ResourceAttributeDesignator_s* y);
void zx_xa_ResourceMatch_PUSH_AttributeSelector(struct zx_xa_ResourceMatch_s* x, struct zx_xa_AttributeSelector_s* y);

void zx_xa_ResourceMatch_PUT_MatchId(struct zx_xa_ResourceMatch_s* x, struct zx_str* y);

void zx_xa_ResourceMatch_PUT_AttributeValue(struct zx_xa_ResourceMatch_s* x, int n, struct zx_xa_AttributeValue_s* y);
void zx_xa_ResourceMatch_PUT_ResourceAttributeDesignator(struct zx_xa_ResourceMatch_s* x, int n, struct zx_xa_ResourceAttributeDesignator_s* y);
void zx_xa_ResourceMatch_PUT_AttributeSelector(struct zx_xa_ResourceMatch_s* x, int n, struct zx_xa_AttributeSelector_s* y);

void zx_xa_ResourceMatch_ADD_AttributeValue(struct zx_xa_ResourceMatch_s* x, int n, struct zx_xa_AttributeValue_s* z);
void zx_xa_ResourceMatch_ADD_ResourceAttributeDesignator(struct zx_xa_ResourceMatch_s* x, int n, struct zx_xa_ResourceAttributeDesignator_s* z);
void zx_xa_ResourceMatch_ADD_AttributeSelector(struct zx_xa_ResourceMatch_s* x, int n, struct zx_xa_AttributeSelector_s* z);

void zx_xa_ResourceMatch_DEL_AttributeValue(struct zx_xa_ResourceMatch_s* x, int n);
void zx_xa_ResourceMatch_DEL_ResourceAttributeDesignator(struct zx_xa_ResourceMatch_s* x, int n);
void zx_xa_ResourceMatch_DEL_AttributeSelector(struct zx_xa_ResourceMatch_s* x, int n);

void zx_xa_ResourceMatch_REV_AttributeValue(struct zx_xa_ResourceMatch_s* x);
void zx_xa_ResourceMatch_REV_ResourceAttributeDesignator(struct zx_xa_ResourceMatch_s* x);
void zx_xa_ResourceMatch_REV_AttributeSelector(struct zx_xa_ResourceMatch_s* x);

#endif
/* -------------------------- xa_Resources -------------------------- */
/* refby( zx_xa_Target_s ) */
#ifndef zx_xa_Resources_EXT
#define zx_xa_Resources_EXT
#endif

struct zx_xa_Resources_s* zx_DEC_xa_Resources(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Resources_s* zx_NEW_xa_Resources(struct zx_ctx* c);
void zx_FREE_xa_Resources(struct zx_ctx* c, struct zx_xa_Resources_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Resources_s* zx_DEEP_CLONE_xa_Resources(struct zx_ctx* c, struct zx_xa_Resources_s* x, int dup_strs);
void zx_DUP_STRS_xa_Resources(struct zx_ctx* c, struct zx_xa_Resources_s* x);
int zx_WALK_SO_xa_Resources(struct zx_ctx* c, struct zx_xa_Resources_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Resources(struct zx_ctx* c, struct zx_xa_Resources_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Resources(struct zx_ctx* c, struct zx_xa_Resources_s* x);
int zx_LEN_WO_xa_Resources(struct zx_ctx* c, struct zx_xa_Resources_s* x);
char* zx_ENC_SO_xa_Resources(struct zx_ctx* c, struct zx_xa_Resources_s* x, char* p);
char* zx_ENC_WO_xa_Resources(struct zx_ctx* c, struct zx_xa_Resources_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Resources(struct zx_ctx* c, struct zx_xa_Resources_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Resources(struct zx_ctx* c, struct zx_xa_Resources_s* x);

struct zx_xa_Resources_s {
  ZX_ELEM_EXT
  zx_xa_Resources_EXT
  struct zx_xa_Resource_s* Resource;	/* {1,-1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_Resource_s* zx_xa_Resources_GET_Resource(struct zx_xa_Resources_s* x, int n);

int zx_xa_Resources_NUM_Resource(struct zx_xa_Resources_s* x);

struct zx_xa_Resource_s* zx_xa_Resources_POP_Resource(struct zx_xa_Resources_s* x);

void zx_xa_Resources_PUSH_Resource(struct zx_xa_Resources_s* x, struct zx_xa_Resource_s* y);


void zx_xa_Resources_PUT_Resource(struct zx_xa_Resources_s* x, int n, struct zx_xa_Resource_s* y);

void zx_xa_Resources_ADD_Resource(struct zx_xa_Resources_s* x, int n, struct zx_xa_Resource_s* z);

void zx_xa_Resources_DEL_Resource(struct zx_xa_Resources_s* x, int n);

void zx_xa_Resources_REV_Resource(struct zx_xa_Resources_s* x);

#endif
/* -------------------------- xa_Rule -------------------------- */
/* refby( zx_xa_Policy_s ) */
#ifndef zx_xa_Rule_EXT
#define zx_xa_Rule_EXT
#endif

struct zx_xa_Rule_s* zx_DEC_xa_Rule(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Rule_s* zx_NEW_xa_Rule(struct zx_ctx* c);
void zx_FREE_xa_Rule(struct zx_ctx* c, struct zx_xa_Rule_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Rule_s* zx_DEEP_CLONE_xa_Rule(struct zx_ctx* c, struct zx_xa_Rule_s* x, int dup_strs);
void zx_DUP_STRS_xa_Rule(struct zx_ctx* c, struct zx_xa_Rule_s* x);
int zx_WALK_SO_xa_Rule(struct zx_ctx* c, struct zx_xa_Rule_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Rule(struct zx_ctx* c, struct zx_xa_Rule_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Rule(struct zx_ctx* c, struct zx_xa_Rule_s* x);
int zx_LEN_WO_xa_Rule(struct zx_ctx* c, struct zx_xa_Rule_s* x);
char* zx_ENC_SO_xa_Rule(struct zx_ctx* c, struct zx_xa_Rule_s* x, char* p);
char* zx_ENC_WO_xa_Rule(struct zx_ctx* c, struct zx_xa_Rule_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Rule(struct zx_ctx* c, struct zx_xa_Rule_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Rule(struct zx_ctx* c, struct zx_xa_Rule_s* x);

struct zx_xa_Rule_s {
  ZX_ELEM_EXT
  zx_xa_Rule_EXT
  struct zx_elem_s* Description;	/* {0,1} xs:string */
  struct zx_xa_Target_s* Target;	/* {0,1} nada */
  struct zx_xa_Condition_s* Condition;	/* {0,1}  */
  struct zx_str* Effect;	/* {1,1} attribute xa:EffectType */
  struct zx_str* RuleId;	/* {1,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_Rule_GET_Effect(struct zx_xa_Rule_s* x);
struct zx_str* zx_xa_Rule_GET_RuleId(struct zx_xa_Rule_s* x);

struct zx_elem_s* zx_xa_Rule_GET_Description(struct zx_xa_Rule_s* x, int n);
struct zx_xa_Target_s* zx_xa_Rule_GET_Target(struct zx_xa_Rule_s* x, int n);
struct zx_xa_Condition_s* zx_xa_Rule_GET_Condition(struct zx_xa_Rule_s* x, int n);

int zx_xa_Rule_NUM_Description(struct zx_xa_Rule_s* x);
int zx_xa_Rule_NUM_Target(struct zx_xa_Rule_s* x);
int zx_xa_Rule_NUM_Condition(struct zx_xa_Rule_s* x);

struct zx_elem_s* zx_xa_Rule_POP_Description(struct zx_xa_Rule_s* x);
struct zx_xa_Target_s* zx_xa_Rule_POP_Target(struct zx_xa_Rule_s* x);
struct zx_xa_Condition_s* zx_xa_Rule_POP_Condition(struct zx_xa_Rule_s* x);

void zx_xa_Rule_PUSH_Description(struct zx_xa_Rule_s* x, struct zx_elem_s* y);
void zx_xa_Rule_PUSH_Target(struct zx_xa_Rule_s* x, struct zx_xa_Target_s* y);
void zx_xa_Rule_PUSH_Condition(struct zx_xa_Rule_s* x, struct zx_xa_Condition_s* y);

void zx_xa_Rule_PUT_Effect(struct zx_xa_Rule_s* x, struct zx_str* y);
void zx_xa_Rule_PUT_RuleId(struct zx_xa_Rule_s* x, struct zx_str* y);

void zx_xa_Rule_PUT_Description(struct zx_xa_Rule_s* x, int n, struct zx_elem_s* y);
void zx_xa_Rule_PUT_Target(struct zx_xa_Rule_s* x, int n, struct zx_xa_Target_s* y);
void zx_xa_Rule_PUT_Condition(struct zx_xa_Rule_s* x, int n, struct zx_xa_Condition_s* y);

void zx_xa_Rule_ADD_Description(struct zx_xa_Rule_s* x, int n, struct zx_elem_s* z);
void zx_xa_Rule_ADD_Target(struct zx_xa_Rule_s* x, int n, struct zx_xa_Target_s* z);
void zx_xa_Rule_ADD_Condition(struct zx_xa_Rule_s* x, int n, struct zx_xa_Condition_s* z);

void zx_xa_Rule_DEL_Description(struct zx_xa_Rule_s* x, int n);
void zx_xa_Rule_DEL_Target(struct zx_xa_Rule_s* x, int n);
void zx_xa_Rule_DEL_Condition(struct zx_xa_Rule_s* x, int n);

void zx_xa_Rule_REV_Description(struct zx_xa_Rule_s* x);
void zx_xa_Rule_REV_Target(struct zx_xa_Rule_s* x);
void zx_xa_Rule_REV_Condition(struct zx_xa_Rule_s* x);

#endif
/* -------------------------- xa_RuleCombinerParameters -------------------------- */
/* refby( zx_xa_Policy_s ) */
#ifndef zx_xa_RuleCombinerParameters_EXT
#define zx_xa_RuleCombinerParameters_EXT
#endif

struct zx_xa_RuleCombinerParameters_s* zx_DEC_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_RuleCombinerParameters_s* zx_NEW_xa_RuleCombinerParameters(struct zx_ctx* c);
void zx_FREE_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_xa_RuleCombinerParameters_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_RuleCombinerParameters_s* zx_DEEP_CLONE_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_xa_RuleCombinerParameters_s* x, int dup_strs);
void zx_DUP_STRS_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_xa_RuleCombinerParameters_s* x);
int zx_WALK_SO_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_xa_RuleCombinerParameters_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_xa_RuleCombinerParameters_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_xa_RuleCombinerParameters_s* x);
int zx_LEN_WO_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_xa_RuleCombinerParameters_s* x);
char* zx_ENC_SO_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_xa_RuleCombinerParameters_s* x, char* p);
char* zx_ENC_WO_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_xa_RuleCombinerParameters_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_xa_RuleCombinerParameters_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_RuleCombinerParameters(struct zx_ctx* c, struct zx_xa_RuleCombinerParameters_s* x);

struct zx_xa_RuleCombinerParameters_s {
  ZX_ELEM_EXT
  zx_xa_RuleCombinerParameters_EXT
  struct zx_xa_CombinerParameter_s* CombinerParameter;	/* {0,-1} nada */
  struct zx_str* RuleIdRef;	/* {1,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_RuleCombinerParameters_GET_RuleIdRef(struct zx_xa_RuleCombinerParameters_s* x);

struct zx_xa_CombinerParameter_s* zx_xa_RuleCombinerParameters_GET_CombinerParameter(struct zx_xa_RuleCombinerParameters_s* x, int n);

int zx_xa_RuleCombinerParameters_NUM_CombinerParameter(struct zx_xa_RuleCombinerParameters_s* x);

struct zx_xa_CombinerParameter_s* zx_xa_RuleCombinerParameters_POP_CombinerParameter(struct zx_xa_RuleCombinerParameters_s* x);

void zx_xa_RuleCombinerParameters_PUSH_CombinerParameter(struct zx_xa_RuleCombinerParameters_s* x, struct zx_xa_CombinerParameter_s* y);

void zx_xa_RuleCombinerParameters_PUT_RuleIdRef(struct zx_xa_RuleCombinerParameters_s* x, struct zx_str* y);

void zx_xa_RuleCombinerParameters_PUT_CombinerParameter(struct zx_xa_RuleCombinerParameters_s* x, int n, struct zx_xa_CombinerParameter_s* y);

void zx_xa_RuleCombinerParameters_ADD_CombinerParameter(struct zx_xa_RuleCombinerParameters_s* x, int n, struct zx_xa_CombinerParameter_s* z);

void zx_xa_RuleCombinerParameters_DEL_CombinerParameter(struct zx_xa_RuleCombinerParameters_s* x, int n);

void zx_xa_RuleCombinerParameters_REV_CombinerParameter(struct zx_xa_RuleCombinerParameters_s* x);

#endif
/* -------------------------- xa_Subject -------------------------- */
/* refby( zx_xa_Subjects_s ) */
#ifndef zx_xa_Subject_EXT
#define zx_xa_Subject_EXT
#endif

struct zx_xa_Subject_s* zx_DEC_xa_Subject(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Subject_s* zx_NEW_xa_Subject(struct zx_ctx* c);
void zx_FREE_xa_Subject(struct zx_ctx* c, struct zx_xa_Subject_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Subject_s* zx_DEEP_CLONE_xa_Subject(struct zx_ctx* c, struct zx_xa_Subject_s* x, int dup_strs);
void zx_DUP_STRS_xa_Subject(struct zx_ctx* c, struct zx_xa_Subject_s* x);
int zx_WALK_SO_xa_Subject(struct zx_ctx* c, struct zx_xa_Subject_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Subject(struct zx_ctx* c, struct zx_xa_Subject_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Subject(struct zx_ctx* c, struct zx_xa_Subject_s* x);
int zx_LEN_WO_xa_Subject(struct zx_ctx* c, struct zx_xa_Subject_s* x);
char* zx_ENC_SO_xa_Subject(struct zx_ctx* c, struct zx_xa_Subject_s* x, char* p);
char* zx_ENC_WO_xa_Subject(struct zx_ctx* c, struct zx_xa_Subject_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Subject(struct zx_ctx* c, struct zx_xa_Subject_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Subject(struct zx_ctx* c, struct zx_xa_Subject_s* x);

struct zx_xa_Subject_s {
  ZX_ELEM_EXT
  zx_xa_Subject_EXT
  struct zx_xa_SubjectMatch_s* SubjectMatch;	/* {1,-1} nada */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_SubjectMatch_s* zx_xa_Subject_GET_SubjectMatch(struct zx_xa_Subject_s* x, int n);

int zx_xa_Subject_NUM_SubjectMatch(struct zx_xa_Subject_s* x);

struct zx_xa_SubjectMatch_s* zx_xa_Subject_POP_SubjectMatch(struct zx_xa_Subject_s* x);

void zx_xa_Subject_PUSH_SubjectMatch(struct zx_xa_Subject_s* x, struct zx_xa_SubjectMatch_s* y);


void zx_xa_Subject_PUT_SubjectMatch(struct zx_xa_Subject_s* x, int n, struct zx_xa_SubjectMatch_s* y);

void zx_xa_Subject_ADD_SubjectMatch(struct zx_xa_Subject_s* x, int n, struct zx_xa_SubjectMatch_s* z);

void zx_xa_Subject_DEL_SubjectMatch(struct zx_xa_Subject_s* x, int n);

void zx_xa_Subject_REV_SubjectMatch(struct zx_xa_Subject_s* x);

#endif
/* -------------------------- xa_SubjectAttributeDesignator -------------------------- */
/* refby( zx_xa_SubjectMatch_s ) */
#ifndef zx_xa_SubjectAttributeDesignator_EXT
#define zx_xa_SubjectAttributeDesignator_EXT
#endif

struct zx_xa_SubjectAttributeDesignator_s* zx_DEC_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_SubjectAttributeDesignator_s* zx_NEW_xa_SubjectAttributeDesignator(struct zx_ctx* c);
void zx_FREE_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_xa_SubjectAttributeDesignator_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_SubjectAttributeDesignator_s* zx_DEEP_CLONE_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_xa_SubjectAttributeDesignator_s* x, int dup_strs);
void zx_DUP_STRS_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_xa_SubjectAttributeDesignator_s* x);
int zx_WALK_SO_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_xa_SubjectAttributeDesignator_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_xa_SubjectAttributeDesignator_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_xa_SubjectAttributeDesignator_s* x);
int zx_LEN_WO_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_xa_SubjectAttributeDesignator_s* x);
char* zx_ENC_SO_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_xa_SubjectAttributeDesignator_s* x, char* p);
char* zx_ENC_WO_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_xa_SubjectAttributeDesignator_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_xa_SubjectAttributeDesignator_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_SubjectAttributeDesignator(struct zx_ctx* c, struct zx_xa_SubjectAttributeDesignator_s* x);

struct zx_xa_SubjectAttributeDesignator_s {
  ZX_ELEM_EXT
  zx_xa_SubjectAttributeDesignator_EXT
  struct zx_str* AttributeId;	/* {1,1} attribute xs:anyURI */
  struct zx_str* DataType;	/* {1,1} attribute xs:anyURI */
  struct zx_str* Issuer;	/* {0,1} attribute xs:string */
  struct zx_str* MustBePresent;	/* {0,1} attribute xs:boolean */
  struct zx_str* SubjectCategory;	/* {0,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_SubjectAttributeDesignator_GET_AttributeId(struct zx_xa_SubjectAttributeDesignator_s* x);
struct zx_str* zx_xa_SubjectAttributeDesignator_GET_DataType(struct zx_xa_SubjectAttributeDesignator_s* x);
struct zx_str* zx_xa_SubjectAttributeDesignator_GET_Issuer(struct zx_xa_SubjectAttributeDesignator_s* x);
struct zx_str* zx_xa_SubjectAttributeDesignator_GET_MustBePresent(struct zx_xa_SubjectAttributeDesignator_s* x);
struct zx_str* zx_xa_SubjectAttributeDesignator_GET_SubjectCategory(struct zx_xa_SubjectAttributeDesignator_s* x);





void zx_xa_SubjectAttributeDesignator_PUT_AttributeId(struct zx_xa_SubjectAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_SubjectAttributeDesignator_PUT_DataType(struct zx_xa_SubjectAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_SubjectAttributeDesignator_PUT_Issuer(struct zx_xa_SubjectAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_SubjectAttributeDesignator_PUT_MustBePresent(struct zx_xa_SubjectAttributeDesignator_s* x, struct zx_str* y);
void zx_xa_SubjectAttributeDesignator_PUT_SubjectCategory(struct zx_xa_SubjectAttributeDesignator_s* x, struct zx_str* y);





#endif
/* -------------------------- xa_SubjectMatch -------------------------- */
/* refby( zx_xa_Subject_s ) */
#ifndef zx_xa_SubjectMatch_EXT
#define zx_xa_SubjectMatch_EXT
#endif

struct zx_xa_SubjectMatch_s* zx_DEC_xa_SubjectMatch(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_SubjectMatch_s* zx_NEW_xa_SubjectMatch(struct zx_ctx* c);
void zx_FREE_xa_SubjectMatch(struct zx_ctx* c, struct zx_xa_SubjectMatch_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_SubjectMatch_s* zx_DEEP_CLONE_xa_SubjectMatch(struct zx_ctx* c, struct zx_xa_SubjectMatch_s* x, int dup_strs);
void zx_DUP_STRS_xa_SubjectMatch(struct zx_ctx* c, struct zx_xa_SubjectMatch_s* x);
int zx_WALK_SO_xa_SubjectMatch(struct zx_ctx* c, struct zx_xa_SubjectMatch_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_SubjectMatch(struct zx_ctx* c, struct zx_xa_SubjectMatch_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_SubjectMatch(struct zx_ctx* c, struct zx_xa_SubjectMatch_s* x);
int zx_LEN_WO_xa_SubjectMatch(struct zx_ctx* c, struct zx_xa_SubjectMatch_s* x);
char* zx_ENC_SO_xa_SubjectMatch(struct zx_ctx* c, struct zx_xa_SubjectMatch_s* x, char* p);
char* zx_ENC_WO_xa_SubjectMatch(struct zx_ctx* c, struct zx_xa_SubjectMatch_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_SubjectMatch(struct zx_ctx* c, struct zx_xa_SubjectMatch_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_SubjectMatch(struct zx_ctx* c, struct zx_xa_SubjectMatch_s* x);

struct zx_xa_SubjectMatch_s {
  ZX_ELEM_EXT
  zx_xa_SubjectMatch_EXT
  struct zx_xa_AttributeValue_s* AttributeValue;	/* {1,1} nada */
  struct zx_xa_SubjectAttributeDesignator_s* SubjectAttributeDesignator;	/* {0,1} nada */
  struct zx_xa_AttributeSelector_s* AttributeSelector;	/* {0,1} nada */
  struct zx_str* MatchId;	/* {1,1} attribute xs:anyURI */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_SubjectMatch_GET_MatchId(struct zx_xa_SubjectMatch_s* x);

struct zx_xa_AttributeValue_s* zx_xa_SubjectMatch_GET_AttributeValue(struct zx_xa_SubjectMatch_s* x, int n);
struct zx_xa_SubjectAttributeDesignator_s* zx_xa_SubjectMatch_GET_SubjectAttributeDesignator(struct zx_xa_SubjectMatch_s* x, int n);
struct zx_xa_AttributeSelector_s* zx_xa_SubjectMatch_GET_AttributeSelector(struct zx_xa_SubjectMatch_s* x, int n);

int zx_xa_SubjectMatch_NUM_AttributeValue(struct zx_xa_SubjectMatch_s* x);
int zx_xa_SubjectMatch_NUM_SubjectAttributeDesignator(struct zx_xa_SubjectMatch_s* x);
int zx_xa_SubjectMatch_NUM_AttributeSelector(struct zx_xa_SubjectMatch_s* x);

struct zx_xa_AttributeValue_s* zx_xa_SubjectMatch_POP_AttributeValue(struct zx_xa_SubjectMatch_s* x);
struct zx_xa_SubjectAttributeDesignator_s* zx_xa_SubjectMatch_POP_SubjectAttributeDesignator(struct zx_xa_SubjectMatch_s* x);
struct zx_xa_AttributeSelector_s* zx_xa_SubjectMatch_POP_AttributeSelector(struct zx_xa_SubjectMatch_s* x);

void zx_xa_SubjectMatch_PUSH_AttributeValue(struct zx_xa_SubjectMatch_s* x, struct zx_xa_AttributeValue_s* y);
void zx_xa_SubjectMatch_PUSH_SubjectAttributeDesignator(struct zx_xa_SubjectMatch_s* x, struct zx_xa_SubjectAttributeDesignator_s* y);
void zx_xa_SubjectMatch_PUSH_AttributeSelector(struct zx_xa_SubjectMatch_s* x, struct zx_xa_AttributeSelector_s* y);

void zx_xa_SubjectMatch_PUT_MatchId(struct zx_xa_SubjectMatch_s* x, struct zx_str* y);

void zx_xa_SubjectMatch_PUT_AttributeValue(struct zx_xa_SubjectMatch_s* x, int n, struct zx_xa_AttributeValue_s* y);
void zx_xa_SubjectMatch_PUT_SubjectAttributeDesignator(struct zx_xa_SubjectMatch_s* x, int n, struct zx_xa_SubjectAttributeDesignator_s* y);
void zx_xa_SubjectMatch_PUT_AttributeSelector(struct zx_xa_SubjectMatch_s* x, int n, struct zx_xa_AttributeSelector_s* y);

void zx_xa_SubjectMatch_ADD_AttributeValue(struct zx_xa_SubjectMatch_s* x, int n, struct zx_xa_AttributeValue_s* z);
void zx_xa_SubjectMatch_ADD_SubjectAttributeDesignator(struct zx_xa_SubjectMatch_s* x, int n, struct zx_xa_SubjectAttributeDesignator_s* z);
void zx_xa_SubjectMatch_ADD_AttributeSelector(struct zx_xa_SubjectMatch_s* x, int n, struct zx_xa_AttributeSelector_s* z);

void zx_xa_SubjectMatch_DEL_AttributeValue(struct zx_xa_SubjectMatch_s* x, int n);
void zx_xa_SubjectMatch_DEL_SubjectAttributeDesignator(struct zx_xa_SubjectMatch_s* x, int n);
void zx_xa_SubjectMatch_DEL_AttributeSelector(struct zx_xa_SubjectMatch_s* x, int n);

void zx_xa_SubjectMatch_REV_AttributeValue(struct zx_xa_SubjectMatch_s* x);
void zx_xa_SubjectMatch_REV_SubjectAttributeDesignator(struct zx_xa_SubjectMatch_s* x);
void zx_xa_SubjectMatch_REV_AttributeSelector(struct zx_xa_SubjectMatch_s* x);

#endif
/* -------------------------- xa_Subjects -------------------------- */
/* refby( zx_xa_Target_s ) */
#ifndef zx_xa_Subjects_EXT
#define zx_xa_Subjects_EXT
#endif

struct zx_xa_Subjects_s* zx_DEC_xa_Subjects(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Subjects_s* zx_NEW_xa_Subjects(struct zx_ctx* c);
void zx_FREE_xa_Subjects(struct zx_ctx* c, struct zx_xa_Subjects_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Subjects_s* zx_DEEP_CLONE_xa_Subjects(struct zx_ctx* c, struct zx_xa_Subjects_s* x, int dup_strs);
void zx_DUP_STRS_xa_Subjects(struct zx_ctx* c, struct zx_xa_Subjects_s* x);
int zx_WALK_SO_xa_Subjects(struct zx_ctx* c, struct zx_xa_Subjects_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Subjects(struct zx_ctx* c, struct zx_xa_Subjects_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Subjects(struct zx_ctx* c, struct zx_xa_Subjects_s* x);
int zx_LEN_WO_xa_Subjects(struct zx_ctx* c, struct zx_xa_Subjects_s* x);
char* zx_ENC_SO_xa_Subjects(struct zx_ctx* c, struct zx_xa_Subjects_s* x, char* p);
char* zx_ENC_WO_xa_Subjects(struct zx_ctx* c, struct zx_xa_Subjects_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Subjects(struct zx_ctx* c, struct zx_xa_Subjects_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Subjects(struct zx_ctx* c, struct zx_xa_Subjects_s* x);

struct zx_xa_Subjects_s {
  ZX_ELEM_EXT
  zx_xa_Subjects_EXT
  struct zx_xa_Subject_s* Subject;	/* {1,-1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_Subject_s* zx_xa_Subjects_GET_Subject(struct zx_xa_Subjects_s* x, int n);

int zx_xa_Subjects_NUM_Subject(struct zx_xa_Subjects_s* x);

struct zx_xa_Subject_s* zx_xa_Subjects_POP_Subject(struct zx_xa_Subjects_s* x);

void zx_xa_Subjects_PUSH_Subject(struct zx_xa_Subjects_s* x, struct zx_xa_Subject_s* y);


void zx_xa_Subjects_PUT_Subject(struct zx_xa_Subjects_s* x, int n, struct zx_xa_Subject_s* y);

void zx_xa_Subjects_ADD_Subject(struct zx_xa_Subjects_s* x, int n, struct zx_xa_Subject_s* z);

void zx_xa_Subjects_DEL_Subject(struct zx_xa_Subjects_s* x, int n);

void zx_xa_Subjects_REV_Subject(struct zx_xa_Subjects_s* x);

#endif
/* -------------------------- xa_Target -------------------------- */
/* refby( zx_xa_Rule_s zx_xa_Policy_s zx_xaspcd1_XACMLPolicyQuery_s zx_xasp_XACMLPolicyQuery_s zx_xa_PolicySet_s ) */
#ifndef zx_xa_Target_EXT
#define zx_xa_Target_EXT
#endif

struct zx_xa_Target_s* zx_DEC_xa_Target(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_Target_s* zx_NEW_xa_Target(struct zx_ctx* c);
void zx_FREE_xa_Target(struct zx_ctx* c, struct zx_xa_Target_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_Target_s* zx_DEEP_CLONE_xa_Target(struct zx_ctx* c, struct zx_xa_Target_s* x, int dup_strs);
void zx_DUP_STRS_xa_Target(struct zx_ctx* c, struct zx_xa_Target_s* x);
int zx_WALK_SO_xa_Target(struct zx_ctx* c, struct zx_xa_Target_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_Target(struct zx_ctx* c, struct zx_xa_Target_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_Target(struct zx_ctx* c, struct zx_xa_Target_s* x);
int zx_LEN_WO_xa_Target(struct zx_ctx* c, struct zx_xa_Target_s* x);
char* zx_ENC_SO_xa_Target(struct zx_ctx* c, struct zx_xa_Target_s* x, char* p);
char* zx_ENC_WO_xa_Target(struct zx_ctx* c, struct zx_xa_Target_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_Target(struct zx_ctx* c, struct zx_xa_Target_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_Target(struct zx_ctx* c, struct zx_xa_Target_s* x);

struct zx_xa_Target_s {
  ZX_ELEM_EXT
  zx_xa_Target_EXT
  struct zx_xa_Subjects_s* Subjects;	/* {0,1}  */
  struct zx_xa_Resources_s* Resources;	/* {0,1}  */
  struct zx_xa_Actions_s* Actions;	/* {0,1}  */
  struct zx_xa_Environments_s* Environments;	/* {0,1}  */
};

#ifdef ZX_ENA_GETPUT

struct zx_xa_Subjects_s* zx_xa_Target_GET_Subjects(struct zx_xa_Target_s* x, int n);
struct zx_xa_Resources_s* zx_xa_Target_GET_Resources(struct zx_xa_Target_s* x, int n);
struct zx_xa_Actions_s* zx_xa_Target_GET_Actions(struct zx_xa_Target_s* x, int n);
struct zx_xa_Environments_s* zx_xa_Target_GET_Environments(struct zx_xa_Target_s* x, int n);

int zx_xa_Target_NUM_Subjects(struct zx_xa_Target_s* x);
int zx_xa_Target_NUM_Resources(struct zx_xa_Target_s* x);
int zx_xa_Target_NUM_Actions(struct zx_xa_Target_s* x);
int zx_xa_Target_NUM_Environments(struct zx_xa_Target_s* x);

struct zx_xa_Subjects_s* zx_xa_Target_POP_Subjects(struct zx_xa_Target_s* x);
struct zx_xa_Resources_s* zx_xa_Target_POP_Resources(struct zx_xa_Target_s* x);
struct zx_xa_Actions_s* zx_xa_Target_POP_Actions(struct zx_xa_Target_s* x);
struct zx_xa_Environments_s* zx_xa_Target_POP_Environments(struct zx_xa_Target_s* x);

void zx_xa_Target_PUSH_Subjects(struct zx_xa_Target_s* x, struct zx_xa_Subjects_s* y);
void zx_xa_Target_PUSH_Resources(struct zx_xa_Target_s* x, struct zx_xa_Resources_s* y);
void zx_xa_Target_PUSH_Actions(struct zx_xa_Target_s* x, struct zx_xa_Actions_s* y);
void zx_xa_Target_PUSH_Environments(struct zx_xa_Target_s* x, struct zx_xa_Environments_s* y);


void zx_xa_Target_PUT_Subjects(struct zx_xa_Target_s* x, int n, struct zx_xa_Subjects_s* y);
void zx_xa_Target_PUT_Resources(struct zx_xa_Target_s* x, int n, struct zx_xa_Resources_s* y);
void zx_xa_Target_PUT_Actions(struct zx_xa_Target_s* x, int n, struct zx_xa_Actions_s* y);
void zx_xa_Target_PUT_Environments(struct zx_xa_Target_s* x, int n, struct zx_xa_Environments_s* y);

void zx_xa_Target_ADD_Subjects(struct zx_xa_Target_s* x, int n, struct zx_xa_Subjects_s* z);
void zx_xa_Target_ADD_Resources(struct zx_xa_Target_s* x, int n, struct zx_xa_Resources_s* z);
void zx_xa_Target_ADD_Actions(struct zx_xa_Target_s* x, int n, struct zx_xa_Actions_s* z);
void zx_xa_Target_ADD_Environments(struct zx_xa_Target_s* x, int n, struct zx_xa_Environments_s* z);

void zx_xa_Target_DEL_Subjects(struct zx_xa_Target_s* x, int n);
void zx_xa_Target_DEL_Resources(struct zx_xa_Target_s* x, int n);
void zx_xa_Target_DEL_Actions(struct zx_xa_Target_s* x, int n);
void zx_xa_Target_DEL_Environments(struct zx_xa_Target_s* x, int n);

void zx_xa_Target_REV_Subjects(struct zx_xa_Target_s* x);
void zx_xa_Target_REV_Resources(struct zx_xa_Target_s* x);
void zx_xa_Target_REV_Actions(struct zx_xa_Target_s* x);
void zx_xa_Target_REV_Environments(struct zx_xa_Target_s* x);

#endif
/* -------------------------- xa_VariableDefinition -------------------------- */
/* refby( zx_xa_Policy_s ) */
#ifndef zx_xa_VariableDefinition_EXT
#define zx_xa_VariableDefinition_EXT
#endif

struct zx_xa_VariableDefinition_s* zx_DEC_xa_VariableDefinition(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_VariableDefinition_s* zx_NEW_xa_VariableDefinition(struct zx_ctx* c);
void zx_FREE_xa_VariableDefinition(struct zx_ctx* c, struct zx_xa_VariableDefinition_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_VariableDefinition_s* zx_DEEP_CLONE_xa_VariableDefinition(struct zx_ctx* c, struct zx_xa_VariableDefinition_s* x, int dup_strs);
void zx_DUP_STRS_xa_VariableDefinition(struct zx_ctx* c, struct zx_xa_VariableDefinition_s* x);
int zx_WALK_SO_xa_VariableDefinition(struct zx_ctx* c, struct zx_xa_VariableDefinition_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_VariableDefinition(struct zx_ctx* c, struct zx_xa_VariableDefinition_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_VariableDefinition(struct zx_ctx* c, struct zx_xa_VariableDefinition_s* x);
int zx_LEN_WO_xa_VariableDefinition(struct zx_ctx* c, struct zx_xa_VariableDefinition_s* x);
char* zx_ENC_SO_xa_VariableDefinition(struct zx_ctx* c, struct zx_xa_VariableDefinition_s* x, char* p);
char* zx_ENC_WO_xa_VariableDefinition(struct zx_ctx* c, struct zx_xa_VariableDefinition_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_VariableDefinition(struct zx_ctx* c, struct zx_xa_VariableDefinition_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_VariableDefinition(struct zx_ctx* c, struct zx_xa_VariableDefinition_s* x);

struct zx_xa_VariableDefinition_s {
  ZX_ELEM_EXT
  zx_xa_VariableDefinition_EXT
  struct zx_elem_s* Expression;	/* {1,1} xa:ExpressionType */
  struct zx_str* VariableId;	/* {1,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_VariableDefinition_GET_VariableId(struct zx_xa_VariableDefinition_s* x);

struct zx_elem_s* zx_xa_VariableDefinition_GET_Expression(struct zx_xa_VariableDefinition_s* x, int n);

int zx_xa_VariableDefinition_NUM_Expression(struct zx_xa_VariableDefinition_s* x);

struct zx_elem_s* zx_xa_VariableDefinition_POP_Expression(struct zx_xa_VariableDefinition_s* x);

void zx_xa_VariableDefinition_PUSH_Expression(struct zx_xa_VariableDefinition_s* x, struct zx_elem_s* y);

void zx_xa_VariableDefinition_PUT_VariableId(struct zx_xa_VariableDefinition_s* x, struct zx_str* y);

void zx_xa_VariableDefinition_PUT_Expression(struct zx_xa_VariableDefinition_s* x, int n, struct zx_elem_s* y);

void zx_xa_VariableDefinition_ADD_Expression(struct zx_xa_VariableDefinition_s* x, int n, struct zx_elem_s* z);

void zx_xa_VariableDefinition_DEL_Expression(struct zx_xa_VariableDefinition_s* x, int n);

void zx_xa_VariableDefinition_REV_Expression(struct zx_xa_VariableDefinition_s* x);

#endif
/* -------------------------- xa_VariableReference -------------------------- */
/* refby( ) */
#ifndef zx_xa_VariableReference_EXT
#define zx_xa_VariableReference_EXT
#endif

struct zx_xa_VariableReference_s* zx_DEC_xa_VariableReference(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_xa_VariableReference_s* zx_NEW_xa_VariableReference(struct zx_ctx* c);
void zx_FREE_xa_VariableReference(struct zx_ctx* c, struct zx_xa_VariableReference_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_xa_VariableReference_s* zx_DEEP_CLONE_xa_VariableReference(struct zx_ctx* c, struct zx_xa_VariableReference_s* x, int dup_strs);
void zx_DUP_STRS_xa_VariableReference(struct zx_ctx* c, struct zx_xa_VariableReference_s* x);
int zx_WALK_SO_xa_VariableReference(struct zx_ctx* c, struct zx_xa_VariableReference_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_xa_VariableReference(struct zx_ctx* c, struct zx_xa_VariableReference_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_xa_VariableReference(struct zx_ctx* c, struct zx_xa_VariableReference_s* x);
int zx_LEN_WO_xa_VariableReference(struct zx_ctx* c, struct zx_xa_VariableReference_s* x);
char* zx_ENC_SO_xa_VariableReference(struct zx_ctx* c, struct zx_xa_VariableReference_s* x, char* p);
char* zx_ENC_WO_xa_VariableReference(struct zx_ctx* c, struct zx_xa_VariableReference_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_xa_VariableReference(struct zx_ctx* c, struct zx_xa_VariableReference_s* x);
struct zx_str* zx_EASY_ENC_WO_xa_VariableReference(struct zx_ctx* c, struct zx_xa_VariableReference_s* x);

struct zx_xa_VariableReference_s {
  ZX_ELEM_EXT
  zx_xa_VariableReference_EXT
  struct zx_str* VariableId;	/* {1,1} attribute xs:string */
};

#ifdef ZX_ENA_GETPUT
struct zx_str* zx_xa_VariableReference_GET_VariableId(struct zx_xa_VariableReference_s* x);





void zx_xa_VariableReference_PUT_VariableId(struct zx_xa_VariableReference_s* x, struct zx_str* y);





#endif

#endif
