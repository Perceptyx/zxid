/* c/zx-tas3sol-data.h - WARNING: This header was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Datastructure design, topography, and layout
 * Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for
 * terms and conditions of use. Element and attributes names as well
 * as some topography are derived from schema descriptions that were used as
 * input and may be subject to their own copright. */

#ifndef _c_zx_tas3sol_data_h
#define _c_zx_tas3sol_data_h

#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"

#ifndef ZX_ELEM_EXT
#define ZX_ELEM_EXT  /* This extension point should be defined by who includes this file. */
#endif

/* -------------------------- tas3sol_Dict -------------------------- */
/* refby( zx_b_UsageDirective_s ) */
#ifndef zx_tas3sol_Dict_EXT
#define zx_tas3sol_Dict_EXT
#endif

struct zx_tas3sol_Dict_s* zx_DEC_tas3sol_Dict(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_tas3sol_Dict_s* zx_NEW_tas3sol_Dict(struct zx_ctx* c);
void zx_FREE_tas3sol_Dict(struct zx_ctx* c, struct zx_tas3sol_Dict_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_tas3sol_Dict_s* zx_DEEP_CLONE_tas3sol_Dict(struct zx_ctx* c, struct zx_tas3sol_Dict_s* x, int dup_strs);
void zx_DUP_STRS_tas3sol_Dict(struct zx_ctx* c, struct zx_tas3sol_Dict_s* x);
int zx_WALK_SO_tas3sol_Dict(struct zx_ctx* c, struct zx_tas3sol_Dict_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_tas3sol_Dict(struct zx_ctx* c, struct zx_tas3sol_Dict_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_tas3sol_Dict(struct zx_ctx* c, struct zx_tas3sol_Dict_s* x);
int zx_LEN_WO_tas3sol_Dict(struct zx_ctx* c, struct zx_tas3sol_Dict_s* x);
char* zx_ENC_SO_tas3sol_Dict(struct zx_ctx* c, struct zx_tas3sol_Dict_s* x, char* p);
char* zx_ENC_WO_tas3sol_Dict(struct zx_ctx* c, struct zx_tas3sol_Dict_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_tas3sol_Dict(struct zx_ctx* c, struct zx_tas3sol_Dict_s* x);
struct zx_str* zx_EASY_ENC_WO_tas3sol_Dict(struct zx_ctx* c, struct zx_tas3sol_Dict_s* x);

struct zx_tas3sol_Dict_s {
  ZX_ELEM_EXT
  zx_tas3sol_Dict_EXT
};

#ifdef ZX_ENA_GETPUT










#endif
/* -------------------------- tas3sol_Obligations -------------------------- */
/* refby( ) */
#ifndef zx_tas3sol_Obligations_EXT
#define zx_tas3sol_Obligations_EXT
#endif

struct zx_tas3sol_Obligations_s* zx_DEC_tas3sol_Obligations(struct zx_ctx* c, struct zx_ns_s* ns);
struct zx_tas3sol_Obligations_s* zx_NEW_tas3sol_Obligations(struct zx_ctx* c);
void zx_FREE_tas3sol_Obligations(struct zx_ctx* c, struct zx_tas3sol_Obligations_s* x, int free_strs);
#ifdef ZX_ENA_AUX
struct zx_tas3sol_Obligations_s* zx_DEEP_CLONE_tas3sol_Obligations(struct zx_ctx* c, struct zx_tas3sol_Obligations_s* x, int dup_strs);
void zx_DUP_STRS_tas3sol_Obligations(struct zx_ctx* c, struct zx_tas3sol_Obligations_s* x);
int zx_WALK_SO_tas3sol_Obligations(struct zx_ctx* c, struct zx_tas3sol_Obligations_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
int zx_WALK_WO_tas3sol_Obligations(struct zx_ctx* c, struct zx_tas3sol_Obligations_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx));
#endif
int zx_LEN_SO_tas3sol_Obligations(struct zx_ctx* c, struct zx_tas3sol_Obligations_s* x);
int zx_LEN_WO_tas3sol_Obligations(struct zx_ctx* c, struct zx_tas3sol_Obligations_s* x);
char* zx_ENC_SO_tas3sol_Obligations(struct zx_ctx* c, struct zx_tas3sol_Obligations_s* x, char* p);
char* zx_ENC_WO_tas3sol_Obligations(struct zx_ctx* c, struct zx_tas3sol_Obligations_s* x, char* p);
struct zx_str* zx_EASY_ENC_SO_tas3sol_Obligations(struct zx_ctx* c, struct zx_tas3sol_Obligations_s* x);
struct zx_str* zx_EASY_ENC_WO_tas3sol_Obligations(struct zx_ctx* c, struct zx_tas3sol_Obligations_s* x);

struct zx_tas3sol_Obligations_s {
  ZX_ELEM_EXT
  zx_tas3sol_Obligations_EXT
};

#ifdef ZX_ENA_GETPUT










#endif

#endif
