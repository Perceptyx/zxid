/* c/zx-pmm-aux.c - WARNING: This file was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Code generation design Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for terms and conditions
 * of use. Some aspects of code generation were driven by schema
 * descriptions that were used as input and may be subject to their own copyright.
 * Code generation uses a template, whose copyright statement follows. */

/** aux-templ.c  -  Auxiliary functions template: cloning, freeing, walking data
 ** Copyright (c) 2006 Symlabs (symlabs@symlabs.com), All Rights Reserved.
 ** Author: Sampo Kellomaki (sampo@iki.fi)
 ** This is confidential unpublished proprietary source code of the author.
 ** NO WARRANTY, not even implied warranties. Contains trade secrets.
 ** Distribution prohibited unless authorized in writing.
 ** Licensed under Apache License 2.0, see file COPYING.
 ** Id: aux-templ.c,v 1.12 2008-10-04 23:42:14 sampo Exp $
 **
 ** 30.5.2006, created, Sampo Kellomaki (sampo@iki.fi)
 ** 6.8.2006, factored from enc-templ.c to separate file --Sampo
 **
 ** N.B: wo=wire order (needed for exc-c14n), so=schema order
 **/

#include <memory.h>
#include "errmac.h"
#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"
#include "c/zx-pmm-data.h"



#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMActivate
#define EL_STRUCT zx_pmm_PMActivate_s
#define EL_NS     pmm
#define EL_TAG    PMActivate

/* FUNC(zx_FREE_pmm_PMActivate) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMActivate(struct zx_ctx* c, struct zx_pmm_PMActivate_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMActivateItem_s* e;
      struct zx_pmm_PMActivateItem_s* en;
      for (e = x->PMActivateItem; e; e = en) {
	  en = (struct zx_pmm_PMActivateItem_s*)e->gg.g.n;
	  zx_FREE_pmm_PMActivateItem(c, e, free_strs);
      }
  }
  zx_free_simple_elems(c, x->NotifyTo, free_strs);


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMActivate) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMActivate_s* zx_NEW_pmm_PMActivate(struct zx_ctx* c)
{
  struct zx_pmm_PMActivate_s* x = ZX_ZALLOC(c, struct zx_pmm_PMActivate_s);
  x->gg.g.tok = zx_pmm_PMActivate_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMActivate) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMActivate(struct zx_ctx* c, struct zx_pmm_PMActivate_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMActivateItem_s* e;
      for (e = x->PMActivateItem; e; e = (struct zx_pmm_PMActivateItem_s*)e->gg.g.n)
	  zx_DUP_STRS_pmm_PMActivateItem(c, e);
  }
  zx_dup_strs_simple_elems(c, x->NotifyTo);

}

/* FUNC(zx_DEEP_CLONE_pmm_PMActivate) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMActivate_s* zx_DEEP_CLONE_pmm_PMActivate(struct zx_ctx* c, struct zx_pmm_PMActivate_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMActivate_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMActivate_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMActivateItem_s* e;
      struct zx_pmm_PMActivateItem_s* en;
      struct zx_pmm_PMActivateItem_s* enn;
      for (enn = 0, e = x->PMActivateItem; e; e = (struct zx_pmm_PMActivateItem_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_pmm_PMActivateItem(c, e, dup_strs);
	  if (!enn)
	      x->PMActivateItem = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }
  x->NotifyTo = zx_deep_clone_simple_elems(c,x->NotifyTo, dup_strs);

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMActivate) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMActivate(struct zx_ctx* c, struct zx_pmm_PMActivate_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_pmm_PMActivateItem_s* e;
      for (e = x->PMActivateItem; e; e = (struct zx_pmm_PMActivateItem_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_pmm_PMActivateItem(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }
  ret = zx_walk_so_simple_elems(c, x->NotifyTo, ctx, callback);
  if (ret)
    return ret;

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMActivate) */

int zx_WALK_WO_pmm_PMActivate(struct zx_ctx* c, struct zx_pmm_PMActivate_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMActivateItem
#define EL_STRUCT zx_pmm_PMActivateItem_s
#define EL_NS     pmm
#define EL_TAG    PMActivateItem

/* FUNC(zx_FREE_pmm_PMActivateItem) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMActivateItem(struct zx_ctx* c, struct zx_pmm_PMActivateItem_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */

  zx_free_attr(c, x->at, free_strs);
  zx_free_attr(c, x->itemID, free_strs);

  {
      struct zx_prov_PMID_s* e;
      struct zx_prov_PMID_s* en;
      for (e = x->PMID; e; e = en) {
	  en = (struct zx_prov_PMID_s*)e->gg.g.n;
	  zx_FREE_prov_PMID(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMActivateItem) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMActivateItem_s* zx_NEW_pmm_PMActivateItem(struct zx_ctx* c)
{
  struct zx_pmm_PMActivateItem_s* x = ZX_ZALLOC(c, struct zx_pmm_PMActivateItem_s);
  x->gg.g.tok = zx_pmm_PMActivateItem_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMActivateItem) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMActivateItem(struct zx_ctx* c, struct zx_pmm_PMActivateItem_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */

  zx_dup_attr(c, x->at);
  zx_dup_attr(c, x->itemID);

  {
      struct zx_prov_PMID_s* e;
      for (e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n)
	  zx_DUP_STRS_prov_PMID(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMActivateItem) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMActivateItem_s* zx_DEEP_CLONE_pmm_PMActivateItem(struct zx_ctx* c, struct zx_pmm_PMActivateItem_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMActivateItem_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMActivateItem_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */

  x->at = zx_clone_attr(c, x->at);
  x->itemID = zx_clone_attr(c, x->itemID);

  {
      struct zx_prov_PMID_s* e;
      struct zx_prov_PMID_s* en;
      struct zx_prov_PMID_s* enn;
      for (enn = 0, e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_prov_PMID(c, e, dup_strs);
	  if (!enn)
	      x->PMID = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMActivateItem) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMActivateItem(struct zx_ctx* c, struct zx_pmm_PMActivateItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_prov_PMID_s* e;
      for (e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_prov_PMID(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMActivateItem) */

int zx_WALK_WO_pmm_PMActivateItem(struct zx_ctx* c, struct zx_pmm_PMActivateItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMActivateResponse
#define EL_STRUCT zx_pmm_PMActivateResponse_s
#define EL_NS     pmm
#define EL_TAG    PMActivateResponse

/* FUNC(zx_FREE_pmm_PMActivateResponse) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMActivateResponse(struct zx_ctx* c, struct zx_pmm_PMActivateResponse_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      for (e = x->Status; e; e = en) {
	  en = (struct zx_lu_Status_s*)e->gg.g.n;
	  zx_FREE_lu_Status(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMActivateResponse) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMActivateResponse_s* zx_NEW_pmm_PMActivateResponse(struct zx_ctx* c)
{
  struct zx_pmm_PMActivateResponse_s* x = ZX_ZALLOC(c, struct zx_pmm_PMActivateResponse_s);
  x->gg.g.tok = zx_pmm_PMActivateResponse_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMActivateResponse) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMActivateResponse(struct zx_ctx* c, struct zx_pmm_PMActivateResponse_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n)
	  zx_DUP_STRS_lu_Status(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMActivateResponse) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMActivateResponse_s* zx_DEEP_CLONE_pmm_PMActivateResponse(struct zx_ctx* c, struct zx_pmm_PMActivateResponse_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMActivateResponse_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMActivateResponse_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      struct zx_lu_Status_s* enn;
      for (enn = 0, e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_lu_Status(c, e, dup_strs);
	  if (!enn)
	      x->Status = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMActivateResponse) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMActivateResponse(struct zx_ctx* c, struct zx_pmm_PMActivateResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_lu_Status(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMActivateResponse) */

int zx_WALK_WO_pmm_PMActivateResponse(struct zx_ctx* c, struct zx_pmm_PMActivateResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMDeactivate
#define EL_STRUCT zx_pmm_PMDeactivate_s
#define EL_NS     pmm
#define EL_TAG    PMDeactivate

/* FUNC(zx_FREE_pmm_PMDeactivate) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMDeactivate(struct zx_ctx* c, struct zx_pmm_PMDeactivate_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMDeactivateItem_s* e;
      struct zx_pmm_PMDeactivateItem_s* en;
      for (e = x->PMDeactivateItem; e; e = en) {
	  en = (struct zx_pmm_PMDeactivateItem_s*)e->gg.g.n;
	  zx_FREE_pmm_PMDeactivateItem(c, e, free_strs);
      }
  }
  zx_free_simple_elems(c, x->NotifyTo, free_strs);


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMDeactivate) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMDeactivate_s* zx_NEW_pmm_PMDeactivate(struct zx_ctx* c)
{
  struct zx_pmm_PMDeactivate_s* x = ZX_ZALLOC(c, struct zx_pmm_PMDeactivate_s);
  x->gg.g.tok = zx_pmm_PMDeactivate_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMDeactivate) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMDeactivate(struct zx_ctx* c, struct zx_pmm_PMDeactivate_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMDeactivateItem_s* e;
      for (e = x->PMDeactivateItem; e; e = (struct zx_pmm_PMDeactivateItem_s*)e->gg.g.n)
	  zx_DUP_STRS_pmm_PMDeactivateItem(c, e);
  }
  zx_dup_strs_simple_elems(c, x->NotifyTo);

}

/* FUNC(zx_DEEP_CLONE_pmm_PMDeactivate) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMDeactivate_s* zx_DEEP_CLONE_pmm_PMDeactivate(struct zx_ctx* c, struct zx_pmm_PMDeactivate_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMDeactivate_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMDeactivate_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMDeactivateItem_s* e;
      struct zx_pmm_PMDeactivateItem_s* en;
      struct zx_pmm_PMDeactivateItem_s* enn;
      for (enn = 0, e = x->PMDeactivateItem; e; e = (struct zx_pmm_PMDeactivateItem_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_pmm_PMDeactivateItem(c, e, dup_strs);
	  if (!enn)
	      x->PMDeactivateItem = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }
  x->NotifyTo = zx_deep_clone_simple_elems(c,x->NotifyTo, dup_strs);

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMDeactivate) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMDeactivate(struct zx_ctx* c, struct zx_pmm_PMDeactivate_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_pmm_PMDeactivateItem_s* e;
      for (e = x->PMDeactivateItem; e; e = (struct zx_pmm_PMDeactivateItem_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_pmm_PMDeactivateItem(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }
  ret = zx_walk_so_simple_elems(c, x->NotifyTo, ctx, callback);
  if (ret)
    return ret;

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMDeactivate) */

int zx_WALK_WO_pmm_PMDeactivate(struct zx_ctx* c, struct zx_pmm_PMDeactivate_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMDeactivateItem
#define EL_STRUCT zx_pmm_PMDeactivateItem_s
#define EL_NS     pmm
#define EL_TAG    PMDeactivateItem

/* FUNC(zx_FREE_pmm_PMDeactivateItem) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMDeactivateItem(struct zx_ctx* c, struct zx_pmm_PMDeactivateItem_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */

  zx_free_attr(c, x->at, free_strs);
  zx_free_attr(c, x->itemID, free_strs);

  {
      struct zx_prov_PMID_s* e;
      struct zx_prov_PMID_s* en;
      for (e = x->PMID; e; e = en) {
	  en = (struct zx_prov_PMID_s*)e->gg.g.n;
	  zx_FREE_prov_PMID(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMDeactivateItem) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMDeactivateItem_s* zx_NEW_pmm_PMDeactivateItem(struct zx_ctx* c)
{
  struct zx_pmm_PMDeactivateItem_s* x = ZX_ZALLOC(c, struct zx_pmm_PMDeactivateItem_s);
  x->gg.g.tok = zx_pmm_PMDeactivateItem_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMDeactivateItem) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMDeactivateItem(struct zx_ctx* c, struct zx_pmm_PMDeactivateItem_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */

  zx_dup_attr(c, x->at);
  zx_dup_attr(c, x->itemID);

  {
      struct zx_prov_PMID_s* e;
      for (e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n)
	  zx_DUP_STRS_prov_PMID(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMDeactivateItem) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMDeactivateItem_s* zx_DEEP_CLONE_pmm_PMDeactivateItem(struct zx_ctx* c, struct zx_pmm_PMDeactivateItem_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMDeactivateItem_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMDeactivateItem_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */

  x->at = zx_clone_attr(c, x->at);
  x->itemID = zx_clone_attr(c, x->itemID);

  {
      struct zx_prov_PMID_s* e;
      struct zx_prov_PMID_s* en;
      struct zx_prov_PMID_s* enn;
      for (enn = 0, e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_prov_PMID(c, e, dup_strs);
	  if (!enn)
	      x->PMID = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMDeactivateItem) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMDeactivateItem(struct zx_ctx* c, struct zx_pmm_PMDeactivateItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_prov_PMID_s* e;
      for (e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_prov_PMID(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMDeactivateItem) */

int zx_WALK_WO_pmm_PMDeactivateItem(struct zx_ctx* c, struct zx_pmm_PMDeactivateItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMDeactivateResponse
#define EL_STRUCT zx_pmm_PMDeactivateResponse_s
#define EL_NS     pmm
#define EL_TAG    PMDeactivateResponse

/* FUNC(zx_FREE_pmm_PMDeactivateResponse) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMDeactivateResponse(struct zx_ctx* c, struct zx_pmm_PMDeactivateResponse_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      for (e = x->Status; e; e = en) {
	  en = (struct zx_lu_Status_s*)e->gg.g.n;
	  zx_FREE_lu_Status(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMDeactivateResponse) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMDeactivateResponse_s* zx_NEW_pmm_PMDeactivateResponse(struct zx_ctx* c)
{
  struct zx_pmm_PMDeactivateResponse_s* x = ZX_ZALLOC(c, struct zx_pmm_PMDeactivateResponse_s);
  x->gg.g.tok = zx_pmm_PMDeactivateResponse_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMDeactivateResponse) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMDeactivateResponse(struct zx_ctx* c, struct zx_pmm_PMDeactivateResponse_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n)
	  zx_DUP_STRS_lu_Status(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMDeactivateResponse) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMDeactivateResponse_s* zx_DEEP_CLONE_pmm_PMDeactivateResponse(struct zx_ctx* c, struct zx_pmm_PMDeactivateResponse_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMDeactivateResponse_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMDeactivateResponse_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      struct zx_lu_Status_s* enn;
      for (enn = 0, e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_lu_Status(c, e, dup_strs);
	  if (!enn)
	      x->Status = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMDeactivateResponse) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMDeactivateResponse(struct zx_ctx* c, struct zx_pmm_PMDeactivateResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_lu_Status(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMDeactivateResponse) */

int zx_WALK_WO_pmm_PMDeactivateResponse(struct zx_ctx* c, struct zx_pmm_PMDeactivateResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMDelete
#define EL_STRUCT zx_pmm_PMDelete_s
#define EL_NS     pmm
#define EL_TAG    PMDelete

/* FUNC(zx_FREE_pmm_PMDelete) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMDelete(struct zx_ctx* c, struct zx_pmm_PMDelete_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMDeleteItem_s* e;
      struct zx_pmm_PMDeleteItem_s* en;
      for (e = x->PMDeleteItem; e; e = en) {
	  en = (struct zx_pmm_PMDeleteItem_s*)e->gg.g.n;
	  zx_FREE_pmm_PMDeleteItem(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMDelete) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMDelete_s* zx_NEW_pmm_PMDelete(struct zx_ctx* c)
{
  struct zx_pmm_PMDelete_s* x = ZX_ZALLOC(c, struct zx_pmm_PMDelete_s);
  x->gg.g.tok = zx_pmm_PMDelete_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMDelete) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMDelete(struct zx_ctx* c, struct zx_pmm_PMDelete_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMDeleteItem_s* e;
      for (e = x->PMDeleteItem; e; e = (struct zx_pmm_PMDeleteItem_s*)e->gg.g.n)
	  zx_DUP_STRS_pmm_PMDeleteItem(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMDelete) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMDelete_s* zx_DEEP_CLONE_pmm_PMDelete(struct zx_ctx* c, struct zx_pmm_PMDelete_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMDelete_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMDelete_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMDeleteItem_s* e;
      struct zx_pmm_PMDeleteItem_s* en;
      struct zx_pmm_PMDeleteItem_s* enn;
      for (enn = 0, e = x->PMDeleteItem; e; e = (struct zx_pmm_PMDeleteItem_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_pmm_PMDeleteItem(c, e, dup_strs);
	  if (!enn)
	      x->PMDeleteItem = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMDelete) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMDelete(struct zx_ctx* c, struct zx_pmm_PMDelete_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_pmm_PMDeleteItem_s* e;
      for (e = x->PMDeleteItem; e; e = (struct zx_pmm_PMDeleteItem_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_pmm_PMDeleteItem(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMDelete) */

int zx_WALK_WO_pmm_PMDelete(struct zx_ctx* c, struct zx_pmm_PMDelete_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMDeleteItem
#define EL_STRUCT zx_pmm_PMDeleteItem_s
#define EL_NS     pmm
#define EL_TAG    PMDeleteItem

/* FUNC(zx_FREE_pmm_PMDeleteItem) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMDeleteItem(struct zx_ctx* c, struct zx_pmm_PMDeleteItem_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */

  zx_free_attr(c, x->itemID, free_strs);

  {
      struct zx_prov_PMID_s* e;
      struct zx_prov_PMID_s* en;
      for (e = x->PMID; e; e = en) {
	  en = (struct zx_prov_PMID_s*)e->gg.g.n;
	  zx_FREE_prov_PMID(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMDeleteItem) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMDeleteItem_s* zx_NEW_pmm_PMDeleteItem(struct zx_ctx* c)
{
  struct zx_pmm_PMDeleteItem_s* x = ZX_ZALLOC(c, struct zx_pmm_PMDeleteItem_s);
  x->gg.g.tok = zx_pmm_PMDeleteItem_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMDeleteItem) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMDeleteItem(struct zx_ctx* c, struct zx_pmm_PMDeleteItem_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */

  zx_dup_attr(c, x->itemID);

  {
      struct zx_prov_PMID_s* e;
      for (e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n)
	  zx_DUP_STRS_prov_PMID(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMDeleteItem) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMDeleteItem_s* zx_DEEP_CLONE_pmm_PMDeleteItem(struct zx_ctx* c, struct zx_pmm_PMDeleteItem_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMDeleteItem_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMDeleteItem_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */

  x->itemID = zx_clone_attr(c, x->itemID);

  {
      struct zx_prov_PMID_s* e;
      struct zx_prov_PMID_s* en;
      struct zx_prov_PMID_s* enn;
      for (enn = 0, e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_prov_PMID(c, e, dup_strs);
	  if (!enn)
	      x->PMID = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMDeleteItem) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMDeleteItem(struct zx_ctx* c, struct zx_pmm_PMDeleteItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_prov_PMID_s* e;
      for (e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_prov_PMID(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMDeleteItem) */

int zx_WALK_WO_pmm_PMDeleteItem(struct zx_ctx* c, struct zx_pmm_PMDeleteItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMDeleteResponse
#define EL_STRUCT zx_pmm_PMDeleteResponse_s
#define EL_NS     pmm
#define EL_TAG    PMDeleteResponse

/* FUNC(zx_FREE_pmm_PMDeleteResponse) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMDeleteResponse(struct zx_ctx* c, struct zx_pmm_PMDeleteResponse_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      for (e = x->Status; e; e = en) {
	  en = (struct zx_lu_Status_s*)e->gg.g.n;
	  zx_FREE_lu_Status(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMDeleteResponse) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMDeleteResponse_s* zx_NEW_pmm_PMDeleteResponse(struct zx_ctx* c)
{
  struct zx_pmm_PMDeleteResponse_s* x = ZX_ZALLOC(c, struct zx_pmm_PMDeleteResponse_s);
  x->gg.g.tok = zx_pmm_PMDeleteResponse_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMDeleteResponse) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMDeleteResponse(struct zx_ctx* c, struct zx_pmm_PMDeleteResponse_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n)
	  zx_DUP_STRS_lu_Status(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMDeleteResponse) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMDeleteResponse_s* zx_DEEP_CLONE_pmm_PMDeleteResponse(struct zx_ctx* c, struct zx_pmm_PMDeleteResponse_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMDeleteResponse_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMDeleteResponse_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      struct zx_lu_Status_s* enn;
      for (enn = 0, e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_lu_Status(c, e, dup_strs);
	  if (!enn)
	      x->Status = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMDeleteResponse) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMDeleteResponse(struct zx_ctx* c, struct zx_pmm_PMDeleteResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_lu_Status(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMDeleteResponse) */

int zx_WALK_WO_pmm_PMDeleteResponse(struct zx_ctx* c, struct zx_pmm_PMDeleteResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMGetStatus
#define EL_STRUCT zx_pmm_PMGetStatus_s
#define EL_NS     pmm
#define EL_TAG    PMGetStatus

/* FUNC(zx_FREE_pmm_PMGetStatus) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMGetStatus(struct zx_ctx* c, struct zx_pmm_PMGetStatus_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_prov_PMID_s* e;
      struct zx_prov_PMID_s* en;
      for (e = x->PMID; e; e = en) {
	  en = (struct zx_prov_PMID_s*)e->gg.g.n;
	  zx_FREE_prov_PMID(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMGetStatus) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMGetStatus_s* zx_NEW_pmm_PMGetStatus(struct zx_ctx* c)
{
  struct zx_pmm_PMGetStatus_s* x = ZX_ZALLOC(c, struct zx_pmm_PMGetStatus_s);
  x->gg.g.tok = zx_pmm_PMGetStatus_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMGetStatus) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMGetStatus(struct zx_ctx* c, struct zx_pmm_PMGetStatus_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_prov_PMID_s* e;
      for (e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n)
	  zx_DUP_STRS_prov_PMID(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMGetStatus) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMGetStatus_s* zx_DEEP_CLONE_pmm_PMGetStatus(struct zx_ctx* c, struct zx_pmm_PMGetStatus_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMGetStatus_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMGetStatus_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_prov_PMID_s* e;
      struct zx_prov_PMID_s* en;
      struct zx_prov_PMID_s* enn;
      for (enn = 0, e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_prov_PMID(c, e, dup_strs);
	  if (!enn)
	      x->PMID = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMGetStatus) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMGetStatus(struct zx_ctx* c, struct zx_pmm_PMGetStatus_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_prov_PMID_s* e;
      for (e = x->PMID; e; e = (struct zx_prov_PMID_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_prov_PMID(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMGetStatus) */

int zx_WALK_WO_pmm_PMGetStatus(struct zx_ctx* c, struct zx_pmm_PMGetStatus_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMGetStatusResponse
#define EL_STRUCT zx_pmm_PMGetStatusResponse_s
#define EL_NS     pmm
#define EL_TAG    PMGetStatusResponse

/* FUNC(zx_FREE_pmm_PMGetStatusResponse) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMGetStatusResponse(struct zx_ctx* c, struct zx_pmm_PMGetStatusResponse_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      for (e = x->Status; e; e = en) {
	  en = (struct zx_lu_Status_s*)e->gg.g.n;
	  zx_FREE_lu_Status(c, e, free_strs);
      }
  }
  {
      struct zx_prov_PMStatus_s* e;
      struct zx_prov_PMStatus_s* en;
      for (e = x->PMStatus; e; e = en) {
	  en = (struct zx_prov_PMStatus_s*)e->gg.g.n;
	  zx_FREE_prov_PMStatus(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMGetStatusResponse) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMGetStatusResponse_s* zx_NEW_pmm_PMGetStatusResponse(struct zx_ctx* c)
{
  struct zx_pmm_PMGetStatusResponse_s* x = ZX_ZALLOC(c, struct zx_pmm_PMGetStatusResponse_s);
  x->gg.g.tok = zx_pmm_PMGetStatusResponse_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMGetStatusResponse) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMGetStatusResponse(struct zx_ctx* c, struct zx_pmm_PMGetStatusResponse_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n)
	  zx_DUP_STRS_lu_Status(c, e);
  }
  {
      struct zx_prov_PMStatus_s* e;
      for (e = x->PMStatus; e; e = (struct zx_prov_PMStatus_s*)e->gg.g.n)
	  zx_DUP_STRS_prov_PMStatus(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMGetStatusResponse) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMGetStatusResponse_s* zx_DEEP_CLONE_pmm_PMGetStatusResponse(struct zx_ctx* c, struct zx_pmm_PMGetStatusResponse_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMGetStatusResponse_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMGetStatusResponse_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      struct zx_lu_Status_s* enn;
      for (enn = 0, e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_lu_Status(c, e, dup_strs);
	  if (!enn)
	      x->Status = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }
  {
      struct zx_prov_PMStatus_s* e;
      struct zx_prov_PMStatus_s* en;
      struct zx_prov_PMStatus_s* enn;
      for (enn = 0, e = x->PMStatus; e; e = (struct zx_prov_PMStatus_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_prov_PMStatus(c, e, dup_strs);
	  if (!enn)
	      x->PMStatus = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMGetStatusResponse) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMGetStatusResponse(struct zx_ctx* c, struct zx_pmm_PMGetStatusResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_lu_Status(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }
  {
      struct zx_prov_PMStatus_s* e;
      for (e = x->PMStatus; e; e = (struct zx_prov_PMStatus_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_prov_PMStatus(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMGetStatusResponse) */

int zx_WALK_WO_pmm_PMGetStatusResponse(struct zx_ctx* c, struct zx_pmm_PMGetStatusResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMSetStatus
#define EL_STRUCT zx_pmm_PMSetStatus_s
#define EL_NS     pmm
#define EL_TAG    PMSetStatus

/* FUNC(zx_FREE_pmm_PMSetStatus) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMSetStatus(struct zx_ctx* c, struct zx_pmm_PMSetStatus_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_prov_PMStatus_s* e;
      struct zx_prov_PMStatus_s* en;
      for (e = x->PMStatus; e; e = en) {
	  en = (struct zx_prov_PMStatus_s*)e->gg.g.n;
	  zx_FREE_prov_PMStatus(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMSetStatus) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMSetStatus_s* zx_NEW_pmm_PMSetStatus(struct zx_ctx* c)
{
  struct zx_pmm_PMSetStatus_s* x = ZX_ZALLOC(c, struct zx_pmm_PMSetStatus_s);
  x->gg.g.tok = zx_pmm_PMSetStatus_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMSetStatus) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMSetStatus(struct zx_ctx* c, struct zx_pmm_PMSetStatus_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_prov_PMStatus_s* e;
      for (e = x->PMStatus; e; e = (struct zx_prov_PMStatus_s*)e->gg.g.n)
	  zx_DUP_STRS_prov_PMStatus(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMSetStatus) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMSetStatus_s* zx_DEEP_CLONE_pmm_PMSetStatus(struct zx_ctx* c, struct zx_pmm_PMSetStatus_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMSetStatus_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMSetStatus_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_prov_PMStatus_s* e;
      struct zx_prov_PMStatus_s* en;
      struct zx_prov_PMStatus_s* enn;
      for (enn = 0, e = x->PMStatus; e; e = (struct zx_prov_PMStatus_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_prov_PMStatus(c, e, dup_strs);
	  if (!enn)
	      x->PMStatus = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMSetStatus) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMSetStatus(struct zx_ctx* c, struct zx_pmm_PMSetStatus_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_prov_PMStatus_s* e;
      for (e = x->PMStatus; e; e = (struct zx_prov_PMStatus_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_prov_PMStatus(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMSetStatus) */

int zx_WALK_WO_pmm_PMSetStatus(struct zx_ctx* c, struct zx_pmm_PMSetStatus_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMSetStatusResponse
#define EL_STRUCT zx_pmm_PMSetStatusResponse_s
#define EL_NS     pmm
#define EL_TAG    PMSetStatusResponse

/* FUNC(zx_FREE_pmm_PMSetStatusResponse) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMSetStatusResponse(struct zx_ctx* c, struct zx_pmm_PMSetStatusResponse_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      for (e = x->Status; e; e = en) {
	  en = (struct zx_lu_Status_s*)e->gg.g.n;
	  zx_FREE_lu_Status(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMSetStatusResponse) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMSetStatusResponse_s* zx_NEW_pmm_PMSetStatusResponse(struct zx_ctx* c)
{
  struct zx_pmm_PMSetStatusResponse_s* x = ZX_ZALLOC(c, struct zx_pmm_PMSetStatusResponse_s);
  x->gg.g.tok = zx_pmm_PMSetStatusResponse_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMSetStatusResponse) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMSetStatusResponse(struct zx_ctx* c, struct zx_pmm_PMSetStatusResponse_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n)
	  zx_DUP_STRS_lu_Status(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMSetStatusResponse) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMSetStatusResponse_s* zx_DEEP_CLONE_pmm_PMSetStatusResponse(struct zx_ctx* c, struct zx_pmm_PMSetStatusResponse_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMSetStatusResponse_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMSetStatusResponse_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      struct zx_lu_Status_s* enn;
      for (enn = 0, e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_lu_Status(c, e, dup_strs);
	  if (!enn)
	      x->Status = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMSetStatusResponse) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMSetStatusResponse(struct zx_ctx* c, struct zx_pmm_PMSetStatusResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_lu_Status(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMSetStatusResponse) */

int zx_WALK_WO_pmm_PMSetStatusResponse(struct zx_ctx* c, struct zx_pmm_PMSetStatusResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMUpdate
#define EL_STRUCT zx_pmm_PMUpdate_s
#define EL_NS     pmm
#define EL_TAG    PMUpdate

/* FUNC(zx_FREE_pmm_PMUpdate) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMUpdate(struct zx_ctx* c, struct zx_pmm_PMUpdate_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMUpdateItem_s* e;
      struct zx_pmm_PMUpdateItem_s* en;
      for (e = x->PMUpdateItem; e; e = en) {
	  en = (struct zx_pmm_PMUpdateItem_s*)e->gg.g.n;
	  zx_FREE_pmm_PMUpdateItem(c, e, free_strs);
      }
  }
  zx_free_simple_elems(c, x->NotifyTo, free_strs);


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMUpdate) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMUpdate_s* zx_NEW_pmm_PMUpdate(struct zx_ctx* c)
{
  struct zx_pmm_PMUpdate_s* x = ZX_ZALLOC(c, struct zx_pmm_PMUpdate_s);
  x->gg.g.tok = zx_pmm_PMUpdate_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMUpdate) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMUpdate(struct zx_ctx* c, struct zx_pmm_PMUpdate_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMUpdateItem_s* e;
      for (e = x->PMUpdateItem; e; e = (struct zx_pmm_PMUpdateItem_s*)e->gg.g.n)
	  zx_DUP_STRS_pmm_PMUpdateItem(c, e);
  }
  zx_dup_strs_simple_elems(c, x->NotifyTo);

}

/* FUNC(zx_DEEP_CLONE_pmm_PMUpdate) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMUpdate_s* zx_DEEP_CLONE_pmm_PMUpdate(struct zx_ctx* c, struct zx_pmm_PMUpdate_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMUpdate_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMUpdate_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_pmm_PMUpdateItem_s* e;
      struct zx_pmm_PMUpdateItem_s* en;
      struct zx_pmm_PMUpdateItem_s* enn;
      for (enn = 0, e = x->PMUpdateItem; e; e = (struct zx_pmm_PMUpdateItem_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_pmm_PMUpdateItem(c, e, dup_strs);
	  if (!enn)
	      x->PMUpdateItem = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }
  x->NotifyTo = zx_deep_clone_simple_elems(c,x->NotifyTo, dup_strs);

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMUpdate) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMUpdate(struct zx_ctx* c, struct zx_pmm_PMUpdate_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_pmm_PMUpdateItem_s* e;
      for (e = x->PMUpdateItem; e; e = (struct zx_pmm_PMUpdateItem_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_pmm_PMUpdateItem(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }
  ret = zx_walk_so_simple_elems(c, x->NotifyTo, ctx, callback);
  if (ret)
    return ret;

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMUpdate) */

int zx_WALK_WO_pmm_PMUpdate(struct zx_ctx* c, struct zx_pmm_PMUpdate_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMUpdateItem
#define EL_STRUCT zx_pmm_PMUpdateItem_s
#define EL_NS     pmm
#define EL_TAG    PMUpdateItem

/* FUNC(zx_FREE_pmm_PMUpdateItem) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMUpdateItem(struct zx_ctx* c, struct zx_pmm_PMUpdateItem_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */

  zx_free_attr(c, x->at, free_strs);
  zx_free_attr(c, x->itemID, free_strs);
  zx_free_attr(c, x->type, free_strs);

  {
      struct zx_prov_PMDescriptor_s* e;
      struct zx_prov_PMDescriptor_s* en;
      for (e = x->PMDescriptor; e; e = en) {
	  en = (struct zx_prov_PMDescriptor_s*)e->gg.g.n;
	  zx_FREE_prov_PMDescriptor(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMUpdateItem) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMUpdateItem_s* zx_NEW_pmm_PMUpdateItem(struct zx_ctx* c)
{
  struct zx_pmm_PMUpdateItem_s* x = ZX_ZALLOC(c, struct zx_pmm_PMUpdateItem_s);
  x->gg.g.tok = zx_pmm_PMUpdateItem_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMUpdateItem) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMUpdateItem(struct zx_ctx* c, struct zx_pmm_PMUpdateItem_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */

  zx_dup_attr(c, x->at);
  zx_dup_attr(c, x->itemID);
  zx_dup_attr(c, x->type);

  {
      struct zx_prov_PMDescriptor_s* e;
      for (e = x->PMDescriptor; e; e = (struct zx_prov_PMDescriptor_s*)e->gg.g.n)
	  zx_DUP_STRS_prov_PMDescriptor(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMUpdateItem) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMUpdateItem_s* zx_DEEP_CLONE_pmm_PMUpdateItem(struct zx_ctx* c, struct zx_pmm_PMUpdateItem_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMUpdateItem_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMUpdateItem_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */

  x->at = zx_clone_attr(c, x->at);
  x->itemID = zx_clone_attr(c, x->itemID);
  x->type = zx_clone_attr(c, x->type);

  {
      struct zx_prov_PMDescriptor_s* e;
      struct zx_prov_PMDescriptor_s* en;
      struct zx_prov_PMDescriptor_s* enn;
      for (enn = 0, e = x->PMDescriptor; e; e = (struct zx_prov_PMDescriptor_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_prov_PMDescriptor(c, e, dup_strs);
	  if (!enn)
	      x->PMDescriptor = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMUpdateItem) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMUpdateItem(struct zx_ctx* c, struct zx_pmm_PMUpdateItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_prov_PMDescriptor_s* e;
      for (e = x->PMDescriptor; e; e = (struct zx_prov_PMDescriptor_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_prov_PMDescriptor(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMUpdateItem) */

int zx_WALK_WO_pmm_PMUpdateItem(struct zx_ctx* c, struct zx_pmm_PMUpdateItem_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_PMUpdateResponse
#define EL_STRUCT zx_pmm_PMUpdateResponse_s
#define EL_NS     pmm
#define EL_TAG    PMUpdateResponse

/* FUNC(zx_FREE_pmm_PMUpdateResponse) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_PMUpdateResponse(struct zx_ctx* c, struct zx_pmm_PMUpdateResponse_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      for (e = x->Status; e; e = en) {
	  en = (struct zx_lu_Status_s*)e->gg.g.n;
	  zx_FREE_lu_Status(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_PMUpdateResponse) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_PMUpdateResponse_s* zx_NEW_pmm_PMUpdateResponse(struct zx_ctx* c)
{
  struct zx_pmm_PMUpdateResponse_s* x = ZX_ZALLOC(c, struct zx_pmm_PMUpdateResponse_s);
  x->gg.g.tok = zx_pmm_PMUpdateResponse_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_PMUpdateResponse) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_PMUpdateResponse(struct zx_ctx* c, struct zx_pmm_PMUpdateResponse_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n)
	  zx_DUP_STRS_lu_Status(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_PMUpdateResponse) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_PMUpdateResponse_s* zx_DEEP_CLONE_pmm_PMUpdateResponse(struct zx_ctx* c, struct zx_pmm_PMUpdateResponse_s* x, int dup_strs)
{
  x = (struct zx_pmm_PMUpdateResponse_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_PMUpdateResponse_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      struct zx_lu_Status_s* enn;
      for (enn = 0, e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_lu_Status(c, e, dup_strs);
	  if (!enn)
	      x->Status = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_PMUpdateResponse) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_PMUpdateResponse(struct zx_ctx* c, struct zx_pmm_PMUpdateResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_lu_Status(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_PMUpdateResponse) */

int zx_WALK_WO_pmm_PMUpdateResponse(struct zx_ctx* c, struct zx_pmm_PMUpdateResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_Provision
#define EL_STRUCT zx_pmm_Provision_s
#define EL_NS     pmm
#define EL_TAG    Provision

/* FUNC(zx_FREE_pmm_Provision) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_Provision(struct zx_ctx* c, struct zx_pmm_Provision_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */

  zx_free_attr(c, x->wait, free_strs);

  {
      struct zx_prov_ProvisioningHandle_s* e;
      struct zx_prov_ProvisioningHandle_s* en;
      for (e = x->ProvisioningHandle; e; e = en) {
	  en = (struct zx_prov_ProvisioningHandle_s*)e->gg.g.n;
	  zx_FREE_prov_ProvisioningHandle(c, e, free_strs);
      }
  }
  {
      struct zx_prov_PMDescriptor_s* e;
      struct zx_prov_PMDescriptor_s* en;
      for (e = x->PMDescriptor; e; e = en) {
	  en = (struct zx_prov_PMDescriptor_s*)e->gg.g.n;
	  zx_FREE_prov_PMDescriptor(c, e, free_strs);
      }
  }
  zx_free_simple_elems(c, x->NotifyTo, free_strs);


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_Provision) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_Provision_s* zx_NEW_pmm_Provision(struct zx_ctx* c)
{
  struct zx_pmm_Provision_s* x = ZX_ZALLOC(c, struct zx_pmm_Provision_s);
  x->gg.g.tok = zx_pmm_Provision_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_Provision) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_Provision(struct zx_ctx* c, struct zx_pmm_Provision_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */

  zx_dup_attr(c, x->wait);

  {
      struct zx_prov_ProvisioningHandle_s* e;
      for (e = x->ProvisioningHandle; e; e = (struct zx_prov_ProvisioningHandle_s*)e->gg.g.n)
	  zx_DUP_STRS_prov_ProvisioningHandle(c, e);
  }
  {
      struct zx_prov_PMDescriptor_s* e;
      for (e = x->PMDescriptor; e; e = (struct zx_prov_PMDescriptor_s*)e->gg.g.n)
	  zx_DUP_STRS_prov_PMDescriptor(c, e);
  }
  zx_dup_strs_simple_elems(c, x->NotifyTo);

}

/* FUNC(zx_DEEP_CLONE_pmm_Provision) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_Provision_s* zx_DEEP_CLONE_pmm_Provision(struct zx_ctx* c, struct zx_pmm_Provision_s* x, int dup_strs)
{
  x = (struct zx_pmm_Provision_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_Provision_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */

  x->wait = zx_clone_attr(c, x->wait);

  {
      struct zx_prov_ProvisioningHandle_s* e;
      struct zx_prov_ProvisioningHandle_s* en;
      struct zx_prov_ProvisioningHandle_s* enn;
      for (enn = 0, e = x->ProvisioningHandle; e; e = (struct zx_prov_ProvisioningHandle_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_prov_ProvisioningHandle(c, e, dup_strs);
	  if (!enn)
	      x->ProvisioningHandle = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }
  {
      struct zx_prov_PMDescriptor_s* e;
      struct zx_prov_PMDescriptor_s* en;
      struct zx_prov_PMDescriptor_s* enn;
      for (enn = 0, e = x->PMDescriptor; e; e = (struct zx_prov_PMDescriptor_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_prov_PMDescriptor(c, e, dup_strs);
	  if (!enn)
	      x->PMDescriptor = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }
  x->NotifyTo = zx_deep_clone_simple_elems(c,x->NotifyTo, dup_strs);

  return x;
}

/* FUNC(zx_WALK_SO_pmm_Provision) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_Provision(struct zx_ctx* c, struct zx_pmm_Provision_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_prov_ProvisioningHandle_s* e;
      for (e = x->ProvisioningHandle; e; e = (struct zx_prov_ProvisioningHandle_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_prov_ProvisioningHandle(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }
  {
      struct zx_prov_PMDescriptor_s* e;
      for (e = x->PMDescriptor; e; e = (struct zx_prov_PMDescriptor_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_prov_PMDescriptor(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }
  ret = zx_walk_so_simple_elems(c, x->NotifyTo, ctx, callback);
  if (ret)
    return ret;

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_Provision) */

int zx_WALK_WO_pmm_Provision(struct zx_ctx* c, struct zx_pmm_Provision_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif




#ifdef EL_NAME
#undef EL_NAME
#endif
#ifdef EL_STRUCT
#undef EL_STRUCT
#endif
#ifdef EL_NS
#undef EL_NS
#endif
#ifdef EL_TAG
#undef EL_TAG
#endif

#define EL_NAME   pmm_ProvisionResponse
#define EL_STRUCT zx_pmm_ProvisionResponse_s
#define EL_NS     pmm
#define EL_TAG    ProvisionResponse

/* FUNC(zx_FREE_pmm_ProvisionResponse) */

/* Depth first traversal of data structure to free it and its subelements. Simple
 * strings are handled as a special case according to the free_strs flag. This
 * is useful if the strings point to underlying data from the wire that was
 * allocated differently. */

/* Called by: */
void zx_FREE_pmm_ProvisionResponse(struct zx_ctx* c, struct zx_pmm_ProvisionResponse_s* x, int free_strs)
{
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      for (e = x->Status; e; e = en) {
	  en = (struct zx_lu_Status_s*)e->gg.g.n;
	  zx_FREE_lu_Status(c, e, free_strs);
      }
  }


  zx_free_elem_common(c, &x->gg, free_strs); 
}

/* FUNC(zx_NEW_pmm_ProvisionResponse) */

/* Trivial allocator/constructor for the datatype. */

/* Called by: */
struct zx_pmm_ProvisionResponse_s* zx_NEW_pmm_ProvisionResponse(struct zx_ctx* c)
{
  struct zx_pmm_ProvisionResponse_s* x = ZX_ZALLOC(c, struct zx_pmm_ProvisionResponse_s);
  x->gg.g.tok = zx_pmm_ProvisionResponse_ELEM;
  return x;
}

#ifdef ZX_ENA_AUX

/* FUNC(zx_DUP_STRS_pmm_ProvisionResponse) */

/* Depth first traversal of data structure to copy its simple strings
 * to memory allocated from the memory allocator. The decoder will
 * use the underlying wireprotocol PDU buffer for strings, i.e.
 * strings are not copied - they point to the real data. If the
 * datastructure needs to outlast the protocol data or needs a different
 * memory allocation strategy, you need to call this function.  */

/* Called by: */
void zx_DUP_STRS_pmm_ProvisionResponse(struct zx_ctx* c, struct zx_pmm_ProvisionResponse_s* x)
{
  zx_dup_strs_common(c, &x->gg);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n)
	  zx_DUP_STRS_lu_Status(c, e);
  }

}

/* FUNC(zx_DEEP_CLONE_pmm_ProvisionResponse) */

/* Depth first traversal of data structure to clone it and its sublements.
 * The simple strings are handled as a special case according to dup_strs flag. */

/* Called by: */
struct zx_pmm_ProvisionResponse_s* zx_DEEP_CLONE_pmm_ProvisionResponse(struct zx_ctx* c, struct zx_pmm_ProvisionResponse_s* x, int dup_strs)
{
  x = (struct zx_pmm_ProvisionResponse_s*)zx_clone_elem_common(c, &x->gg, sizeof(struct zx_pmm_ProvisionResponse_s), dup_strs);
  /* *** deal with xmlns specifications in exc c14n way */


  {
      struct zx_lu_Status_s* e;
      struct zx_lu_Status_s* en;
      struct zx_lu_Status_s* enn;
      for (enn = 0, e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  en = zx_DEEP_CLONE_lu_Status(c, e, dup_strs);
	  if (!enn)
	      x->Status = en;
	  else
	      enn->gg.g.n = &en->gg.g;
	  enn = en;
      }
  }

  return x;
}

/* FUNC(zx_WALK_SO_pmm_ProvisionResponse) */

/* Depth first traversal of the tree in either schema order or the wire order. */
 
int zx_WALK_SO_pmm_ProvisionResponse(struct zx_ctx* c, struct zx_pmm_ProvisionResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  int ret = callback(&x->gg.g, ctx);
  if (ret)
    return ret;
  
  /* *** deal with xmlns specifications in exc c14n way */


  
  ret = zx_walk_so_unknown_attributes(c, &x->gg, ctx, callback); 
  if (ret)
    return ret;

  {
      struct zx_lu_Status_s* e;
      for (e = x->Status; e; e = (struct zx_lu_Status_s*)e->gg.g.n) {
	  ret = zx_WALK_SO_lu_Status(c, e, ctx, callback);
	  if (ret)
	      return ret;
      }
  }

  
  return zx_walk_so_unknown_elems_and_content(c, &x->gg, ctx, callback);
}

/* FUNC(zx_WALK_WO_pmm_ProvisionResponse) */

int zx_WALK_WO_pmm_ProvisionResponse(struct zx_ctx* c, struct zx_pmm_ProvisionResponse_s* x, void* ctx, int (*callback)(struct zx_node_s* node, void* ctx))
{
  ERR("*** walk_wo not implemented %d", 0);
  return 0;
}

#endif


/* EOF -- c/zx-pmm-aux.c */
