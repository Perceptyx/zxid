/* c/zx-ff12-getput.c - WARNING: This file was automatically generated. DO NOT EDIT!
 * $Id$ */
/* Code generation design Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for terms and conditions
 * of use. Some aspects of code generation were driven by schema
 * descriptions that were used as input and may be subject to their own copyright.
 * Code generation uses a template, whose copyright statement follows. */

/** getput-templ.c  -  Auxiliary functions template: cloning, freeing, walking data
 ** Copyright (c) 2006 Symlabs (symlabs@symlabs.com), All Rights Reserved.
 ** Author: Sampo Kellomaki (sampo@iki.fi)
 ** This is confidential unpublished proprietary source code of the author.
 ** NO WARRANTY, not even implied warranties. Contains trade secrets.
 ** Distribution prohibited unless authorized in writing.
 ** Licensed under Apache License 2.0, see file COPYING.
 ** Id: getput-templ.c,v 1.8 2009-08-30 15:09:26 sampo Exp $
 **
 ** 30.5.2006, created, Sampo Kellomaki (sampo@iki.fi)
 ** 6.8.2006, factored from enc-templ.c to separate file --Sampo
 **
 ** N.B: wo=wire order (needed for exc-c14n), so=schema order
 ** Edit with care! xsd2sg.pl applies various substitutions to this file.
 **/

#include <memory.h>
#include "errmac.h"
#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"
#include "c/zx-ff12-data.h"



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_Conditions) */

int zx_ff12_Assertion_NUM_Conditions(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_Conditions_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Conditions; y; ++n, y = (struct zx_sa11_Conditions_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_Conditions) */

struct zx_sa11_Conditions_s* zx_ff12_Assertion_GET_Conditions(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_Conditions_s* y;
  if (!x) return 0;
  for (y = x->Conditions; n>=0 && y; --n, y = (struct zx_sa11_Conditions_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_Conditions) */

struct zx_sa11_Conditions_s* zx_ff12_Assertion_POP_Conditions(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_Conditions_s* y;
  if (!x) return 0;
  y = x->Conditions;
  if (y)
    x->Conditions = (struct zx_sa11_Conditions_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_Conditions) */

void zx_ff12_Assertion_PUSH_Conditions(struct zx_ff12_Assertion_s* x, struct zx_sa11_Conditions_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Conditions->gg.g;
  x->Conditions = z;
}

/* FUNC(zx_ff12_Assertion_REV_Conditions) */

void zx_ff12_Assertion_REV_Conditions(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_Conditions_s* nxt;
  struct zx_sa11_Conditions_s* y;
  if (!x) return;
  y = x->Conditions;
  if (!y) return;
  x->Conditions = 0;
  while (y) {
    nxt = (struct zx_sa11_Conditions_s*)y->gg.g.n;
    y->gg.g.n = &x->Conditions->gg.g;
    x->Conditions = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_Conditions) */

void zx_ff12_Assertion_PUT_Conditions(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_Conditions_s* z)
{
  struct zx_sa11_Conditions_s* y;
  if (!x || !z) return;
  y = x->Conditions;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Conditions = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_Conditions_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_Conditions) */

void zx_ff12_Assertion_ADD_Conditions(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_Conditions_s* z)
{
  struct zx_sa11_Conditions_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Conditions->gg.g;
    x->Conditions = z;
    return;
  case -1:
    y = x->Conditions;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_Conditions_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Conditions; n > 1 && y; --n, y = (struct zx_sa11_Conditions_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Assertion_DEL_Conditions) */

void zx_ff12_Assertion_DEL_Conditions(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_Conditions_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Conditions = (struct zx_sa11_Conditions_s*)x->Conditions->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_Conditions_s*)x->Conditions;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_Conditions_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Conditions; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_Conditions_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_Advice) */

int zx_ff12_Assertion_NUM_Advice(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_Advice_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Advice; y; ++n, y = (struct zx_sa11_Advice_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_Advice) */

struct zx_sa11_Advice_s* zx_ff12_Assertion_GET_Advice(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_Advice_s* y;
  if (!x) return 0;
  for (y = x->Advice; n>=0 && y; --n, y = (struct zx_sa11_Advice_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_Advice) */

struct zx_sa11_Advice_s* zx_ff12_Assertion_POP_Advice(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_Advice_s* y;
  if (!x) return 0;
  y = x->Advice;
  if (y)
    x->Advice = (struct zx_sa11_Advice_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_Advice) */

void zx_ff12_Assertion_PUSH_Advice(struct zx_ff12_Assertion_s* x, struct zx_sa11_Advice_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Advice->gg.g;
  x->Advice = z;
}

/* FUNC(zx_ff12_Assertion_REV_Advice) */

void zx_ff12_Assertion_REV_Advice(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_Advice_s* nxt;
  struct zx_sa11_Advice_s* y;
  if (!x) return;
  y = x->Advice;
  if (!y) return;
  x->Advice = 0;
  while (y) {
    nxt = (struct zx_sa11_Advice_s*)y->gg.g.n;
    y->gg.g.n = &x->Advice->gg.g;
    x->Advice = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_Advice) */

void zx_ff12_Assertion_PUT_Advice(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_Advice_s* z)
{
  struct zx_sa11_Advice_s* y;
  if (!x || !z) return;
  y = x->Advice;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Advice = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_Advice_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_Advice) */

void zx_ff12_Assertion_ADD_Advice(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_Advice_s* z)
{
  struct zx_sa11_Advice_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Advice->gg.g;
    x->Advice = z;
    return;
  case -1:
    y = x->Advice;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_Advice_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Advice; n > 1 && y; --n, y = (struct zx_sa11_Advice_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Assertion_DEL_Advice) */

void zx_ff12_Assertion_DEL_Advice(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_Advice_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Advice = (struct zx_sa11_Advice_s*)x->Advice->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_Advice_s*)x->Advice;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_Advice_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Advice; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_Advice_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_Statement) */

int zx_ff12_Assertion_NUM_Statement(struct zx_ff12_Assertion_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Statement; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_Statement) */

struct zx_elem_s* zx_ff12_Assertion_GET_Statement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->Statement; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_Statement) */

struct zx_elem_s* zx_ff12_Assertion_POP_Statement(struct zx_ff12_Assertion_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->Statement;
  if (y)
    x->Statement = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_Statement) */

void zx_ff12_Assertion_PUSH_Statement(struct zx_ff12_Assertion_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->Statement->g;
  x->Statement = z;
}

/* FUNC(zx_ff12_Assertion_REV_Statement) */

void zx_ff12_Assertion_REV_Statement(struct zx_ff12_Assertion_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->Statement;
  if (!y) return;
  x->Statement = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->Statement->g;
    x->Statement = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_Statement) */

void zx_ff12_Assertion_PUT_Statement(struct zx_ff12_Assertion_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->Statement;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->Statement = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_Statement) */

void zx_ff12_Assertion_ADD_Statement(struct zx_ff12_Assertion_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->Statement->g;
    x->Statement = z;
    return;
  case -1:
    y = x->Statement;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->Statement; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_Assertion_DEL_Statement) */

void zx_ff12_Assertion_DEL_Statement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Statement = (struct zx_elem_s*)x->Statement->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->Statement;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->Statement; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_SubjectStatement) */

int zx_ff12_Assertion_NUM_SubjectStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_SubjectStatement_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->SubjectStatement; y; ++n, y = (struct zx_sa11_SubjectStatement_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_SubjectStatement) */

struct zx_sa11_SubjectStatement_s* zx_ff12_Assertion_GET_SubjectStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_SubjectStatement_s* y;
  if (!x) return 0;
  for (y = x->SubjectStatement; n>=0 && y; --n, y = (struct zx_sa11_SubjectStatement_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_SubjectStatement) */

struct zx_sa11_SubjectStatement_s* zx_ff12_Assertion_POP_SubjectStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_SubjectStatement_s* y;
  if (!x) return 0;
  y = x->SubjectStatement;
  if (y)
    x->SubjectStatement = (struct zx_sa11_SubjectStatement_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_SubjectStatement) */

void zx_ff12_Assertion_PUSH_SubjectStatement(struct zx_ff12_Assertion_s* x, struct zx_sa11_SubjectStatement_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->SubjectStatement->gg.g;
  x->SubjectStatement = z;
}

/* FUNC(zx_ff12_Assertion_REV_SubjectStatement) */

void zx_ff12_Assertion_REV_SubjectStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_SubjectStatement_s* nxt;
  struct zx_sa11_SubjectStatement_s* y;
  if (!x) return;
  y = x->SubjectStatement;
  if (!y) return;
  x->SubjectStatement = 0;
  while (y) {
    nxt = (struct zx_sa11_SubjectStatement_s*)y->gg.g.n;
    y->gg.g.n = &x->SubjectStatement->gg.g;
    x->SubjectStatement = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_SubjectStatement) */

void zx_ff12_Assertion_PUT_SubjectStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_SubjectStatement_s* z)
{
  struct zx_sa11_SubjectStatement_s* y;
  if (!x || !z) return;
  y = x->SubjectStatement;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->SubjectStatement = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_SubjectStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_SubjectStatement) */

void zx_ff12_Assertion_ADD_SubjectStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_SubjectStatement_s* z)
{
  struct zx_sa11_SubjectStatement_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->SubjectStatement->gg.g;
    x->SubjectStatement = z;
    return;
  case -1:
    y = x->SubjectStatement;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_SubjectStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->SubjectStatement; n > 1 && y; --n, y = (struct zx_sa11_SubjectStatement_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Assertion_DEL_SubjectStatement) */

void zx_ff12_Assertion_DEL_SubjectStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_SubjectStatement_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->SubjectStatement = (struct zx_sa11_SubjectStatement_s*)x->SubjectStatement->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_SubjectStatement_s*)x->SubjectStatement;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_SubjectStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->SubjectStatement; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_SubjectStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_AuthenticationStatement) */

int zx_ff12_Assertion_NUM_AuthenticationStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_AuthenticationStatement_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthenticationStatement; y; ++n, y = (struct zx_sa11_AuthenticationStatement_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_AuthenticationStatement) */

struct zx_sa11_AuthenticationStatement_s* zx_ff12_Assertion_GET_AuthenticationStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_AuthenticationStatement_s* y;
  if (!x) return 0;
  for (y = x->AuthenticationStatement; n>=0 && y; --n, y = (struct zx_sa11_AuthenticationStatement_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_AuthenticationStatement) */

struct zx_sa11_AuthenticationStatement_s* zx_ff12_Assertion_POP_AuthenticationStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_AuthenticationStatement_s* y;
  if (!x) return 0;
  y = x->AuthenticationStatement;
  if (y)
    x->AuthenticationStatement = (struct zx_sa11_AuthenticationStatement_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_AuthenticationStatement) */

void zx_ff12_Assertion_PUSH_AuthenticationStatement(struct zx_ff12_Assertion_s* x, struct zx_sa11_AuthenticationStatement_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->AuthenticationStatement->gg.g;
  x->AuthenticationStatement = z;
}

/* FUNC(zx_ff12_Assertion_REV_AuthenticationStatement) */

void zx_ff12_Assertion_REV_AuthenticationStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_AuthenticationStatement_s* nxt;
  struct zx_sa11_AuthenticationStatement_s* y;
  if (!x) return;
  y = x->AuthenticationStatement;
  if (!y) return;
  x->AuthenticationStatement = 0;
  while (y) {
    nxt = (struct zx_sa11_AuthenticationStatement_s*)y->gg.g.n;
    y->gg.g.n = &x->AuthenticationStatement->gg.g;
    x->AuthenticationStatement = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_AuthenticationStatement) */

void zx_ff12_Assertion_PUT_AuthenticationStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_AuthenticationStatement_s* z)
{
  struct zx_sa11_AuthenticationStatement_s* y;
  if (!x || !z) return;
  y = x->AuthenticationStatement;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->AuthenticationStatement = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_AuthenticationStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_AuthenticationStatement) */

void zx_ff12_Assertion_ADD_AuthenticationStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_AuthenticationStatement_s* z)
{
  struct zx_sa11_AuthenticationStatement_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->AuthenticationStatement->gg.g;
    x->AuthenticationStatement = z;
    return;
  case -1:
    y = x->AuthenticationStatement;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_AuthenticationStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthenticationStatement; n > 1 && y; --n, y = (struct zx_sa11_AuthenticationStatement_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Assertion_DEL_AuthenticationStatement) */

void zx_ff12_Assertion_DEL_AuthenticationStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_AuthenticationStatement_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthenticationStatement = (struct zx_sa11_AuthenticationStatement_s*)x->AuthenticationStatement->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_AuthenticationStatement_s*)x->AuthenticationStatement;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_AuthenticationStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthenticationStatement; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_AuthenticationStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_AuthorizationDecisionStatement) */

int zx_ff12_Assertion_NUM_AuthorizationDecisionStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_AuthorizationDecisionStatement_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthorizationDecisionStatement; y; ++n, y = (struct zx_sa11_AuthorizationDecisionStatement_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_AuthorizationDecisionStatement) */

struct zx_sa11_AuthorizationDecisionStatement_s* zx_ff12_Assertion_GET_AuthorizationDecisionStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_AuthorizationDecisionStatement_s* y;
  if (!x) return 0;
  for (y = x->AuthorizationDecisionStatement; n>=0 && y; --n, y = (struct zx_sa11_AuthorizationDecisionStatement_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_AuthorizationDecisionStatement) */

struct zx_sa11_AuthorizationDecisionStatement_s* zx_ff12_Assertion_POP_AuthorizationDecisionStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_AuthorizationDecisionStatement_s* y;
  if (!x) return 0;
  y = x->AuthorizationDecisionStatement;
  if (y)
    x->AuthorizationDecisionStatement = (struct zx_sa11_AuthorizationDecisionStatement_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_AuthorizationDecisionStatement) */

void zx_ff12_Assertion_PUSH_AuthorizationDecisionStatement(struct zx_ff12_Assertion_s* x, struct zx_sa11_AuthorizationDecisionStatement_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->AuthorizationDecisionStatement->gg.g;
  x->AuthorizationDecisionStatement = z;
}

/* FUNC(zx_ff12_Assertion_REV_AuthorizationDecisionStatement) */

void zx_ff12_Assertion_REV_AuthorizationDecisionStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_AuthorizationDecisionStatement_s* nxt;
  struct zx_sa11_AuthorizationDecisionStatement_s* y;
  if (!x) return;
  y = x->AuthorizationDecisionStatement;
  if (!y) return;
  x->AuthorizationDecisionStatement = 0;
  while (y) {
    nxt = (struct zx_sa11_AuthorizationDecisionStatement_s*)y->gg.g.n;
    y->gg.g.n = &x->AuthorizationDecisionStatement->gg.g;
    x->AuthorizationDecisionStatement = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_AuthorizationDecisionStatement) */

void zx_ff12_Assertion_PUT_AuthorizationDecisionStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_AuthorizationDecisionStatement_s* z)
{
  struct zx_sa11_AuthorizationDecisionStatement_s* y;
  if (!x || !z) return;
  y = x->AuthorizationDecisionStatement;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->AuthorizationDecisionStatement = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_AuthorizationDecisionStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_AuthorizationDecisionStatement) */

void zx_ff12_Assertion_ADD_AuthorizationDecisionStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_AuthorizationDecisionStatement_s* z)
{
  struct zx_sa11_AuthorizationDecisionStatement_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->AuthorizationDecisionStatement->gg.g;
    x->AuthorizationDecisionStatement = z;
    return;
  case -1:
    y = x->AuthorizationDecisionStatement;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_AuthorizationDecisionStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthorizationDecisionStatement; n > 1 && y; --n, y = (struct zx_sa11_AuthorizationDecisionStatement_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Assertion_DEL_AuthorizationDecisionStatement) */

void zx_ff12_Assertion_DEL_AuthorizationDecisionStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_AuthorizationDecisionStatement_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthorizationDecisionStatement = (struct zx_sa11_AuthorizationDecisionStatement_s*)x->AuthorizationDecisionStatement->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_AuthorizationDecisionStatement_s*)x->AuthorizationDecisionStatement;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_AuthorizationDecisionStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthorizationDecisionStatement; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_AuthorizationDecisionStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_AttributeStatement) */

int zx_ff12_Assertion_NUM_AttributeStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_AttributeStatement_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AttributeStatement; y; ++n, y = (struct zx_sa11_AttributeStatement_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_AttributeStatement) */

struct zx_sa11_AttributeStatement_s* zx_ff12_Assertion_GET_AttributeStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_AttributeStatement_s* y;
  if (!x) return 0;
  for (y = x->AttributeStatement; n>=0 && y; --n, y = (struct zx_sa11_AttributeStatement_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_AttributeStatement) */

struct zx_sa11_AttributeStatement_s* zx_ff12_Assertion_POP_AttributeStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_AttributeStatement_s* y;
  if (!x) return 0;
  y = x->AttributeStatement;
  if (y)
    x->AttributeStatement = (struct zx_sa11_AttributeStatement_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_AttributeStatement) */

void zx_ff12_Assertion_PUSH_AttributeStatement(struct zx_ff12_Assertion_s* x, struct zx_sa11_AttributeStatement_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->AttributeStatement->gg.g;
  x->AttributeStatement = z;
}

/* FUNC(zx_ff12_Assertion_REV_AttributeStatement) */

void zx_ff12_Assertion_REV_AttributeStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_sa11_AttributeStatement_s* nxt;
  struct zx_sa11_AttributeStatement_s* y;
  if (!x) return;
  y = x->AttributeStatement;
  if (!y) return;
  x->AttributeStatement = 0;
  while (y) {
    nxt = (struct zx_sa11_AttributeStatement_s*)y->gg.g.n;
    y->gg.g.n = &x->AttributeStatement->gg.g;
    x->AttributeStatement = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_AttributeStatement) */

void zx_ff12_Assertion_PUT_AttributeStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_AttributeStatement_s* z)
{
  struct zx_sa11_AttributeStatement_s* y;
  if (!x || !z) return;
  y = x->AttributeStatement;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->AttributeStatement = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_AttributeStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_AttributeStatement) */

void zx_ff12_Assertion_ADD_AttributeStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_sa11_AttributeStatement_s* z)
{
  struct zx_sa11_AttributeStatement_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->AttributeStatement->gg.g;
    x->AttributeStatement = z;
    return;
  case -1:
    y = x->AttributeStatement;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_AttributeStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AttributeStatement; n > 1 && y; --n, y = (struct zx_sa11_AttributeStatement_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Assertion_DEL_AttributeStatement) */

void zx_ff12_Assertion_DEL_AttributeStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_sa11_AttributeStatement_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AttributeStatement = (struct zx_sa11_AttributeStatement_s*)x->AttributeStatement->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_AttributeStatement_s*)x->AttributeStatement;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_AttributeStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AttributeStatement; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_AttributeStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_XACMLAuthzDecisionStatement) */

int zx_ff12_Assertion_NUM_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasa_XACMLAuthzDecisionStatement_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->XACMLAuthzDecisionStatement; y; ++n, y = (struct zx_xasa_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_XACMLAuthzDecisionStatement) */

struct zx_xasa_XACMLAuthzDecisionStatement_s* zx_ff12_Assertion_GET_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_xasa_XACMLAuthzDecisionStatement_s* y;
  if (!x) return 0;
  for (y = x->XACMLAuthzDecisionStatement; n>=0 && y; --n, y = (struct zx_xasa_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_XACMLAuthzDecisionStatement) */

struct zx_xasa_XACMLAuthzDecisionStatement_s* zx_ff12_Assertion_POP_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasa_XACMLAuthzDecisionStatement_s* y;
  if (!x) return 0;
  y = x->XACMLAuthzDecisionStatement;
  if (y)
    x->XACMLAuthzDecisionStatement = (struct zx_xasa_XACMLAuthzDecisionStatement_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_XACMLAuthzDecisionStatement) */

void zx_ff12_Assertion_PUSH_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x, struct zx_xasa_XACMLAuthzDecisionStatement_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->XACMLAuthzDecisionStatement->gg.g;
  x->XACMLAuthzDecisionStatement = z;
}

/* FUNC(zx_ff12_Assertion_REV_XACMLAuthzDecisionStatement) */

void zx_ff12_Assertion_REV_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasa_XACMLAuthzDecisionStatement_s* nxt;
  struct zx_xasa_XACMLAuthzDecisionStatement_s* y;
  if (!x) return;
  y = x->XACMLAuthzDecisionStatement;
  if (!y) return;
  x->XACMLAuthzDecisionStatement = 0;
  while (y) {
    nxt = (struct zx_xasa_XACMLAuthzDecisionStatement_s*)y->gg.g.n;
    y->gg.g.n = &x->XACMLAuthzDecisionStatement->gg.g;
    x->XACMLAuthzDecisionStatement = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_XACMLAuthzDecisionStatement) */

void zx_ff12_Assertion_PUT_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_xasa_XACMLAuthzDecisionStatement_s* z)
{
  struct zx_xasa_XACMLAuthzDecisionStatement_s* y;
  if (!x || !z) return;
  y = x->XACMLAuthzDecisionStatement;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->XACMLAuthzDecisionStatement = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_xasa_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_XACMLAuthzDecisionStatement) */

void zx_ff12_Assertion_ADD_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_xasa_XACMLAuthzDecisionStatement_s* z)
{
  struct zx_xasa_XACMLAuthzDecisionStatement_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->XACMLAuthzDecisionStatement->gg.g;
    x->XACMLAuthzDecisionStatement = z;
    return;
  case -1:
    y = x->XACMLAuthzDecisionStatement;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_xasa_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->XACMLAuthzDecisionStatement; n > 1 && y; --n, y = (struct zx_xasa_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Assertion_DEL_XACMLAuthzDecisionStatement) */

void zx_ff12_Assertion_DEL_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_xasa_XACMLAuthzDecisionStatement_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->XACMLAuthzDecisionStatement = (struct zx_xasa_XACMLAuthzDecisionStatement_s*)x->XACMLAuthzDecisionStatement->gg.g.n;
    return;
  case -1:
    y = (struct zx_xasa_XACMLAuthzDecisionStatement_s*)x->XACMLAuthzDecisionStatement;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_xasa_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->XACMLAuthzDecisionStatement; n > 1 && y->gg.g.n; --n, y = (struct zx_xasa_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_XACMLPolicyStatement) */

int zx_ff12_Assertion_NUM_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasa_XACMLPolicyStatement_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->XACMLPolicyStatement; y; ++n, y = (struct zx_xasa_XACMLPolicyStatement_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_XACMLPolicyStatement) */

struct zx_xasa_XACMLPolicyStatement_s* zx_ff12_Assertion_GET_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_xasa_XACMLPolicyStatement_s* y;
  if (!x) return 0;
  for (y = x->XACMLPolicyStatement; n>=0 && y; --n, y = (struct zx_xasa_XACMLPolicyStatement_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_XACMLPolicyStatement) */

struct zx_xasa_XACMLPolicyStatement_s* zx_ff12_Assertion_POP_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasa_XACMLPolicyStatement_s* y;
  if (!x) return 0;
  y = x->XACMLPolicyStatement;
  if (y)
    x->XACMLPolicyStatement = (struct zx_xasa_XACMLPolicyStatement_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_XACMLPolicyStatement) */

void zx_ff12_Assertion_PUSH_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x, struct zx_xasa_XACMLPolicyStatement_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->XACMLPolicyStatement->gg.g;
  x->XACMLPolicyStatement = z;
}

/* FUNC(zx_ff12_Assertion_REV_XACMLPolicyStatement) */

void zx_ff12_Assertion_REV_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasa_XACMLPolicyStatement_s* nxt;
  struct zx_xasa_XACMLPolicyStatement_s* y;
  if (!x) return;
  y = x->XACMLPolicyStatement;
  if (!y) return;
  x->XACMLPolicyStatement = 0;
  while (y) {
    nxt = (struct zx_xasa_XACMLPolicyStatement_s*)y->gg.g.n;
    y->gg.g.n = &x->XACMLPolicyStatement->gg.g;
    x->XACMLPolicyStatement = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_XACMLPolicyStatement) */

void zx_ff12_Assertion_PUT_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_xasa_XACMLPolicyStatement_s* z)
{
  struct zx_xasa_XACMLPolicyStatement_s* y;
  if (!x || !z) return;
  y = x->XACMLPolicyStatement;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->XACMLPolicyStatement = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_xasa_XACMLPolicyStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_XACMLPolicyStatement) */

void zx_ff12_Assertion_ADD_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_xasa_XACMLPolicyStatement_s* z)
{
  struct zx_xasa_XACMLPolicyStatement_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->XACMLPolicyStatement->gg.g;
    x->XACMLPolicyStatement = z;
    return;
  case -1:
    y = x->XACMLPolicyStatement;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_xasa_XACMLPolicyStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->XACMLPolicyStatement; n > 1 && y; --n, y = (struct zx_xasa_XACMLPolicyStatement_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Assertion_DEL_XACMLPolicyStatement) */

void zx_ff12_Assertion_DEL_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_xasa_XACMLPolicyStatement_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->XACMLPolicyStatement = (struct zx_xasa_XACMLPolicyStatement_s*)x->XACMLPolicyStatement->gg.g.n;
    return;
  case -1:
    y = (struct zx_xasa_XACMLPolicyStatement_s*)x->XACMLPolicyStatement;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_xasa_XACMLPolicyStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->XACMLPolicyStatement; n > 1 && y->gg.g.n; --n, y = (struct zx_xasa_XACMLPolicyStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_xasacd1_XACMLAuthzDecisionStatement) */

int zx_ff12_Assertion_NUM_xasacd1_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasacd1_XACMLAuthzDecisionStatement_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->xasacd1_XACMLAuthzDecisionStatement; y; ++n, y = (struct zx_xasacd1_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_xasacd1_XACMLAuthzDecisionStatement) */

struct zx_xasacd1_XACMLAuthzDecisionStatement_s* zx_ff12_Assertion_GET_xasacd1_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_xasacd1_XACMLAuthzDecisionStatement_s* y;
  if (!x) return 0;
  for (y = x->xasacd1_XACMLAuthzDecisionStatement; n>=0 && y; --n, y = (struct zx_xasacd1_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_xasacd1_XACMLAuthzDecisionStatement) */

struct zx_xasacd1_XACMLAuthzDecisionStatement_s* zx_ff12_Assertion_POP_xasacd1_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasacd1_XACMLAuthzDecisionStatement_s* y;
  if (!x) return 0;
  y = x->xasacd1_XACMLAuthzDecisionStatement;
  if (y)
    x->xasacd1_XACMLAuthzDecisionStatement = (struct zx_xasacd1_XACMLAuthzDecisionStatement_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_xasacd1_XACMLAuthzDecisionStatement) */

void zx_ff12_Assertion_PUSH_xasacd1_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x, struct zx_xasacd1_XACMLAuthzDecisionStatement_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->xasacd1_XACMLAuthzDecisionStatement->gg.g;
  x->xasacd1_XACMLAuthzDecisionStatement = z;
}

/* FUNC(zx_ff12_Assertion_REV_xasacd1_XACMLAuthzDecisionStatement) */

void zx_ff12_Assertion_REV_xasacd1_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasacd1_XACMLAuthzDecisionStatement_s* nxt;
  struct zx_xasacd1_XACMLAuthzDecisionStatement_s* y;
  if (!x) return;
  y = x->xasacd1_XACMLAuthzDecisionStatement;
  if (!y) return;
  x->xasacd1_XACMLAuthzDecisionStatement = 0;
  while (y) {
    nxt = (struct zx_xasacd1_XACMLAuthzDecisionStatement_s*)y->gg.g.n;
    y->gg.g.n = &x->xasacd1_XACMLAuthzDecisionStatement->gg.g;
    x->xasacd1_XACMLAuthzDecisionStatement = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_xasacd1_XACMLAuthzDecisionStatement) */

void zx_ff12_Assertion_PUT_xasacd1_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_xasacd1_XACMLAuthzDecisionStatement_s* z)
{
  struct zx_xasacd1_XACMLAuthzDecisionStatement_s* y;
  if (!x || !z) return;
  y = x->xasacd1_XACMLAuthzDecisionStatement;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->xasacd1_XACMLAuthzDecisionStatement = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_xasacd1_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_xasacd1_XACMLAuthzDecisionStatement) */

void zx_ff12_Assertion_ADD_xasacd1_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_xasacd1_XACMLAuthzDecisionStatement_s* z)
{
  struct zx_xasacd1_XACMLAuthzDecisionStatement_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->xasacd1_XACMLAuthzDecisionStatement->gg.g;
    x->xasacd1_XACMLAuthzDecisionStatement = z;
    return;
  case -1:
    y = x->xasacd1_XACMLAuthzDecisionStatement;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_xasacd1_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->xasacd1_XACMLAuthzDecisionStatement; n > 1 && y; --n, y = (struct zx_xasacd1_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Assertion_DEL_xasacd1_XACMLAuthzDecisionStatement) */

void zx_ff12_Assertion_DEL_xasacd1_XACMLAuthzDecisionStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_xasacd1_XACMLAuthzDecisionStatement_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->xasacd1_XACMLAuthzDecisionStatement = (struct zx_xasacd1_XACMLAuthzDecisionStatement_s*)x->xasacd1_XACMLAuthzDecisionStatement->gg.g.n;
    return;
  case -1:
    y = (struct zx_xasacd1_XACMLAuthzDecisionStatement_s*)x->xasacd1_XACMLAuthzDecisionStatement;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_xasacd1_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->xasacd1_XACMLAuthzDecisionStatement; n > 1 && y->gg.g.n; --n, y = (struct zx_xasacd1_XACMLAuthzDecisionStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_xasacd1_XACMLPolicyStatement) */

int zx_ff12_Assertion_NUM_xasacd1_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasacd1_XACMLPolicyStatement_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->xasacd1_XACMLPolicyStatement; y; ++n, y = (struct zx_xasacd1_XACMLPolicyStatement_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_xasacd1_XACMLPolicyStatement) */

struct zx_xasacd1_XACMLPolicyStatement_s* zx_ff12_Assertion_GET_xasacd1_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_xasacd1_XACMLPolicyStatement_s* y;
  if (!x) return 0;
  for (y = x->xasacd1_XACMLPolicyStatement; n>=0 && y; --n, y = (struct zx_xasacd1_XACMLPolicyStatement_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_xasacd1_XACMLPolicyStatement) */

struct zx_xasacd1_XACMLPolicyStatement_s* zx_ff12_Assertion_POP_xasacd1_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasacd1_XACMLPolicyStatement_s* y;
  if (!x) return 0;
  y = x->xasacd1_XACMLPolicyStatement;
  if (y)
    x->xasacd1_XACMLPolicyStatement = (struct zx_xasacd1_XACMLPolicyStatement_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_xasacd1_XACMLPolicyStatement) */

void zx_ff12_Assertion_PUSH_xasacd1_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x, struct zx_xasacd1_XACMLPolicyStatement_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->xasacd1_XACMLPolicyStatement->gg.g;
  x->xasacd1_XACMLPolicyStatement = z;
}

/* FUNC(zx_ff12_Assertion_REV_xasacd1_XACMLPolicyStatement) */

void zx_ff12_Assertion_REV_xasacd1_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x)
{
  struct zx_xasacd1_XACMLPolicyStatement_s* nxt;
  struct zx_xasacd1_XACMLPolicyStatement_s* y;
  if (!x) return;
  y = x->xasacd1_XACMLPolicyStatement;
  if (!y) return;
  x->xasacd1_XACMLPolicyStatement = 0;
  while (y) {
    nxt = (struct zx_xasacd1_XACMLPolicyStatement_s*)y->gg.g.n;
    y->gg.g.n = &x->xasacd1_XACMLPolicyStatement->gg.g;
    x->xasacd1_XACMLPolicyStatement = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_xasacd1_XACMLPolicyStatement) */

void zx_ff12_Assertion_PUT_xasacd1_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_xasacd1_XACMLPolicyStatement_s* z)
{
  struct zx_xasacd1_XACMLPolicyStatement_s* y;
  if (!x || !z) return;
  y = x->xasacd1_XACMLPolicyStatement;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->xasacd1_XACMLPolicyStatement = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_xasacd1_XACMLPolicyStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_xasacd1_XACMLPolicyStatement) */

void zx_ff12_Assertion_ADD_xasacd1_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x, int n, struct zx_xasacd1_XACMLPolicyStatement_s* z)
{
  struct zx_xasacd1_XACMLPolicyStatement_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->xasacd1_XACMLPolicyStatement->gg.g;
    x->xasacd1_XACMLPolicyStatement = z;
    return;
  case -1:
    y = x->xasacd1_XACMLPolicyStatement;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_xasacd1_XACMLPolicyStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->xasacd1_XACMLPolicyStatement; n > 1 && y; --n, y = (struct zx_xasacd1_XACMLPolicyStatement_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Assertion_DEL_xasacd1_XACMLPolicyStatement) */

void zx_ff12_Assertion_DEL_xasacd1_XACMLPolicyStatement(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_xasacd1_XACMLPolicyStatement_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->xasacd1_XACMLPolicyStatement = (struct zx_xasacd1_XACMLPolicyStatement_s*)x->xasacd1_XACMLPolicyStatement->gg.g.n;
    return;
  case -1:
    y = (struct zx_xasacd1_XACMLPolicyStatement_s*)x->xasacd1_XACMLPolicyStatement;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_xasacd1_XACMLPolicyStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->xasacd1_XACMLPolicyStatement; n > 1 && y->gg.g.n; --n, y = (struct zx_xasacd1_XACMLPolicyStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Assertion_NUM_Signature) */

int zx_ff12_Assertion_NUM_Signature(struct zx_ff12_Assertion_s* x)
{
  struct zx_ds_Signature_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Signature; y; ++n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Assertion_GET_Signature) */

struct zx_ds_Signature_s* zx_ff12_Assertion_GET_Signature(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  for (y = x->Signature; n>=0 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Assertion_POP_Signature) */

struct zx_ds_Signature_s* zx_ff12_Assertion_POP_Signature(struct zx_ff12_Assertion_s* x)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  y = x->Signature;
  if (y)
    x->Signature = (struct zx_ds_Signature_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Assertion_PUSH_Signature) */

void zx_ff12_Assertion_PUSH_Signature(struct zx_ff12_Assertion_s* x, struct zx_ds_Signature_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Signature->gg.g;
  x->Signature = z;
}

/* FUNC(zx_ff12_Assertion_REV_Signature) */

void zx_ff12_Assertion_REV_Signature(struct zx_ff12_Assertion_s* x)
{
  struct zx_ds_Signature_s* nxt;
  struct zx_ds_Signature_s* y;
  if (!x) return;
  y = x->Signature;
  if (!y) return;
  x->Signature = 0;
  while (y) {
    nxt = (struct zx_ds_Signature_s*)y->gg.g.n;
    y->gg.g.n = &x->Signature->gg.g;
    x->Signature = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Assertion_PUT_Signature) */

void zx_ff12_Assertion_PUT_Signature(struct zx_ff12_Assertion_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  y = x->Signature;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Signature = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Assertion_ADD_Signature) */

void zx_ff12_Assertion_ADD_Signature(struct zx_ff12_Assertion_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Signature->gg.g;
    x->Signature = z;
    return;
  case -1:
    y = x->Signature;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Assertion_DEL_Signature) */

void zx_ff12_Assertion_DEL_Signature(struct zx_ff12_Assertion_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Signature = (struct zx_ds_Signature_s*)x->Signature->gg.g.n;
    return;
  case -1:
    y = (struct zx_ds_Signature_s*)x->Signature;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif

/* FUNC(zx_ff12_Assertion_GET_AssertionID) */
struct zx_str* zx_ff12_Assertion_GET_AssertionID(struct zx_ff12_Assertion_s* x) { return x->AssertionID; }
/* FUNC(zx_ff12_Assertion_PUT_AssertionID) */
void zx_ff12_Assertion_PUT_AssertionID(struct zx_ff12_Assertion_s* x, struct zx_str* y) { x->AssertionID = y; }
/* FUNC(zx_ff12_Assertion_GET_InResponseTo) */
struct zx_str* zx_ff12_Assertion_GET_InResponseTo(struct zx_ff12_Assertion_s* x) { return x->InResponseTo; }
/* FUNC(zx_ff12_Assertion_PUT_InResponseTo) */
void zx_ff12_Assertion_PUT_InResponseTo(struct zx_ff12_Assertion_s* x, struct zx_str* y) { x->InResponseTo = y; }
/* FUNC(zx_ff12_Assertion_GET_IssueInstant) */
struct zx_str* zx_ff12_Assertion_GET_IssueInstant(struct zx_ff12_Assertion_s* x) { return x->IssueInstant; }
/* FUNC(zx_ff12_Assertion_PUT_IssueInstant) */
void zx_ff12_Assertion_PUT_IssueInstant(struct zx_ff12_Assertion_s* x, struct zx_str* y) { x->IssueInstant = y; }
/* FUNC(zx_ff12_Assertion_GET_Issuer) */
struct zx_str* zx_ff12_Assertion_GET_Issuer(struct zx_ff12_Assertion_s* x) { return x->Issuer; }
/* FUNC(zx_ff12_Assertion_PUT_Issuer) */
void zx_ff12_Assertion_PUT_Issuer(struct zx_ff12_Assertion_s* x, struct zx_str* y) { x->Issuer = y; }
/* FUNC(zx_ff12_Assertion_GET_MajorVersion) */
struct zx_str* zx_ff12_Assertion_GET_MajorVersion(struct zx_ff12_Assertion_s* x) { return x->MajorVersion; }
/* FUNC(zx_ff12_Assertion_PUT_MajorVersion) */
void zx_ff12_Assertion_PUT_MajorVersion(struct zx_ff12_Assertion_s* x, struct zx_str* y) { x->MajorVersion = y; }
/* FUNC(zx_ff12_Assertion_GET_MinorVersion) */
struct zx_str* zx_ff12_Assertion_GET_MinorVersion(struct zx_ff12_Assertion_s* x) { return x->MinorVersion; }
/* FUNC(zx_ff12_Assertion_PUT_MinorVersion) */
void zx_ff12_Assertion_PUT_MinorVersion(struct zx_ff12_Assertion_s* x, struct zx_str* y) { x->MinorVersion = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthenticationStatement_NUM_Subject) */

int zx_ff12_AuthenticationStatement_NUM_Subject(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_sa11_Subject_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Subject; y; ++n, y = (struct zx_sa11_Subject_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthenticationStatement_GET_Subject) */

struct zx_sa11_Subject_s* zx_ff12_AuthenticationStatement_GET_Subject(struct zx_ff12_AuthenticationStatement_s* x, int n)
{
  struct zx_sa11_Subject_s* y;
  if (!x) return 0;
  for (y = x->Subject; n>=0 && y; --n, y = (struct zx_sa11_Subject_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthenticationStatement_POP_Subject) */

struct zx_sa11_Subject_s* zx_ff12_AuthenticationStatement_POP_Subject(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_sa11_Subject_s* y;
  if (!x) return 0;
  y = x->Subject;
  if (y)
    x->Subject = (struct zx_sa11_Subject_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthenticationStatement_PUSH_Subject) */

void zx_ff12_AuthenticationStatement_PUSH_Subject(struct zx_ff12_AuthenticationStatement_s* x, struct zx_sa11_Subject_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Subject->gg.g;
  x->Subject = z;
}

/* FUNC(zx_ff12_AuthenticationStatement_REV_Subject) */

void zx_ff12_AuthenticationStatement_REV_Subject(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_sa11_Subject_s* nxt;
  struct zx_sa11_Subject_s* y;
  if (!x) return;
  y = x->Subject;
  if (!y) return;
  x->Subject = 0;
  while (y) {
    nxt = (struct zx_sa11_Subject_s*)y->gg.g.n;
    y->gg.g.n = &x->Subject->gg.g;
    x->Subject = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthenticationStatement_PUT_Subject) */

void zx_ff12_AuthenticationStatement_PUT_Subject(struct zx_ff12_AuthenticationStatement_s* x, int n, struct zx_sa11_Subject_s* z)
{
  struct zx_sa11_Subject_s* y;
  if (!x || !z) return;
  y = x->Subject;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Subject = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_Subject_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthenticationStatement_ADD_Subject) */

void zx_ff12_AuthenticationStatement_ADD_Subject(struct zx_ff12_AuthenticationStatement_s* x, int n, struct zx_sa11_Subject_s* z)
{
  struct zx_sa11_Subject_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Subject->gg.g;
    x->Subject = z;
    return;
  case -1:
    y = x->Subject;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_Subject_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Subject; n > 1 && y; --n, y = (struct zx_sa11_Subject_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthenticationStatement_DEL_Subject) */

void zx_ff12_AuthenticationStatement_DEL_Subject(struct zx_ff12_AuthenticationStatement_s* x, int n)
{
  struct zx_sa11_Subject_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Subject = (struct zx_sa11_Subject_s*)x->Subject->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_Subject_s*)x->Subject;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_Subject_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Subject; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_Subject_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthenticationStatement_NUM_SubjectLocality) */

int zx_ff12_AuthenticationStatement_NUM_SubjectLocality(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_sa11_SubjectLocality_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->SubjectLocality; y; ++n, y = (struct zx_sa11_SubjectLocality_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthenticationStatement_GET_SubjectLocality) */

struct zx_sa11_SubjectLocality_s* zx_ff12_AuthenticationStatement_GET_SubjectLocality(struct zx_ff12_AuthenticationStatement_s* x, int n)
{
  struct zx_sa11_SubjectLocality_s* y;
  if (!x) return 0;
  for (y = x->SubjectLocality; n>=0 && y; --n, y = (struct zx_sa11_SubjectLocality_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthenticationStatement_POP_SubjectLocality) */

struct zx_sa11_SubjectLocality_s* zx_ff12_AuthenticationStatement_POP_SubjectLocality(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_sa11_SubjectLocality_s* y;
  if (!x) return 0;
  y = x->SubjectLocality;
  if (y)
    x->SubjectLocality = (struct zx_sa11_SubjectLocality_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthenticationStatement_PUSH_SubjectLocality) */

void zx_ff12_AuthenticationStatement_PUSH_SubjectLocality(struct zx_ff12_AuthenticationStatement_s* x, struct zx_sa11_SubjectLocality_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->SubjectLocality->gg.g;
  x->SubjectLocality = z;
}

/* FUNC(zx_ff12_AuthenticationStatement_REV_SubjectLocality) */

void zx_ff12_AuthenticationStatement_REV_SubjectLocality(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_sa11_SubjectLocality_s* nxt;
  struct zx_sa11_SubjectLocality_s* y;
  if (!x) return;
  y = x->SubjectLocality;
  if (!y) return;
  x->SubjectLocality = 0;
  while (y) {
    nxt = (struct zx_sa11_SubjectLocality_s*)y->gg.g.n;
    y->gg.g.n = &x->SubjectLocality->gg.g;
    x->SubjectLocality = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthenticationStatement_PUT_SubjectLocality) */

void zx_ff12_AuthenticationStatement_PUT_SubjectLocality(struct zx_ff12_AuthenticationStatement_s* x, int n, struct zx_sa11_SubjectLocality_s* z)
{
  struct zx_sa11_SubjectLocality_s* y;
  if (!x || !z) return;
  y = x->SubjectLocality;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->SubjectLocality = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_SubjectLocality_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthenticationStatement_ADD_SubjectLocality) */

void zx_ff12_AuthenticationStatement_ADD_SubjectLocality(struct zx_ff12_AuthenticationStatement_s* x, int n, struct zx_sa11_SubjectLocality_s* z)
{
  struct zx_sa11_SubjectLocality_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->SubjectLocality->gg.g;
    x->SubjectLocality = z;
    return;
  case -1:
    y = x->SubjectLocality;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_SubjectLocality_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->SubjectLocality; n > 1 && y; --n, y = (struct zx_sa11_SubjectLocality_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthenticationStatement_DEL_SubjectLocality) */

void zx_ff12_AuthenticationStatement_DEL_SubjectLocality(struct zx_ff12_AuthenticationStatement_s* x, int n)
{
  struct zx_sa11_SubjectLocality_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->SubjectLocality = (struct zx_sa11_SubjectLocality_s*)x->SubjectLocality->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_SubjectLocality_s*)x->SubjectLocality;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_SubjectLocality_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->SubjectLocality; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_SubjectLocality_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthenticationStatement_NUM_AuthorityBinding) */

int zx_ff12_AuthenticationStatement_NUM_AuthorityBinding(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_sa11_AuthorityBinding_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthorityBinding; y; ++n, y = (struct zx_sa11_AuthorityBinding_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthenticationStatement_GET_AuthorityBinding) */

struct zx_sa11_AuthorityBinding_s* zx_ff12_AuthenticationStatement_GET_AuthorityBinding(struct zx_ff12_AuthenticationStatement_s* x, int n)
{
  struct zx_sa11_AuthorityBinding_s* y;
  if (!x) return 0;
  for (y = x->AuthorityBinding; n>=0 && y; --n, y = (struct zx_sa11_AuthorityBinding_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthenticationStatement_POP_AuthorityBinding) */

struct zx_sa11_AuthorityBinding_s* zx_ff12_AuthenticationStatement_POP_AuthorityBinding(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_sa11_AuthorityBinding_s* y;
  if (!x) return 0;
  y = x->AuthorityBinding;
  if (y)
    x->AuthorityBinding = (struct zx_sa11_AuthorityBinding_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthenticationStatement_PUSH_AuthorityBinding) */

void zx_ff12_AuthenticationStatement_PUSH_AuthorityBinding(struct zx_ff12_AuthenticationStatement_s* x, struct zx_sa11_AuthorityBinding_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->AuthorityBinding->gg.g;
  x->AuthorityBinding = z;
}

/* FUNC(zx_ff12_AuthenticationStatement_REV_AuthorityBinding) */

void zx_ff12_AuthenticationStatement_REV_AuthorityBinding(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_sa11_AuthorityBinding_s* nxt;
  struct zx_sa11_AuthorityBinding_s* y;
  if (!x) return;
  y = x->AuthorityBinding;
  if (!y) return;
  x->AuthorityBinding = 0;
  while (y) {
    nxt = (struct zx_sa11_AuthorityBinding_s*)y->gg.g.n;
    y->gg.g.n = &x->AuthorityBinding->gg.g;
    x->AuthorityBinding = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthenticationStatement_PUT_AuthorityBinding) */

void zx_ff12_AuthenticationStatement_PUT_AuthorityBinding(struct zx_ff12_AuthenticationStatement_s* x, int n, struct zx_sa11_AuthorityBinding_s* z)
{
  struct zx_sa11_AuthorityBinding_s* y;
  if (!x || !z) return;
  y = x->AuthorityBinding;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->AuthorityBinding = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_AuthorityBinding_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthenticationStatement_ADD_AuthorityBinding) */

void zx_ff12_AuthenticationStatement_ADD_AuthorityBinding(struct zx_ff12_AuthenticationStatement_s* x, int n, struct zx_sa11_AuthorityBinding_s* z)
{
  struct zx_sa11_AuthorityBinding_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->AuthorityBinding->gg.g;
    x->AuthorityBinding = z;
    return;
  case -1:
    y = x->AuthorityBinding;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_AuthorityBinding_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthorityBinding; n > 1 && y; --n, y = (struct zx_sa11_AuthorityBinding_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthenticationStatement_DEL_AuthorityBinding) */

void zx_ff12_AuthenticationStatement_DEL_AuthorityBinding(struct zx_ff12_AuthenticationStatement_s* x, int n)
{
  struct zx_sa11_AuthorityBinding_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthorityBinding = (struct zx_sa11_AuthorityBinding_s*)x->AuthorityBinding->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_AuthorityBinding_s*)x->AuthorityBinding;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_AuthorityBinding_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthorityBinding; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_AuthorityBinding_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthenticationStatement_NUM_AuthnContext) */

int zx_ff12_AuthenticationStatement_NUM_AuthnContext(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_ff12_AuthnContext_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthnContext; y; ++n, y = (struct zx_ff12_AuthnContext_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthenticationStatement_GET_AuthnContext) */

struct zx_ff12_AuthnContext_s* zx_ff12_AuthenticationStatement_GET_AuthnContext(struct zx_ff12_AuthenticationStatement_s* x, int n)
{
  struct zx_ff12_AuthnContext_s* y;
  if (!x) return 0;
  for (y = x->AuthnContext; n>=0 && y; --n, y = (struct zx_ff12_AuthnContext_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthenticationStatement_POP_AuthnContext) */

struct zx_ff12_AuthnContext_s* zx_ff12_AuthenticationStatement_POP_AuthnContext(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_ff12_AuthnContext_s* y;
  if (!x) return 0;
  y = x->AuthnContext;
  if (y)
    x->AuthnContext = (struct zx_ff12_AuthnContext_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthenticationStatement_PUSH_AuthnContext) */

void zx_ff12_AuthenticationStatement_PUSH_AuthnContext(struct zx_ff12_AuthenticationStatement_s* x, struct zx_ff12_AuthnContext_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->AuthnContext->gg.g;
  x->AuthnContext = z;
}

/* FUNC(zx_ff12_AuthenticationStatement_REV_AuthnContext) */

void zx_ff12_AuthenticationStatement_REV_AuthnContext(struct zx_ff12_AuthenticationStatement_s* x)
{
  struct zx_ff12_AuthnContext_s* nxt;
  struct zx_ff12_AuthnContext_s* y;
  if (!x) return;
  y = x->AuthnContext;
  if (!y) return;
  x->AuthnContext = 0;
  while (y) {
    nxt = (struct zx_ff12_AuthnContext_s*)y->gg.g.n;
    y->gg.g.n = &x->AuthnContext->gg.g;
    x->AuthnContext = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthenticationStatement_PUT_AuthnContext) */

void zx_ff12_AuthenticationStatement_PUT_AuthnContext(struct zx_ff12_AuthenticationStatement_s* x, int n, struct zx_ff12_AuthnContext_s* z)
{
  struct zx_ff12_AuthnContext_s* y;
  if (!x || !z) return;
  y = x->AuthnContext;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->AuthnContext = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_AuthnContext_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthenticationStatement_ADD_AuthnContext) */

void zx_ff12_AuthenticationStatement_ADD_AuthnContext(struct zx_ff12_AuthenticationStatement_s* x, int n, struct zx_ff12_AuthnContext_s* z)
{
  struct zx_ff12_AuthnContext_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->AuthnContext->gg.g;
    x->AuthnContext = z;
    return;
  case -1:
    y = x->AuthnContext;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_AuthnContext_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthnContext; n > 1 && y; --n, y = (struct zx_ff12_AuthnContext_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthenticationStatement_DEL_AuthnContext) */

void zx_ff12_AuthenticationStatement_DEL_AuthnContext(struct zx_ff12_AuthenticationStatement_s* x, int n)
{
  struct zx_ff12_AuthnContext_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthnContext = (struct zx_ff12_AuthnContext_s*)x->AuthnContext->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_AuthnContext_s*)x->AuthnContext;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_AuthnContext_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthnContext; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_AuthnContext_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif

/* FUNC(zx_ff12_AuthenticationStatement_GET_AuthenticationInstant) */
struct zx_str* zx_ff12_AuthenticationStatement_GET_AuthenticationInstant(struct zx_ff12_AuthenticationStatement_s* x) { return x->AuthenticationInstant; }
/* FUNC(zx_ff12_AuthenticationStatement_PUT_AuthenticationInstant) */
void zx_ff12_AuthenticationStatement_PUT_AuthenticationInstant(struct zx_ff12_AuthenticationStatement_s* x, struct zx_str* y) { x->AuthenticationInstant = y; }
/* FUNC(zx_ff12_AuthenticationStatement_GET_AuthenticationMethod) */
struct zx_str* zx_ff12_AuthenticationStatement_GET_AuthenticationMethod(struct zx_ff12_AuthenticationStatement_s* x) { return x->AuthenticationMethod; }
/* FUNC(zx_ff12_AuthenticationStatement_PUT_AuthenticationMethod) */
void zx_ff12_AuthenticationStatement_PUT_AuthenticationMethod(struct zx_ff12_AuthenticationStatement_s* x, struct zx_str* y) { x->AuthenticationMethod = y; }
/* FUNC(zx_ff12_AuthenticationStatement_GET_ReauthenticateOnOrAfter) */
struct zx_str* zx_ff12_AuthenticationStatement_GET_ReauthenticateOnOrAfter(struct zx_ff12_AuthenticationStatement_s* x) { return x->ReauthenticateOnOrAfter; }
/* FUNC(zx_ff12_AuthenticationStatement_PUT_ReauthenticateOnOrAfter) */
void zx_ff12_AuthenticationStatement_PUT_ReauthenticateOnOrAfter(struct zx_ff12_AuthenticationStatement_s* x, struct zx_str* y) { x->ReauthenticateOnOrAfter = y; }
/* FUNC(zx_ff12_AuthenticationStatement_GET_SessionIndex) */
struct zx_str* zx_ff12_AuthenticationStatement_GET_SessionIndex(struct zx_ff12_AuthenticationStatement_s* x) { return x->SessionIndex; }
/* FUNC(zx_ff12_AuthenticationStatement_PUT_SessionIndex) */
void zx_ff12_AuthenticationStatement_PUT_SessionIndex(struct zx_ff12_AuthenticationStatement_s* x, struct zx_str* y) { x->SessionIndex = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnContext_NUM_AuthnContextClassRef) */

int zx_ff12_AuthnContext_NUM_AuthnContextClassRef(struct zx_ff12_AuthnContext_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthnContextClassRef; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnContext_GET_AuthnContextClassRef) */

struct zx_elem_s* zx_ff12_AuthnContext_GET_AuthnContextClassRef(struct zx_ff12_AuthnContext_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->AuthnContextClassRef; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnContext_POP_AuthnContextClassRef) */

struct zx_elem_s* zx_ff12_AuthnContext_POP_AuthnContextClassRef(struct zx_ff12_AuthnContext_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->AuthnContextClassRef;
  if (y)
    x->AuthnContextClassRef = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnContext_PUSH_AuthnContextClassRef) */

void zx_ff12_AuthnContext_PUSH_AuthnContextClassRef(struct zx_ff12_AuthnContext_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->AuthnContextClassRef->g;
  x->AuthnContextClassRef = z;
}

/* FUNC(zx_ff12_AuthnContext_REV_AuthnContextClassRef) */

void zx_ff12_AuthnContext_REV_AuthnContextClassRef(struct zx_ff12_AuthnContext_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->AuthnContextClassRef;
  if (!y) return;
  x->AuthnContextClassRef = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->AuthnContextClassRef->g;
    x->AuthnContextClassRef = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnContext_PUT_AuthnContextClassRef) */

void zx_ff12_AuthnContext_PUT_AuthnContextClassRef(struct zx_ff12_AuthnContext_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->AuthnContextClassRef;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->AuthnContextClassRef = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnContext_ADD_AuthnContextClassRef) */

void zx_ff12_AuthnContext_ADD_AuthnContextClassRef(struct zx_ff12_AuthnContext_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->AuthnContextClassRef->g;
    x->AuthnContextClassRef = z;
    return;
  case -1:
    y = x->AuthnContextClassRef;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AuthnContextClassRef; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnContext_DEL_AuthnContextClassRef) */

void zx_ff12_AuthnContext_DEL_AuthnContextClassRef(struct zx_ff12_AuthnContext_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthnContextClassRef = (struct zx_elem_s*)x->AuthnContextClassRef->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->AuthnContextClassRef;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AuthnContextClassRef; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnContext_NUM_AuthenticationContextStatement) */

int zx_ff12_AuthnContext_NUM_AuthenticationContextStatement(struct zx_ff12_AuthnContext_s* x)
{
  struct zx_ac_AuthenticationContextStatement_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthenticationContextStatement; y; ++n, y = (struct zx_ac_AuthenticationContextStatement_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnContext_GET_AuthenticationContextStatement) */

struct zx_ac_AuthenticationContextStatement_s* zx_ff12_AuthnContext_GET_AuthenticationContextStatement(struct zx_ff12_AuthnContext_s* x, int n)
{
  struct zx_ac_AuthenticationContextStatement_s* y;
  if (!x) return 0;
  for (y = x->AuthenticationContextStatement; n>=0 && y; --n, y = (struct zx_ac_AuthenticationContextStatement_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnContext_POP_AuthenticationContextStatement) */

struct zx_ac_AuthenticationContextStatement_s* zx_ff12_AuthnContext_POP_AuthenticationContextStatement(struct zx_ff12_AuthnContext_s* x)
{
  struct zx_ac_AuthenticationContextStatement_s* y;
  if (!x) return 0;
  y = x->AuthenticationContextStatement;
  if (y)
    x->AuthenticationContextStatement = (struct zx_ac_AuthenticationContextStatement_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnContext_PUSH_AuthenticationContextStatement) */

void zx_ff12_AuthnContext_PUSH_AuthenticationContextStatement(struct zx_ff12_AuthnContext_s* x, struct zx_ac_AuthenticationContextStatement_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->AuthenticationContextStatement->gg.g;
  x->AuthenticationContextStatement = z;
}

/* FUNC(zx_ff12_AuthnContext_REV_AuthenticationContextStatement) */

void zx_ff12_AuthnContext_REV_AuthenticationContextStatement(struct zx_ff12_AuthnContext_s* x)
{
  struct zx_ac_AuthenticationContextStatement_s* nxt;
  struct zx_ac_AuthenticationContextStatement_s* y;
  if (!x) return;
  y = x->AuthenticationContextStatement;
  if (!y) return;
  x->AuthenticationContextStatement = 0;
  while (y) {
    nxt = (struct zx_ac_AuthenticationContextStatement_s*)y->gg.g.n;
    y->gg.g.n = &x->AuthenticationContextStatement->gg.g;
    x->AuthenticationContextStatement = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnContext_PUT_AuthenticationContextStatement) */

void zx_ff12_AuthnContext_PUT_AuthenticationContextStatement(struct zx_ff12_AuthnContext_s* x, int n, struct zx_ac_AuthenticationContextStatement_s* z)
{
  struct zx_ac_AuthenticationContextStatement_s* y;
  if (!x || !z) return;
  y = x->AuthenticationContextStatement;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->AuthenticationContextStatement = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ac_AuthenticationContextStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnContext_ADD_AuthenticationContextStatement) */

void zx_ff12_AuthnContext_ADD_AuthenticationContextStatement(struct zx_ff12_AuthnContext_s* x, int n, struct zx_ac_AuthenticationContextStatement_s* z)
{
  struct zx_ac_AuthenticationContextStatement_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->AuthenticationContextStatement->gg.g;
    x->AuthenticationContextStatement = z;
    return;
  case -1:
    y = x->AuthenticationContextStatement;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ac_AuthenticationContextStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthenticationContextStatement; n > 1 && y; --n, y = (struct zx_ac_AuthenticationContextStatement_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnContext_DEL_AuthenticationContextStatement) */

void zx_ff12_AuthnContext_DEL_AuthenticationContextStatement(struct zx_ff12_AuthnContext_s* x, int n)
{
  struct zx_ac_AuthenticationContextStatement_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthenticationContextStatement = (struct zx_ac_AuthenticationContextStatement_s*)x->AuthenticationContextStatement->gg.g.n;
    return;
  case -1:
    y = (struct zx_ac_AuthenticationContextStatement_s*)x->AuthenticationContextStatement;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ac_AuthenticationContextStatement_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthenticationContextStatement; n > 1 && y->gg.g.n; --n, y = (struct zx_ac_AuthenticationContextStatement_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnContext_NUM_AuthnContextStatementRef) */

int zx_ff12_AuthnContext_NUM_AuthnContextStatementRef(struct zx_ff12_AuthnContext_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthnContextStatementRef; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnContext_GET_AuthnContextStatementRef) */

struct zx_elem_s* zx_ff12_AuthnContext_GET_AuthnContextStatementRef(struct zx_ff12_AuthnContext_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->AuthnContextStatementRef; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnContext_POP_AuthnContextStatementRef) */

struct zx_elem_s* zx_ff12_AuthnContext_POP_AuthnContextStatementRef(struct zx_ff12_AuthnContext_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->AuthnContextStatementRef;
  if (y)
    x->AuthnContextStatementRef = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnContext_PUSH_AuthnContextStatementRef) */

void zx_ff12_AuthnContext_PUSH_AuthnContextStatementRef(struct zx_ff12_AuthnContext_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->AuthnContextStatementRef->g;
  x->AuthnContextStatementRef = z;
}

/* FUNC(zx_ff12_AuthnContext_REV_AuthnContextStatementRef) */

void zx_ff12_AuthnContext_REV_AuthnContextStatementRef(struct zx_ff12_AuthnContext_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->AuthnContextStatementRef;
  if (!y) return;
  x->AuthnContextStatementRef = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->AuthnContextStatementRef->g;
    x->AuthnContextStatementRef = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnContext_PUT_AuthnContextStatementRef) */

void zx_ff12_AuthnContext_PUT_AuthnContextStatementRef(struct zx_ff12_AuthnContext_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->AuthnContextStatementRef;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->AuthnContextStatementRef = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnContext_ADD_AuthnContextStatementRef) */

void zx_ff12_AuthnContext_ADD_AuthnContextStatementRef(struct zx_ff12_AuthnContext_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->AuthnContextStatementRef->g;
    x->AuthnContextStatementRef = z;
    return;
  case -1:
    y = x->AuthnContextStatementRef;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AuthnContextStatementRef; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnContext_DEL_AuthnContextStatementRef) */

void zx_ff12_AuthnContext_DEL_AuthnContextStatementRef(struct zx_ff12_AuthnContext_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthnContextStatementRef = (struct zx_elem_s*)x->AuthnContextStatementRef->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->AuthnContextStatementRef;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AuthnContextStatementRef; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif








#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_RespondWith) */

int zx_ff12_AuthnRequest_NUM_RespondWith(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RespondWith; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_RespondWith) */

struct zx_elem_s* zx_ff12_AuthnRequest_GET_RespondWith(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->RespondWith; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_RespondWith) */

struct zx_elem_s* zx_ff12_AuthnRequest_POP_RespondWith(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->RespondWith;
  if (y)
    x->RespondWith = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_RespondWith) */

void zx_ff12_AuthnRequest_PUSH_RespondWith(struct zx_ff12_AuthnRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->RespondWith->g;
  x->RespondWith = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_RespondWith) */

void zx_ff12_AuthnRequest_REV_RespondWith(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->RespondWith;
  if (!y) return;
  x->RespondWith = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->RespondWith->g;
    x->RespondWith = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_RespondWith) */

void zx_ff12_AuthnRequest_PUT_RespondWith(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->RespondWith;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->RespondWith = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_RespondWith) */

void zx_ff12_AuthnRequest_ADD_RespondWith(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->RespondWith->g;
    x->RespondWith = z;
    return;
  case -1:
    y = x->RespondWith;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RespondWith; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_RespondWith) */

void zx_ff12_AuthnRequest_DEL_RespondWith(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RespondWith = (struct zx_elem_s*)x->RespondWith->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->RespondWith;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RespondWith; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_Signature) */

int zx_ff12_AuthnRequest_NUM_Signature(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ds_Signature_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Signature; y; ++n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_Signature) */

struct zx_ds_Signature_s* zx_ff12_AuthnRequest_GET_Signature(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  for (y = x->Signature; n>=0 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_Signature) */

struct zx_ds_Signature_s* zx_ff12_AuthnRequest_POP_Signature(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  y = x->Signature;
  if (y)
    x->Signature = (struct zx_ds_Signature_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_Signature) */

void zx_ff12_AuthnRequest_PUSH_Signature(struct zx_ff12_AuthnRequest_s* x, struct zx_ds_Signature_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Signature->gg.g;
  x->Signature = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_Signature) */

void zx_ff12_AuthnRequest_REV_Signature(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ds_Signature_s* nxt;
  struct zx_ds_Signature_s* y;
  if (!x) return;
  y = x->Signature;
  if (!y) return;
  x->Signature = 0;
  while (y) {
    nxt = (struct zx_ds_Signature_s*)y->gg.g.n;
    y->gg.g.n = &x->Signature->gg.g;
    x->Signature = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_Signature) */

void zx_ff12_AuthnRequest_PUT_Signature(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  y = x->Signature;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Signature = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_Signature) */

void zx_ff12_AuthnRequest_ADD_Signature(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Signature->gg.g;
    x->Signature = z;
    return;
  case -1:
    y = x->Signature;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_Signature) */

void zx_ff12_AuthnRequest_DEL_Signature(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Signature = (struct zx_ds_Signature_s*)x->Signature->gg.g.n;
    return;
  case -1:
    y = (struct zx_ds_Signature_s*)x->Signature;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_Extension) */

int zx_ff12_AuthnRequest_NUM_Extension(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ff12_Extension_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Extension; y; ++n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_Extension) */

struct zx_ff12_Extension_s* zx_ff12_AuthnRequest_GET_Extension(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  for (y = x->Extension; n>=0 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_Extension) */

struct zx_ff12_Extension_s* zx_ff12_AuthnRequest_POP_Extension(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  y = x->Extension;
  if (y)
    x->Extension = (struct zx_ff12_Extension_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_Extension) */

void zx_ff12_AuthnRequest_PUSH_Extension(struct zx_ff12_AuthnRequest_s* x, struct zx_ff12_Extension_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Extension->gg.g;
  x->Extension = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_Extension) */

void zx_ff12_AuthnRequest_REV_Extension(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ff12_Extension_s* nxt;
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  y = x->Extension;
  if (!y) return;
  x->Extension = 0;
  while (y) {
    nxt = (struct zx_ff12_Extension_s*)y->gg.g.n;
    y->gg.g.n = &x->Extension->gg.g;
    x->Extension = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_Extension) */

void zx_ff12_AuthnRequest_PUT_Extension(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  y = x->Extension;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Extension = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_Extension) */

void zx_ff12_AuthnRequest_ADD_Extension(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Extension->gg.g;
    x->Extension = z;
    return;
  case -1:
    y = x->Extension;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_Extension) */

void zx_ff12_AuthnRequest_DEL_Extension(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Extension = (struct zx_ff12_Extension_s*)x->Extension->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Extension_s*)x->Extension;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_ProviderID) */

int zx_ff12_AuthnRequest_NUM_ProviderID(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_ProviderID) */

struct zx_elem_s* zx_ff12_AuthnRequest_GET_ProviderID(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_ProviderID) */

struct zx_elem_s* zx_ff12_AuthnRequest_POP_ProviderID(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderID;
  if (y)
    x->ProviderID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_ProviderID) */

void zx_ff12_AuthnRequest_PUSH_ProviderID(struct zx_ff12_AuthnRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderID->g;
  x->ProviderID = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_ProviderID) */

void zx_ff12_AuthnRequest_REV_ProviderID(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderID;
  if (!y) return;
  x->ProviderID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderID->g;
    x->ProviderID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_ProviderID) */

void zx_ff12_AuthnRequest_PUT_ProviderID(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_ProviderID) */

void zx_ff12_AuthnRequest_ADD_ProviderID(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderID->g;
    x->ProviderID = z;
    return;
  case -1:
    y = x->ProviderID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_ProviderID) */

void zx_ff12_AuthnRequest_DEL_ProviderID(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderID = (struct zx_elem_s*)x->ProviderID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_AffiliationID) */

int zx_ff12_AuthnRequest_NUM_AffiliationID(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AffiliationID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_AffiliationID) */

struct zx_elem_s* zx_ff12_AuthnRequest_GET_AffiliationID(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->AffiliationID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_AffiliationID) */

struct zx_elem_s* zx_ff12_AuthnRequest_POP_AffiliationID(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->AffiliationID;
  if (y)
    x->AffiliationID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_AffiliationID) */

void zx_ff12_AuthnRequest_PUSH_AffiliationID(struct zx_ff12_AuthnRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->AffiliationID->g;
  x->AffiliationID = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_AffiliationID) */

void zx_ff12_AuthnRequest_REV_AffiliationID(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->AffiliationID;
  if (!y) return;
  x->AffiliationID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->AffiliationID->g;
    x->AffiliationID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_AffiliationID) */

void zx_ff12_AuthnRequest_PUT_AffiliationID(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->AffiliationID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->AffiliationID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_AffiliationID) */

void zx_ff12_AuthnRequest_ADD_AffiliationID(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->AffiliationID->g;
    x->AffiliationID = z;
    return;
  case -1:
    y = x->AffiliationID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AffiliationID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_AffiliationID) */

void zx_ff12_AuthnRequest_DEL_AffiliationID(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AffiliationID = (struct zx_elem_s*)x->AffiliationID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->AffiliationID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AffiliationID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_NameIDPolicy) */

int zx_ff12_AuthnRequest_NUM_NameIDPolicy(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->NameIDPolicy; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_NameIDPolicy) */

struct zx_elem_s* zx_ff12_AuthnRequest_GET_NameIDPolicy(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->NameIDPolicy; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_NameIDPolicy) */

struct zx_elem_s* zx_ff12_AuthnRequest_POP_NameIDPolicy(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->NameIDPolicy;
  if (y)
    x->NameIDPolicy = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_NameIDPolicy) */

void zx_ff12_AuthnRequest_PUSH_NameIDPolicy(struct zx_ff12_AuthnRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->NameIDPolicy->g;
  x->NameIDPolicy = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_NameIDPolicy) */

void zx_ff12_AuthnRequest_REV_NameIDPolicy(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->NameIDPolicy;
  if (!y) return;
  x->NameIDPolicy = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->NameIDPolicy->g;
    x->NameIDPolicy = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_NameIDPolicy) */

void zx_ff12_AuthnRequest_PUT_NameIDPolicy(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->NameIDPolicy;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->NameIDPolicy = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_NameIDPolicy) */

void zx_ff12_AuthnRequest_ADD_NameIDPolicy(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->NameIDPolicy->g;
    x->NameIDPolicy = z;
    return;
  case -1:
    y = x->NameIDPolicy;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->NameIDPolicy; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_NameIDPolicy) */

void zx_ff12_AuthnRequest_DEL_NameIDPolicy(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->NameIDPolicy = (struct zx_elem_s*)x->NameIDPolicy->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->NameIDPolicy;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->NameIDPolicy; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_ForceAuthn) */

int zx_ff12_AuthnRequest_NUM_ForceAuthn(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ForceAuthn; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_ForceAuthn) */

struct zx_elem_s* zx_ff12_AuthnRequest_GET_ForceAuthn(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ForceAuthn; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_ForceAuthn) */

struct zx_elem_s* zx_ff12_AuthnRequest_POP_ForceAuthn(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ForceAuthn;
  if (y)
    x->ForceAuthn = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_ForceAuthn) */

void zx_ff12_AuthnRequest_PUSH_ForceAuthn(struct zx_ff12_AuthnRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ForceAuthn->g;
  x->ForceAuthn = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_ForceAuthn) */

void zx_ff12_AuthnRequest_REV_ForceAuthn(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ForceAuthn;
  if (!y) return;
  x->ForceAuthn = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ForceAuthn->g;
    x->ForceAuthn = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_ForceAuthn) */

void zx_ff12_AuthnRequest_PUT_ForceAuthn(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ForceAuthn;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ForceAuthn = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_ForceAuthn) */

void zx_ff12_AuthnRequest_ADD_ForceAuthn(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ForceAuthn->g;
    x->ForceAuthn = z;
    return;
  case -1:
    y = x->ForceAuthn;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ForceAuthn; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_ForceAuthn) */

void zx_ff12_AuthnRequest_DEL_ForceAuthn(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ForceAuthn = (struct zx_elem_s*)x->ForceAuthn->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ForceAuthn;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ForceAuthn; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_IsPassive) */

int zx_ff12_AuthnRequest_NUM_IsPassive(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->IsPassive; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_IsPassive) */

struct zx_elem_s* zx_ff12_AuthnRequest_GET_IsPassive(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->IsPassive; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_IsPassive) */

struct zx_elem_s* zx_ff12_AuthnRequest_POP_IsPassive(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->IsPassive;
  if (y)
    x->IsPassive = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_IsPassive) */

void zx_ff12_AuthnRequest_PUSH_IsPassive(struct zx_ff12_AuthnRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->IsPassive->g;
  x->IsPassive = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_IsPassive) */

void zx_ff12_AuthnRequest_REV_IsPassive(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->IsPassive;
  if (!y) return;
  x->IsPassive = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->IsPassive->g;
    x->IsPassive = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_IsPassive) */

void zx_ff12_AuthnRequest_PUT_IsPassive(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->IsPassive;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->IsPassive = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_IsPassive) */

void zx_ff12_AuthnRequest_ADD_IsPassive(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->IsPassive->g;
    x->IsPassive = z;
    return;
  case -1:
    y = x->IsPassive;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->IsPassive; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_IsPassive) */

void zx_ff12_AuthnRequest_DEL_IsPassive(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->IsPassive = (struct zx_elem_s*)x->IsPassive->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->IsPassive;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->IsPassive; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_ProtocolProfile) */

int zx_ff12_AuthnRequest_NUM_ProtocolProfile(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProtocolProfile; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_ProtocolProfile) */

struct zx_elem_s* zx_ff12_AuthnRequest_GET_ProtocolProfile(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProtocolProfile; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_ProtocolProfile) */

struct zx_elem_s* zx_ff12_AuthnRequest_POP_ProtocolProfile(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProtocolProfile;
  if (y)
    x->ProtocolProfile = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_ProtocolProfile) */

void zx_ff12_AuthnRequest_PUSH_ProtocolProfile(struct zx_ff12_AuthnRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProtocolProfile->g;
  x->ProtocolProfile = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_ProtocolProfile) */

void zx_ff12_AuthnRequest_REV_ProtocolProfile(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProtocolProfile;
  if (!y) return;
  x->ProtocolProfile = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProtocolProfile->g;
    x->ProtocolProfile = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_ProtocolProfile) */

void zx_ff12_AuthnRequest_PUT_ProtocolProfile(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProtocolProfile;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProtocolProfile = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_ProtocolProfile) */

void zx_ff12_AuthnRequest_ADD_ProtocolProfile(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProtocolProfile->g;
    x->ProtocolProfile = z;
    return;
  case -1:
    y = x->ProtocolProfile;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProtocolProfile; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_ProtocolProfile) */

void zx_ff12_AuthnRequest_DEL_ProtocolProfile(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProtocolProfile = (struct zx_elem_s*)x->ProtocolProfile->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProtocolProfile;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProtocolProfile; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_AssertionConsumerServiceID) */

int zx_ff12_AuthnRequest_NUM_AssertionConsumerServiceID(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AssertionConsumerServiceID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_AssertionConsumerServiceID) */

struct zx_elem_s* zx_ff12_AuthnRequest_GET_AssertionConsumerServiceID(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->AssertionConsumerServiceID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_AssertionConsumerServiceID) */

struct zx_elem_s* zx_ff12_AuthnRequest_POP_AssertionConsumerServiceID(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->AssertionConsumerServiceID;
  if (y)
    x->AssertionConsumerServiceID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_AssertionConsumerServiceID) */

void zx_ff12_AuthnRequest_PUSH_AssertionConsumerServiceID(struct zx_ff12_AuthnRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->AssertionConsumerServiceID->g;
  x->AssertionConsumerServiceID = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_AssertionConsumerServiceID) */

void zx_ff12_AuthnRequest_REV_AssertionConsumerServiceID(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->AssertionConsumerServiceID;
  if (!y) return;
  x->AssertionConsumerServiceID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->AssertionConsumerServiceID->g;
    x->AssertionConsumerServiceID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_AssertionConsumerServiceID) */

void zx_ff12_AuthnRequest_PUT_AssertionConsumerServiceID(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->AssertionConsumerServiceID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->AssertionConsumerServiceID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_AssertionConsumerServiceID) */

void zx_ff12_AuthnRequest_ADD_AssertionConsumerServiceID(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->AssertionConsumerServiceID->g;
    x->AssertionConsumerServiceID = z;
    return;
  case -1:
    y = x->AssertionConsumerServiceID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AssertionConsumerServiceID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_AssertionConsumerServiceID) */

void zx_ff12_AuthnRequest_DEL_AssertionConsumerServiceID(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AssertionConsumerServiceID = (struct zx_elem_s*)x->AssertionConsumerServiceID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->AssertionConsumerServiceID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AssertionConsumerServiceID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_RequestAuthnContext) */

int zx_ff12_AuthnRequest_NUM_RequestAuthnContext(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ff12_RequestAuthnContext_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RequestAuthnContext; y; ++n, y = (struct zx_ff12_RequestAuthnContext_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_RequestAuthnContext) */

struct zx_ff12_RequestAuthnContext_s* zx_ff12_AuthnRequest_GET_RequestAuthnContext(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_ff12_RequestAuthnContext_s* y;
  if (!x) return 0;
  for (y = x->RequestAuthnContext; n>=0 && y; --n, y = (struct zx_ff12_RequestAuthnContext_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_RequestAuthnContext) */

struct zx_ff12_RequestAuthnContext_s* zx_ff12_AuthnRequest_POP_RequestAuthnContext(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ff12_RequestAuthnContext_s* y;
  if (!x) return 0;
  y = x->RequestAuthnContext;
  if (y)
    x->RequestAuthnContext = (struct zx_ff12_RequestAuthnContext_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_RequestAuthnContext) */

void zx_ff12_AuthnRequest_PUSH_RequestAuthnContext(struct zx_ff12_AuthnRequest_s* x, struct zx_ff12_RequestAuthnContext_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->RequestAuthnContext->gg.g;
  x->RequestAuthnContext = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_RequestAuthnContext) */

void zx_ff12_AuthnRequest_REV_RequestAuthnContext(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ff12_RequestAuthnContext_s* nxt;
  struct zx_ff12_RequestAuthnContext_s* y;
  if (!x) return;
  y = x->RequestAuthnContext;
  if (!y) return;
  x->RequestAuthnContext = 0;
  while (y) {
    nxt = (struct zx_ff12_RequestAuthnContext_s*)y->gg.g.n;
    y->gg.g.n = &x->RequestAuthnContext->gg.g;
    x->RequestAuthnContext = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_RequestAuthnContext) */

void zx_ff12_AuthnRequest_PUT_RequestAuthnContext(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_ff12_RequestAuthnContext_s* z)
{
  struct zx_ff12_RequestAuthnContext_s* y;
  if (!x || !z) return;
  y = x->RequestAuthnContext;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->RequestAuthnContext = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_RequestAuthnContext_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_RequestAuthnContext) */

void zx_ff12_AuthnRequest_ADD_RequestAuthnContext(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_ff12_RequestAuthnContext_s* z)
{
  struct zx_ff12_RequestAuthnContext_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->RequestAuthnContext->gg.g;
    x->RequestAuthnContext = z;
    return;
  case -1:
    y = x->RequestAuthnContext;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_RequestAuthnContext_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->RequestAuthnContext; n > 1 && y; --n, y = (struct zx_ff12_RequestAuthnContext_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_RequestAuthnContext) */

void zx_ff12_AuthnRequest_DEL_RequestAuthnContext(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_ff12_RequestAuthnContext_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RequestAuthnContext = (struct zx_ff12_RequestAuthnContext_s*)x->RequestAuthnContext->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_RequestAuthnContext_s*)x->RequestAuthnContext;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_RequestAuthnContext_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->RequestAuthnContext; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_RequestAuthnContext_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_RelayState) */

int zx_ff12_AuthnRequest_NUM_RelayState(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RelayState; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_RelayState) */

struct zx_elem_s* zx_ff12_AuthnRequest_GET_RelayState(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->RelayState; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_RelayState) */

struct zx_elem_s* zx_ff12_AuthnRequest_POP_RelayState(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->RelayState;
  if (y)
    x->RelayState = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_RelayState) */

void zx_ff12_AuthnRequest_PUSH_RelayState(struct zx_ff12_AuthnRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->RelayState->g;
  x->RelayState = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_RelayState) */

void zx_ff12_AuthnRequest_REV_RelayState(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->RelayState;
  if (!y) return;
  x->RelayState = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->RelayState->g;
    x->RelayState = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_RelayState) */

void zx_ff12_AuthnRequest_PUT_RelayState(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->RelayState;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->RelayState = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_RelayState) */

void zx_ff12_AuthnRequest_ADD_RelayState(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->RelayState->g;
    x->RelayState = z;
    return;
  case -1:
    y = x->RelayState;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_RelayState) */

void zx_ff12_AuthnRequest_DEL_RelayState(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RelayState = (struct zx_elem_s*)x->RelayState->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->RelayState;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequest_NUM_Scoping) */

int zx_ff12_AuthnRequest_NUM_Scoping(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ff12_Scoping_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Scoping; y; ++n, y = (struct zx_ff12_Scoping_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequest_GET_Scoping) */

struct zx_ff12_Scoping_s* zx_ff12_AuthnRequest_GET_Scoping(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_ff12_Scoping_s* y;
  if (!x) return 0;
  for (y = x->Scoping; n>=0 && y; --n, y = (struct zx_ff12_Scoping_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_POP_Scoping) */

struct zx_ff12_Scoping_s* zx_ff12_AuthnRequest_POP_Scoping(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ff12_Scoping_s* y;
  if (!x) return 0;
  y = x->Scoping;
  if (y)
    x->Scoping = (struct zx_ff12_Scoping_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequest_PUSH_Scoping) */

void zx_ff12_AuthnRequest_PUSH_Scoping(struct zx_ff12_AuthnRequest_s* x, struct zx_ff12_Scoping_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Scoping->gg.g;
  x->Scoping = z;
}

/* FUNC(zx_ff12_AuthnRequest_REV_Scoping) */

void zx_ff12_AuthnRequest_REV_Scoping(struct zx_ff12_AuthnRequest_s* x)
{
  struct zx_ff12_Scoping_s* nxt;
  struct zx_ff12_Scoping_s* y;
  if (!x) return;
  y = x->Scoping;
  if (!y) return;
  x->Scoping = 0;
  while (y) {
    nxt = (struct zx_ff12_Scoping_s*)y->gg.g.n;
    y->gg.g.n = &x->Scoping->gg.g;
    x->Scoping = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequest_PUT_Scoping) */

void zx_ff12_AuthnRequest_PUT_Scoping(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_ff12_Scoping_s* z)
{
  struct zx_ff12_Scoping_s* y;
  if (!x || !z) return;
  y = x->Scoping;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Scoping = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Scoping_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnRequest_ADD_Scoping) */

void zx_ff12_AuthnRequest_ADD_Scoping(struct zx_ff12_AuthnRequest_s* x, int n, struct zx_ff12_Scoping_s* z)
{
  struct zx_ff12_Scoping_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Scoping->gg.g;
    x->Scoping = z;
    return;
  case -1:
    y = x->Scoping;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Scoping_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Scoping; n > 1 && y; --n, y = (struct zx_ff12_Scoping_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnRequest_DEL_Scoping) */

void zx_ff12_AuthnRequest_DEL_Scoping(struct zx_ff12_AuthnRequest_s* x, int n)
{
  struct zx_ff12_Scoping_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Scoping = (struct zx_ff12_Scoping_s*)x->Scoping->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Scoping_s*)x->Scoping;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Scoping_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Scoping; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Scoping_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif

/* FUNC(zx_ff12_AuthnRequest_GET_IssueInstant) */
struct zx_str* zx_ff12_AuthnRequest_GET_IssueInstant(struct zx_ff12_AuthnRequest_s* x) { return x->IssueInstant; }
/* FUNC(zx_ff12_AuthnRequest_PUT_IssueInstant) */
void zx_ff12_AuthnRequest_PUT_IssueInstant(struct zx_ff12_AuthnRequest_s* x, struct zx_str* y) { x->IssueInstant = y; }
/* FUNC(zx_ff12_AuthnRequest_GET_MajorVersion) */
struct zx_str* zx_ff12_AuthnRequest_GET_MajorVersion(struct zx_ff12_AuthnRequest_s* x) { return x->MajorVersion; }
/* FUNC(zx_ff12_AuthnRequest_PUT_MajorVersion) */
void zx_ff12_AuthnRequest_PUT_MajorVersion(struct zx_ff12_AuthnRequest_s* x, struct zx_str* y) { x->MajorVersion = y; }
/* FUNC(zx_ff12_AuthnRequest_GET_MinorVersion) */
struct zx_str* zx_ff12_AuthnRequest_GET_MinorVersion(struct zx_ff12_AuthnRequest_s* x) { return x->MinorVersion; }
/* FUNC(zx_ff12_AuthnRequest_PUT_MinorVersion) */
void zx_ff12_AuthnRequest_PUT_MinorVersion(struct zx_ff12_AuthnRequest_s* x, struct zx_str* y) { x->MinorVersion = y; }
/* FUNC(zx_ff12_AuthnRequest_GET_RequestID) */
struct zx_str* zx_ff12_AuthnRequest_GET_RequestID(struct zx_ff12_AuthnRequest_s* x) { return x->RequestID; }
/* FUNC(zx_ff12_AuthnRequest_PUT_RequestID) */
void zx_ff12_AuthnRequest_PUT_RequestID(struct zx_ff12_AuthnRequest_s* x, struct zx_str* y) { x->RequestID = y; }
/* FUNC(zx_ff12_AuthnRequest_GET_consent) */
struct zx_str* zx_ff12_AuthnRequest_GET_consent(struct zx_ff12_AuthnRequest_s* x) { return x->consent; }
/* FUNC(zx_ff12_AuthnRequest_PUT_consent) */
void zx_ff12_AuthnRequest_PUT_consent(struct zx_ff12_AuthnRequest_s* x, struct zx_str* y) { x->consent = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequestEnvelope_NUM_Extension) */

int zx_ff12_AuthnRequestEnvelope_NUM_Extension(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_ff12_Extension_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Extension; y; ++n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_GET_Extension) */

struct zx_ff12_Extension_s* zx_ff12_AuthnRequestEnvelope_GET_Extension(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  for (y = x->Extension; n>=0 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_POP_Extension) */

struct zx_ff12_Extension_s* zx_ff12_AuthnRequestEnvelope_POP_Extension(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  y = x->Extension;
  if (y)
    x->Extension = (struct zx_ff12_Extension_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUSH_Extension) */

void zx_ff12_AuthnRequestEnvelope_PUSH_Extension(struct zx_ff12_AuthnRequestEnvelope_s* x, struct zx_ff12_Extension_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Extension->gg.g;
  x->Extension = z;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_REV_Extension) */

void zx_ff12_AuthnRequestEnvelope_REV_Extension(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_ff12_Extension_s* nxt;
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  y = x->Extension;
  if (!y) return;
  x->Extension = 0;
  while (y) {
    nxt = (struct zx_ff12_Extension_s*)y->gg.g.n;
    y->gg.g.n = &x->Extension->gg.g;
    x->Extension = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUT_Extension) */

void zx_ff12_AuthnRequestEnvelope_PUT_Extension(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  y = x->Extension;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Extension = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_ADD_Extension) */

void zx_ff12_AuthnRequestEnvelope_ADD_Extension(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Extension->gg.g;
    x->Extension = z;
    return;
  case -1:
    y = x->Extension;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_DEL_Extension) */

void zx_ff12_AuthnRequestEnvelope_DEL_Extension(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Extension = (struct zx_ff12_Extension_s*)x->Extension->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Extension_s*)x->Extension;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequestEnvelope_NUM_AuthnRequest) */

int zx_ff12_AuthnRequestEnvelope_NUM_AuthnRequest(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_ff12_AuthnRequest_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthnRequest; y; ++n, y = (struct zx_ff12_AuthnRequest_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_GET_AuthnRequest) */

struct zx_ff12_AuthnRequest_s* zx_ff12_AuthnRequestEnvelope_GET_AuthnRequest(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_ff12_AuthnRequest_s* y;
  if (!x) return 0;
  for (y = x->AuthnRequest; n>=0 && y; --n, y = (struct zx_ff12_AuthnRequest_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_POP_AuthnRequest) */

struct zx_ff12_AuthnRequest_s* zx_ff12_AuthnRequestEnvelope_POP_AuthnRequest(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_ff12_AuthnRequest_s* y;
  if (!x) return 0;
  y = x->AuthnRequest;
  if (y)
    x->AuthnRequest = (struct zx_ff12_AuthnRequest_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUSH_AuthnRequest) */

void zx_ff12_AuthnRequestEnvelope_PUSH_AuthnRequest(struct zx_ff12_AuthnRequestEnvelope_s* x, struct zx_ff12_AuthnRequest_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->AuthnRequest->gg.g;
  x->AuthnRequest = z;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_REV_AuthnRequest) */

void zx_ff12_AuthnRequestEnvelope_REV_AuthnRequest(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_ff12_AuthnRequest_s* nxt;
  struct zx_ff12_AuthnRequest_s* y;
  if (!x) return;
  y = x->AuthnRequest;
  if (!y) return;
  x->AuthnRequest = 0;
  while (y) {
    nxt = (struct zx_ff12_AuthnRequest_s*)y->gg.g.n;
    y->gg.g.n = &x->AuthnRequest->gg.g;
    x->AuthnRequest = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUT_AuthnRequest) */

void zx_ff12_AuthnRequestEnvelope_PUT_AuthnRequest(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_ff12_AuthnRequest_s* z)
{
  struct zx_ff12_AuthnRequest_s* y;
  if (!x || !z) return;
  y = x->AuthnRequest;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->AuthnRequest = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_AuthnRequest_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_ADD_AuthnRequest) */

void zx_ff12_AuthnRequestEnvelope_ADD_AuthnRequest(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_ff12_AuthnRequest_s* z)
{
  struct zx_ff12_AuthnRequest_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->AuthnRequest->gg.g;
    x->AuthnRequest = z;
    return;
  case -1:
    y = x->AuthnRequest;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_AuthnRequest_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthnRequest; n > 1 && y; --n, y = (struct zx_ff12_AuthnRequest_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_DEL_AuthnRequest) */

void zx_ff12_AuthnRequestEnvelope_DEL_AuthnRequest(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_ff12_AuthnRequest_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthnRequest = (struct zx_ff12_AuthnRequest_s*)x->AuthnRequest->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_AuthnRequest_s*)x->AuthnRequest;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_AuthnRequest_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthnRequest; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_AuthnRequest_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequestEnvelope_NUM_ProviderID) */

int zx_ff12_AuthnRequestEnvelope_NUM_ProviderID(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_GET_ProviderID) */

struct zx_elem_s* zx_ff12_AuthnRequestEnvelope_GET_ProviderID(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_POP_ProviderID) */

struct zx_elem_s* zx_ff12_AuthnRequestEnvelope_POP_ProviderID(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderID;
  if (y)
    x->ProviderID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUSH_ProviderID) */

void zx_ff12_AuthnRequestEnvelope_PUSH_ProviderID(struct zx_ff12_AuthnRequestEnvelope_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderID->g;
  x->ProviderID = z;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_REV_ProviderID) */

void zx_ff12_AuthnRequestEnvelope_REV_ProviderID(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderID;
  if (!y) return;
  x->ProviderID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderID->g;
    x->ProviderID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUT_ProviderID) */

void zx_ff12_AuthnRequestEnvelope_PUT_ProviderID(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_ADD_ProviderID) */

void zx_ff12_AuthnRequestEnvelope_ADD_ProviderID(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderID->g;
    x->ProviderID = z;
    return;
  case -1:
    y = x->ProviderID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_DEL_ProviderID) */

void zx_ff12_AuthnRequestEnvelope_DEL_ProviderID(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderID = (struct zx_elem_s*)x->ProviderID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequestEnvelope_NUM_ProviderName) */

int zx_ff12_AuthnRequestEnvelope_NUM_ProviderName(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderName; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_GET_ProviderName) */

struct zx_elem_s* zx_ff12_AuthnRequestEnvelope_GET_ProviderName(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderName; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_POP_ProviderName) */

struct zx_elem_s* zx_ff12_AuthnRequestEnvelope_POP_ProviderName(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderName;
  if (y)
    x->ProviderName = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUSH_ProviderName) */

void zx_ff12_AuthnRequestEnvelope_PUSH_ProviderName(struct zx_ff12_AuthnRequestEnvelope_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderName->g;
  x->ProviderName = z;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_REV_ProviderName) */

void zx_ff12_AuthnRequestEnvelope_REV_ProviderName(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderName;
  if (!y) return;
  x->ProviderName = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderName->g;
    x->ProviderName = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUT_ProviderName) */

void zx_ff12_AuthnRequestEnvelope_PUT_ProviderName(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderName;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderName = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_ADD_ProviderName) */

void zx_ff12_AuthnRequestEnvelope_ADD_ProviderName(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderName->g;
    x->ProviderName = z;
    return;
  case -1:
    y = x->ProviderName;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderName; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_DEL_ProviderName) */

void zx_ff12_AuthnRequestEnvelope_DEL_ProviderName(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderName = (struct zx_elem_s*)x->ProviderName->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderName;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderName; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequestEnvelope_NUM_AssertionConsumerServiceURL) */

int zx_ff12_AuthnRequestEnvelope_NUM_AssertionConsumerServiceURL(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AssertionConsumerServiceURL; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_GET_AssertionConsumerServiceURL) */

struct zx_elem_s* zx_ff12_AuthnRequestEnvelope_GET_AssertionConsumerServiceURL(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->AssertionConsumerServiceURL; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_POP_AssertionConsumerServiceURL) */

struct zx_elem_s* zx_ff12_AuthnRequestEnvelope_POP_AssertionConsumerServiceURL(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->AssertionConsumerServiceURL;
  if (y)
    x->AssertionConsumerServiceURL = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUSH_AssertionConsumerServiceURL) */

void zx_ff12_AuthnRequestEnvelope_PUSH_AssertionConsumerServiceURL(struct zx_ff12_AuthnRequestEnvelope_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->AssertionConsumerServiceURL->g;
  x->AssertionConsumerServiceURL = z;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_REV_AssertionConsumerServiceURL) */

void zx_ff12_AuthnRequestEnvelope_REV_AssertionConsumerServiceURL(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->AssertionConsumerServiceURL;
  if (!y) return;
  x->AssertionConsumerServiceURL = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->AssertionConsumerServiceURL->g;
    x->AssertionConsumerServiceURL = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUT_AssertionConsumerServiceURL) */

void zx_ff12_AuthnRequestEnvelope_PUT_AssertionConsumerServiceURL(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->AssertionConsumerServiceURL;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->AssertionConsumerServiceURL = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_ADD_AssertionConsumerServiceURL) */

void zx_ff12_AuthnRequestEnvelope_ADD_AssertionConsumerServiceURL(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->AssertionConsumerServiceURL->g;
    x->AssertionConsumerServiceURL = z;
    return;
  case -1:
    y = x->AssertionConsumerServiceURL;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AssertionConsumerServiceURL; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_DEL_AssertionConsumerServiceURL) */

void zx_ff12_AuthnRequestEnvelope_DEL_AssertionConsumerServiceURL(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AssertionConsumerServiceURL = (struct zx_elem_s*)x->AssertionConsumerServiceURL->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->AssertionConsumerServiceURL;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AssertionConsumerServiceURL; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequestEnvelope_NUM_IDPList) */

int zx_ff12_AuthnRequestEnvelope_NUM_IDPList(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_ff12_IDPList_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->IDPList; y; ++n, y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_GET_IDPList) */

struct zx_ff12_IDPList_s* zx_ff12_AuthnRequestEnvelope_GET_IDPList(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_ff12_IDPList_s* y;
  if (!x) return 0;
  for (y = x->IDPList; n>=0 && y; --n, y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_POP_IDPList) */

struct zx_ff12_IDPList_s* zx_ff12_AuthnRequestEnvelope_POP_IDPList(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_ff12_IDPList_s* y;
  if (!x) return 0;
  y = x->IDPList;
  if (y)
    x->IDPList = (struct zx_ff12_IDPList_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUSH_IDPList) */

void zx_ff12_AuthnRequestEnvelope_PUSH_IDPList(struct zx_ff12_AuthnRequestEnvelope_s* x, struct zx_ff12_IDPList_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->IDPList->gg.g;
  x->IDPList = z;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_REV_IDPList) */

void zx_ff12_AuthnRequestEnvelope_REV_IDPList(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_ff12_IDPList_s* nxt;
  struct zx_ff12_IDPList_s* y;
  if (!x) return;
  y = x->IDPList;
  if (!y) return;
  x->IDPList = 0;
  while (y) {
    nxt = (struct zx_ff12_IDPList_s*)y->gg.g.n;
    y->gg.g.n = &x->IDPList->gg.g;
    x->IDPList = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUT_IDPList) */

void zx_ff12_AuthnRequestEnvelope_PUT_IDPList(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_ff12_IDPList_s* z)
{
  struct zx_ff12_IDPList_s* y;
  if (!x || !z) return;
  y = x->IDPList;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->IDPList = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_ADD_IDPList) */

void zx_ff12_AuthnRequestEnvelope_ADD_IDPList(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_ff12_IDPList_s* z)
{
  struct zx_ff12_IDPList_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->IDPList->gg.g;
    x->IDPList = z;
    return;
  case -1:
    y = x->IDPList;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPList; n > 1 && y; --n, y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_DEL_IDPList) */

void zx_ff12_AuthnRequestEnvelope_DEL_IDPList(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_ff12_IDPList_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->IDPList = (struct zx_ff12_IDPList_s*)x->IDPList->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_IDPList_s*)x->IDPList;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPList; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnRequestEnvelope_NUM_IsPassive) */

int zx_ff12_AuthnRequestEnvelope_NUM_IsPassive(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->IsPassive; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_GET_IsPassive) */

struct zx_elem_s* zx_ff12_AuthnRequestEnvelope_GET_IsPassive(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->IsPassive; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_POP_IsPassive) */

struct zx_elem_s* zx_ff12_AuthnRequestEnvelope_POP_IsPassive(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->IsPassive;
  if (y)
    x->IsPassive = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUSH_IsPassive) */

void zx_ff12_AuthnRequestEnvelope_PUSH_IsPassive(struct zx_ff12_AuthnRequestEnvelope_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->IsPassive->g;
  x->IsPassive = z;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_REV_IsPassive) */

void zx_ff12_AuthnRequestEnvelope_REV_IsPassive(struct zx_ff12_AuthnRequestEnvelope_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->IsPassive;
  if (!y) return;
  x->IsPassive = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->IsPassive->g;
    x->IsPassive = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_PUT_IsPassive) */

void zx_ff12_AuthnRequestEnvelope_PUT_IsPassive(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->IsPassive;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->IsPassive = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_ADD_IsPassive) */

void zx_ff12_AuthnRequestEnvelope_ADD_IsPassive(struct zx_ff12_AuthnRequestEnvelope_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->IsPassive->g;
    x->IsPassive = z;
    return;
  case -1:
    y = x->IsPassive;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->IsPassive; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnRequestEnvelope_DEL_IsPassive) */

void zx_ff12_AuthnRequestEnvelope_DEL_IsPassive(struct zx_ff12_AuthnRequestEnvelope_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->IsPassive = (struct zx_elem_s*)x->IsPassive->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->IsPassive;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->IsPassive; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif








#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnResponse_NUM_Signature) */

int zx_ff12_AuthnResponse_NUM_Signature(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_ds_Signature_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Signature; y; ++n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnResponse_GET_Signature) */

struct zx_ds_Signature_s* zx_ff12_AuthnResponse_GET_Signature(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  for (y = x->Signature; n>=0 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_POP_Signature) */

struct zx_ds_Signature_s* zx_ff12_AuthnResponse_POP_Signature(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  y = x->Signature;
  if (y)
    x->Signature = (struct zx_ds_Signature_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_PUSH_Signature) */

void zx_ff12_AuthnResponse_PUSH_Signature(struct zx_ff12_AuthnResponse_s* x, struct zx_ds_Signature_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Signature->gg.g;
  x->Signature = z;
}

/* FUNC(zx_ff12_AuthnResponse_REV_Signature) */

void zx_ff12_AuthnResponse_REV_Signature(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_ds_Signature_s* nxt;
  struct zx_ds_Signature_s* y;
  if (!x) return;
  y = x->Signature;
  if (!y) return;
  x->Signature = 0;
  while (y) {
    nxt = (struct zx_ds_Signature_s*)y->gg.g.n;
    y->gg.g.n = &x->Signature->gg.g;
    x->Signature = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnResponse_PUT_Signature) */

void zx_ff12_AuthnResponse_PUT_Signature(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  y = x->Signature;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Signature = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnResponse_ADD_Signature) */

void zx_ff12_AuthnResponse_ADD_Signature(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Signature->gg.g;
    x->Signature = z;
    return;
  case -1:
    y = x->Signature;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnResponse_DEL_Signature) */

void zx_ff12_AuthnResponse_DEL_Signature(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Signature = (struct zx_ds_Signature_s*)x->Signature->gg.g.n;
    return;
  case -1:
    y = (struct zx_ds_Signature_s*)x->Signature;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnResponse_NUM_Status) */

int zx_ff12_AuthnResponse_NUM_Status(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_sp11_Status_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Status; y; ++n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnResponse_GET_Status) */

struct zx_sp11_Status_s* zx_ff12_AuthnResponse_GET_Status(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_sp11_Status_s* y;
  if (!x) return 0;
  for (y = x->Status; n>=0 && y; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_POP_Status) */

struct zx_sp11_Status_s* zx_ff12_AuthnResponse_POP_Status(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_sp11_Status_s* y;
  if (!x) return 0;
  y = x->Status;
  if (y)
    x->Status = (struct zx_sp11_Status_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_PUSH_Status) */

void zx_ff12_AuthnResponse_PUSH_Status(struct zx_ff12_AuthnResponse_s* x, struct zx_sp11_Status_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Status->gg.g;
  x->Status = z;
}

/* FUNC(zx_ff12_AuthnResponse_REV_Status) */

void zx_ff12_AuthnResponse_REV_Status(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_sp11_Status_s* nxt;
  struct zx_sp11_Status_s* y;
  if (!x) return;
  y = x->Status;
  if (!y) return;
  x->Status = 0;
  while (y) {
    nxt = (struct zx_sp11_Status_s*)y->gg.g.n;
    y->gg.g.n = &x->Status->gg.g;
    x->Status = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnResponse_PUT_Status) */

void zx_ff12_AuthnResponse_PUT_Status(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_sp11_Status_s* z)
{
  struct zx_sp11_Status_s* y;
  if (!x || !z) return;
  y = x->Status;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Status = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnResponse_ADD_Status) */

void zx_ff12_AuthnResponse_ADD_Status(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_sp11_Status_s* z)
{
  struct zx_sp11_Status_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Status->gg.g;
    x->Status = z;
    return;
  case -1:
    y = x->Status;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Status; n > 1 && y; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnResponse_DEL_Status) */

void zx_ff12_AuthnResponse_DEL_Status(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_sp11_Status_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Status = (struct zx_sp11_Status_s*)x->Status->gg.g.n;
    return;
  case -1:
    y = (struct zx_sp11_Status_s*)x->Status;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Status; n > 1 && y->gg.g.n; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnResponse_NUM_Assertion) */

int zx_ff12_AuthnResponse_NUM_Assertion(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_sa11_Assertion_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Assertion; y; ++n, y = (struct zx_sa11_Assertion_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnResponse_GET_Assertion) */

struct zx_sa11_Assertion_s* zx_ff12_AuthnResponse_GET_Assertion(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_sa11_Assertion_s* y;
  if (!x) return 0;
  for (y = x->Assertion; n>=0 && y; --n, y = (struct zx_sa11_Assertion_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_POP_Assertion) */

struct zx_sa11_Assertion_s* zx_ff12_AuthnResponse_POP_Assertion(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_sa11_Assertion_s* y;
  if (!x) return 0;
  y = x->Assertion;
  if (y)
    x->Assertion = (struct zx_sa11_Assertion_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_PUSH_Assertion) */

void zx_ff12_AuthnResponse_PUSH_Assertion(struct zx_ff12_AuthnResponse_s* x, struct zx_sa11_Assertion_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Assertion->gg.g;
  x->Assertion = z;
}

/* FUNC(zx_ff12_AuthnResponse_REV_Assertion) */

void zx_ff12_AuthnResponse_REV_Assertion(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_sa11_Assertion_s* nxt;
  struct zx_sa11_Assertion_s* y;
  if (!x) return;
  y = x->Assertion;
  if (!y) return;
  x->Assertion = 0;
  while (y) {
    nxt = (struct zx_sa11_Assertion_s*)y->gg.g.n;
    y->gg.g.n = &x->Assertion->gg.g;
    x->Assertion = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnResponse_PUT_Assertion) */

void zx_ff12_AuthnResponse_PUT_Assertion(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_sa11_Assertion_s* z)
{
  struct zx_sa11_Assertion_s* y;
  if (!x || !z) return;
  y = x->Assertion;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Assertion = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_Assertion_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnResponse_ADD_Assertion) */

void zx_ff12_AuthnResponse_ADD_Assertion(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_sa11_Assertion_s* z)
{
  struct zx_sa11_Assertion_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Assertion->gg.g;
    x->Assertion = z;
    return;
  case -1:
    y = x->Assertion;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_Assertion_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Assertion; n > 1 && y; --n, y = (struct zx_sa11_Assertion_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnResponse_DEL_Assertion) */

void zx_ff12_AuthnResponse_DEL_Assertion(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_sa11_Assertion_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Assertion = (struct zx_sa11_Assertion_s*)x->Assertion->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_Assertion_s*)x->Assertion;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_Assertion_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Assertion; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_Assertion_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnResponse_NUM_Extension) */

int zx_ff12_AuthnResponse_NUM_Extension(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_ff12_Extension_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Extension; y; ++n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnResponse_GET_Extension) */

struct zx_ff12_Extension_s* zx_ff12_AuthnResponse_GET_Extension(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  for (y = x->Extension; n>=0 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_POP_Extension) */

struct zx_ff12_Extension_s* zx_ff12_AuthnResponse_POP_Extension(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  y = x->Extension;
  if (y)
    x->Extension = (struct zx_ff12_Extension_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_PUSH_Extension) */

void zx_ff12_AuthnResponse_PUSH_Extension(struct zx_ff12_AuthnResponse_s* x, struct zx_ff12_Extension_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Extension->gg.g;
  x->Extension = z;
}

/* FUNC(zx_ff12_AuthnResponse_REV_Extension) */

void zx_ff12_AuthnResponse_REV_Extension(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_ff12_Extension_s* nxt;
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  y = x->Extension;
  if (!y) return;
  x->Extension = 0;
  while (y) {
    nxt = (struct zx_ff12_Extension_s*)y->gg.g.n;
    y->gg.g.n = &x->Extension->gg.g;
    x->Extension = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnResponse_PUT_Extension) */

void zx_ff12_AuthnResponse_PUT_Extension(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  y = x->Extension;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Extension = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnResponse_ADD_Extension) */

void zx_ff12_AuthnResponse_ADD_Extension(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Extension->gg.g;
    x->Extension = z;
    return;
  case -1:
    y = x->Extension;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnResponse_DEL_Extension) */

void zx_ff12_AuthnResponse_DEL_Extension(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Extension = (struct zx_ff12_Extension_s*)x->Extension->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Extension_s*)x->Extension;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnResponse_NUM_ProviderID) */

int zx_ff12_AuthnResponse_NUM_ProviderID(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnResponse_GET_ProviderID) */

struct zx_elem_s* zx_ff12_AuthnResponse_GET_ProviderID(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_POP_ProviderID) */

struct zx_elem_s* zx_ff12_AuthnResponse_POP_ProviderID(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderID;
  if (y)
    x->ProviderID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_PUSH_ProviderID) */

void zx_ff12_AuthnResponse_PUSH_ProviderID(struct zx_ff12_AuthnResponse_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderID->g;
  x->ProviderID = z;
}

/* FUNC(zx_ff12_AuthnResponse_REV_ProviderID) */

void zx_ff12_AuthnResponse_REV_ProviderID(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderID;
  if (!y) return;
  x->ProviderID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderID->g;
    x->ProviderID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnResponse_PUT_ProviderID) */

void zx_ff12_AuthnResponse_PUT_ProviderID(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnResponse_ADD_ProviderID) */

void zx_ff12_AuthnResponse_ADD_ProviderID(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderID->g;
    x->ProviderID = z;
    return;
  case -1:
    y = x->ProviderID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnResponse_DEL_ProviderID) */

void zx_ff12_AuthnResponse_DEL_ProviderID(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderID = (struct zx_elem_s*)x->ProviderID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnResponse_NUM_RelayState) */

int zx_ff12_AuthnResponse_NUM_RelayState(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RelayState; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnResponse_GET_RelayState) */

struct zx_elem_s* zx_ff12_AuthnResponse_GET_RelayState(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->RelayState; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_POP_RelayState) */

struct zx_elem_s* zx_ff12_AuthnResponse_POP_RelayState(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->RelayState;
  if (y)
    x->RelayState = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnResponse_PUSH_RelayState) */

void zx_ff12_AuthnResponse_PUSH_RelayState(struct zx_ff12_AuthnResponse_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->RelayState->g;
  x->RelayState = z;
}

/* FUNC(zx_ff12_AuthnResponse_REV_RelayState) */

void zx_ff12_AuthnResponse_REV_RelayState(struct zx_ff12_AuthnResponse_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->RelayState;
  if (!y) return;
  x->RelayState = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->RelayState->g;
    x->RelayState = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnResponse_PUT_RelayState) */

void zx_ff12_AuthnResponse_PUT_RelayState(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->RelayState;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->RelayState = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnResponse_ADD_RelayState) */

void zx_ff12_AuthnResponse_ADD_RelayState(struct zx_ff12_AuthnResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->RelayState->g;
    x->RelayState = z;
    return;
  case -1:
    y = x->RelayState;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnResponse_DEL_RelayState) */

void zx_ff12_AuthnResponse_DEL_RelayState(struct zx_ff12_AuthnResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RelayState = (struct zx_elem_s*)x->RelayState->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->RelayState;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif

/* FUNC(zx_ff12_AuthnResponse_GET_InResponseTo) */
struct zx_str* zx_ff12_AuthnResponse_GET_InResponseTo(struct zx_ff12_AuthnResponse_s* x) { return x->InResponseTo; }
/* FUNC(zx_ff12_AuthnResponse_PUT_InResponseTo) */
void zx_ff12_AuthnResponse_PUT_InResponseTo(struct zx_ff12_AuthnResponse_s* x, struct zx_str* y) { x->InResponseTo = y; }
/* FUNC(zx_ff12_AuthnResponse_GET_IssueInstant) */
struct zx_str* zx_ff12_AuthnResponse_GET_IssueInstant(struct zx_ff12_AuthnResponse_s* x) { return x->IssueInstant; }
/* FUNC(zx_ff12_AuthnResponse_PUT_IssueInstant) */
void zx_ff12_AuthnResponse_PUT_IssueInstant(struct zx_ff12_AuthnResponse_s* x, struct zx_str* y) { x->IssueInstant = y; }
/* FUNC(zx_ff12_AuthnResponse_GET_MajorVersion) */
struct zx_str* zx_ff12_AuthnResponse_GET_MajorVersion(struct zx_ff12_AuthnResponse_s* x) { return x->MajorVersion; }
/* FUNC(zx_ff12_AuthnResponse_PUT_MajorVersion) */
void zx_ff12_AuthnResponse_PUT_MajorVersion(struct zx_ff12_AuthnResponse_s* x, struct zx_str* y) { x->MajorVersion = y; }
/* FUNC(zx_ff12_AuthnResponse_GET_MinorVersion) */
struct zx_str* zx_ff12_AuthnResponse_GET_MinorVersion(struct zx_ff12_AuthnResponse_s* x) { return x->MinorVersion; }
/* FUNC(zx_ff12_AuthnResponse_PUT_MinorVersion) */
void zx_ff12_AuthnResponse_PUT_MinorVersion(struct zx_ff12_AuthnResponse_s* x, struct zx_str* y) { x->MinorVersion = y; }
/* FUNC(zx_ff12_AuthnResponse_GET_Recipient) */
struct zx_str* zx_ff12_AuthnResponse_GET_Recipient(struct zx_ff12_AuthnResponse_s* x) { return x->Recipient; }
/* FUNC(zx_ff12_AuthnResponse_PUT_Recipient) */
void zx_ff12_AuthnResponse_PUT_Recipient(struct zx_ff12_AuthnResponse_s* x, struct zx_str* y) { x->Recipient = y; }
/* FUNC(zx_ff12_AuthnResponse_GET_ResponseID) */
struct zx_str* zx_ff12_AuthnResponse_GET_ResponseID(struct zx_ff12_AuthnResponse_s* x) { return x->ResponseID; }
/* FUNC(zx_ff12_AuthnResponse_PUT_ResponseID) */
void zx_ff12_AuthnResponse_PUT_ResponseID(struct zx_ff12_AuthnResponse_s* x, struct zx_str* y) { x->ResponseID = y; }
/* FUNC(zx_ff12_AuthnResponse_GET_consent) */
struct zx_str* zx_ff12_AuthnResponse_GET_consent(struct zx_ff12_AuthnResponse_s* x) { return x->consent; }
/* FUNC(zx_ff12_AuthnResponse_PUT_consent) */
void zx_ff12_AuthnResponse_PUT_consent(struct zx_ff12_AuthnResponse_s* x, struct zx_str* y) { x->consent = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnResponseEnvelope_NUM_Extension) */

int zx_ff12_AuthnResponseEnvelope_NUM_Extension(struct zx_ff12_AuthnResponseEnvelope_s* x)
{
  struct zx_ff12_Extension_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Extension; y; ++n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_GET_Extension) */

struct zx_ff12_Extension_s* zx_ff12_AuthnResponseEnvelope_GET_Extension(struct zx_ff12_AuthnResponseEnvelope_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  for (y = x->Extension; n>=0 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_POP_Extension) */

struct zx_ff12_Extension_s* zx_ff12_AuthnResponseEnvelope_POP_Extension(struct zx_ff12_AuthnResponseEnvelope_s* x)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  y = x->Extension;
  if (y)
    x->Extension = (struct zx_ff12_Extension_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_PUSH_Extension) */

void zx_ff12_AuthnResponseEnvelope_PUSH_Extension(struct zx_ff12_AuthnResponseEnvelope_s* x, struct zx_ff12_Extension_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Extension->gg.g;
  x->Extension = z;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_REV_Extension) */

void zx_ff12_AuthnResponseEnvelope_REV_Extension(struct zx_ff12_AuthnResponseEnvelope_s* x)
{
  struct zx_ff12_Extension_s* nxt;
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  y = x->Extension;
  if (!y) return;
  x->Extension = 0;
  while (y) {
    nxt = (struct zx_ff12_Extension_s*)y->gg.g.n;
    y->gg.g.n = &x->Extension->gg.g;
    x->Extension = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_PUT_Extension) */

void zx_ff12_AuthnResponseEnvelope_PUT_Extension(struct zx_ff12_AuthnResponseEnvelope_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  y = x->Extension;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Extension = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_ADD_Extension) */

void zx_ff12_AuthnResponseEnvelope_ADD_Extension(struct zx_ff12_AuthnResponseEnvelope_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Extension->gg.g;
    x->Extension = z;
    return;
  case -1:
    y = x->Extension;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_DEL_Extension) */

void zx_ff12_AuthnResponseEnvelope_DEL_Extension(struct zx_ff12_AuthnResponseEnvelope_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Extension = (struct zx_ff12_Extension_s*)x->Extension->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Extension_s*)x->Extension;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnResponseEnvelope_NUM_AuthnResponse) */

int zx_ff12_AuthnResponseEnvelope_NUM_AuthnResponse(struct zx_ff12_AuthnResponseEnvelope_s* x)
{
  struct zx_ff12_AuthnResponse_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthnResponse; y; ++n, y = (struct zx_ff12_AuthnResponse_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_GET_AuthnResponse) */

struct zx_ff12_AuthnResponse_s* zx_ff12_AuthnResponseEnvelope_GET_AuthnResponse(struct zx_ff12_AuthnResponseEnvelope_s* x, int n)
{
  struct zx_ff12_AuthnResponse_s* y;
  if (!x) return 0;
  for (y = x->AuthnResponse; n>=0 && y; --n, y = (struct zx_ff12_AuthnResponse_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_POP_AuthnResponse) */

struct zx_ff12_AuthnResponse_s* zx_ff12_AuthnResponseEnvelope_POP_AuthnResponse(struct zx_ff12_AuthnResponseEnvelope_s* x)
{
  struct zx_ff12_AuthnResponse_s* y;
  if (!x) return 0;
  y = x->AuthnResponse;
  if (y)
    x->AuthnResponse = (struct zx_ff12_AuthnResponse_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_PUSH_AuthnResponse) */

void zx_ff12_AuthnResponseEnvelope_PUSH_AuthnResponse(struct zx_ff12_AuthnResponseEnvelope_s* x, struct zx_ff12_AuthnResponse_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->AuthnResponse->gg.g;
  x->AuthnResponse = z;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_REV_AuthnResponse) */

void zx_ff12_AuthnResponseEnvelope_REV_AuthnResponse(struct zx_ff12_AuthnResponseEnvelope_s* x)
{
  struct zx_ff12_AuthnResponse_s* nxt;
  struct zx_ff12_AuthnResponse_s* y;
  if (!x) return;
  y = x->AuthnResponse;
  if (!y) return;
  x->AuthnResponse = 0;
  while (y) {
    nxt = (struct zx_ff12_AuthnResponse_s*)y->gg.g.n;
    y->gg.g.n = &x->AuthnResponse->gg.g;
    x->AuthnResponse = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_PUT_AuthnResponse) */

void zx_ff12_AuthnResponseEnvelope_PUT_AuthnResponse(struct zx_ff12_AuthnResponseEnvelope_s* x, int n, struct zx_ff12_AuthnResponse_s* z)
{
  struct zx_ff12_AuthnResponse_s* y;
  if (!x || !z) return;
  y = x->AuthnResponse;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->AuthnResponse = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_AuthnResponse_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_ADD_AuthnResponse) */

void zx_ff12_AuthnResponseEnvelope_ADD_AuthnResponse(struct zx_ff12_AuthnResponseEnvelope_s* x, int n, struct zx_ff12_AuthnResponse_s* z)
{
  struct zx_ff12_AuthnResponse_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->AuthnResponse->gg.g;
    x->AuthnResponse = z;
    return;
  case -1:
    y = x->AuthnResponse;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_AuthnResponse_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthnResponse; n > 1 && y; --n, y = (struct zx_ff12_AuthnResponse_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_DEL_AuthnResponse) */

void zx_ff12_AuthnResponseEnvelope_DEL_AuthnResponse(struct zx_ff12_AuthnResponseEnvelope_s* x, int n)
{
  struct zx_ff12_AuthnResponse_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthnResponse = (struct zx_ff12_AuthnResponse_s*)x->AuthnResponse->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_AuthnResponse_s*)x->AuthnResponse;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_AuthnResponse_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->AuthnResponse; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_AuthnResponse_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_AuthnResponseEnvelope_NUM_AssertionConsumerServiceURL) */

int zx_ff12_AuthnResponseEnvelope_NUM_AssertionConsumerServiceURL(struct zx_ff12_AuthnResponseEnvelope_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AssertionConsumerServiceURL; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_GET_AssertionConsumerServiceURL) */

struct zx_elem_s* zx_ff12_AuthnResponseEnvelope_GET_AssertionConsumerServiceURL(struct zx_ff12_AuthnResponseEnvelope_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->AssertionConsumerServiceURL; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_POP_AssertionConsumerServiceURL) */

struct zx_elem_s* zx_ff12_AuthnResponseEnvelope_POP_AssertionConsumerServiceURL(struct zx_ff12_AuthnResponseEnvelope_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->AssertionConsumerServiceURL;
  if (y)
    x->AssertionConsumerServiceURL = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_PUSH_AssertionConsumerServiceURL) */

void zx_ff12_AuthnResponseEnvelope_PUSH_AssertionConsumerServiceURL(struct zx_ff12_AuthnResponseEnvelope_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->AssertionConsumerServiceURL->g;
  x->AssertionConsumerServiceURL = z;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_REV_AssertionConsumerServiceURL) */

void zx_ff12_AuthnResponseEnvelope_REV_AssertionConsumerServiceURL(struct zx_ff12_AuthnResponseEnvelope_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->AssertionConsumerServiceURL;
  if (!y) return;
  x->AssertionConsumerServiceURL = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->AssertionConsumerServiceURL->g;
    x->AssertionConsumerServiceURL = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_PUT_AssertionConsumerServiceURL) */

void zx_ff12_AuthnResponseEnvelope_PUT_AssertionConsumerServiceURL(struct zx_ff12_AuthnResponseEnvelope_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->AssertionConsumerServiceURL;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->AssertionConsumerServiceURL = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_ADD_AssertionConsumerServiceURL) */

void zx_ff12_AuthnResponseEnvelope_ADD_AssertionConsumerServiceURL(struct zx_ff12_AuthnResponseEnvelope_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->AssertionConsumerServiceURL->g;
    x->AssertionConsumerServiceURL = z;
    return;
  case -1:
    y = x->AssertionConsumerServiceURL;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AssertionConsumerServiceURL; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_AuthnResponseEnvelope_DEL_AssertionConsumerServiceURL) */

void zx_ff12_AuthnResponseEnvelope_DEL_AssertionConsumerServiceURL(struct zx_ff12_AuthnResponseEnvelope_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AssertionConsumerServiceURL = (struct zx_elem_s*)x->AssertionConsumerServiceURL->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->AssertionConsumerServiceURL;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AssertionConsumerServiceURL; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif






/* FUNC(zx_ff12_EncryptableNameIdentifier_GET_Format) */
struct zx_str* zx_ff12_EncryptableNameIdentifier_GET_Format(struct zx_ff12_EncryptableNameIdentifier_s* x) { return x->Format; }
/* FUNC(zx_ff12_EncryptableNameIdentifier_PUT_Format) */
void zx_ff12_EncryptableNameIdentifier_PUT_Format(struct zx_ff12_EncryptableNameIdentifier_s* x, struct zx_str* y) { x->Format = y; }
/* FUNC(zx_ff12_EncryptableNameIdentifier_GET_IssueInstant) */
struct zx_str* zx_ff12_EncryptableNameIdentifier_GET_IssueInstant(struct zx_ff12_EncryptableNameIdentifier_s* x) { return x->IssueInstant; }
/* FUNC(zx_ff12_EncryptableNameIdentifier_PUT_IssueInstant) */
void zx_ff12_EncryptableNameIdentifier_PUT_IssueInstant(struct zx_ff12_EncryptableNameIdentifier_s* x, struct zx_str* y) { x->IssueInstant = y; }
/* FUNC(zx_ff12_EncryptableNameIdentifier_GET_NameQualifier) */
struct zx_str* zx_ff12_EncryptableNameIdentifier_GET_NameQualifier(struct zx_ff12_EncryptableNameIdentifier_s* x) { return x->NameQualifier; }
/* FUNC(zx_ff12_EncryptableNameIdentifier_PUT_NameQualifier) */
void zx_ff12_EncryptableNameIdentifier_PUT_NameQualifier(struct zx_ff12_EncryptableNameIdentifier_s* x, struct zx_str* y) { x->NameQualifier = y; }
/* FUNC(zx_ff12_EncryptableNameIdentifier_GET_Nonce) */
struct zx_str* zx_ff12_EncryptableNameIdentifier_GET_Nonce(struct zx_ff12_EncryptableNameIdentifier_s* x) { return x->Nonce; }
/* FUNC(zx_ff12_EncryptableNameIdentifier_PUT_Nonce) */
void zx_ff12_EncryptableNameIdentifier_PUT_Nonce(struct zx_ff12_EncryptableNameIdentifier_s* x, struct zx_str* y) { x->Nonce = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_EncryptedNameIdentifier_NUM_EncryptedData) */

int zx_ff12_EncryptedNameIdentifier_NUM_EncryptedData(struct zx_ff12_EncryptedNameIdentifier_s* x)
{
  struct zx_xenc_EncryptedData_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->EncryptedData; y; ++n, y = (struct zx_xenc_EncryptedData_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_GET_EncryptedData) */

struct zx_xenc_EncryptedData_s* zx_ff12_EncryptedNameIdentifier_GET_EncryptedData(struct zx_ff12_EncryptedNameIdentifier_s* x, int n)
{
  struct zx_xenc_EncryptedData_s* y;
  if (!x) return 0;
  for (y = x->EncryptedData; n>=0 && y; --n, y = (struct zx_xenc_EncryptedData_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_POP_EncryptedData) */

struct zx_xenc_EncryptedData_s* zx_ff12_EncryptedNameIdentifier_POP_EncryptedData(struct zx_ff12_EncryptedNameIdentifier_s* x)
{
  struct zx_xenc_EncryptedData_s* y;
  if (!x) return 0;
  y = x->EncryptedData;
  if (y)
    x->EncryptedData = (struct zx_xenc_EncryptedData_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_PUSH_EncryptedData) */

void zx_ff12_EncryptedNameIdentifier_PUSH_EncryptedData(struct zx_ff12_EncryptedNameIdentifier_s* x, struct zx_xenc_EncryptedData_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->EncryptedData->gg.g;
  x->EncryptedData = z;
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_REV_EncryptedData) */

void zx_ff12_EncryptedNameIdentifier_REV_EncryptedData(struct zx_ff12_EncryptedNameIdentifier_s* x)
{
  struct zx_xenc_EncryptedData_s* nxt;
  struct zx_xenc_EncryptedData_s* y;
  if (!x) return;
  y = x->EncryptedData;
  if (!y) return;
  x->EncryptedData = 0;
  while (y) {
    nxt = (struct zx_xenc_EncryptedData_s*)y->gg.g.n;
    y->gg.g.n = &x->EncryptedData->gg.g;
    x->EncryptedData = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_PUT_EncryptedData) */

void zx_ff12_EncryptedNameIdentifier_PUT_EncryptedData(struct zx_ff12_EncryptedNameIdentifier_s* x, int n, struct zx_xenc_EncryptedData_s* z)
{
  struct zx_xenc_EncryptedData_s* y;
  if (!x || !z) return;
  y = x->EncryptedData;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->EncryptedData = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_xenc_EncryptedData_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_ADD_EncryptedData) */

void zx_ff12_EncryptedNameIdentifier_ADD_EncryptedData(struct zx_ff12_EncryptedNameIdentifier_s* x, int n, struct zx_xenc_EncryptedData_s* z)
{
  struct zx_xenc_EncryptedData_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->EncryptedData->gg.g;
    x->EncryptedData = z;
    return;
  case -1:
    y = x->EncryptedData;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_xenc_EncryptedData_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->EncryptedData; n > 1 && y; --n, y = (struct zx_xenc_EncryptedData_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_DEL_EncryptedData) */

void zx_ff12_EncryptedNameIdentifier_DEL_EncryptedData(struct zx_ff12_EncryptedNameIdentifier_s* x, int n)
{
  struct zx_xenc_EncryptedData_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->EncryptedData = (struct zx_xenc_EncryptedData_s*)x->EncryptedData->gg.g.n;
    return;
  case -1:
    y = (struct zx_xenc_EncryptedData_s*)x->EncryptedData;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_xenc_EncryptedData_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->EncryptedData; n > 1 && y->gg.g.n; --n, y = (struct zx_xenc_EncryptedData_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_EncryptedNameIdentifier_NUM_EncryptedKey) */

int zx_ff12_EncryptedNameIdentifier_NUM_EncryptedKey(struct zx_ff12_EncryptedNameIdentifier_s* x)
{
  struct zx_xenc_EncryptedKey_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->EncryptedKey; y; ++n, y = (struct zx_xenc_EncryptedKey_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_GET_EncryptedKey) */

struct zx_xenc_EncryptedKey_s* zx_ff12_EncryptedNameIdentifier_GET_EncryptedKey(struct zx_ff12_EncryptedNameIdentifier_s* x, int n)
{
  struct zx_xenc_EncryptedKey_s* y;
  if (!x) return 0;
  for (y = x->EncryptedKey; n>=0 && y; --n, y = (struct zx_xenc_EncryptedKey_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_POP_EncryptedKey) */

struct zx_xenc_EncryptedKey_s* zx_ff12_EncryptedNameIdentifier_POP_EncryptedKey(struct zx_ff12_EncryptedNameIdentifier_s* x)
{
  struct zx_xenc_EncryptedKey_s* y;
  if (!x) return 0;
  y = x->EncryptedKey;
  if (y)
    x->EncryptedKey = (struct zx_xenc_EncryptedKey_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_PUSH_EncryptedKey) */

void zx_ff12_EncryptedNameIdentifier_PUSH_EncryptedKey(struct zx_ff12_EncryptedNameIdentifier_s* x, struct zx_xenc_EncryptedKey_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->EncryptedKey->gg.g;
  x->EncryptedKey = z;
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_REV_EncryptedKey) */

void zx_ff12_EncryptedNameIdentifier_REV_EncryptedKey(struct zx_ff12_EncryptedNameIdentifier_s* x)
{
  struct zx_xenc_EncryptedKey_s* nxt;
  struct zx_xenc_EncryptedKey_s* y;
  if (!x) return;
  y = x->EncryptedKey;
  if (!y) return;
  x->EncryptedKey = 0;
  while (y) {
    nxt = (struct zx_xenc_EncryptedKey_s*)y->gg.g.n;
    y->gg.g.n = &x->EncryptedKey->gg.g;
    x->EncryptedKey = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_PUT_EncryptedKey) */

void zx_ff12_EncryptedNameIdentifier_PUT_EncryptedKey(struct zx_ff12_EncryptedNameIdentifier_s* x, int n, struct zx_xenc_EncryptedKey_s* z)
{
  struct zx_xenc_EncryptedKey_s* y;
  if (!x || !z) return;
  y = x->EncryptedKey;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->EncryptedKey = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_xenc_EncryptedKey_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_ADD_EncryptedKey) */

void zx_ff12_EncryptedNameIdentifier_ADD_EncryptedKey(struct zx_ff12_EncryptedNameIdentifier_s* x, int n, struct zx_xenc_EncryptedKey_s* z)
{
  struct zx_xenc_EncryptedKey_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->EncryptedKey->gg.g;
    x->EncryptedKey = z;
    return;
  case -1:
    y = x->EncryptedKey;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_xenc_EncryptedKey_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->EncryptedKey; n > 1 && y; --n, y = (struct zx_xenc_EncryptedKey_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_EncryptedNameIdentifier_DEL_EncryptedKey) */

void zx_ff12_EncryptedNameIdentifier_DEL_EncryptedKey(struct zx_ff12_EncryptedNameIdentifier_s* x, int n)
{
  struct zx_xenc_EncryptedKey_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->EncryptedKey = (struct zx_xenc_EncryptedKey_s*)x->EncryptedKey->gg.g.n;
    return;
  case -1:
    y = (struct zx_xenc_EncryptedKey_s*)x->EncryptedKey;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_xenc_EncryptedKey_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->EncryptedKey; n > 1 && y->gg.g.n; --n, y = (struct zx_xenc_EncryptedKey_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif













#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_FederationTerminationNotification_NUM_RespondWith) */

int zx_ff12_FederationTerminationNotification_NUM_RespondWith(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RespondWith; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_FederationTerminationNotification_GET_RespondWith) */

struct zx_elem_s* zx_ff12_FederationTerminationNotification_GET_RespondWith(struct zx_ff12_FederationTerminationNotification_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->RespondWith; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_FederationTerminationNotification_POP_RespondWith) */

struct zx_elem_s* zx_ff12_FederationTerminationNotification_POP_RespondWith(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->RespondWith;
  if (y)
    x->RespondWith = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_FederationTerminationNotification_PUSH_RespondWith) */

void zx_ff12_FederationTerminationNotification_PUSH_RespondWith(struct zx_ff12_FederationTerminationNotification_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->RespondWith->g;
  x->RespondWith = z;
}

/* FUNC(zx_ff12_FederationTerminationNotification_REV_RespondWith) */

void zx_ff12_FederationTerminationNotification_REV_RespondWith(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->RespondWith;
  if (!y) return;
  x->RespondWith = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->RespondWith->g;
    x->RespondWith = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_FederationTerminationNotification_PUT_RespondWith) */

void zx_ff12_FederationTerminationNotification_PUT_RespondWith(struct zx_ff12_FederationTerminationNotification_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->RespondWith;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->RespondWith = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_FederationTerminationNotification_ADD_RespondWith) */

void zx_ff12_FederationTerminationNotification_ADD_RespondWith(struct zx_ff12_FederationTerminationNotification_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->RespondWith->g;
    x->RespondWith = z;
    return;
  case -1:
    y = x->RespondWith;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RespondWith; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_FederationTerminationNotification_DEL_RespondWith) */

void zx_ff12_FederationTerminationNotification_DEL_RespondWith(struct zx_ff12_FederationTerminationNotification_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RespondWith = (struct zx_elem_s*)x->RespondWith->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->RespondWith;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RespondWith; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_FederationTerminationNotification_NUM_Signature) */

int zx_ff12_FederationTerminationNotification_NUM_Signature(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_ds_Signature_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Signature; y; ++n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_FederationTerminationNotification_GET_Signature) */

struct zx_ds_Signature_s* zx_ff12_FederationTerminationNotification_GET_Signature(struct zx_ff12_FederationTerminationNotification_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  for (y = x->Signature; n>=0 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_FederationTerminationNotification_POP_Signature) */

struct zx_ds_Signature_s* zx_ff12_FederationTerminationNotification_POP_Signature(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  y = x->Signature;
  if (y)
    x->Signature = (struct zx_ds_Signature_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_FederationTerminationNotification_PUSH_Signature) */

void zx_ff12_FederationTerminationNotification_PUSH_Signature(struct zx_ff12_FederationTerminationNotification_s* x, struct zx_ds_Signature_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Signature->gg.g;
  x->Signature = z;
}

/* FUNC(zx_ff12_FederationTerminationNotification_REV_Signature) */

void zx_ff12_FederationTerminationNotification_REV_Signature(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_ds_Signature_s* nxt;
  struct zx_ds_Signature_s* y;
  if (!x) return;
  y = x->Signature;
  if (!y) return;
  x->Signature = 0;
  while (y) {
    nxt = (struct zx_ds_Signature_s*)y->gg.g.n;
    y->gg.g.n = &x->Signature->gg.g;
    x->Signature = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_FederationTerminationNotification_PUT_Signature) */

void zx_ff12_FederationTerminationNotification_PUT_Signature(struct zx_ff12_FederationTerminationNotification_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  y = x->Signature;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Signature = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_FederationTerminationNotification_ADD_Signature) */

void zx_ff12_FederationTerminationNotification_ADD_Signature(struct zx_ff12_FederationTerminationNotification_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Signature->gg.g;
    x->Signature = z;
    return;
  case -1:
    y = x->Signature;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_FederationTerminationNotification_DEL_Signature) */

void zx_ff12_FederationTerminationNotification_DEL_Signature(struct zx_ff12_FederationTerminationNotification_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Signature = (struct zx_ds_Signature_s*)x->Signature->gg.g.n;
    return;
  case -1:
    y = (struct zx_ds_Signature_s*)x->Signature;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_FederationTerminationNotification_NUM_Extension) */

int zx_ff12_FederationTerminationNotification_NUM_Extension(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_ff12_Extension_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Extension; y; ++n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_FederationTerminationNotification_GET_Extension) */

struct zx_ff12_Extension_s* zx_ff12_FederationTerminationNotification_GET_Extension(struct zx_ff12_FederationTerminationNotification_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  for (y = x->Extension; n>=0 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_FederationTerminationNotification_POP_Extension) */

struct zx_ff12_Extension_s* zx_ff12_FederationTerminationNotification_POP_Extension(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  y = x->Extension;
  if (y)
    x->Extension = (struct zx_ff12_Extension_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_FederationTerminationNotification_PUSH_Extension) */

void zx_ff12_FederationTerminationNotification_PUSH_Extension(struct zx_ff12_FederationTerminationNotification_s* x, struct zx_ff12_Extension_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Extension->gg.g;
  x->Extension = z;
}

/* FUNC(zx_ff12_FederationTerminationNotification_REV_Extension) */

void zx_ff12_FederationTerminationNotification_REV_Extension(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_ff12_Extension_s* nxt;
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  y = x->Extension;
  if (!y) return;
  x->Extension = 0;
  while (y) {
    nxt = (struct zx_ff12_Extension_s*)y->gg.g.n;
    y->gg.g.n = &x->Extension->gg.g;
    x->Extension = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_FederationTerminationNotification_PUT_Extension) */

void zx_ff12_FederationTerminationNotification_PUT_Extension(struct zx_ff12_FederationTerminationNotification_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  y = x->Extension;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Extension = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_FederationTerminationNotification_ADD_Extension) */

void zx_ff12_FederationTerminationNotification_ADD_Extension(struct zx_ff12_FederationTerminationNotification_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Extension->gg.g;
    x->Extension = z;
    return;
  case -1:
    y = x->Extension;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_FederationTerminationNotification_DEL_Extension) */

void zx_ff12_FederationTerminationNotification_DEL_Extension(struct zx_ff12_FederationTerminationNotification_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Extension = (struct zx_ff12_Extension_s*)x->Extension->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Extension_s*)x->Extension;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_FederationTerminationNotification_NUM_ProviderID) */

int zx_ff12_FederationTerminationNotification_NUM_ProviderID(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_FederationTerminationNotification_GET_ProviderID) */

struct zx_elem_s* zx_ff12_FederationTerminationNotification_GET_ProviderID(struct zx_ff12_FederationTerminationNotification_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_FederationTerminationNotification_POP_ProviderID) */

struct zx_elem_s* zx_ff12_FederationTerminationNotification_POP_ProviderID(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderID;
  if (y)
    x->ProviderID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_FederationTerminationNotification_PUSH_ProviderID) */

void zx_ff12_FederationTerminationNotification_PUSH_ProviderID(struct zx_ff12_FederationTerminationNotification_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderID->g;
  x->ProviderID = z;
}

/* FUNC(zx_ff12_FederationTerminationNotification_REV_ProviderID) */

void zx_ff12_FederationTerminationNotification_REV_ProviderID(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderID;
  if (!y) return;
  x->ProviderID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderID->g;
    x->ProviderID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_FederationTerminationNotification_PUT_ProviderID) */

void zx_ff12_FederationTerminationNotification_PUT_ProviderID(struct zx_ff12_FederationTerminationNotification_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_FederationTerminationNotification_ADD_ProviderID) */

void zx_ff12_FederationTerminationNotification_ADD_ProviderID(struct zx_ff12_FederationTerminationNotification_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderID->g;
    x->ProviderID = z;
    return;
  case -1:
    y = x->ProviderID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_FederationTerminationNotification_DEL_ProviderID) */

void zx_ff12_FederationTerminationNotification_DEL_ProviderID(struct zx_ff12_FederationTerminationNotification_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderID = (struct zx_elem_s*)x->ProviderID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_FederationTerminationNotification_NUM_NameIdentifier) */

int zx_ff12_FederationTerminationNotification_NUM_NameIdentifier(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_sa11_NameIdentifier_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->NameIdentifier; y; ++n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_FederationTerminationNotification_GET_NameIdentifier) */

struct zx_sa11_NameIdentifier_s* zx_ff12_FederationTerminationNotification_GET_NameIdentifier(struct zx_ff12_FederationTerminationNotification_s* x, int n)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return 0;
  for (y = x->NameIdentifier; n>=0 && y; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_FederationTerminationNotification_POP_NameIdentifier) */

struct zx_sa11_NameIdentifier_s* zx_ff12_FederationTerminationNotification_POP_NameIdentifier(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return 0;
  y = x->NameIdentifier;
  if (y)
    x->NameIdentifier = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_FederationTerminationNotification_PUSH_NameIdentifier) */

void zx_ff12_FederationTerminationNotification_PUSH_NameIdentifier(struct zx_ff12_FederationTerminationNotification_s* x, struct zx_sa11_NameIdentifier_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->NameIdentifier->gg.g;
  x->NameIdentifier = z;
}

/* FUNC(zx_ff12_FederationTerminationNotification_REV_NameIdentifier) */

void zx_ff12_FederationTerminationNotification_REV_NameIdentifier(struct zx_ff12_FederationTerminationNotification_s* x)
{
  struct zx_sa11_NameIdentifier_s* nxt;
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return;
  y = x->NameIdentifier;
  if (!y) return;
  x->NameIdentifier = 0;
  while (y) {
    nxt = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n;
    y->gg.g.n = &x->NameIdentifier->gg.g;
    x->NameIdentifier = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_FederationTerminationNotification_PUT_NameIdentifier) */

void zx_ff12_FederationTerminationNotification_PUT_NameIdentifier(struct zx_ff12_FederationTerminationNotification_s* x, int n, struct zx_sa11_NameIdentifier_s* z)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x || !z) return;
  y = x->NameIdentifier;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->NameIdentifier = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_FederationTerminationNotification_ADD_NameIdentifier) */

void zx_ff12_FederationTerminationNotification_ADD_NameIdentifier(struct zx_ff12_FederationTerminationNotification_s* x, int n, struct zx_sa11_NameIdentifier_s* z)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->NameIdentifier->gg.g;
    x->NameIdentifier = z;
    return;
  case -1:
    y = x->NameIdentifier;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->NameIdentifier; n > 1 && y; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_FederationTerminationNotification_DEL_NameIdentifier) */

void zx_ff12_FederationTerminationNotification_DEL_NameIdentifier(struct zx_ff12_FederationTerminationNotification_s* x, int n)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->NameIdentifier = (struct zx_sa11_NameIdentifier_s*)x->NameIdentifier->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_NameIdentifier_s*)x->NameIdentifier;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->NameIdentifier; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif

/* FUNC(zx_ff12_FederationTerminationNotification_GET_IssueInstant) */
struct zx_str* zx_ff12_FederationTerminationNotification_GET_IssueInstant(struct zx_ff12_FederationTerminationNotification_s* x) { return x->IssueInstant; }
/* FUNC(zx_ff12_FederationTerminationNotification_PUT_IssueInstant) */
void zx_ff12_FederationTerminationNotification_PUT_IssueInstant(struct zx_ff12_FederationTerminationNotification_s* x, struct zx_str* y) { x->IssueInstant = y; }
/* FUNC(zx_ff12_FederationTerminationNotification_GET_MajorVersion) */
struct zx_str* zx_ff12_FederationTerminationNotification_GET_MajorVersion(struct zx_ff12_FederationTerminationNotification_s* x) { return x->MajorVersion; }
/* FUNC(zx_ff12_FederationTerminationNotification_PUT_MajorVersion) */
void zx_ff12_FederationTerminationNotification_PUT_MajorVersion(struct zx_ff12_FederationTerminationNotification_s* x, struct zx_str* y) { x->MajorVersion = y; }
/* FUNC(zx_ff12_FederationTerminationNotification_GET_MinorVersion) */
struct zx_str* zx_ff12_FederationTerminationNotification_GET_MinorVersion(struct zx_ff12_FederationTerminationNotification_s* x) { return x->MinorVersion; }
/* FUNC(zx_ff12_FederationTerminationNotification_PUT_MinorVersion) */
void zx_ff12_FederationTerminationNotification_PUT_MinorVersion(struct zx_ff12_FederationTerminationNotification_s* x, struct zx_str* y) { x->MinorVersion = y; }
/* FUNC(zx_ff12_FederationTerminationNotification_GET_RequestID) */
struct zx_str* zx_ff12_FederationTerminationNotification_GET_RequestID(struct zx_ff12_FederationTerminationNotification_s* x) { return x->RequestID; }
/* FUNC(zx_ff12_FederationTerminationNotification_PUT_RequestID) */
void zx_ff12_FederationTerminationNotification_PUT_RequestID(struct zx_ff12_FederationTerminationNotification_s* x, struct zx_str* y) { x->RequestID = y; }
/* FUNC(zx_ff12_FederationTerminationNotification_GET_consent) */
struct zx_str* zx_ff12_FederationTerminationNotification_GET_consent(struct zx_ff12_FederationTerminationNotification_s* x) { return x->consent; }
/* FUNC(zx_ff12_FederationTerminationNotification_PUT_consent) */
void zx_ff12_FederationTerminationNotification_PUT_consent(struct zx_ff12_FederationTerminationNotification_s* x, struct zx_str* y) { x->consent = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_IDPEntries_NUM_IDPEntry) */

int zx_ff12_IDPEntries_NUM_IDPEntry(struct zx_ff12_IDPEntries_s* x)
{
  struct zx_ff12_IDPEntry_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->IDPEntry; y; ++n, y = (struct zx_ff12_IDPEntry_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_IDPEntries_GET_IDPEntry) */

struct zx_ff12_IDPEntry_s* zx_ff12_IDPEntries_GET_IDPEntry(struct zx_ff12_IDPEntries_s* x, int n)
{
  struct zx_ff12_IDPEntry_s* y;
  if (!x) return 0;
  for (y = x->IDPEntry; n>=0 && y; --n, y = (struct zx_ff12_IDPEntry_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_IDPEntries_POP_IDPEntry) */

struct zx_ff12_IDPEntry_s* zx_ff12_IDPEntries_POP_IDPEntry(struct zx_ff12_IDPEntries_s* x)
{
  struct zx_ff12_IDPEntry_s* y;
  if (!x) return 0;
  y = x->IDPEntry;
  if (y)
    x->IDPEntry = (struct zx_ff12_IDPEntry_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_IDPEntries_PUSH_IDPEntry) */

void zx_ff12_IDPEntries_PUSH_IDPEntry(struct zx_ff12_IDPEntries_s* x, struct zx_ff12_IDPEntry_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->IDPEntry->gg.g;
  x->IDPEntry = z;
}

/* FUNC(zx_ff12_IDPEntries_REV_IDPEntry) */

void zx_ff12_IDPEntries_REV_IDPEntry(struct zx_ff12_IDPEntries_s* x)
{
  struct zx_ff12_IDPEntry_s* nxt;
  struct zx_ff12_IDPEntry_s* y;
  if (!x) return;
  y = x->IDPEntry;
  if (!y) return;
  x->IDPEntry = 0;
  while (y) {
    nxt = (struct zx_ff12_IDPEntry_s*)y->gg.g.n;
    y->gg.g.n = &x->IDPEntry->gg.g;
    x->IDPEntry = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_IDPEntries_PUT_IDPEntry) */

void zx_ff12_IDPEntries_PUT_IDPEntry(struct zx_ff12_IDPEntries_s* x, int n, struct zx_ff12_IDPEntry_s* z)
{
  struct zx_ff12_IDPEntry_s* y;
  if (!x || !z) return;
  y = x->IDPEntry;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->IDPEntry = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPEntry_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_IDPEntries_ADD_IDPEntry) */

void zx_ff12_IDPEntries_ADD_IDPEntry(struct zx_ff12_IDPEntries_s* x, int n, struct zx_ff12_IDPEntry_s* z)
{
  struct zx_ff12_IDPEntry_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->IDPEntry->gg.g;
    x->IDPEntry = z;
    return;
  case -1:
    y = x->IDPEntry;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPEntry_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPEntry; n > 1 && y; --n, y = (struct zx_ff12_IDPEntry_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_IDPEntries_DEL_IDPEntry) */

void zx_ff12_IDPEntries_DEL_IDPEntry(struct zx_ff12_IDPEntries_s* x, int n)
{
  struct zx_ff12_IDPEntry_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->IDPEntry = (struct zx_ff12_IDPEntry_s*)x->IDPEntry->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_IDPEntry_s*)x->IDPEntry;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPEntry_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPEntry; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPEntry_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif








#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_IDPEntry_NUM_ProviderID) */

int zx_ff12_IDPEntry_NUM_ProviderID(struct zx_ff12_IDPEntry_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_IDPEntry_GET_ProviderID) */

struct zx_elem_s* zx_ff12_IDPEntry_GET_ProviderID(struct zx_ff12_IDPEntry_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_IDPEntry_POP_ProviderID) */

struct zx_elem_s* zx_ff12_IDPEntry_POP_ProviderID(struct zx_ff12_IDPEntry_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderID;
  if (y)
    x->ProviderID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_IDPEntry_PUSH_ProviderID) */

void zx_ff12_IDPEntry_PUSH_ProviderID(struct zx_ff12_IDPEntry_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderID->g;
  x->ProviderID = z;
}

/* FUNC(zx_ff12_IDPEntry_REV_ProviderID) */

void zx_ff12_IDPEntry_REV_ProviderID(struct zx_ff12_IDPEntry_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderID;
  if (!y) return;
  x->ProviderID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderID->g;
    x->ProviderID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_IDPEntry_PUT_ProviderID) */

void zx_ff12_IDPEntry_PUT_ProviderID(struct zx_ff12_IDPEntry_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_IDPEntry_ADD_ProviderID) */

void zx_ff12_IDPEntry_ADD_ProviderID(struct zx_ff12_IDPEntry_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderID->g;
    x->ProviderID = z;
    return;
  case -1:
    y = x->ProviderID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_IDPEntry_DEL_ProviderID) */

void zx_ff12_IDPEntry_DEL_ProviderID(struct zx_ff12_IDPEntry_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderID = (struct zx_elem_s*)x->ProviderID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_IDPEntry_NUM_ProviderName) */

int zx_ff12_IDPEntry_NUM_ProviderName(struct zx_ff12_IDPEntry_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderName; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_IDPEntry_GET_ProviderName) */

struct zx_elem_s* zx_ff12_IDPEntry_GET_ProviderName(struct zx_ff12_IDPEntry_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderName; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_IDPEntry_POP_ProviderName) */

struct zx_elem_s* zx_ff12_IDPEntry_POP_ProviderName(struct zx_ff12_IDPEntry_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderName;
  if (y)
    x->ProviderName = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_IDPEntry_PUSH_ProviderName) */

void zx_ff12_IDPEntry_PUSH_ProviderName(struct zx_ff12_IDPEntry_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderName->g;
  x->ProviderName = z;
}

/* FUNC(zx_ff12_IDPEntry_REV_ProviderName) */

void zx_ff12_IDPEntry_REV_ProviderName(struct zx_ff12_IDPEntry_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderName;
  if (!y) return;
  x->ProviderName = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderName->g;
    x->ProviderName = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_IDPEntry_PUT_ProviderName) */

void zx_ff12_IDPEntry_PUT_ProviderName(struct zx_ff12_IDPEntry_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderName;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderName = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_IDPEntry_ADD_ProviderName) */

void zx_ff12_IDPEntry_ADD_ProviderName(struct zx_ff12_IDPEntry_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderName->g;
    x->ProviderName = z;
    return;
  case -1:
    y = x->ProviderName;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderName; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_IDPEntry_DEL_ProviderName) */

void zx_ff12_IDPEntry_DEL_ProviderName(struct zx_ff12_IDPEntry_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderName = (struct zx_elem_s*)x->ProviderName->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderName;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderName; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_IDPEntry_NUM_Loc) */

int zx_ff12_IDPEntry_NUM_Loc(struct zx_ff12_IDPEntry_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Loc; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_IDPEntry_GET_Loc) */

struct zx_elem_s* zx_ff12_IDPEntry_GET_Loc(struct zx_ff12_IDPEntry_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->Loc; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_IDPEntry_POP_Loc) */

struct zx_elem_s* zx_ff12_IDPEntry_POP_Loc(struct zx_ff12_IDPEntry_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->Loc;
  if (y)
    x->Loc = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_IDPEntry_PUSH_Loc) */

void zx_ff12_IDPEntry_PUSH_Loc(struct zx_ff12_IDPEntry_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->Loc->g;
  x->Loc = z;
}

/* FUNC(zx_ff12_IDPEntry_REV_Loc) */

void zx_ff12_IDPEntry_REV_Loc(struct zx_ff12_IDPEntry_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->Loc;
  if (!y) return;
  x->Loc = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->Loc->g;
    x->Loc = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_IDPEntry_PUT_Loc) */

void zx_ff12_IDPEntry_PUT_Loc(struct zx_ff12_IDPEntry_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->Loc;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->Loc = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_IDPEntry_ADD_Loc) */

void zx_ff12_IDPEntry_ADD_Loc(struct zx_ff12_IDPEntry_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->Loc->g;
    x->Loc = z;
    return;
  case -1:
    y = x->Loc;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->Loc; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_IDPEntry_DEL_Loc) */

void zx_ff12_IDPEntry_DEL_Loc(struct zx_ff12_IDPEntry_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Loc = (struct zx_elem_s*)x->Loc->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->Loc;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->Loc; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif








#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_IDPList_NUM_IDPEntries) */

int zx_ff12_IDPList_NUM_IDPEntries(struct zx_ff12_IDPList_s* x)
{
  struct zx_ff12_IDPEntries_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->IDPEntries; y; ++n, y = (struct zx_ff12_IDPEntries_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_IDPList_GET_IDPEntries) */

struct zx_ff12_IDPEntries_s* zx_ff12_IDPList_GET_IDPEntries(struct zx_ff12_IDPList_s* x, int n)
{
  struct zx_ff12_IDPEntries_s* y;
  if (!x) return 0;
  for (y = x->IDPEntries; n>=0 && y; --n, y = (struct zx_ff12_IDPEntries_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_IDPList_POP_IDPEntries) */

struct zx_ff12_IDPEntries_s* zx_ff12_IDPList_POP_IDPEntries(struct zx_ff12_IDPList_s* x)
{
  struct zx_ff12_IDPEntries_s* y;
  if (!x) return 0;
  y = x->IDPEntries;
  if (y)
    x->IDPEntries = (struct zx_ff12_IDPEntries_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_IDPList_PUSH_IDPEntries) */

void zx_ff12_IDPList_PUSH_IDPEntries(struct zx_ff12_IDPList_s* x, struct zx_ff12_IDPEntries_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->IDPEntries->gg.g;
  x->IDPEntries = z;
}

/* FUNC(zx_ff12_IDPList_REV_IDPEntries) */

void zx_ff12_IDPList_REV_IDPEntries(struct zx_ff12_IDPList_s* x)
{
  struct zx_ff12_IDPEntries_s* nxt;
  struct zx_ff12_IDPEntries_s* y;
  if (!x) return;
  y = x->IDPEntries;
  if (!y) return;
  x->IDPEntries = 0;
  while (y) {
    nxt = (struct zx_ff12_IDPEntries_s*)y->gg.g.n;
    y->gg.g.n = &x->IDPEntries->gg.g;
    x->IDPEntries = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_IDPList_PUT_IDPEntries) */

void zx_ff12_IDPList_PUT_IDPEntries(struct zx_ff12_IDPList_s* x, int n, struct zx_ff12_IDPEntries_s* z)
{
  struct zx_ff12_IDPEntries_s* y;
  if (!x || !z) return;
  y = x->IDPEntries;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->IDPEntries = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPEntries_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_IDPList_ADD_IDPEntries) */

void zx_ff12_IDPList_ADD_IDPEntries(struct zx_ff12_IDPList_s* x, int n, struct zx_ff12_IDPEntries_s* z)
{
  struct zx_ff12_IDPEntries_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->IDPEntries->gg.g;
    x->IDPEntries = z;
    return;
  case -1:
    y = x->IDPEntries;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPEntries_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPEntries; n > 1 && y; --n, y = (struct zx_ff12_IDPEntries_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_IDPList_DEL_IDPEntries) */

void zx_ff12_IDPList_DEL_IDPEntries(struct zx_ff12_IDPList_s* x, int n)
{
  struct zx_ff12_IDPEntries_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->IDPEntries = (struct zx_ff12_IDPEntries_s*)x->IDPEntries->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_IDPEntries_s*)x->IDPEntries;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPEntries_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPEntries; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPEntries_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_IDPList_NUM_GetComplete) */

int zx_ff12_IDPList_NUM_GetComplete(struct zx_ff12_IDPList_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->GetComplete; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_IDPList_GET_GetComplete) */

struct zx_elem_s* zx_ff12_IDPList_GET_GetComplete(struct zx_ff12_IDPList_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->GetComplete; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_IDPList_POP_GetComplete) */

struct zx_elem_s* zx_ff12_IDPList_POP_GetComplete(struct zx_ff12_IDPList_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->GetComplete;
  if (y)
    x->GetComplete = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_IDPList_PUSH_GetComplete) */

void zx_ff12_IDPList_PUSH_GetComplete(struct zx_ff12_IDPList_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->GetComplete->g;
  x->GetComplete = z;
}

/* FUNC(zx_ff12_IDPList_REV_GetComplete) */

void zx_ff12_IDPList_REV_GetComplete(struct zx_ff12_IDPList_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->GetComplete;
  if (!y) return;
  x->GetComplete = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->GetComplete->g;
    x->GetComplete = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_IDPList_PUT_GetComplete) */

void zx_ff12_IDPList_PUT_GetComplete(struct zx_ff12_IDPList_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->GetComplete;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->GetComplete = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_IDPList_ADD_GetComplete) */

void zx_ff12_IDPList_ADD_GetComplete(struct zx_ff12_IDPList_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->GetComplete->g;
    x->GetComplete = z;
    return;
  case -1:
    y = x->GetComplete;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->GetComplete; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_IDPList_DEL_GetComplete) */

void zx_ff12_IDPList_DEL_GetComplete(struct zx_ff12_IDPList_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->GetComplete = (struct zx_elem_s*)x->GetComplete->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->GetComplete;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->GetComplete; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif






/* FUNC(zx_ff12_IDPProvidedNameIdentifier_GET_Format) */
struct zx_str* zx_ff12_IDPProvidedNameIdentifier_GET_Format(struct zx_ff12_IDPProvidedNameIdentifier_s* x) { return x->Format; }
/* FUNC(zx_ff12_IDPProvidedNameIdentifier_PUT_Format) */
void zx_ff12_IDPProvidedNameIdentifier_PUT_Format(struct zx_ff12_IDPProvidedNameIdentifier_s* x, struct zx_str* y) { x->Format = y; }
/* FUNC(zx_ff12_IDPProvidedNameIdentifier_GET_NameQualifier) */
struct zx_str* zx_ff12_IDPProvidedNameIdentifier_GET_NameQualifier(struct zx_ff12_IDPProvidedNameIdentifier_s* x) { return x->NameQualifier; }
/* FUNC(zx_ff12_IDPProvidedNameIdentifier_PUT_NameQualifier) */
void zx_ff12_IDPProvidedNameIdentifier_PUT_NameQualifier(struct zx_ff12_IDPProvidedNameIdentifier_s* x, struct zx_str* y) { x->NameQualifier = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutRequest_NUM_RespondWith) */

int zx_ff12_LogoutRequest_NUM_RespondWith(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RespondWith; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutRequest_GET_RespondWith) */

struct zx_elem_s* zx_ff12_LogoutRequest_GET_RespondWith(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->RespondWith; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_POP_RespondWith) */

struct zx_elem_s* zx_ff12_LogoutRequest_POP_RespondWith(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->RespondWith;
  if (y)
    x->RespondWith = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_PUSH_RespondWith) */

void zx_ff12_LogoutRequest_PUSH_RespondWith(struct zx_ff12_LogoutRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->RespondWith->g;
  x->RespondWith = z;
}

/* FUNC(zx_ff12_LogoutRequest_REV_RespondWith) */

void zx_ff12_LogoutRequest_REV_RespondWith(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->RespondWith;
  if (!y) return;
  x->RespondWith = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->RespondWith->g;
    x->RespondWith = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutRequest_PUT_RespondWith) */

void zx_ff12_LogoutRequest_PUT_RespondWith(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->RespondWith;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->RespondWith = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_LogoutRequest_ADD_RespondWith) */

void zx_ff12_LogoutRequest_ADD_RespondWith(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->RespondWith->g;
    x->RespondWith = z;
    return;
  case -1:
    y = x->RespondWith;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RespondWith; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_LogoutRequest_DEL_RespondWith) */

void zx_ff12_LogoutRequest_DEL_RespondWith(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RespondWith = (struct zx_elem_s*)x->RespondWith->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->RespondWith;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RespondWith; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutRequest_NUM_Signature) */

int zx_ff12_LogoutRequest_NUM_Signature(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_ds_Signature_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Signature; y; ++n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutRequest_GET_Signature) */

struct zx_ds_Signature_s* zx_ff12_LogoutRequest_GET_Signature(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  for (y = x->Signature; n>=0 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_POP_Signature) */

struct zx_ds_Signature_s* zx_ff12_LogoutRequest_POP_Signature(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  y = x->Signature;
  if (y)
    x->Signature = (struct zx_ds_Signature_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_PUSH_Signature) */

void zx_ff12_LogoutRequest_PUSH_Signature(struct zx_ff12_LogoutRequest_s* x, struct zx_ds_Signature_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Signature->gg.g;
  x->Signature = z;
}

/* FUNC(zx_ff12_LogoutRequest_REV_Signature) */

void zx_ff12_LogoutRequest_REV_Signature(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_ds_Signature_s* nxt;
  struct zx_ds_Signature_s* y;
  if (!x) return;
  y = x->Signature;
  if (!y) return;
  x->Signature = 0;
  while (y) {
    nxt = (struct zx_ds_Signature_s*)y->gg.g.n;
    y->gg.g.n = &x->Signature->gg.g;
    x->Signature = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutRequest_PUT_Signature) */

void zx_ff12_LogoutRequest_PUT_Signature(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  y = x->Signature;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Signature = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_LogoutRequest_ADD_Signature) */

void zx_ff12_LogoutRequest_ADD_Signature(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Signature->gg.g;
    x->Signature = z;
    return;
  case -1:
    y = x->Signature;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_LogoutRequest_DEL_Signature) */

void zx_ff12_LogoutRequest_DEL_Signature(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Signature = (struct zx_ds_Signature_s*)x->Signature->gg.g.n;
    return;
  case -1:
    y = (struct zx_ds_Signature_s*)x->Signature;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutRequest_NUM_Extension) */

int zx_ff12_LogoutRequest_NUM_Extension(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_ff12_Extension_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Extension; y; ++n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutRequest_GET_Extension) */

struct zx_ff12_Extension_s* zx_ff12_LogoutRequest_GET_Extension(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  for (y = x->Extension; n>=0 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_POP_Extension) */

struct zx_ff12_Extension_s* zx_ff12_LogoutRequest_POP_Extension(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  y = x->Extension;
  if (y)
    x->Extension = (struct zx_ff12_Extension_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_PUSH_Extension) */

void zx_ff12_LogoutRequest_PUSH_Extension(struct zx_ff12_LogoutRequest_s* x, struct zx_ff12_Extension_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Extension->gg.g;
  x->Extension = z;
}

/* FUNC(zx_ff12_LogoutRequest_REV_Extension) */

void zx_ff12_LogoutRequest_REV_Extension(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_ff12_Extension_s* nxt;
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  y = x->Extension;
  if (!y) return;
  x->Extension = 0;
  while (y) {
    nxt = (struct zx_ff12_Extension_s*)y->gg.g.n;
    y->gg.g.n = &x->Extension->gg.g;
    x->Extension = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutRequest_PUT_Extension) */

void zx_ff12_LogoutRequest_PUT_Extension(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  y = x->Extension;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Extension = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_LogoutRequest_ADD_Extension) */

void zx_ff12_LogoutRequest_ADD_Extension(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Extension->gg.g;
    x->Extension = z;
    return;
  case -1:
    y = x->Extension;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_LogoutRequest_DEL_Extension) */

void zx_ff12_LogoutRequest_DEL_Extension(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Extension = (struct zx_ff12_Extension_s*)x->Extension->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Extension_s*)x->Extension;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutRequest_NUM_ProviderID) */

int zx_ff12_LogoutRequest_NUM_ProviderID(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutRequest_GET_ProviderID) */

struct zx_elem_s* zx_ff12_LogoutRequest_GET_ProviderID(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_POP_ProviderID) */

struct zx_elem_s* zx_ff12_LogoutRequest_POP_ProviderID(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderID;
  if (y)
    x->ProviderID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_PUSH_ProviderID) */

void zx_ff12_LogoutRequest_PUSH_ProviderID(struct zx_ff12_LogoutRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderID->g;
  x->ProviderID = z;
}

/* FUNC(zx_ff12_LogoutRequest_REV_ProviderID) */

void zx_ff12_LogoutRequest_REV_ProviderID(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderID;
  if (!y) return;
  x->ProviderID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderID->g;
    x->ProviderID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutRequest_PUT_ProviderID) */

void zx_ff12_LogoutRequest_PUT_ProviderID(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_LogoutRequest_ADD_ProviderID) */

void zx_ff12_LogoutRequest_ADD_ProviderID(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderID->g;
    x->ProviderID = z;
    return;
  case -1:
    y = x->ProviderID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_LogoutRequest_DEL_ProviderID) */

void zx_ff12_LogoutRequest_DEL_ProviderID(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderID = (struct zx_elem_s*)x->ProviderID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutRequest_NUM_NameIdentifier) */

int zx_ff12_LogoutRequest_NUM_NameIdentifier(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_sa11_NameIdentifier_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->NameIdentifier; y; ++n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutRequest_GET_NameIdentifier) */

struct zx_sa11_NameIdentifier_s* zx_ff12_LogoutRequest_GET_NameIdentifier(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return 0;
  for (y = x->NameIdentifier; n>=0 && y; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_POP_NameIdentifier) */

struct zx_sa11_NameIdentifier_s* zx_ff12_LogoutRequest_POP_NameIdentifier(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return 0;
  y = x->NameIdentifier;
  if (y)
    x->NameIdentifier = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_PUSH_NameIdentifier) */

void zx_ff12_LogoutRequest_PUSH_NameIdentifier(struct zx_ff12_LogoutRequest_s* x, struct zx_sa11_NameIdentifier_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->NameIdentifier->gg.g;
  x->NameIdentifier = z;
}

/* FUNC(zx_ff12_LogoutRequest_REV_NameIdentifier) */

void zx_ff12_LogoutRequest_REV_NameIdentifier(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_sa11_NameIdentifier_s* nxt;
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return;
  y = x->NameIdentifier;
  if (!y) return;
  x->NameIdentifier = 0;
  while (y) {
    nxt = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n;
    y->gg.g.n = &x->NameIdentifier->gg.g;
    x->NameIdentifier = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutRequest_PUT_NameIdentifier) */

void zx_ff12_LogoutRequest_PUT_NameIdentifier(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_sa11_NameIdentifier_s* z)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x || !z) return;
  y = x->NameIdentifier;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->NameIdentifier = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_LogoutRequest_ADD_NameIdentifier) */

void zx_ff12_LogoutRequest_ADD_NameIdentifier(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_sa11_NameIdentifier_s* z)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->NameIdentifier->gg.g;
    x->NameIdentifier = z;
    return;
  case -1:
    y = x->NameIdentifier;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->NameIdentifier; n > 1 && y; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_LogoutRequest_DEL_NameIdentifier) */

void zx_ff12_LogoutRequest_DEL_NameIdentifier(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->NameIdentifier = (struct zx_sa11_NameIdentifier_s*)x->NameIdentifier->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_NameIdentifier_s*)x->NameIdentifier;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->NameIdentifier; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutRequest_NUM_SessionIndex) */

int zx_ff12_LogoutRequest_NUM_SessionIndex(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->SessionIndex; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutRequest_GET_SessionIndex) */

struct zx_elem_s* zx_ff12_LogoutRequest_GET_SessionIndex(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->SessionIndex; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_POP_SessionIndex) */

struct zx_elem_s* zx_ff12_LogoutRequest_POP_SessionIndex(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->SessionIndex;
  if (y)
    x->SessionIndex = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_PUSH_SessionIndex) */

void zx_ff12_LogoutRequest_PUSH_SessionIndex(struct zx_ff12_LogoutRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->SessionIndex->g;
  x->SessionIndex = z;
}

/* FUNC(zx_ff12_LogoutRequest_REV_SessionIndex) */

void zx_ff12_LogoutRequest_REV_SessionIndex(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->SessionIndex;
  if (!y) return;
  x->SessionIndex = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->SessionIndex->g;
    x->SessionIndex = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutRequest_PUT_SessionIndex) */

void zx_ff12_LogoutRequest_PUT_SessionIndex(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->SessionIndex;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->SessionIndex = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_LogoutRequest_ADD_SessionIndex) */

void zx_ff12_LogoutRequest_ADD_SessionIndex(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->SessionIndex->g;
    x->SessionIndex = z;
    return;
  case -1:
    y = x->SessionIndex;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->SessionIndex; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_LogoutRequest_DEL_SessionIndex) */

void zx_ff12_LogoutRequest_DEL_SessionIndex(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->SessionIndex = (struct zx_elem_s*)x->SessionIndex->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->SessionIndex;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->SessionIndex; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutRequest_NUM_RelayState) */

int zx_ff12_LogoutRequest_NUM_RelayState(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RelayState; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutRequest_GET_RelayState) */

struct zx_elem_s* zx_ff12_LogoutRequest_GET_RelayState(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->RelayState; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_POP_RelayState) */

struct zx_elem_s* zx_ff12_LogoutRequest_POP_RelayState(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->RelayState;
  if (y)
    x->RelayState = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutRequest_PUSH_RelayState) */

void zx_ff12_LogoutRequest_PUSH_RelayState(struct zx_ff12_LogoutRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->RelayState->g;
  x->RelayState = z;
}

/* FUNC(zx_ff12_LogoutRequest_REV_RelayState) */

void zx_ff12_LogoutRequest_REV_RelayState(struct zx_ff12_LogoutRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->RelayState;
  if (!y) return;
  x->RelayState = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->RelayState->g;
    x->RelayState = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutRequest_PUT_RelayState) */

void zx_ff12_LogoutRequest_PUT_RelayState(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->RelayState;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->RelayState = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_LogoutRequest_ADD_RelayState) */

void zx_ff12_LogoutRequest_ADD_RelayState(struct zx_ff12_LogoutRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->RelayState->g;
    x->RelayState = z;
    return;
  case -1:
    y = x->RelayState;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_LogoutRequest_DEL_RelayState) */

void zx_ff12_LogoutRequest_DEL_RelayState(struct zx_ff12_LogoutRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RelayState = (struct zx_elem_s*)x->RelayState->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->RelayState;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif

/* FUNC(zx_ff12_LogoutRequest_GET_IssueInstant) */
struct zx_str* zx_ff12_LogoutRequest_GET_IssueInstant(struct zx_ff12_LogoutRequest_s* x) { return x->IssueInstant; }
/* FUNC(zx_ff12_LogoutRequest_PUT_IssueInstant) */
void zx_ff12_LogoutRequest_PUT_IssueInstant(struct zx_ff12_LogoutRequest_s* x, struct zx_str* y) { x->IssueInstant = y; }
/* FUNC(zx_ff12_LogoutRequest_GET_MajorVersion) */
struct zx_str* zx_ff12_LogoutRequest_GET_MajorVersion(struct zx_ff12_LogoutRequest_s* x) { return x->MajorVersion; }
/* FUNC(zx_ff12_LogoutRequest_PUT_MajorVersion) */
void zx_ff12_LogoutRequest_PUT_MajorVersion(struct zx_ff12_LogoutRequest_s* x, struct zx_str* y) { x->MajorVersion = y; }
/* FUNC(zx_ff12_LogoutRequest_GET_MinorVersion) */
struct zx_str* zx_ff12_LogoutRequest_GET_MinorVersion(struct zx_ff12_LogoutRequest_s* x) { return x->MinorVersion; }
/* FUNC(zx_ff12_LogoutRequest_PUT_MinorVersion) */
void zx_ff12_LogoutRequest_PUT_MinorVersion(struct zx_ff12_LogoutRequest_s* x, struct zx_str* y) { x->MinorVersion = y; }
/* FUNC(zx_ff12_LogoutRequest_GET_NotOnOrAfter) */
struct zx_str* zx_ff12_LogoutRequest_GET_NotOnOrAfter(struct zx_ff12_LogoutRequest_s* x) { return x->NotOnOrAfter; }
/* FUNC(zx_ff12_LogoutRequest_PUT_NotOnOrAfter) */
void zx_ff12_LogoutRequest_PUT_NotOnOrAfter(struct zx_ff12_LogoutRequest_s* x, struct zx_str* y) { x->NotOnOrAfter = y; }
/* FUNC(zx_ff12_LogoutRequest_GET_RequestID) */
struct zx_str* zx_ff12_LogoutRequest_GET_RequestID(struct zx_ff12_LogoutRequest_s* x) { return x->RequestID; }
/* FUNC(zx_ff12_LogoutRequest_PUT_RequestID) */
void zx_ff12_LogoutRequest_PUT_RequestID(struct zx_ff12_LogoutRequest_s* x, struct zx_str* y) { x->RequestID = y; }
/* FUNC(zx_ff12_LogoutRequest_GET_consent) */
struct zx_str* zx_ff12_LogoutRequest_GET_consent(struct zx_ff12_LogoutRequest_s* x) { return x->consent; }
/* FUNC(zx_ff12_LogoutRequest_PUT_consent) */
void zx_ff12_LogoutRequest_PUT_consent(struct zx_ff12_LogoutRequest_s* x, struct zx_str* y) { x->consent = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutResponse_NUM_Signature) */

int zx_ff12_LogoutResponse_NUM_Signature(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_ds_Signature_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Signature; y; ++n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutResponse_GET_Signature) */

struct zx_ds_Signature_s* zx_ff12_LogoutResponse_GET_Signature(struct zx_ff12_LogoutResponse_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  for (y = x->Signature; n>=0 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutResponse_POP_Signature) */

struct zx_ds_Signature_s* zx_ff12_LogoutResponse_POP_Signature(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  y = x->Signature;
  if (y)
    x->Signature = (struct zx_ds_Signature_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutResponse_PUSH_Signature) */

void zx_ff12_LogoutResponse_PUSH_Signature(struct zx_ff12_LogoutResponse_s* x, struct zx_ds_Signature_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Signature->gg.g;
  x->Signature = z;
}

/* FUNC(zx_ff12_LogoutResponse_REV_Signature) */

void zx_ff12_LogoutResponse_REV_Signature(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_ds_Signature_s* nxt;
  struct zx_ds_Signature_s* y;
  if (!x) return;
  y = x->Signature;
  if (!y) return;
  x->Signature = 0;
  while (y) {
    nxt = (struct zx_ds_Signature_s*)y->gg.g.n;
    y->gg.g.n = &x->Signature->gg.g;
    x->Signature = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutResponse_PUT_Signature) */

void zx_ff12_LogoutResponse_PUT_Signature(struct zx_ff12_LogoutResponse_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  y = x->Signature;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Signature = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_LogoutResponse_ADD_Signature) */

void zx_ff12_LogoutResponse_ADD_Signature(struct zx_ff12_LogoutResponse_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Signature->gg.g;
    x->Signature = z;
    return;
  case -1:
    y = x->Signature;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_LogoutResponse_DEL_Signature) */

void zx_ff12_LogoutResponse_DEL_Signature(struct zx_ff12_LogoutResponse_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Signature = (struct zx_ds_Signature_s*)x->Signature->gg.g.n;
    return;
  case -1:
    y = (struct zx_ds_Signature_s*)x->Signature;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutResponse_NUM_Extension) */

int zx_ff12_LogoutResponse_NUM_Extension(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_ff12_Extension_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Extension; y; ++n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutResponse_GET_Extension) */

struct zx_ff12_Extension_s* zx_ff12_LogoutResponse_GET_Extension(struct zx_ff12_LogoutResponse_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  for (y = x->Extension; n>=0 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutResponse_POP_Extension) */

struct zx_ff12_Extension_s* zx_ff12_LogoutResponse_POP_Extension(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  y = x->Extension;
  if (y)
    x->Extension = (struct zx_ff12_Extension_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutResponse_PUSH_Extension) */

void zx_ff12_LogoutResponse_PUSH_Extension(struct zx_ff12_LogoutResponse_s* x, struct zx_ff12_Extension_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Extension->gg.g;
  x->Extension = z;
}

/* FUNC(zx_ff12_LogoutResponse_REV_Extension) */

void zx_ff12_LogoutResponse_REV_Extension(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_ff12_Extension_s* nxt;
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  y = x->Extension;
  if (!y) return;
  x->Extension = 0;
  while (y) {
    nxt = (struct zx_ff12_Extension_s*)y->gg.g.n;
    y->gg.g.n = &x->Extension->gg.g;
    x->Extension = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutResponse_PUT_Extension) */

void zx_ff12_LogoutResponse_PUT_Extension(struct zx_ff12_LogoutResponse_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  y = x->Extension;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Extension = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_LogoutResponse_ADD_Extension) */

void zx_ff12_LogoutResponse_ADD_Extension(struct zx_ff12_LogoutResponse_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Extension->gg.g;
    x->Extension = z;
    return;
  case -1:
    y = x->Extension;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_LogoutResponse_DEL_Extension) */

void zx_ff12_LogoutResponse_DEL_Extension(struct zx_ff12_LogoutResponse_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Extension = (struct zx_ff12_Extension_s*)x->Extension->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Extension_s*)x->Extension;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutResponse_NUM_ProviderID) */

int zx_ff12_LogoutResponse_NUM_ProviderID(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutResponse_GET_ProviderID) */

struct zx_elem_s* zx_ff12_LogoutResponse_GET_ProviderID(struct zx_ff12_LogoutResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutResponse_POP_ProviderID) */

struct zx_elem_s* zx_ff12_LogoutResponse_POP_ProviderID(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderID;
  if (y)
    x->ProviderID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutResponse_PUSH_ProviderID) */

void zx_ff12_LogoutResponse_PUSH_ProviderID(struct zx_ff12_LogoutResponse_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderID->g;
  x->ProviderID = z;
}

/* FUNC(zx_ff12_LogoutResponse_REV_ProviderID) */

void zx_ff12_LogoutResponse_REV_ProviderID(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderID;
  if (!y) return;
  x->ProviderID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderID->g;
    x->ProviderID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutResponse_PUT_ProviderID) */

void zx_ff12_LogoutResponse_PUT_ProviderID(struct zx_ff12_LogoutResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_LogoutResponse_ADD_ProviderID) */

void zx_ff12_LogoutResponse_ADD_ProviderID(struct zx_ff12_LogoutResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderID->g;
    x->ProviderID = z;
    return;
  case -1:
    y = x->ProviderID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_LogoutResponse_DEL_ProviderID) */

void zx_ff12_LogoutResponse_DEL_ProviderID(struct zx_ff12_LogoutResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderID = (struct zx_elem_s*)x->ProviderID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutResponse_NUM_Status) */

int zx_ff12_LogoutResponse_NUM_Status(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_sp11_Status_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Status; y; ++n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutResponse_GET_Status) */

struct zx_sp11_Status_s* zx_ff12_LogoutResponse_GET_Status(struct zx_ff12_LogoutResponse_s* x, int n)
{
  struct zx_sp11_Status_s* y;
  if (!x) return 0;
  for (y = x->Status; n>=0 && y; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutResponse_POP_Status) */

struct zx_sp11_Status_s* zx_ff12_LogoutResponse_POP_Status(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_sp11_Status_s* y;
  if (!x) return 0;
  y = x->Status;
  if (y)
    x->Status = (struct zx_sp11_Status_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutResponse_PUSH_Status) */

void zx_ff12_LogoutResponse_PUSH_Status(struct zx_ff12_LogoutResponse_s* x, struct zx_sp11_Status_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Status->gg.g;
  x->Status = z;
}

/* FUNC(zx_ff12_LogoutResponse_REV_Status) */

void zx_ff12_LogoutResponse_REV_Status(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_sp11_Status_s* nxt;
  struct zx_sp11_Status_s* y;
  if (!x) return;
  y = x->Status;
  if (!y) return;
  x->Status = 0;
  while (y) {
    nxt = (struct zx_sp11_Status_s*)y->gg.g.n;
    y->gg.g.n = &x->Status->gg.g;
    x->Status = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutResponse_PUT_Status) */

void zx_ff12_LogoutResponse_PUT_Status(struct zx_ff12_LogoutResponse_s* x, int n, struct zx_sp11_Status_s* z)
{
  struct zx_sp11_Status_s* y;
  if (!x || !z) return;
  y = x->Status;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Status = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_LogoutResponse_ADD_Status) */

void zx_ff12_LogoutResponse_ADD_Status(struct zx_ff12_LogoutResponse_s* x, int n, struct zx_sp11_Status_s* z)
{
  struct zx_sp11_Status_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Status->gg.g;
    x->Status = z;
    return;
  case -1:
    y = x->Status;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Status; n > 1 && y; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_LogoutResponse_DEL_Status) */

void zx_ff12_LogoutResponse_DEL_Status(struct zx_ff12_LogoutResponse_s* x, int n)
{
  struct zx_sp11_Status_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Status = (struct zx_sp11_Status_s*)x->Status->gg.g.n;
    return;
  case -1:
    y = (struct zx_sp11_Status_s*)x->Status;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Status; n > 1 && y->gg.g.n; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_LogoutResponse_NUM_RelayState) */

int zx_ff12_LogoutResponse_NUM_RelayState(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RelayState; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_LogoutResponse_GET_RelayState) */

struct zx_elem_s* zx_ff12_LogoutResponse_GET_RelayState(struct zx_ff12_LogoutResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->RelayState; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_LogoutResponse_POP_RelayState) */

struct zx_elem_s* zx_ff12_LogoutResponse_POP_RelayState(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->RelayState;
  if (y)
    x->RelayState = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_LogoutResponse_PUSH_RelayState) */

void zx_ff12_LogoutResponse_PUSH_RelayState(struct zx_ff12_LogoutResponse_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->RelayState->g;
  x->RelayState = z;
}

/* FUNC(zx_ff12_LogoutResponse_REV_RelayState) */

void zx_ff12_LogoutResponse_REV_RelayState(struct zx_ff12_LogoutResponse_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->RelayState;
  if (!y) return;
  x->RelayState = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->RelayState->g;
    x->RelayState = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_LogoutResponse_PUT_RelayState) */

void zx_ff12_LogoutResponse_PUT_RelayState(struct zx_ff12_LogoutResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->RelayState;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->RelayState = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_LogoutResponse_ADD_RelayState) */

void zx_ff12_LogoutResponse_ADD_RelayState(struct zx_ff12_LogoutResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->RelayState->g;
    x->RelayState = z;
    return;
  case -1:
    y = x->RelayState;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_LogoutResponse_DEL_RelayState) */

void zx_ff12_LogoutResponse_DEL_RelayState(struct zx_ff12_LogoutResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RelayState = (struct zx_elem_s*)x->RelayState->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->RelayState;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif

/* FUNC(zx_ff12_LogoutResponse_GET_InResponseTo) */
struct zx_str* zx_ff12_LogoutResponse_GET_InResponseTo(struct zx_ff12_LogoutResponse_s* x) { return x->InResponseTo; }
/* FUNC(zx_ff12_LogoutResponse_PUT_InResponseTo) */
void zx_ff12_LogoutResponse_PUT_InResponseTo(struct zx_ff12_LogoutResponse_s* x, struct zx_str* y) { x->InResponseTo = y; }
/* FUNC(zx_ff12_LogoutResponse_GET_IssueInstant) */
struct zx_str* zx_ff12_LogoutResponse_GET_IssueInstant(struct zx_ff12_LogoutResponse_s* x) { return x->IssueInstant; }
/* FUNC(zx_ff12_LogoutResponse_PUT_IssueInstant) */
void zx_ff12_LogoutResponse_PUT_IssueInstant(struct zx_ff12_LogoutResponse_s* x, struct zx_str* y) { x->IssueInstant = y; }
/* FUNC(zx_ff12_LogoutResponse_GET_MajorVersion) */
struct zx_str* zx_ff12_LogoutResponse_GET_MajorVersion(struct zx_ff12_LogoutResponse_s* x) { return x->MajorVersion; }
/* FUNC(zx_ff12_LogoutResponse_PUT_MajorVersion) */
void zx_ff12_LogoutResponse_PUT_MajorVersion(struct zx_ff12_LogoutResponse_s* x, struct zx_str* y) { x->MajorVersion = y; }
/* FUNC(zx_ff12_LogoutResponse_GET_MinorVersion) */
struct zx_str* zx_ff12_LogoutResponse_GET_MinorVersion(struct zx_ff12_LogoutResponse_s* x) { return x->MinorVersion; }
/* FUNC(zx_ff12_LogoutResponse_PUT_MinorVersion) */
void zx_ff12_LogoutResponse_PUT_MinorVersion(struct zx_ff12_LogoutResponse_s* x, struct zx_str* y) { x->MinorVersion = y; }
/* FUNC(zx_ff12_LogoutResponse_GET_Recipient) */
struct zx_str* zx_ff12_LogoutResponse_GET_Recipient(struct zx_ff12_LogoutResponse_s* x) { return x->Recipient; }
/* FUNC(zx_ff12_LogoutResponse_PUT_Recipient) */
void zx_ff12_LogoutResponse_PUT_Recipient(struct zx_ff12_LogoutResponse_s* x, struct zx_str* y) { x->Recipient = y; }
/* FUNC(zx_ff12_LogoutResponse_GET_ResponseID) */
struct zx_str* zx_ff12_LogoutResponse_GET_ResponseID(struct zx_ff12_LogoutResponse_s* x) { return x->ResponseID; }
/* FUNC(zx_ff12_LogoutResponse_PUT_ResponseID) */
void zx_ff12_LogoutResponse_PUT_ResponseID(struct zx_ff12_LogoutResponse_s* x, struct zx_str* y) { x->ResponseID = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_NameIdentifierMappingRequest_NUM_RespondWith) */

int zx_ff12_NameIdentifierMappingRequest_NUM_RespondWith(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RespondWith; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_GET_RespondWith) */

struct zx_elem_s* zx_ff12_NameIdentifierMappingRequest_GET_RespondWith(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->RespondWith; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_POP_RespondWith) */

struct zx_elem_s* zx_ff12_NameIdentifierMappingRequest_POP_RespondWith(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->RespondWith;
  if (y)
    x->RespondWith = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUSH_RespondWith) */

void zx_ff12_NameIdentifierMappingRequest_PUSH_RespondWith(struct zx_ff12_NameIdentifierMappingRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->RespondWith->g;
  x->RespondWith = z;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_REV_RespondWith) */

void zx_ff12_NameIdentifierMappingRequest_REV_RespondWith(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->RespondWith;
  if (!y) return;
  x->RespondWith = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->RespondWith->g;
    x->RespondWith = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUT_RespondWith) */

void zx_ff12_NameIdentifierMappingRequest_PUT_RespondWith(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->RespondWith;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->RespondWith = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_ADD_RespondWith) */

void zx_ff12_NameIdentifierMappingRequest_ADD_RespondWith(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->RespondWith->g;
    x->RespondWith = z;
    return;
  case -1:
    y = x->RespondWith;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RespondWith; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_DEL_RespondWith) */

void zx_ff12_NameIdentifierMappingRequest_DEL_RespondWith(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RespondWith = (struct zx_elem_s*)x->RespondWith->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->RespondWith;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RespondWith; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_NameIdentifierMappingRequest_NUM_Signature) */

int zx_ff12_NameIdentifierMappingRequest_NUM_Signature(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_ds_Signature_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Signature; y; ++n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_GET_Signature) */

struct zx_ds_Signature_s* zx_ff12_NameIdentifierMappingRequest_GET_Signature(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  for (y = x->Signature; n>=0 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_POP_Signature) */

struct zx_ds_Signature_s* zx_ff12_NameIdentifierMappingRequest_POP_Signature(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  y = x->Signature;
  if (y)
    x->Signature = (struct zx_ds_Signature_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUSH_Signature) */

void zx_ff12_NameIdentifierMappingRequest_PUSH_Signature(struct zx_ff12_NameIdentifierMappingRequest_s* x, struct zx_ds_Signature_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Signature->gg.g;
  x->Signature = z;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_REV_Signature) */

void zx_ff12_NameIdentifierMappingRequest_REV_Signature(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_ds_Signature_s* nxt;
  struct zx_ds_Signature_s* y;
  if (!x) return;
  y = x->Signature;
  if (!y) return;
  x->Signature = 0;
  while (y) {
    nxt = (struct zx_ds_Signature_s*)y->gg.g.n;
    y->gg.g.n = &x->Signature->gg.g;
    x->Signature = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUT_Signature) */

void zx_ff12_NameIdentifierMappingRequest_PUT_Signature(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  y = x->Signature;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Signature = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_ADD_Signature) */

void zx_ff12_NameIdentifierMappingRequest_ADD_Signature(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Signature->gg.g;
    x->Signature = z;
    return;
  case -1:
    y = x->Signature;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_DEL_Signature) */

void zx_ff12_NameIdentifierMappingRequest_DEL_Signature(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Signature = (struct zx_ds_Signature_s*)x->Signature->gg.g.n;
    return;
  case -1:
    y = (struct zx_ds_Signature_s*)x->Signature;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_NameIdentifierMappingRequest_NUM_Extension) */

int zx_ff12_NameIdentifierMappingRequest_NUM_Extension(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_ff12_Extension_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Extension; y; ++n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_GET_Extension) */

struct zx_ff12_Extension_s* zx_ff12_NameIdentifierMappingRequest_GET_Extension(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  for (y = x->Extension; n>=0 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_POP_Extension) */

struct zx_ff12_Extension_s* zx_ff12_NameIdentifierMappingRequest_POP_Extension(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  y = x->Extension;
  if (y)
    x->Extension = (struct zx_ff12_Extension_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUSH_Extension) */

void zx_ff12_NameIdentifierMappingRequest_PUSH_Extension(struct zx_ff12_NameIdentifierMappingRequest_s* x, struct zx_ff12_Extension_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Extension->gg.g;
  x->Extension = z;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_REV_Extension) */

void zx_ff12_NameIdentifierMappingRequest_REV_Extension(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_ff12_Extension_s* nxt;
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  y = x->Extension;
  if (!y) return;
  x->Extension = 0;
  while (y) {
    nxt = (struct zx_ff12_Extension_s*)y->gg.g.n;
    y->gg.g.n = &x->Extension->gg.g;
    x->Extension = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUT_Extension) */

void zx_ff12_NameIdentifierMappingRequest_PUT_Extension(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  y = x->Extension;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Extension = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_ADD_Extension) */

void zx_ff12_NameIdentifierMappingRequest_ADD_Extension(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Extension->gg.g;
    x->Extension = z;
    return;
  case -1:
    y = x->Extension;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_DEL_Extension) */

void zx_ff12_NameIdentifierMappingRequest_DEL_Extension(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Extension = (struct zx_ff12_Extension_s*)x->Extension->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Extension_s*)x->Extension;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_NameIdentifierMappingRequest_NUM_ProviderID) */

int zx_ff12_NameIdentifierMappingRequest_NUM_ProviderID(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_GET_ProviderID) */

struct zx_elem_s* zx_ff12_NameIdentifierMappingRequest_GET_ProviderID(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_POP_ProviderID) */

struct zx_elem_s* zx_ff12_NameIdentifierMappingRequest_POP_ProviderID(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderID;
  if (y)
    x->ProviderID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUSH_ProviderID) */

void zx_ff12_NameIdentifierMappingRequest_PUSH_ProviderID(struct zx_ff12_NameIdentifierMappingRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderID->g;
  x->ProviderID = z;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_REV_ProviderID) */

void zx_ff12_NameIdentifierMappingRequest_REV_ProviderID(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderID;
  if (!y) return;
  x->ProviderID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderID->g;
    x->ProviderID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUT_ProviderID) */

void zx_ff12_NameIdentifierMappingRequest_PUT_ProviderID(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_ADD_ProviderID) */

void zx_ff12_NameIdentifierMappingRequest_ADD_ProviderID(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderID->g;
    x->ProviderID = z;
    return;
  case -1:
    y = x->ProviderID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_DEL_ProviderID) */

void zx_ff12_NameIdentifierMappingRequest_DEL_ProviderID(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderID = (struct zx_elem_s*)x->ProviderID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_NameIdentifierMappingRequest_NUM_NameIdentifier) */

int zx_ff12_NameIdentifierMappingRequest_NUM_NameIdentifier(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_sa11_NameIdentifier_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->NameIdentifier; y; ++n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_GET_NameIdentifier) */

struct zx_sa11_NameIdentifier_s* zx_ff12_NameIdentifierMappingRequest_GET_NameIdentifier(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return 0;
  for (y = x->NameIdentifier; n>=0 && y; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_POP_NameIdentifier) */

struct zx_sa11_NameIdentifier_s* zx_ff12_NameIdentifierMappingRequest_POP_NameIdentifier(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return 0;
  y = x->NameIdentifier;
  if (y)
    x->NameIdentifier = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUSH_NameIdentifier) */

void zx_ff12_NameIdentifierMappingRequest_PUSH_NameIdentifier(struct zx_ff12_NameIdentifierMappingRequest_s* x, struct zx_sa11_NameIdentifier_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->NameIdentifier->gg.g;
  x->NameIdentifier = z;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_REV_NameIdentifier) */

void zx_ff12_NameIdentifierMappingRequest_REV_NameIdentifier(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_sa11_NameIdentifier_s* nxt;
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return;
  y = x->NameIdentifier;
  if (!y) return;
  x->NameIdentifier = 0;
  while (y) {
    nxt = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n;
    y->gg.g.n = &x->NameIdentifier->gg.g;
    x->NameIdentifier = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUT_NameIdentifier) */

void zx_ff12_NameIdentifierMappingRequest_PUT_NameIdentifier(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_sa11_NameIdentifier_s* z)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x || !z) return;
  y = x->NameIdentifier;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->NameIdentifier = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_ADD_NameIdentifier) */

void zx_ff12_NameIdentifierMappingRequest_ADD_NameIdentifier(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_sa11_NameIdentifier_s* z)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->NameIdentifier->gg.g;
    x->NameIdentifier = z;
    return;
  case -1:
    y = x->NameIdentifier;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->NameIdentifier; n > 1 && y; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_DEL_NameIdentifier) */

void zx_ff12_NameIdentifierMappingRequest_DEL_NameIdentifier(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->NameIdentifier = (struct zx_sa11_NameIdentifier_s*)x->NameIdentifier->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_NameIdentifier_s*)x->NameIdentifier;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->NameIdentifier; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_NameIdentifierMappingRequest_NUM_TargetNamespace) */

int zx_ff12_NameIdentifierMappingRequest_NUM_TargetNamespace(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->TargetNamespace; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_GET_TargetNamespace) */

struct zx_elem_s* zx_ff12_NameIdentifierMappingRequest_GET_TargetNamespace(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->TargetNamespace; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_POP_TargetNamespace) */

struct zx_elem_s* zx_ff12_NameIdentifierMappingRequest_POP_TargetNamespace(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->TargetNamespace;
  if (y)
    x->TargetNamespace = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUSH_TargetNamespace) */

void zx_ff12_NameIdentifierMappingRequest_PUSH_TargetNamespace(struct zx_ff12_NameIdentifierMappingRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->TargetNamespace->g;
  x->TargetNamespace = z;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_REV_TargetNamespace) */

void zx_ff12_NameIdentifierMappingRequest_REV_TargetNamespace(struct zx_ff12_NameIdentifierMappingRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->TargetNamespace;
  if (!y) return;
  x->TargetNamespace = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->TargetNamespace->g;
    x->TargetNamespace = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUT_TargetNamespace) */

void zx_ff12_NameIdentifierMappingRequest_PUT_TargetNamespace(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->TargetNamespace;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->TargetNamespace = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_ADD_TargetNamespace) */

void zx_ff12_NameIdentifierMappingRequest_ADD_TargetNamespace(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->TargetNamespace->g;
    x->TargetNamespace = z;
    return;
  case -1:
    y = x->TargetNamespace;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->TargetNamespace; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_NameIdentifierMappingRequest_DEL_TargetNamespace) */

void zx_ff12_NameIdentifierMappingRequest_DEL_TargetNamespace(struct zx_ff12_NameIdentifierMappingRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->TargetNamespace = (struct zx_elem_s*)x->TargetNamespace->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->TargetNamespace;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->TargetNamespace; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif

/* FUNC(zx_ff12_NameIdentifierMappingRequest_GET_IssueInstant) */
struct zx_str* zx_ff12_NameIdentifierMappingRequest_GET_IssueInstant(struct zx_ff12_NameIdentifierMappingRequest_s* x) { return x->IssueInstant; }
/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUT_IssueInstant) */
void zx_ff12_NameIdentifierMappingRequest_PUT_IssueInstant(struct zx_ff12_NameIdentifierMappingRequest_s* x, struct zx_str* y) { x->IssueInstant = y; }
/* FUNC(zx_ff12_NameIdentifierMappingRequest_GET_MajorVersion) */
struct zx_str* zx_ff12_NameIdentifierMappingRequest_GET_MajorVersion(struct zx_ff12_NameIdentifierMappingRequest_s* x) { return x->MajorVersion; }
/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUT_MajorVersion) */
void zx_ff12_NameIdentifierMappingRequest_PUT_MajorVersion(struct zx_ff12_NameIdentifierMappingRequest_s* x, struct zx_str* y) { x->MajorVersion = y; }
/* FUNC(zx_ff12_NameIdentifierMappingRequest_GET_MinorVersion) */
struct zx_str* zx_ff12_NameIdentifierMappingRequest_GET_MinorVersion(struct zx_ff12_NameIdentifierMappingRequest_s* x) { return x->MinorVersion; }
/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUT_MinorVersion) */
void zx_ff12_NameIdentifierMappingRequest_PUT_MinorVersion(struct zx_ff12_NameIdentifierMappingRequest_s* x, struct zx_str* y) { x->MinorVersion = y; }
/* FUNC(zx_ff12_NameIdentifierMappingRequest_GET_RequestID) */
struct zx_str* zx_ff12_NameIdentifierMappingRequest_GET_RequestID(struct zx_ff12_NameIdentifierMappingRequest_s* x) { return x->RequestID; }
/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUT_RequestID) */
void zx_ff12_NameIdentifierMappingRequest_PUT_RequestID(struct zx_ff12_NameIdentifierMappingRequest_s* x, struct zx_str* y) { x->RequestID = y; }
/* FUNC(zx_ff12_NameIdentifierMappingRequest_GET_consent) */
struct zx_str* zx_ff12_NameIdentifierMappingRequest_GET_consent(struct zx_ff12_NameIdentifierMappingRequest_s* x) { return x->consent; }
/* FUNC(zx_ff12_NameIdentifierMappingRequest_PUT_consent) */
void zx_ff12_NameIdentifierMappingRequest_PUT_consent(struct zx_ff12_NameIdentifierMappingRequest_s* x, struct zx_str* y) { x->consent = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_NameIdentifierMappingResponse_NUM_Signature) */

int zx_ff12_NameIdentifierMappingResponse_NUM_Signature(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_ds_Signature_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Signature; y; ++n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_GET_Signature) */

struct zx_ds_Signature_s* zx_ff12_NameIdentifierMappingResponse_GET_Signature(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  for (y = x->Signature; n>=0 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_POP_Signature) */

struct zx_ds_Signature_s* zx_ff12_NameIdentifierMappingResponse_POP_Signature(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  y = x->Signature;
  if (y)
    x->Signature = (struct zx_ds_Signature_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUSH_Signature) */

void zx_ff12_NameIdentifierMappingResponse_PUSH_Signature(struct zx_ff12_NameIdentifierMappingResponse_s* x, struct zx_ds_Signature_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Signature->gg.g;
  x->Signature = z;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_REV_Signature) */

void zx_ff12_NameIdentifierMappingResponse_REV_Signature(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_ds_Signature_s* nxt;
  struct zx_ds_Signature_s* y;
  if (!x) return;
  y = x->Signature;
  if (!y) return;
  x->Signature = 0;
  while (y) {
    nxt = (struct zx_ds_Signature_s*)y->gg.g.n;
    y->gg.g.n = &x->Signature->gg.g;
    x->Signature = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUT_Signature) */

void zx_ff12_NameIdentifierMappingResponse_PUT_Signature(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  y = x->Signature;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Signature = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_ADD_Signature) */

void zx_ff12_NameIdentifierMappingResponse_ADD_Signature(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Signature->gg.g;
    x->Signature = z;
    return;
  case -1:
    y = x->Signature;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_DEL_Signature) */

void zx_ff12_NameIdentifierMappingResponse_DEL_Signature(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Signature = (struct zx_ds_Signature_s*)x->Signature->gg.g.n;
    return;
  case -1:
    y = (struct zx_ds_Signature_s*)x->Signature;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_NameIdentifierMappingResponse_NUM_Extension) */

int zx_ff12_NameIdentifierMappingResponse_NUM_Extension(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_ff12_Extension_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Extension; y; ++n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_GET_Extension) */

struct zx_ff12_Extension_s* zx_ff12_NameIdentifierMappingResponse_GET_Extension(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  for (y = x->Extension; n>=0 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_POP_Extension) */

struct zx_ff12_Extension_s* zx_ff12_NameIdentifierMappingResponse_POP_Extension(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  y = x->Extension;
  if (y)
    x->Extension = (struct zx_ff12_Extension_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUSH_Extension) */

void zx_ff12_NameIdentifierMappingResponse_PUSH_Extension(struct zx_ff12_NameIdentifierMappingResponse_s* x, struct zx_ff12_Extension_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Extension->gg.g;
  x->Extension = z;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_REV_Extension) */

void zx_ff12_NameIdentifierMappingResponse_REV_Extension(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_ff12_Extension_s* nxt;
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  y = x->Extension;
  if (!y) return;
  x->Extension = 0;
  while (y) {
    nxt = (struct zx_ff12_Extension_s*)y->gg.g.n;
    y->gg.g.n = &x->Extension->gg.g;
    x->Extension = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUT_Extension) */

void zx_ff12_NameIdentifierMappingResponse_PUT_Extension(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  y = x->Extension;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Extension = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_ADD_Extension) */

void zx_ff12_NameIdentifierMappingResponse_ADD_Extension(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Extension->gg.g;
    x->Extension = z;
    return;
  case -1:
    y = x->Extension;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_DEL_Extension) */

void zx_ff12_NameIdentifierMappingResponse_DEL_Extension(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Extension = (struct zx_ff12_Extension_s*)x->Extension->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Extension_s*)x->Extension;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_NameIdentifierMappingResponse_NUM_ProviderID) */

int zx_ff12_NameIdentifierMappingResponse_NUM_ProviderID(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_GET_ProviderID) */

struct zx_elem_s* zx_ff12_NameIdentifierMappingResponse_GET_ProviderID(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_POP_ProviderID) */

struct zx_elem_s* zx_ff12_NameIdentifierMappingResponse_POP_ProviderID(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderID;
  if (y)
    x->ProviderID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUSH_ProviderID) */

void zx_ff12_NameIdentifierMappingResponse_PUSH_ProviderID(struct zx_ff12_NameIdentifierMappingResponse_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderID->g;
  x->ProviderID = z;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_REV_ProviderID) */

void zx_ff12_NameIdentifierMappingResponse_REV_ProviderID(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderID;
  if (!y) return;
  x->ProviderID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderID->g;
    x->ProviderID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUT_ProviderID) */

void zx_ff12_NameIdentifierMappingResponse_PUT_ProviderID(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_ADD_ProviderID) */

void zx_ff12_NameIdentifierMappingResponse_ADD_ProviderID(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderID->g;
    x->ProviderID = z;
    return;
  case -1:
    y = x->ProviderID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_DEL_ProviderID) */

void zx_ff12_NameIdentifierMappingResponse_DEL_ProviderID(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderID = (struct zx_elem_s*)x->ProviderID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_NameIdentifierMappingResponse_NUM_Status) */

int zx_ff12_NameIdentifierMappingResponse_NUM_Status(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_sp11_Status_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Status; y; ++n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_GET_Status) */

struct zx_sp11_Status_s* zx_ff12_NameIdentifierMappingResponse_GET_Status(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n)
{
  struct zx_sp11_Status_s* y;
  if (!x) return 0;
  for (y = x->Status; n>=0 && y; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_POP_Status) */

struct zx_sp11_Status_s* zx_ff12_NameIdentifierMappingResponse_POP_Status(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_sp11_Status_s* y;
  if (!x) return 0;
  y = x->Status;
  if (y)
    x->Status = (struct zx_sp11_Status_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUSH_Status) */

void zx_ff12_NameIdentifierMappingResponse_PUSH_Status(struct zx_ff12_NameIdentifierMappingResponse_s* x, struct zx_sp11_Status_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Status->gg.g;
  x->Status = z;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_REV_Status) */

void zx_ff12_NameIdentifierMappingResponse_REV_Status(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_sp11_Status_s* nxt;
  struct zx_sp11_Status_s* y;
  if (!x) return;
  y = x->Status;
  if (!y) return;
  x->Status = 0;
  while (y) {
    nxt = (struct zx_sp11_Status_s*)y->gg.g.n;
    y->gg.g.n = &x->Status->gg.g;
    x->Status = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUT_Status) */

void zx_ff12_NameIdentifierMappingResponse_PUT_Status(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n, struct zx_sp11_Status_s* z)
{
  struct zx_sp11_Status_s* y;
  if (!x || !z) return;
  y = x->Status;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Status = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_ADD_Status) */

void zx_ff12_NameIdentifierMappingResponse_ADD_Status(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n, struct zx_sp11_Status_s* z)
{
  struct zx_sp11_Status_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Status->gg.g;
    x->Status = z;
    return;
  case -1:
    y = x->Status;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Status; n > 1 && y; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_DEL_Status) */

void zx_ff12_NameIdentifierMappingResponse_DEL_Status(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n)
{
  struct zx_sp11_Status_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Status = (struct zx_sp11_Status_s*)x->Status->gg.g.n;
    return;
  case -1:
    y = (struct zx_sp11_Status_s*)x->Status;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Status; n > 1 && y->gg.g.n; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_NameIdentifierMappingResponse_NUM_NameIdentifier) */

int zx_ff12_NameIdentifierMappingResponse_NUM_NameIdentifier(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_sa11_NameIdentifier_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->NameIdentifier; y; ++n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_GET_NameIdentifier) */

struct zx_sa11_NameIdentifier_s* zx_ff12_NameIdentifierMappingResponse_GET_NameIdentifier(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return 0;
  for (y = x->NameIdentifier; n>=0 && y; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_POP_NameIdentifier) */

struct zx_sa11_NameIdentifier_s* zx_ff12_NameIdentifierMappingResponse_POP_NameIdentifier(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return 0;
  y = x->NameIdentifier;
  if (y)
    x->NameIdentifier = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUSH_NameIdentifier) */

void zx_ff12_NameIdentifierMappingResponse_PUSH_NameIdentifier(struct zx_ff12_NameIdentifierMappingResponse_s* x, struct zx_sa11_NameIdentifier_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->NameIdentifier->gg.g;
  x->NameIdentifier = z;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_REV_NameIdentifier) */

void zx_ff12_NameIdentifierMappingResponse_REV_NameIdentifier(struct zx_ff12_NameIdentifierMappingResponse_s* x)
{
  struct zx_sa11_NameIdentifier_s* nxt;
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return;
  y = x->NameIdentifier;
  if (!y) return;
  x->NameIdentifier = 0;
  while (y) {
    nxt = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n;
    y->gg.g.n = &x->NameIdentifier->gg.g;
    x->NameIdentifier = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUT_NameIdentifier) */

void zx_ff12_NameIdentifierMappingResponse_PUT_NameIdentifier(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n, struct zx_sa11_NameIdentifier_s* z)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x || !z) return;
  y = x->NameIdentifier;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->NameIdentifier = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_ADD_NameIdentifier) */

void zx_ff12_NameIdentifierMappingResponse_ADD_NameIdentifier(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n, struct zx_sa11_NameIdentifier_s* z)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->NameIdentifier->gg.g;
    x->NameIdentifier = z;
    return;
  case -1:
    y = x->NameIdentifier;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->NameIdentifier; n > 1 && y; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_NameIdentifierMappingResponse_DEL_NameIdentifier) */

void zx_ff12_NameIdentifierMappingResponse_DEL_NameIdentifier(struct zx_ff12_NameIdentifierMappingResponse_s* x, int n)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->NameIdentifier = (struct zx_sa11_NameIdentifier_s*)x->NameIdentifier->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_NameIdentifier_s*)x->NameIdentifier;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->NameIdentifier; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif

/* FUNC(zx_ff12_NameIdentifierMappingResponse_GET_InResponseTo) */
struct zx_str* zx_ff12_NameIdentifierMappingResponse_GET_InResponseTo(struct zx_ff12_NameIdentifierMappingResponse_s* x) { return x->InResponseTo; }
/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUT_InResponseTo) */
void zx_ff12_NameIdentifierMappingResponse_PUT_InResponseTo(struct zx_ff12_NameIdentifierMappingResponse_s* x, struct zx_str* y) { x->InResponseTo = y; }
/* FUNC(zx_ff12_NameIdentifierMappingResponse_GET_IssueInstant) */
struct zx_str* zx_ff12_NameIdentifierMappingResponse_GET_IssueInstant(struct zx_ff12_NameIdentifierMappingResponse_s* x) { return x->IssueInstant; }
/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUT_IssueInstant) */
void zx_ff12_NameIdentifierMappingResponse_PUT_IssueInstant(struct zx_ff12_NameIdentifierMappingResponse_s* x, struct zx_str* y) { x->IssueInstant = y; }
/* FUNC(zx_ff12_NameIdentifierMappingResponse_GET_MajorVersion) */
struct zx_str* zx_ff12_NameIdentifierMappingResponse_GET_MajorVersion(struct zx_ff12_NameIdentifierMappingResponse_s* x) { return x->MajorVersion; }
/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUT_MajorVersion) */
void zx_ff12_NameIdentifierMappingResponse_PUT_MajorVersion(struct zx_ff12_NameIdentifierMappingResponse_s* x, struct zx_str* y) { x->MajorVersion = y; }
/* FUNC(zx_ff12_NameIdentifierMappingResponse_GET_MinorVersion) */
struct zx_str* zx_ff12_NameIdentifierMappingResponse_GET_MinorVersion(struct zx_ff12_NameIdentifierMappingResponse_s* x) { return x->MinorVersion; }
/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUT_MinorVersion) */
void zx_ff12_NameIdentifierMappingResponse_PUT_MinorVersion(struct zx_ff12_NameIdentifierMappingResponse_s* x, struct zx_str* y) { x->MinorVersion = y; }
/* FUNC(zx_ff12_NameIdentifierMappingResponse_GET_Recipient) */
struct zx_str* zx_ff12_NameIdentifierMappingResponse_GET_Recipient(struct zx_ff12_NameIdentifierMappingResponse_s* x) { return x->Recipient; }
/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUT_Recipient) */
void zx_ff12_NameIdentifierMappingResponse_PUT_Recipient(struct zx_ff12_NameIdentifierMappingResponse_s* x, struct zx_str* y) { x->Recipient = y; }
/* FUNC(zx_ff12_NameIdentifierMappingResponse_GET_ResponseID) */
struct zx_str* zx_ff12_NameIdentifierMappingResponse_GET_ResponseID(struct zx_ff12_NameIdentifierMappingResponse_s* x) { return x->ResponseID; }
/* FUNC(zx_ff12_NameIdentifierMappingResponse_PUT_ResponseID) */
void zx_ff12_NameIdentifierMappingResponse_PUT_ResponseID(struct zx_ff12_NameIdentifierMappingResponse_s* x, struct zx_str* y) { x->ResponseID = y; }





/* FUNC(zx_ff12_OldProvidedNameIdentifier_GET_Format) */
struct zx_str* zx_ff12_OldProvidedNameIdentifier_GET_Format(struct zx_ff12_OldProvidedNameIdentifier_s* x) { return x->Format; }
/* FUNC(zx_ff12_OldProvidedNameIdentifier_PUT_Format) */
void zx_ff12_OldProvidedNameIdentifier_PUT_Format(struct zx_ff12_OldProvidedNameIdentifier_s* x, struct zx_str* y) { x->Format = y; }
/* FUNC(zx_ff12_OldProvidedNameIdentifier_GET_NameQualifier) */
struct zx_str* zx_ff12_OldProvidedNameIdentifier_GET_NameQualifier(struct zx_ff12_OldProvidedNameIdentifier_s* x) { return x->NameQualifier; }
/* FUNC(zx_ff12_OldProvidedNameIdentifier_PUT_NameQualifier) */
void zx_ff12_OldProvidedNameIdentifier_PUT_NameQualifier(struct zx_ff12_OldProvidedNameIdentifier_s* x, struct zx_str* y) { x->NameQualifier = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_NUM_RespondWith) */

int zx_ff12_RegisterNameIdentifierRequest_NUM_RespondWith(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RespondWith; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_RespondWith) */

struct zx_elem_s* zx_ff12_RegisterNameIdentifierRequest_GET_RespondWith(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->RespondWith; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_POP_RespondWith) */

struct zx_elem_s* zx_ff12_RegisterNameIdentifierRequest_POP_RespondWith(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->RespondWith;
  if (y)
    x->RespondWith = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUSH_RespondWith) */

void zx_ff12_RegisterNameIdentifierRequest_PUSH_RespondWith(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->RespondWith->g;
  x->RespondWith = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_REV_RespondWith) */

void zx_ff12_RegisterNameIdentifierRequest_REV_RespondWith(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->RespondWith;
  if (!y) return;
  x->RespondWith = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->RespondWith->g;
    x->RespondWith = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_RespondWith) */

void zx_ff12_RegisterNameIdentifierRequest_PUT_RespondWith(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->RespondWith;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->RespondWith = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_ADD_RespondWith) */

void zx_ff12_RegisterNameIdentifierRequest_ADD_RespondWith(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->RespondWith->g;
    x->RespondWith = z;
    return;
  case -1:
    y = x->RespondWith;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RespondWith; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_DEL_RespondWith) */

void zx_ff12_RegisterNameIdentifierRequest_DEL_RespondWith(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RespondWith = (struct zx_elem_s*)x->RespondWith->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->RespondWith;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RespondWith; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_NUM_Signature) */

int zx_ff12_RegisterNameIdentifierRequest_NUM_Signature(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ds_Signature_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Signature; y; ++n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_Signature) */

struct zx_ds_Signature_s* zx_ff12_RegisterNameIdentifierRequest_GET_Signature(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  for (y = x->Signature; n>=0 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_POP_Signature) */

struct zx_ds_Signature_s* zx_ff12_RegisterNameIdentifierRequest_POP_Signature(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  y = x->Signature;
  if (y)
    x->Signature = (struct zx_ds_Signature_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUSH_Signature) */

void zx_ff12_RegisterNameIdentifierRequest_PUSH_Signature(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_ds_Signature_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Signature->gg.g;
  x->Signature = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_REV_Signature) */

void zx_ff12_RegisterNameIdentifierRequest_REV_Signature(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ds_Signature_s* nxt;
  struct zx_ds_Signature_s* y;
  if (!x) return;
  y = x->Signature;
  if (!y) return;
  x->Signature = 0;
  while (y) {
    nxt = (struct zx_ds_Signature_s*)y->gg.g.n;
    y->gg.g.n = &x->Signature->gg.g;
    x->Signature = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_Signature) */

void zx_ff12_RegisterNameIdentifierRequest_PUT_Signature(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  y = x->Signature;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Signature = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_ADD_Signature) */

void zx_ff12_RegisterNameIdentifierRequest_ADD_Signature(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Signature->gg.g;
    x->Signature = z;
    return;
  case -1:
    y = x->Signature;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_DEL_Signature) */

void zx_ff12_RegisterNameIdentifierRequest_DEL_Signature(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Signature = (struct zx_ds_Signature_s*)x->Signature->gg.g.n;
    return;
  case -1:
    y = (struct zx_ds_Signature_s*)x->Signature;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_NUM_Extension) */

int zx_ff12_RegisterNameIdentifierRequest_NUM_Extension(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_Extension_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Extension; y; ++n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_Extension) */

struct zx_ff12_Extension_s* zx_ff12_RegisterNameIdentifierRequest_GET_Extension(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  for (y = x->Extension; n>=0 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_POP_Extension) */

struct zx_ff12_Extension_s* zx_ff12_RegisterNameIdentifierRequest_POP_Extension(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  y = x->Extension;
  if (y)
    x->Extension = (struct zx_ff12_Extension_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUSH_Extension) */

void zx_ff12_RegisterNameIdentifierRequest_PUSH_Extension(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_ff12_Extension_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Extension->gg.g;
  x->Extension = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_REV_Extension) */

void zx_ff12_RegisterNameIdentifierRequest_REV_Extension(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_Extension_s* nxt;
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  y = x->Extension;
  if (!y) return;
  x->Extension = 0;
  while (y) {
    nxt = (struct zx_ff12_Extension_s*)y->gg.g.n;
    y->gg.g.n = &x->Extension->gg.g;
    x->Extension = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_Extension) */

void zx_ff12_RegisterNameIdentifierRequest_PUT_Extension(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  y = x->Extension;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Extension = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_ADD_Extension) */

void zx_ff12_RegisterNameIdentifierRequest_ADD_Extension(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Extension->gg.g;
    x->Extension = z;
    return;
  case -1:
    y = x->Extension;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_DEL_Extension) */

void zx_ff12_RegisterNameIdentifierRequest_DEL_Extension(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Extension = (struct zx_ff12_Extension_s*)x->Extension->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Extension_s*)x->Extension;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_NUM_ProviderID) */

int zx_ff12_RegisterNameIdentifierRequest_NUM_ProviderID(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_ProviderID) */

struct zx_elem_s* zx_ff12_RegisterNameIdentifierRequest_GET_ProviderID(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_POP_ProviderID) */

struct zx_elem_s* zx_ff12_RegisterNameIdentifierRequest_POP_ProviderID(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderID;
  if (y)
    x->ProviderID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUSH_ProviderID) */

void zx_ff12_RegisterNameIdentifierRequest_PUSH_ProviderID(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderID->g;
  x->ProviderID = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_REV_ProviderID) */

void zx_ff12_RegisterNameIdentifierRequest_REV_ProviderID(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderID;
  if (!y) return;
  x->ProviderID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderID->g;
    x->ProviderID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_ProviderID) */

void zx_ff12_RegisterNameIdentifierRequest_PUT_ProviderID(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_ADD_ProviderID) */

void zx_ff12_RegisterNameIdentifierRequest_ADD_ProviderID(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderID->g;
    x->ProviderID = z;
    return;
  case -1:
    y = x->ProviderID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_DEL_ProviderID) */

void zx_ff12_RegisterNameIdentifierRequest_DEL_ProviderID(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderID = (struct zx_elem_s*)x->ProviderID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_NUM_IDPProvidedNameIdentifier) */

int zx_ff12_RegisterNameIdentifierRequest_NUM_IDPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->IDPProvidedNameIdentifier; y; ++n, y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_IDPProvidedNameIdentifier) */

struct zx_ff12_IDPProvidedNameIdentifier_s* zx_ff12_RegisterNameIdentifierRequest_GET_IDPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x) return 0;
  for (y = x->IDPProvidedNameIdentifier; n>=0 && y; --n, y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_POP_IDPProvidedNameIdentifier) */

struct zx_ff12_IDPProvidedNameIdentifier_s* zx_ff12_RegisterNameIdentifierRequest_POP_IDPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x) return 0;
  y = x->IDPProvidedNameIdentifier;
  if (y)
    x->IDPProvidedNameIdentifier = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUSH_IDPProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_PUSH_IDPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_ff12_IDPProvidedNameIdentifier_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->IDPProvidedNameIdentifier->gg.g;
  x->IDPProvidedNameIdentifier = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_REV_IDPProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_REV_IDPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* nxt;
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x) return;
  y = x->IDPProvidedNameIdentifier;
  if (!y) return;
  x->IDPProvidedNameIdentifier = 0;
  while (y) {
    nxt = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n;
    y->gg.g.n = &x->IDPProvidedNameIdentifier->gg.g;
    x->IDPProvidedNameIdentifier = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_IDPProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_PUT_IDPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_ff12_IDPProvidedNameIdentifier_s* z)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x || !z) return;
  y = x->IDPProvidedNameIdentifier;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->IDPProvidedNameIdentifier = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_ADD_IDPProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_ADD_IDPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_ff12_IDPProvidedNameIdentifier_s* z)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->IDPProvidedNameIdentifier->gg.g;
    x->IDPProvidedNameIdentifier = z;
    return;
  case -1:
    y = x->IDPProvidedNameIdentifier;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPProvidedNameIdentifier; n > 1 && y; --n, y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_DEL_IDPProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_DEL_IDPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->IDPProvidedNameIdentifier = (struct zx_ff12_IDPProvidedNameIdentifier_s*)x->IDPProvidedNameIdentifier->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)x->IDPProvidedNameIdentifier;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPProvidedNameIdentifier; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_NUM_SPProvidedNameIdentifier) */

int zx_ff12_RegisterNameIdentifierRequest_NUM_SPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_SPProvidedNameIdentifier_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->SPProvidedNameIdentifier; y; ++n, y = (struct zx_ff12_SPProvidedNameIdentifier_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_SPProvidedNameIdentifier) */

struct zx_ff12_SPProvidedNameIdentifier_s* zx_ff12_RegisterNameIdentifierRequest_GET_SPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_ff12_SPProvidedNameIdentifier_s* y;
  if (!x) return 0;
  for (y = x->SPProvidedNameIdentifier; n>=0 && y; --n, y = (struct zx_ff12_SPProvidedNameIdentifier_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_POP_SPProvidedNameIdentifier) */

struct zx_ff12_SPProvidedNameIdentifier_s* zx_ff12_RegisterNameIdentifierRequest_POP_SPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_SPProvidedNameIdentifier_s* y;
  if (!x) return 0;
  y = x->SPProvidedNameIdentifier;
  if (y)
    x->SPProvidedNameIdentifier = (struct zx_ff12_SPProvidedNameIdentifier_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUSH_SPProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_PUSH_SPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_ff12_SPProvidedNameIdentifier_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->SPProvidedNameIdentifier->gg.g;
  x->SPProvidedNameIdentifier = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_REV_SPProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_REV_SPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_SPProvidedNameIdentifier_s* nxt;
  struct zx_ff12_SPProvidedNameIdentifier_s* y;
  if (!x) return;
  y = x->SPProvidedNameIdentifier;
  if (!y) return;
  x->SPProvidedNameIdentifier = 0;
  while (y) {
    nxt = (struct zx_ff12_SPProvidedNameIdentifier_s*)y->gg.g.n;
    y->gg.g.n = &x->SPProvidedNameIdentifier->gg.g;
    x->SPProvidedNameIdentifier = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_SPProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_PUT_SPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_ff12_SPProvidedNameIdentifier_s* z)
{
  struct zx_ff12_SPProvidedNameIdentifier_s* y;
  if (!x || !z) return;
  y = x->SPProvidedNameIdentifier;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->SPProvidedNameIdentifier = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_SPProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_ADD_SPProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_ADD_SPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_ff12_SPProvidedNameIdentifier_s* z)
{
  struct zx_ff12_SPProvidedNameIdentifier_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->SPProvidedNameIdentifier->gg.g;
    x->SPProvidedNameIdentifier = z;
    return;
  case -1:
    y = x->SPProvidedNameIdentifier;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_SPProvidedNameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->SPProvidedNameIdentifier; n > 1 && y; --n, y = (struct zx_ff12_SPProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_DEL_SPProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_DEL_SPProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_ff12_SPProvidedNameIdentifier_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->SPProvidedNameIdentifier = (struct zx_ff12_SPProvidedNameIdentifier_s*)x->SPProvidedNameIdentifier->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_SPProvidedNameIdentifier_s*)x->SPProvidedNameIdentifier;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_SPProvidedNameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->SPProvidedNameIdentifier; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_SPProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_NUM_OldProvidedNameIdentifier) */

int zx_ff12_RegisterNameIdentifierRequest_NUM_OldProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_OldProvidedNameIdentifier_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->OldProvidedNameIdentifier; y; ++n, y = (struct zx_ff12_OldProvidedNameIdentifier_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_OldProvidedNameIdentifier) */

struct zx_ff12_OldProvidedNameIdentifier_s* zx_ff12_RegisterNameIdentifierRequest_GET_OldProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_ff12_OldProvidedNameIdentifier_s* y;
  if (!x) return 0;
  for (y = x->OldProvidedNameIdentifier; n>=0 && y; --n, y = (struct zx_ff12_OldProvidedNameIdentifier_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_POP_OldProvidedNameIdentifier) */

struct zx_ff12_OldProvidedNameIdentifier_s* zx_ff12_RegisterNameIdentifierRequest_POP_OldProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_OldProvidedNameIdentifier_s* y;
  if (!x) return 0;
  y = x->OldProvidedNameIdentifier;
  if (y)
    x->OldProvidedNameIdentifier = (struct zx_ff12_OldProvidedNameIdentifier_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUSH_OldProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_PUSH_OldProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_ff12_OldProvidedNameIdentifier_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->OldProvidedNameIdentifier->gg.g;
  x->OldProvidedNameIdentifier = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_REV_OldProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_REV_OldProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_ff12_OldProvidedNameIdentifier_s* nxt;
  struct zx_ff12_OldProvidedNameIdentifier_s* y;
  if (!x) return;
  y = x->OldProvidedNameIdentifier;
  if (!y) return;
  x->OldProvidedNameIdentifier = 0;
  while (y) {
    nxt = (struct zx_ff12_OldProvidedNameIdentifier_s*)y->gg.g.n;
    y->gg.g.n = &x->OldProvidedNameIdentifier->gg.g;
    x->OldProvidedNameIdentifier = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_OldProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_PUT_OldProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_ff12_OldProvidedNameIdentifier_s* z)
{
  struct zx_ff12_OldProvidedNameIdentifier_s* y;
  if (!x || !z) return;
  y = x->OldProvidedNameIdentifier;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->OldProvidedNameIdentifier = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_OldProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_ADD_OldProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_ADD_OldProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_ff12_OldProvidedNameIdentifier_s* z)
{
  struct zx_ff12_OldProvidedNameIdentifier_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->OldProvidedNameIdentifier->gg.g;
    x->OldProvidedNameIdentifier = z;
    return;
  case -1:
    y = x->OldProvidedNameIdentifier;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_OldProvidedNameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->OldProvidedNameIdentifier; n > 1 && y; --n, y = (struct zx_ff12_OldProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_DEL_OldProvidedNameIdentifier) */

void zx_ff12_RegisterNameIdentifierRequest_DEL_OldProvidedNameIdentifier(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_ff12_OldProvidedNameIdentifier_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->OldProvidedNameIdentifier = (struct zx_ff12_OldProvidedNameIdentifier_s*)x->OldProvidedNameIdentifier->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_OldProvidedNameIdentifier_s*)x->OldProvidedNameIdentifier;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_OldProvidedNameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->OldProvidedNameIdentifier; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_OldProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_NUM_RelayState) */

int zx_ff12_RegisterNameIdentifierRequest_NUM_RelayState(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RelayState; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_RelayState) */

struct zx_elem_s* zx_ff12_RegisterNameIdentifierRequest_GET_RelayState(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->RelayState; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_POP_RelayState) */

struct zx_elem_s* zx_ff12_RegisterNameIdentifierRequest_POP_RelayState(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->RelayState;
  if (y)
    x->RelayState = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUSH_RelayState) */

void zx_ff12_RegisterNameIdentifierRequest_PUSH_RelayState(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->RelayState->g;
  x->RelayState = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_REV_RelayState) */

void zx_ff12_RegisterNameIdentifierRequest_REV_RelayState(struct zx_ff12_RegisterNameIdentifierRequest_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->RelayState;
  if (!y) return;
  x->RelayState = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->RelayState->g;
    x->RelayState = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_RelayState) */

void zx_ff12_RegisterNameIdentifierRequest_PUT_RelayState(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->RelayState;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->RelayState = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_ADD_RelayState) */

void zx_ff12_RegisterNameIdentifierRequest_ADD_RelayState(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->RelayState->g;
    x->RelayState = z;
    return;
  case -1:
    y = x->RelayState;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_DEL_RelayState) */

void zx_ff12_RegisterNameIdentifierRequest_DEL_RelayState(struct zx_ff12_RegisterNameIdentifierRequest_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RelayState = (struct zx_elem_s*)x->RelayState->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->RelayState;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif

/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_IssueInstant) */
struct zx_str* zx_ff12_RegisterNameIdentifierRequest_GET_IssueInstant(struct zx_ff12_RegisterNameIdentifierRequest_s* x) { return x->IssueInstant; }
/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_IssueInstant) */
void zx_ff12_RegisterNameIdentifierRequest_PUT_IssueInstant(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_str* y) { x->IssueInstant = y; }
/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_MajorVersion) */
struct zx_str* zx_ff12_RegisterNameIdentifierRequest_GET_MajorVersion(struct zx_ff12_RegisterNameIdentifierRequest_s* x) { return x->MajorVersion; }
/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_MajorVersion) */
void zx_ff12_RegisterNameIdentifierRequest_PUT_MajorVersion(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_str* y) { x->MajorVersion = y; }
/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_MinorVersion) */
struct zx_str* zx_ff12_RegisterNameIdentifierRequest_GET_MinorVersion(struct zx_ff12_RegisterNameIdentifierRequest_s* x) { return x->MinorVersion; }
/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_MinorVersion) */
void zx_ff12_RegisterNameIdentifierRequest_PUT_MinorVersion(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_str* y) { x->MinorVersion = y; }
/* FUNC(zx_ff12_RegisterNameIdentifierRequest_GET_RequestID) */
struct zx_str* zx_ff12_RegisterNameIdentifierRequest_GET_RequestID(struct zx_ff12_RegisterNameIdentifierRequest_s* x) { return x->RequestID; }
/* FUNC(zx_ff12_RegisterNameIdentifierRequest_PUT_RequestID) */
void zx_ff12_RegisterNameIdentifierRequest_PUT_RequestID(struct zx_ff12_RegisterNameIdentifierRequest_s* x, struct zx_str* y) { x->RequestID = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_NUM_Signature) */

int zx_ff12_RegisterNameIdentifierResponse_NUM_Signature(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_ds_Signature_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Signature; y; ++n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_GET_Signature) */

struct zx_ds_Signature_s* zx_ff12_RegisterNameIdentifierResponse_GET_Signature(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  for (y = x->Signature; n>=0 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_POP_Signature) */

struct zx_ds_Signature_s* zx_ff12_RegisterNameIdentifierResponse_POP_Signature(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_ds_Signature_s* y;
  if (!x) return 0;
  y = x->Signature;
  if (y)
    x->Signature = (struct zx_ds_Signature_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUSH_Signature) */

void zx_ff12_RegisterNameIdentifierResponse_PUSH_Signature(struct zx_ff12_RegisterNameIdentifierResponse_s* x, struct zx_ds_Signature_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Signature->gg.g;
  x->Signature = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_REV_Signature) */

void zx_ff12_RegisterNameIdentifierResponse_REV_Signature(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_ds_Signature_s* nxt;
  struct zx_ds_Signature_s* y;
  if (!x) return;
  y = x->Signature;
  if (!y) return;
  x->Signature = 0;
  while (y) {
    nxt = (struct zx_ds_Signature_s*)y->gg.g.n;
    y->gg.g.n = &x->Signature->gg.g;
    x->Signature = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUT_Signature) */

void zx_ff12_RegisterNameIdentifierResponse_PUT_Signature(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  y = x->Signature;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Signature = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_ADD_Signature) */

void zx_ff12_RegisterNameIdentifierResponse_ADD_Signature(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n, struct zx_ds_Signature_s* z)
{
  struct zx_ds_Signature_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Signature->gg.g;
    x->Signature = z;
    return;
  case -1:
    y = x->Signature;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_DEL_Signature) */

void zx_ff12_RegisterNameIdentifierResponse_DEL_Signature(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n)
{
  struct zx_ds_Signature_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Signature = (struct zx_ds_Signature_s*)x->Signature->gg.g.n;
    return;
  case -1:
    y = (struct zx_ds_Signature_s*)x->Signature;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Signature; n > 1 && y->gg.g.n; --n, y = (struct zx_ds_Signature_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_NUM_Extension) */

int zx_ff12_RegisterNameIdentifierResponse_NUM_Extension(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_ff12_Extension_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Extension; y; ++n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_GET_Extension) */

struct zx_ff12_Extension_s* zx_ff12_RegisterNameIdentifierResponse_GET_Extension(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  for (y = x->Extension; n>=0 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_POP_Extension) */

struct zx_ff12_Extension_s* zx_ff12_RegisterNameIdentifierResponse_POP_Extension(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return 0;
  y = x->Extension;
  if (y)
    x->Extension = (struct zx_ff12_Extension_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUSH_Extension) */

void zx_ff12_RegisterNameIdentifierResponse_PUSH_Extension(struct zx_ff12_RegisterNameIdentifierResponse_s* x, struct zx_ff12_Extension_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Extension->gg.g;
  x->Extension = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_REV_Extension) */

void zx_ff12_RegisterNameIdentifierResponse_REV_Extension(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_ff12_Extension_s* nxt;
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  y = x->Extension;
  if (!y) return;
  x->Extension = 0;
  while (y) {
    nxt = (struct zx_ff12_Extension_s*)y->gg.g.n;
    y->gg.g.n = &x->Extension->gg.g;
    x->Extension = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUT_Extension) */

void zx_ff12_RegisterNameIdentifierResponse_PUT_Extension(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  y = x->Extension;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Extension = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_ADD_Extension) */

void zx_ff12_RegisterNameIdentifierResponse_ADD_Extension(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n, struct zx_ff12_Extension_s* z)
{
  struct zx_ff12_Extension_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Extension->gg.g;
    x->Extension = z;
    return;
  case -1:
    y = x->Extension;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_DEL_Extension) */

void zx_ff12_RegisterNameIdentifierResponse_DEL_Extension(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n)
{
  struct zx_ff12_Extension_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Extension = (struct zx_ff12_Extension_s*)x->Extension->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_Extension_s*)x->Extension;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Extension; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_Extension_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_NUM_ProviderID) */

int zx_ff12_RegisterNameIdentifierResponse_NUM_ProviderID(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProviderID; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_GET_ProviderID) */

struct zx_elem_s* zx_ff12_RegisterNameIdentifierResponse_GET_ProviderID(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProviderID; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_POP_ProviderID) */

struct zx_elem_s* zx_ff12_RegisterNameIdentifierResponse_POP_ProviderID(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProviderID;
  if (y)
    x->ProviderID = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUSH_ProviderID) */

void zx_ff12_RegisterNameIdentifierResponse_PUSH_ProviderID(struct zx_ff12_RegisterNameIdentifierResponse_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProviderID->g;
  x->ProviderID = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_REV_ProviderID) */

void zx_ff12_RegisterNameIdentifierResponse_REV_ProviderID(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProviderID;
  if (!y) return;
  x->ProviderID = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProviderID->g;
    x->ProviderID = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUT_ProviderID) */

void zx_ff12_RegisterNameIdentifierResponse_PUT_ProviderID(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProviderID;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProviderID = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_ADD_ProviderID) */

void zx_ff12_RegisterNameIdentifierResponse_ADD_ProviderID(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProviderID->g;
    x->ProviderID = z;
    return;
  case -1:
    y = x->ProviderID;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_DEL_ProviderID) */

void zx_ff12_RegisterNameIdentifierResponse_DEL_ProviderID(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProviderID = (struct zx_elem_s*)x->ProviderID->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProviderID;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProviderID; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_NUM_Status) */

int zx_ff12_RegisterNameIdentifierResponse_NUM_Status(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_sp11_Status_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->Status; y; ++n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_GET_Status) */

struct zx_sp11_Status_s* zx_ff12_RegisterNameIdentifierResponse_GET_Status(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n)
{
  struct zx_sp11_Status_s* y;
  if (!x) return 0;
  for (y = x->Status; n>=0 && y; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_POP_Status) */

struct zx_sp11_Status_s* zx_ff12_RegisterNameIdentifierResponse_POP_Status(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_sp11_Status_s* y;
  if (!x) return 0;
  y = x->Status;
  if (y)
    x->Status = (struct zx_sp11_Status_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUSH_Status) */

void zx_ff12_RegisterNameIdentifierResponse_PUSH_Status(struct zx_ff12_RegisterNameIdentifierResponse_s* x, struct zx_sp11_Status_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->Status->gg.g;
  x->Status = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_REV_Status) */

void zx_ff12_RegisterNameIdentifierResponse_REV_Status(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_sp11_Status_s* nxt;
  struct zx_sp11_Status_s* y;
  if (!x) return;
  y = x->Status;
  if (!y) return;
  x->Status = 0;
  while (y) {
    nxt = (struct zx_sp11_Status_s*)y->gg.g.n;
    y->gg.g.n = &x->Status->gg.g;
    x->Status = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUT_Status) */

void zx_ff12_RegisterNameIdentifierResponse_PUT_Status(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n, struct zx_sp11_Status_s* z)
{
  struct zx_sp11_Status_s* y;
  if (!x || !z) return;
  y = x->Status;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->Status = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_ADD_Status) */

void zx_ff12_RegisterNameIdentifierResponse_ADD_Status(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n, struct zx_sp11_Status_s* z)
{
  struct zx_sp11_Status_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->Status->gg.g;
    x->Status = z;
    return;
  case -1:
    y = x->Status;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Status; n > 1 && y; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_DEL_Status) */

void zx_ff12_RegisterNameIdentifierResponse_DEL_Status(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n)
{
  struct zx_sp11_Status_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->Status = (struct zx_sp11_Status_s*)x->Status->gg.g.n;
    return;
  case -1:
    y = (struct zx_sp11_Status_s*)x->Status;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->Status; n > 1 && y->gg.g.n; --n, y = (struct zx_sp11_Status_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_NUM_RelayState) */

int zx_ff12_RegisterNameIdentifierResponse_NUM_RelayState(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->RelayState; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_GET_RelayState) */

struct zx_elem_s* zx_ff12_RegisterNameIdentifierResponse_GET_RelayState(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->RelayState; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_POP_RelayState) */

struct zx_elem_s* zx_ff12_RegisterNameIdentifierResponse_POP_RelayState(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->RelayState;
  if (y)
    x->RelayState = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUSH_RelayState) */

void zx_ff12_RegisterNameIdentifierResponse_PUSH_RelayState(struct zx_ff12_RegisterNameIdentifierResponse_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->RelayState->g;
  x->RelayState = z;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_REV_RelayState) */

void zx_ff12_RegisterNameIdentifierResponse_REV_RelayState(struct zx_ff12_RegisterNameIdentifierResponse_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->RelayState;
  if (!y) return;
  x->RelayState = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->RelayState->g;
    x->RelayState = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUT_RelayState) */

void zx_ff12_RegisterNameIdentifierResponse_PUT_RelayState(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->RelayState;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->RelayState = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_ADD_RelayState) */

void zx_ff12_RegisterNameIdentifierResponse_ADD_RelayState(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->RelayState->g;
    x->RelayState = z;
    return;
  case -1:
    y = x->RelayState;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_DEL_RelayState) */

void zx_ff12_RegisterNameIdentifierResponse_DEL_RelayState(struct zx_ff12_RegisterNameIdentifierResponse_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->RelayState = (struct zx_elem_s*)x->RelayState->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->RelayState;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->RelayState; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif

/* FUNC(zx_ff12_RegisterNameIdentifierResponse_GET_InResponseTo) */
struct zx_str* zx_ff12_RegisterNameIdentifierResponse_GET_InResponseTo(struct zx_ff12_RegisterNameIdentifierResponse_s* x) { return x->InResponseTo; }
/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUT_InResponseTo) */
void zx_ff12_RegisterNameIdentifierResponse_PUT_InResponseTo(struct zx_ff12_RegisterNameIdentifierResponse_s* x, struct zx_str* y) { x->InResponseTo = y; }
/* FUNC(zx_ff12_RegisterNameIdentifierResponse_GET_IssueInstant) */
struct zx_str* zx_ff12_RegisterNameIdentifierResponse_GET_IssueInstant(struct zx_ff12_RegisterNameIdentifierResponse_s* x) { return x->IssueInstant; }
/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUT_IssueInstant) */
void zx_ff12_RegisterNameIdentifierResponse_PUT_IssueInstant(struct zx_ff12_RegisterNameIdentifierResponse_s* x, struct zx_str* y) { x->IssueInstant = y; }
/* FUNC(zx_ff12_RegisterNameIdentifierResponse_GET_MajorVersion) */
struct zx_str* zx_ff12_RegisterNameIdentifierResponse_GET_MajorVersion(struct zx_ff12_RegisterNameIdentifierResponse_s* x) { return x->MajorVersion; }
/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUT_MajorVersion) */
void zx_ff12_RegisterNameIdentifierResponse_PUT_MajorVersion(struct zx_ff12_RegisterNameIdentifierResponse_s* x, struct zx_str* y) { x->MajorVersion = y; }
/* FUNC(zx_ff12_RegisterNameIdentifierResponse_GET_MinorVersion) */
struct zx_str* zx_ff12_RegisterNameIdentifierResponse_GET_MinorVersion(struct zx_ff12_RegisterNameIdentifierResponse_s* x) { return x->MinorVersion; }
/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUT_MinorVersion) */
void zx_ff12_RegisterNameIdentifierResponse_PUT_MinorVersion(struct zx_ff12_RegisterNameIdentifierResponse_s* x, struct zx_str* y) { x->MinorVersion = y; }
/* FUNC(zx_ff12_RegisterNameIdentifierResponse_GET_Recipient) */
struct zx_str* zx_ff12_RegisterNameIdentifierResponse_GET_Recipient(struct zx_ff12_RegisterNameIdentifierResponse_s* x) { return x->Recipient; }
/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUT_Recipient) */
void zx_ff12_RegisterNameIdentifierResponse_PUT_Recipient(struct zx_ff12_RegisterNameIdentifierResponse_s* x, struct zx_str* y) { x->Recipient = y; }
/* FUNC(zx_ff12_RegisterNameIdentifierResponse_GET_ResponseID) */
struct zx_str* zx_ff12_RegisterNameIdentifierResponse_GET_ResponseID(struct zx_ff12_RegisterNameIdentifierResponse_s* x) { return x->ResponseID; }
/* FUNC(zx_ff12_RegisterNameIdentifierResponse_PUT_ResponseID) */
void zx_ff12_RegisterNameIdentifierResponse_PUT_ResponseID(struct zx_ff12_RegisterNameIdentifierResponse_s* x, struct zx_str* y) { x->ResponseID = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RequestAuthnContext_NUM_AuthnContextClassRef) */

int zx_ff12_RequestAuthnContext_NUM_AuthnContextClassRef(struct zx_ff12_RequestAuthnContext_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthnContextClassRef; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_RequestAuthnContext_GET_AuthnContextClassRef) */

struct zx_elem_s* zx_ff12_RequestAuthnContext_GET_AuthnContextClassRef(struct zx_ff12_RequestAuthnContext_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->AuthnContextClassRef; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_RequestAuthnContext_POP_AuthnContextClassRef) */

struct zx_elem_s* zx_ff12_RequestAuthnContext_POP_AuthnContextClassRef(struct zx_ff12_RequestAuthnContext_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->AuthnContextClassRef;
  if (y)
    x->AuthnContextClassRef = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_RequestAuthnContext_PUSH_AuthnContextClassRef) */

void zx_ff12_RequestAuthnContext_PUSH_AuthnContextClassRef(struct zx_ff12_RequestAuthnContext_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->AuthnContextClassRef->g;
  x->AuthnContextClassRef = z;
}

/* FUNC(zx_ff12_RequestAuthnContext_REV_AuthnContextClassRef) */

void zx_ff12_RequestAuthnContext_REV_AuthnContextClassRef(struct zx_ff12_RequestAuthnContext_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->AuthnContextClassRef;
  if (!y) return;
  x->AuthnContextClassRef = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->AuthnContextClassRef->g;
    x->AuthnContextClassRef = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RequestAuthnContext_PUT_AuthnContextClassRef) */

void zx_ff12_RequestAuthnContext_PUT_AuthnContextClassRef(struct zx_ff12_RequestAuthnContext_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->AuthnContextClassRef;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->AuthnContextClassRef = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_RequestAuthnContext_ADD_AuthnContextClassRef) */

void zx_ff12_RequestAuthnContext_ADD_AuthnContextClassRef(struct zx_ff12_RequestAuthnContext_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->AuthnContextClassRef->g;
    x->AuthnContextClassRef = z;
    return;
  case -1:
    y = x->AuthnContextClassRef;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AuthnContextClassRef; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_RequestAuthnContext_DEL_AuthnContextClassRef) */

void zx_ff12_RequestAuthnContext_DEL_AuthnContextClassRef(struct zx_ff12_RequestAuthnContext_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthnContextClassRef = (struct zx_elem_s*)x->AuthnContextClassRef->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->AuthnContextClassRef;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AuthnContextClassRef; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RequestAuthnContext_NUM_AuthnContextStatementRef) */

int zx_ff12_RequestAuthnContext_NUM_AuthnContextStatementRef(struct zx_ff12_RequestAuthnContext_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthnContextStatementRef; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_RequestAuthnContext_GET_AuthnContextStatementRef) */

struct zx_elem_s* zx_ff12_RequestAuthnContext_GET_AuthnContextStatementRef(struct zx_ff12_RequestAuthnContext_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->AuthnContextStatementRef; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_RequestAuthnContext_POP_AuthnContextStatementRef) */

struct zx_elem_s* zx_ff12_RequestAuthnContext_POP_AuthnContextStatementRef(struct zx_ff12_RequestAuthnContext_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->AuthnContextStatementRef;
  if (y)
    x->AuthnContextStatementRef = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_RequestAuthnContext_PUSH_AuthnContextStatementRef) */

void zx_ff12_RequestAuthnContext_PUSH_AuthnContextStatementRef(struct zx_ff12_RequestAuthnContext_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->AuthnContextStatementRef->g;
  x->AuthnContextStatementRef = z;
}

/* FUNC(zx_ff12_RequestAuthnContext_REV_AuthnContextStatementRef) */

void zx_ff12_RequestAuthnContext_REV_AuthnContextStatementRef(struct zx_ff12_RequestAuthnContext_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->AuthnContextStatementRef;
  if (!y) return;
  x->AuthnContextStatementRef = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->AuthnContextStatementRef->g;
    x->AuthnContextStatementRef = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RequestAuthnContext_PUT_AuthnContextStatementRef) */

void zx_ff12_RequestAuthnContext_PUT_AuthnContextStatementRef(struct zx_ff12_RequestAuthnContext_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->AuthnContextStatementRef;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->AuthnContextStatementRef = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_RequestAuthnContext_ADD_AuthnContextStatementRef) */

void zx_ff12_RequestAuthnContext_ADD_AuthnContextStatementRef(struct zx_ff12_RequestAuthnContext_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->AuthnContextStatementRef->g;
    x->AuthnContextStatementRef = z;
    return;
  case -1:
    y = x->AuthnContextStatementRef;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AuthnContextStatementRef; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_RequestAuthnContext_DEL_AuthnContextStatementRef) */

void zx_ff12_RequestAuthnContext_DEL_AuthnContextStatementRef(struct zx_ff12_RequestAuthnContext_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthnContextStatementRef = (struct zx_elem_s*)x->AuthnContextStatementRef->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->AuthnContextStatementRef;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AuthnContextStatementRef; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_RequestAuthnContext_NUM_AuthnContextComparison) */

int zx_ff12_RequestAuthnContext_NUM_AuthnContextComparison(struct zx_ff12_RequestAuthnContext_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->AuthnContextComparison; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_RequestAuthnContext_GET_AuthnContextComparison) */

struct zx_elem_s* zx_ff12_RequestAuthnContext_GET_AuthnContextComparison(struct zx_ff12_RequestAuthnContext_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->AuthnContextComparison; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_RequestAuthnContext_POP_AuthnContextComparison) */

struct zx_elem_s* zx_ff12_RequestAuthnContext_POP_AuthnContextComparison(struct zx_ff12_RequestAuthnContext_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->AuthnContextComparison;
  if (y)
    x->AuthnContextComparison = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_RequestAuthnContext_PUSH_AuthnContextComparison) */

void zx_ff12_RequestAuthnContext_PUSH_AuthnContextComparison(struct zx_ff12_RequestAuthnContext_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->AuthnContextComparison->g;
  x->AuthnContextComparison = z;
}

/* FUNC(zx_ff12_RequestAuthnContext_REV_AuthnContextComparison) */

void zx_ff12_RequestAuthnContext_REV_AuthnContextComparison(struct zx_ff12_RequestAuthnContext_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->AuthnContextComparison;
  if (!y) return;
  x->AuthnContextComparison = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->AuthnContextComparison->g;
    x->AuthnContextComparison = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_RequestAuthnContext_PUT_AuthnContextComparison) */

void zx_ff12_RequestAuthnContext_PUT_AuthnContextComparison(struct zx_ff12_RequestAuthnContext_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->AuthnContextComparison;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->AuthnContextComparison = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_RequestAuthnContext_ADD_AuthnContextComparison) */

void zx_ff12_RequestAuthnContext_ADD_AuthnContextComparison(struct zx_ff12_RequestAuthnContext_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->AuthnContextComparison->g;
    x->AuthnContextComparison = z;
    return;
  case -1:
    y = x->AuthnContextComparison;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AuthnContextComparison; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_RequestAuthnContext_DEL_AuthnContextComparison) */

void zx_ff12_RequestAuthnContext_DEL_AuthnContextComparison(struct zx_ff12_RequestAuthnContext_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->AuthnContextComparison = (struct zx_elem_s*)x->AuthnContextComparison->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->AuthnContextComparison;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->AuthnContextComparison; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif






/* FUNC(zx_ff12_SPProvidedNameIdentifier_GET_Format) */
struct zx_str* zx_ff12_SPProvidedNameIdentifier_GET_Format(struct zx_ff12_SPProvidedNameIdentifier_s* x) { return x->Format; }
/* FUNC(zx_ff12_SPProvidedNameIdentifier_PUT_Format) */
void zx_ff12_SPProvidedNameIdentifier_PUT_Format(struct zx_ff12_SPProvidedNameIdentifier_s* x, struct zx_str* y) { x->Format = y; }
/* FUNC(zx_ff12_SPProvidedNameIdentifier_GET_NameQualifier) */
struct zx_str* zx_ff12_SPProvidedNameIdentifier_GET_NameQualifier(struct zx_ff12_SPProvidedNameIdentifier_s* x) { return x->NameQualifier; }
/* FUNC(zx_ff12_SPProvidedNameIdentifier_PUT_NameQualifier) */
void zx_ff12_SPProvidedNameIdentifier_PUT_NameQualifier(struct zx_ff12_SPProvidedNameIdentifier_s* x, struct zx_str* y) { x->NameQualifier = y; }







#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Scoping_NUM_ProxyCount) */

int zx_ff12_Scoping_NUM_ProxyCount(struct zx_ff12_Scoping_s* x)
{
  struct zx_elem_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->ProxyCount; y; ++n, y = (struct zx_elem_s*)y->g.n) ;
  return n;
}

/* FUNC(zx_ff12_Scoping_GET_ProxyCount) */

struct zx_elem_s* zx_ff12_Scoping_GET_ProxyCount(struct zx_ff12_Scoping_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  for (y = x->ProxyCount; n>=0 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
  return y;
}

/* FUNC(zx_ff12_Scoping_POP_ProxyCount) */

struct zx_elem_s* zx_ff12_Scoping_POP_ProxyCount(struct zx_ff12_Scoping_s* x)
{
  struct zx_elem_s* y;
  if (!x) return 0;
  y = x->ProxyCount;
  if (y)
    x->ProxyCount = (struct zx_elem_s*)y->g.n;
  return y;
}

/* FUNC(zx_ff12_Scoping_PUSH_ProxyCount) */

void zx_ff12_Scoping_PUSH_ProxyCount(struct zx_ff12_Scoping_s* x, struct zx_elem_s* z)
{
  if (!x || !z) return;
  z->g.n = &x->ProxyCount->g;
  x->ProxyCount = z;
}

/* FUNC(zx_ff12_Scoping_REV_ProxyCount) */

void zx_ff12_Scoping_REV_ProxyCount(struct zx_ff12_Scoping_s* x)
{
  struct zx_elem_s* nxt;
  struct zx_elem_s* y;
  if (!x) return;
  y = x->ProxyCount;
  if (!y) return;
  x->ProxyCount = 0;
  while (y) {
    nxt = (struct zx_elem_s*)y->g.n;
    y->g.n = &x->ProxyCount->g;
    x->ProxyCount = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Scoping_PUT_ProxyCount) */

void zx_ff12_Scoping_PUT_ProxyCount(struct zx_ff12_Scoping_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  y = x->ProxyCount;
  if (!y) return;
  switch (n) {
  case 0:
    z->g.n = y->g.n;
    x->ProxyCount = z;
    return;
  default:
    for (; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
    z->g.n = y->g.n->n;
    y->g.n = &z->g;
  }
}

/* FUNC(zx_ff12_Scoping_ADD_ProxyCount) */

void zx_ff12_Scoping_ADD_ProxyCount(struct zx_ff12_Scoping_s* x, int n, struct zx_elem_s* z)
{
  struct zx_elem_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->g.n = &x->ProxyCount->g;
    x->ProxyCount = z;
    return;
  case -1:
    y = x->ProxyCount;
    if (!y) goto add_to_start;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProxyCount; n > 1 && y; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y) return;
  }
  z->g.n = y->g.n;
  y->g.n = &z->g;
}

/* FUNC(zx_ff12_Scoping_DEL_ProxyCount) */

void zx_ff12_Scoping_DEL_ProxyCount(struct zx_ff12_Scoping_s* x, int n)
{
  struct zx_elem_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->ProxyCount = (struct zx_elem_s*)x->ProxyCount->g.n;
    return;
  case -1:
    y = (struct zx_elem_s*)x->ProxyCount;
    if (!y) return;
    for (; y->g.n; y = (struct zx_elem_s*)y->g.n) ;
    break;
  default:
    for (y = x->ProxyCount; n > 1 && y->g.n; --n, y = (struct zx_elem_s*)y->g.n) ;
    if (!y->g.n) return;
  }
  y->g.n = y->g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Scoping_NUM_IDPList) */

int zx_ff12_Scoping_NUM_IDPList(struct zx_ff12_Scoping_s* x)
{
  struct zx_ff12_IDPList_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->IDPList; y; ++n, y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Scoping_GET_IDPList) */

struct zx_ff12_IDPList_s* zx_ff12_Scoping_GET_IDPList(struct zx_ff12_Scoping_s* x, int n)
{
  struct zx_ff12_IDPList_s* y;
  if (!x) return 0;
  for (y = x->IDPList; n>=0 && y; --n, y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Scoping_POP_IDPList) */

struct zx_ff12_IDPList_s* zx_ff12_Scoping_POP_IDPList(struct zx_ff12_Scoping_s* x)
{
  struct zx_ff12_IDPList_s* y;
  if (!x) return 0;
  y = x->IDPList;
  if (y)
    x->IDPList = (struct zx_ff12_IDPList_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Scoping_PUSH_IDPList) */

void zx_ff12_Scoping_PUSH_IDPList(struct zx_ff12_Scoping_s* x, struct zx_ff12_IDPList_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->IDPList->gg.g;
  x->IDPList = z;
}

/* FUNC(zx_ff12_Scoping_REV_IDPList) */

void zx_ff12_Scoping_REV_IDPList(struct zx_ff12_Scoping_s* x)
{
  struct zx_ff12_IDPList_s* nxt;
  struct zx_ff12_IDPList_s* y;
  if (!x) return;
  y = x->IDPList;
  if (!y) return;
  x->IDPList = 0;
  while (y) {
    nxt = (struct zx_ff12_IDPList_s*)y->gg.g.n;
    y->gg.g.n = &x->IDPList->gg.g;
    x->IDPList = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Scoping_PUT_IDPList) */

void zx_ff12_Scoping_PUT_IDPList(struct zx_ff12_Scoping_s* x, int n, struct zx_ff12_IDPList_s* z)
{
  struct zx_ff12_IDPList_s* y;
  if (!x || !z) return;
  y = x->IDPList;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->IDPList = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Scoping_ADD_IDPList) */

void zx_ff12_Scoping_ADD_IDPList(struct zx_ff12_Scoping_s* x, int n, struct zx_ff12_IDPList_s* z)
{
  struct zx_ff12_IDPList_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->IDPList->gg.g;
    x->IDPList = z;
    return;
  case -1:
    y = x->IDPList;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPList; n > 1 && y; --n, y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Scoping_DEL_IDPList) */

void zx_ff12_Scoping_DEL_IDPList(struct zx_ff12_Scoping_s* x, int n)
{
  struct zx_ff12_IDPList_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->IDPList = (struct zx_ff12_IDPList_s*)x->IDPList->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_IDPList_s*)x->IDPList;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPList; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPList_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif








#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Subject_NUM_NameIdentifier) */

int zx_ff12_Subject_NUM_NameIdentifier(struct zx_ff12_Subject_s* x)
{
  struct zx_sa11_NameIdentifier_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->NameIdentifier; y; ++n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Subject_GET_NameIdentifier) */

struct zx_sa11_NameIdentifier_s* zx_ff12_Subject_GET_NameIdentifier(struct zx_ff12_Subject_s* x, int n)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return 0;
  for (y = x->NameIdentifier; n>=0 && y; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Subject_POP_NameIdentifier) */

struct zx_sa11_NameIdentifier_s* zx_ff12_Subject_POP_NameIdentifier(struct zx_ff12_Subject_s* x)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return 0;
  y = x->NameIdentifier;
  if (y)
    x->NameIdentifier = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Subject_PUSH_NameIdentifier) */

void zx_ff12_Subject_PUSH_NameIdentifier(struct zx_ff12_Subject_s* x, struct zx_sa11_NameIdentifier_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->NameIdentifier->gg.g;
  x->NameIdentifier = z;
}

/* FUNC(zx_ff12_Subject_REV_NameIdentifier) */

void zx_ff12_Subject_REV_NameIdentifier(struct zx_ff12_Subject_s* x)
{
  struct zx_sa11_NameIdentifier_s* nxt;
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return;
  y = x->NameIdentifier;
  if (!y) return;
  x->NameIdentifier = 0;
  while (y) {
    nxt = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n;
    y->gg.g.n = &x->NameIdentifier->gg.g;
    x->NameIdentifier = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Subject_PUT_NameIdentifier) */

void zx_ff12_Subject_PUT_NameIdentifier(struct zx_ff12_Subject_s* x, int n, struct zx_sa11_NameIdentifier_s* z)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x || !z) return;
  y = x->NameIdentifier;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->NameIdentifier = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Subject_ADD_NameIdentifier) */

void zx_ff12_Subject_ADD_NameIdentifier(struct zx_ff12_Subject_s* x, int n, struct zx_sa11_NameIdentifier_s* z)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->NameIdentifier->gg.g;
    x->NameIdentifier = z;
    return;
  case -1:
    y = x->NameIdentifier;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->NameIdentifier; n > 1 && y; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Subject_DEL_NameIdentifier) */

void zx_ff12_Subject_DEL_NameIdentifier(struct zx_ff12_Subject_s* x, int n)
{
  struct zx_sa11_NameIdentifier_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->NameIdentifier = (struct zx_sa11_NameIdentifier_s*)x->NameIdentifier->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_NameIdentifier_s*)x->NameIdentifier;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->NameIdentifier; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_NameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Subject_NUM_SubjectConfirmation) */

int zx_ff12_Subject_NUM_SubjectConfirmation(struct zx_ff12_Subject_s* x)
{
  struct zx_sa11_SubjectConfirmation_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->SubjectConfirmation; y; ++n, y = (struct zx_sa11_SubjectConfirmation_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Subject_GET_SubjectConfirmation) */

struct zx_sa11_SubjectConfirmation_s* zx_ff12_Subject_GET_SubjectConfirmation(struct zx_ff12_Subject_s* x, int n)
{
  struct zx_sa11_SubjectConfirmation_s* y;
  if (!x) return 0;
  for (y = x->SubjectConfirmation; n>=0 && y; --n, y = (struct zx_sa11_SubjectConfirmation_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Subject_POP_SubjectConfirmation) */

struct zx_sa11_SubjectConfirmation_s* zx_ff12_Subject_POP_SubjectConfirmation(struct zx_ff12_Subject_s* x)
{
  struct zx_sa11_SubjectConfirmation_s* y;
  if (!x) return 0;
  y = x->SubjectConfirmation;
  if (y)
    x->SubjectConfirmation = (struct zx_sa11_SubjectConfirmation_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Subject_PUSH_SubjectConfirmation) */

void zx_ff12_Subject_PUSH_SubjectConfirmation(struct zx_ff12_Subject_s* x, struct zx_sa11_SubjectConfirmation_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->SubjectConfirmation->gg.g;
  x->SubjectConfirmation = z;
}

/* FUNC(zx_ff12_Subject_REV_SubjectConfirmation) */

void zx_ff12_Subject_REV_SubjectConfirmation(struct zx_ff12_Subject_s* x)
{
  struct zx_sa11_SubjectConfirmation_s* nxt;
  struct zx_sa11_SubjectConfirmation_s* y;
  if (!x) return;
  y = x->SubjectConfirmation;
  if (!y) return;
  x->SubjectConfirmation = 0;
  while (y) {
    nxt = (struct zx_sa11_SubjectConfirmation_s*)y->gg.g.n;
    y->gg.g.n = &x->SubjectConfirmation->gg.g;
    x->SubjectConfirmation = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Subject_PUT_SubjectConfirmation) */

void zx_ff12_Subject_PUT_SubjectConfirmation(struct zx_ff12_Subject_s* x, int n, struct zx_sa11_SubjectConfirmation_s* z)
{
  struct zx_sa11_SubjectConfirmation_s* y;
  if (!x || !z) return;
  y = x->SubjectConfirmation;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->SubjectConfirmation = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_SubjectConfirmation_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Subject_ADD_SubjectConfirmation) */

void zx_ff12_Subject_ADD_SubjectConfirmation(struct zx_ff12_Subject_s* x, int n, struct zx_sa11_SubjectConfirmation_s* z)
{
  struct zx_sa11_SubjectConfirmation_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->SubjectConfirmation->gg.g;
    x->SubjectConfirmation = z;
    return;
  case -1:
    y = x->SubjectConfirmation;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_sa11_SubjectConfirmation_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->SubjectConfirmation; n > 1 && y; --n, y = (struct zx_sa11_SubjectConfirmation_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Subject_DEL_SubjectConfirmation) */

void zx_ff12_Subject_DEL_SubjectConfirmation(struct zx_ff12_Subject_s* x, int n)
{
  struct zx_sa11_SubjectConfirmation_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->SubjectConfirmation = (struct zx_sa11_SubjectConfirmation_s*)x->SubjectConfirmation->gg.g.n;
    return;
  case -1:
    y = (struct zx_sa11_SubjectConfirmation_s*)x->SubjectConfirmation;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_sa11_SubjectConfirmation_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->SubjectConfirmation; n > 1 && y->gg.g.n; --n, y = (struct zx_sa11_SubjectConfirmation_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif



#ifdef ZX_ENA_GETPUT

/* FUNC(zx_ff12_Subject_NUM_IDPProvidedNameIdentifier) */

int zx_ff12_Subject_NUM_IDPProvidedNameIdentifier(struct zx_ff12_Subject_s* x)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  int n = 0;
  if (!x) return 0;
  for (y = x->IDPProvidedNameIdentifier; y; ++n, y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
  return n;
}

/* FUNC(zx_ff12_Subject_GET_IDPProvidedNameIdentifier) */

struct zx_ff12_IDPProvidedNameIdentifier_s* zx_ff12_Subject_GET_IDPProvidedNameIdentifier(struct zx_ff12_Subject_s* x, int n)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x) return 0;
  for (y = x->IDPProvidedNameIdentifier; n>=0 && y; --n, y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
  return y;
}

/* FUNC(zx_ff12_Subject_POP_IDPProvidedNameIdentifier) */

struct zx_ff12_IDPProvidedNameIdentifier_s* zx_ff12_Subject_POP_IDPProvidedNameIdentifier(struct zx_ff12_Subject_s* x)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x) return 0;
  y = x->IDPProvidedNameIdentifier;
  if (y)
    x->IDPProvidedNameIdentifier = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n;
  return y;
}

/* FUNC(zx_ff12_Subject_PUSH_IDPProvidedNameIdentifier) */

void zx_ff12_Subject_PUSH_IDPProvidedNameIdentifier(struct zx_ff12_Subject_s* x, struct zx_ff12_IDPProvidedNameIdentifier_s* z)
{
  if (!x || !z) return;
  z->gg.g.n = &x->IDPProvidedNameIdentifier->gg.g;
  x->IDPProvidedNameIdentifier = z;
}

/* FUNC(zx_ff12_Subject_REV_IDPProvidedNameIdentifier) */

void zx_ff12_Subject_REV_IDPProvidedNameIdentifier(struct zx_ff12_Subject_s* x)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* nxt;
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x) return;
  y = x->IDPProvidedNameIdentifier;
  if (!y) return;
  x->IDPProvidedNameIdentifier = 0;
  while (y) {
    nxt = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n;
    y->gg.g.n = &x->IDPProvidedNameIdentifier->gg.g;
    x->IDPProvidedNameIdentifier = y;
    y = nxt;
  }
}

/* FUNC(zx_ff12_Subject_PUT_IDPProvidedNameIdentifier) */

void zx_ff12_Subject_PUT_IDPProvidedNameIdentifier(struct zx_ff12_Subject_s* x, int n, struct zx_ff12_IDPProvidedNameIdentifier_s* z)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x || !z) return;
  y = x->IDPProvidedNameIdentifier;
  if (!y) return;
  switch (n) {
  case 0:
    z->gg.g.n = y->gg.g.n;
    x->IDPProvidedNameIdentifier = z;
    return;
  default:
    for (; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
    z->gg.g.n = y->gg.g.n->n;
    y->gg.g.n = &z->gg.g;
  }
}

/* FUNC(zx_ff12_Subject_ADD_IDPProvidedNameIdentifier) */

void zx_ff12_Subject_ADD_IDPProvidedNameIdentifier(struct zx_ff12_Subject_s* x, int n, struct zx_ff12_IDPProvidedNameIdentifier_s* z)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x || !z) return;
  switch (n) {
  case 0:
  add_to_start:
    z->gg.g.n = &x->IDPProvidedNameIdentifier->gg.g;
    x->IDPProvidedNameIdentifier = z;
    return;
  case -1:
    y = x->IDPProvidedNameIdentifier;
    if (!y) goto add_to_start;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPProvidedNameIdentifier; n > 1 && y; --n, y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y) return;
  }
  z->gg.g.n = y->gg.g.n;
  y->gg.g.n = &z->gg.g;
}

/* FUNC(zx_ff12_Subject_DEL_IDPProvidedNameIdentifier) */

void zx_ff12_Subject_DEL_IDPProvidedNameIdentifier(struct zx_ff12_Subject_s* x, int n)
{
  struct zx_ff12_IDPProvidedNameIdentifier_s* y;
  if (!x) return;
  switch (n) {
  case 0:
    x->IDPProvidedNameIdentifier = (struct zx_ff12_IDPProvidedNameIdentifier_s*)x->IDPProvidedNameIdentifier->gg.g.n;
    return;
  case -1:
    y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)x->IDPProvidedNameIdentifier;
    if (!y) return;
    for (; y->gg.g.n; y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
    break;
  default:
    for (y = x->IDPProvidedNameIdentifier; n > 1 && y->gg.g.n; --n, y = (struct zx_ff12_IDPProvidedNameIdentifier_s*)y->gg.g.n) ;
    if (!y->gg.g.n) return;
  }
  y->gg.g.n = y->gg.g.n->n;
}

#endif






/* EOF -- c/zx-ff12-getput.c */