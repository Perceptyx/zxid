/* c/zx-is12-dec.c - WARNING: This file was auto generated by xsd2sg.pl. DO NOT EDIT!
 * $Id$ */
/* Code generation design Copyright (c) 2006 Sampo Kellomaki (sampo@iki.fi),
 * All Rights Reserved. NO WARRANTY. See file COPYING for terms and conditions
 * of use. Some aspects of code generation were driven by schema
 * descriptions that were used as input and may be subject to their own copyright.
 * Code generation uses a template, whose copyright statement follows. */

/** dec-templ.c  -  XML decoder template, used in code generation
 ** Copyright (c) 2010 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 ** Copyright (c) 2006-2007 Symlabs (symlabs@symlabs.com), All Rights Reserved.
 ** Author: Sampo Kellomaki (sampo@iki.fi)
 ** This is confidential unpublished proprietary source code of the author.
 ** NO WARRANTY, not even implied warranties. Contains trade secrets.
 ** Distribution prohibited unless authorized in writing.
 ** Licensed under Apache License 2.0, see file COPYING.
 ** Id: dec-templ.c,v 1.30 2008-10-04 23:42:14 sampo Exp $
 **
 ** 28.5.2006, created, Sampo Kellomaki (sampo@iki.fi)
 ** 8.8.2006,  reworked namespace handling --Sampo
 ** 12.8.2006, added special scanning of xmlns to avoid backtracking elem recognition --Sampo
 ** 23.9.2006, added collection of WO information --Sampo
 ** 21.6.2007, improved handling of undeclared namespace prefixes --Sampo
 ** 27.10.2010, CSE refactoring, re-engineered namespace handling --Sampo
 ** 21.11.2010, re-engineered to extract most code to zx_DEC_elem, leaving just switches --Sampo
 **
 ** N.B: This template is meant to be processed by pd/xsd2sg.pl. Beware
 ** of special markers that xsd2sg.pl expects to find and understand.
 **/

#include "errmac.h"
#include "zx.h"
#include "c/zx-const.h"
#include "c/zx-data.h"
#include "c/zx-is12-data.h"
#define TPF zx_
#include "zx_ext_pt.h"



int zx_DEC_ATTR_is12_Confirm(struct zx_ctx* c, struct zx_is12_Confirm_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_name_ATTR:  x->name = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_Confirm(struct zx_ctx* c, struct zx_is12_Confirm_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_is12_Help_ELEM:
    if (!x->Help)
      x->Help = (struct zx_is12_Help_s*)el;
    return 1;
  case zx_is12_Hint_ELEM:
    if (!x->Hint)
      x->Hint = el;
    return 1;
  case zx_is12_Label_ELEM:
    if (!x->Label)
      x->Label = el;
    return 1;
  case zx_is12_Value_ELEM:
    if (!x->Value)
      x->Value = el;
    return 1;

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_EncryptedResourceID(struct zx_ctx* c, struct zx_is12_EncryptedResourceID_s* x)
{
  switch (x->gg.attr->g.tok) {

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_EncryptedResourceID(struct zx_ctx* c, struct zx_is12_EncryptedResourceID_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_xenc_EncryptedData_ELEM:
    if (!x->EncryptedData)
      x->EncryptedData = (struct zx_xenc_EncryptedData_s*)el;
    return 1;
  case zx_xenc_EncryptedKey_ELEM:
    if (!x->EncryptedKey)
      x->EncryptedKey = (struct zx_xenc_EncryptedKey_s*)el;
    return 1;

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_Extension(struct zx_ctx* c, struct zx_is12_Extension_s* x)
{
  switch (x->gg.attr->g.tok) {

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_Extension(struct zx_ctx* c, struct zx_is12_Extension_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_Help(struct zx_ctx* c, struct zx_is12_Help_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_label_ATTR:  x->label = x->gg.attr; return 1;
    case zx_link_ATTR:  x->link = x->gg.attr; return 1;
    case zx_moreLink_ATTR:  x->moreLink = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_Help(struct zx_ctx* c, struct zx_is12_Help_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_Inquiry(struct zx_ctx* c, struct zx_is12_Inquiry_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_id_ATTR:  x->id = x->gg.attr; return 1;
    case zx_title_ATTR:  x->title = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_Inquiry(struct zx_ctx* c, struct zx_is12_Inquiry_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_is12_Help_ELEM:
    if (!x->Help)
      x->Help = (struct zx_is12_Help_s*)el;
    return 1;
  case zx_is12_Select_ELEM:
    if (!x->Select)
      x->Select = (struct zx_is12_Select_s*)el;
    return 1;
  case zx_is12_Confirm_ELEM:
    if (!x->Confirm)
      x->Confirm = (struct zx_is12_Confirm_s*)el;
    return 1;
  case zx_is12_Text_ELEM:
    if (!x->Text)
      x->Text = (struct zx_is12_Text_s*)el;
    return 1;

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_InteractionRequest(struct zx_ctx* c, struct zx_is12_InteractionRequest_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_id_ATTR:  x->id = x->gg.attr; return 1;
    case zx_language_ATTR:  x->language = x->gg.attr; return 1;
    case zx_maxInteractTime_ATTR:  x->maxInteractTime = x->gg.attr; return 1;
    case zx_signed_ATTR:  x->signed_is_c_keyword = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_InteractionRequest(struct zx_ctx* c, struct zx_is12_InteractionRequest_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_is12_Inquiry_ELEM:
    if (!x->Inquiry)
      x->Inquiry = (struct zx_is12_Inquiry_s*)el;
    return 1;
  case zx_ds_KeyInfo_ELEM:
    if (!x->KeyInfo)
      x->KeyInfo = (struct zx_ds_KeyInfo_s*)el;
    return 1;

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_InteractionResponse(struct zx_ctx* c, struct zx_is12_InteractionResponse_s* x)
{
  switch (x->gg.attr->g.tok) {

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_InteractionResponse(struct zx_ctx* c, struct zx_is12_InteractionResponse_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_is12_Status_ELEM:
    if (!x->Status)
      x->Status = (struct zx_is12_Status_s*)el;
    return 1;
  case zx_is12_InteractionStatement_ELEM:
    if (!x->InteractionStatement)
      x->InteractionStatement = (struct zx_is12_InteractionStatement_s*)el;
    return 1;
  case zx_is12_Parameter_ELEM:
    if (!x->Parameter)
      x->Parameter = (struct zx_is12_Parameter_s*)el;
    return 1;

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_InteractionService(struct zx_ctx* c, struct zx_is12_InteractionService_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_entryID_ATTR:  x->entryID = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_InteractionService(struct zx_ctx* c, struct zx_is12_InteractionService_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_di12_ResourceID_ELEM:
    if (!x->ResourceID)
      x->ResourceID = (struct zx_di12_ResourceID_s*)el;
    return 1;
  case zx_di12_EncryptedResourceID_ELEM:
    if (!x->EncryptedResourceID)
      x->EncryptedResourceID = (struct zx_di12_EncryptedResourceID_s*)el;
    return 1;
  case zx_di12_ServiceInstance_ELEM:
    if (!x->ServiceInstance)
      x->ServiceInstance = (struct zx_di12_ServiceInstance_s*)el;
    return 1;
  case zx_di12_Options_ELEM:
    if (!x->Options)
      x->Options = (struct zx_di12_Options_s*)el;
    return 1;
  case zx_di12_Abstract_ELEM:
    if (!x->Abstract)
      x->Abstract = el;
    return 1;

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_InteractionStatement(struct zx_ctx* c, struct zx_is12_InteractionStatement_s* x)
{
  switch (x->gg.attr->g.tok) {

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_InteractionStatement(struct zx_ctx* c, struct zx_is12_InteractionStatement_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_is12_Inquiry_ELEM:
    if (!x->Inquiry)
      x->Inquiry = (struct zx_is12_Inquiry_s*)el;
    return 1;
  case zx_ds_Signature_ELEM:
    if (!x->Signature)
      x->Signature = (struct zx_ds_Signature_s*)el;
    return 1;

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_Item(struct zx_ctx* c, struct zx_is12_Item_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_label_ATTR:  x->label = x->gg.attr; return 1;
    case zx_value_ATTR:  x->value = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_Item(struct zx_ctx* c, struct zx_is12_Item_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_is12_Hint_ELEM:
    if (!x->Hint)
      x->Hint = el;
    return 1;

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_Parameter(struct zx_ctx* c, struct zx_is12_Parameter_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_name_ATTR:  x->name = x->gg.attr; return 1;
    case zx_value_ATTR:  x->value = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_Parameter(struct zx_ctx* c, struct zx_is12_Parameter_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_RedirectRequest(struct zx_ctx* c, struct zx_is12_RedirectRequest_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_redirectURL_ATTR:  x->redirectURL = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_RedirectRequest(struct zx_ctx* c, struct zx_is12_RedirectRequest_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_ResourceID(struct zx_ctx* c, struct zx_is12_ResourceID_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_id_ATTR:  x->id = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_ResourceID(struct zx_ctx* c, struct zx_is12_ResourceID_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_Select(struct zx_ctx* c, struct zx_is12_Select_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_multiple_ATTR:  x->multiple = x->gg.attr; return 1;
    case zx_name_ATTR:  x->name = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_Select(struct zx_ctx* c, struct zx_is12_Select_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_is12_Help_ELEM:
    if (!x->Help)
      x->Help = (struct zx_is12_Help_s*)el;
    return 1;
  case zx_is12_Hint_ELEM:
    if (!x->Hint)
      x->Hint = el;
    return 1;
  case zx_is12_Label_ELEM:
    if (!x->Label)
      x->Label = el;
    return 1;
  case zx_is12_Value_ELEM:
    if (!x->Value)
      x->Value = el;
    return 1;
  case zx_is12_Item_ELEM:
    if (!x->Item)
      x->Item = (struct zx_is12_Item_s*)el;
    return 1;

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_Status(struct zx_ctx* c, struct zx_is12_Status_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_code_ATTR:  x->code = x->gg.attr; return 1;
    case zx_comment_ATTR:  x->comment = x->gg.attr; return 1;
    case zx_ref_ATTR:  x->ref = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_Status(struct zx_ctx* c, struct zx_is12_Status_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_is12_Status_ELEM:
    if (!x->Status)
      x->Status = (struct zx_is12_Status_s*)el;
    return 1;

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_Text(struct zx_ctx* c, struct zx_is12_Text_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_format_ATTR:  x->format = x->gg.attr; return 1;
    case zx_maxChars_ATTR:  x->maxChars = x->gg.attr; return 1;
    case zx_minChars_ATTR:  x->minChars = x->gg.attr; return 1;
    case zx_name_ATTR:  x->name = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_Text(struct zx_ctx* c, struct zx_is12_Text_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_is12_Help_ELEM:
    if (!x->Help)
      x->Help = (struct zx_is12_Help_s*)el;
    return 1;
  case zx_is12_Hint_ELEM:
    if (!x->Hint)
      x->Hint = el;
    return 1;
  case zx_is12_Label_ELEM:
    if (!x->Label)
      x->Label = el;
    return 1;
  case zx_is12_Value_ELEM:
    if (!x->Value)
      x->Value = el;
    return 1;

  default: return 0;
  }
}




int zx_DEC_ATTR_is12_UserInteraction(struct zx_ctx* c, struct zx_is12_UserInteraction_s* x)
{
  switch (x->gg.attr->g.tok) {
    case zx_id_ATTR:  x->id = x->gg.attr; return 1;
    case zx_interact_ATTR:  x->interact = x->gg.attr; return 1;
    case zx_language_ATTR:  x->language = x->gg.attr; return 1;
    case zx_maxInteractTime_ATTR:  x->maxInteractTime = x->gg.attr; return 1;
    case zx_redirect_ATTR:  x->redirect = x->gg.attr; return 1;
    case zx_actor_ATTR|zx_e_NS:  x->actor = x->gg.attr; return 1;
    case zx_mustUnderstand_ATTR|zx_e_NS:  x->mustUnderstand = x->gg.attr; return 1;

  default: return 0;
  }
}

int zx_DEC_ELEM_is12_UserInteraction(struct zx_ctx* c, struct zx_is12_UserInteraction_s* x)
{
  struct zx_elem_s* el = x->gg.kids;
  switch (el->g.tok) {
  case zx_is12_InteractionService_ELEM:
    if (!x->InteractionService)
      x->InteractionService = (struct zx_is12_InteractionService_s*)el;
    return 1;

  default: return 0;
  }
}


/* EOF -- c/zx-is12-dec.c */
