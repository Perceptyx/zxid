/* csharpzxid.i  -  SWIG interface file for C# extension for libzxid
 * Copyright (c) 2016 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 * Author: Sampo Kellomaki (sampo@iki.fi)
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing.
 * Licensed under Apache License 2.0, see file COPYING.
 * $Id: csharpzxid.i,v 1.3 2008-08-07 13:06:59 sampo Exp $
 * 7.4.2016, created --Sampo
 *
 * See also: http://swig.org/Doc1.3/CSharp.html
 *           http://www.mono-project.com/docs/advanced/pinvoke/
 */
%module "zxidcs"
%{

#include "errmac.h"
#include "zx.h"
#include "zxid.h"
#include "saml2.h"

#include "c/zx-const.h"
#include "c/zx-data.h"
#include "c/zx-ns.h"
#include "c/zxidvers.h"

%}

/*
*** figure out C# equivalent of java (*jenv)->GetStringUTFLength(env, jstring)
%typemap (in) (int len, char* s) %{
  // The following casts could probably be avoided with proper use of typemaps
  $1 = (*env)->GetStringUTFLength(env, (string)$input);
  $2 = (char*)(*env)->GetStringUTFChars(env, (string)$input, 0);
  // *** Whether we can free, or not, the obtained string depends
  //     on whether the zxid API will take reference to the string.
%}
%typemap (freearg) (int len, char* s) "(*env)->ReleaseStringUTFChars(jenv, (jstring)$input, $2);"
*/


//%typemap (out) struct zx_str* {
//  ZVAL_STRINGL($result, $1->s, $1->len, 1);
//  /* Do not free underlying zx_str because they are usually returned by reference. */
//}

%include "zx.h"
%include "zxid.h"
%include "saml2.h"
%include "wsf.h"
%include "c/zxidvers.h"
%include "c/zx-ns.h"

/* EOF */
