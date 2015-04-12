/* httpdglue.c  -  Handwritten functions for Apache httpd interface
 * Copyright (c) 2015 Synergetics NV (sampo@synergetics.be), All Rights Reserved.
 * Author: Sampo Kellomaki (sampo@iki.fi)
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing or as licensed below.
 * Licensed under Apache License 2.0, see file COPYING.
 *
 * 5.3.2015,  improved Apache httpd-2.4 compatibility --Sampo
 * 9.3.2015,  factored out of mod_auth_saml.c --Sampo
 *
 * The functions in this file act as buffer between mod_auth_saml
 * and changing ABI of Apache httpd, namely versions 2.2 and 2.4.
 * They are compiled twice: once with each header set and macros
 * defined differently.
 */

#define _LARGEFILE64_SOURCE   /* So off64_t is found, see: man 3 lseek64 */

#include <stdio.h>
#include "httpd.h"            /* request_rec et al. Apache httpd version dependent. */

#include "HRR.h"

void* HRR_field(request_rec* r, int field)
{
  switch (field) {
  case HRRC_headers_in:  return r->headers_in;
  case HRRC_headers_out: return r->headers_out;
  case HRRC_err_headers_out: return r->err_headers_out;
  case HRRC_pool: return r->pool;
  case HRRC_subprocess_env:  return r->subprocess_env;
  case HRRC_args: return r->args;
  case HRRC_uri:  return r->uri;
  case HRRC_user: return r->user;
  case HRRC_filename:  return r->filename;
  case HRRC_path_info: return r->path_info;
  case HRRC_main: return r->main;
  case HRRC_per_dir_config:  return r->per_dir_config;
  default:
    fprintf(stderr, "HRR field %d not known", field);
  }
  return 0;
}

int HRR_field_int(request_rec* r, int field)
{
  switch (field) {
  case HRRC_header_only:   return r->header_only;
  case HRRC_remaining:     return r->remaining;
  case HRRC_method_number: return r->method_number;
  default:
    fprintf(stderr, "HRR field %d not known", field);
  }
  return 0;
}

void HRR_set_field(request_rec* r, int field, void* v)
{
  switch (field) {
  case HRRC_args: r->args = v; return;
  case HRRC_uri:  r->uri  = v; return;
  case HRRC_user: r->user = v; return;
  default:
    fprintf(stderr, "HRR field %d not known", field);
  }
}

/* EOF - httpdglue.c */
