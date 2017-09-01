/* zxidoauth.c  -  Handwritten nitty-gritty functions for constructing OAUTH URLs
 * Copyright (c) 2011-2017 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing.
 * Licensed under Apache License 2.0, see file COPYING.
 * $Id$
 *
 * While this file contains some protocol encoders and decoders for OAUTH2,
 * the main logic of the flows is integrated to other parts, such as zxidsimp.c
 * 
 * http://openid.net/specs/openid-connect-basic-1_0.html
 * http://openid.net/specs/openid-connect-session-1_0.html
 * http://openid.net/specs/openid-connect-messages-1_0.html
 * http://tools.ietf.org/html/draft-ietf-oauth-v2-22
 * http://tools.ietf.org/html/draft-jones-json-web-encryption-01
 * RFC6749 OAuth2 Core
 * RFC6750 OAuth2 Bearer Token Usage
 *
 * 11.12.2011, created --Sampo
 * 9.10.2014,  UMA related addtionas, JWK, dynamic client registration, etc. --Sampo
 * 30.11.2016, tweaked to make real life Facebook OAUTH pass --Sampo
 * 2.12.2016,  separated Facebook Connect to a separate flow --Sampo
 * 7.12.2016,  added storing ssoreq state on disk instead of shipping to other IdP --Sampo
 * 20170901    added OpenSSL-1.1.0 support --Sampo
 */

#include "platform.h"
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef USE_OPENSSL
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#endif
#include "errmac.h"
#include "zx.h"
#include "zxid.h"
#include "zxidpriv.h"
#include "zxidutil.h"
#include "zxidconf.h"
#include "saml2.h"   /* for bindings like OAUTH2_REDIR */
#include "c/zx-data.h"
#include "c/zxidvers.h"

#if 1

/* Called by:  zxid_mk_jwk x2 */
char* zxid_bn2b64(zxid_conf* cf, BIGNUM* bn)
{
  char* bin;
  char* b64;
  char* e;
  int len;

  if (!bn)
    return zx_dup_cstr(cf->ctx, "");
  bin = ZX_ALLOC(cf->ctx, BN_num_bytes(bn));
  len = BN_bn2bin(bn, (unsigned char*)bin);
  b64 = ZX_ALLOC(cf->ctx, SIMPLE_BASE64_LEN(len)+1);
  e = base64_fancy_raw(bin, len, b64, safe_basis_64, 1000000, 0, "", '=');
  *e = 0;
  ZX_FREE(cf->ctx, bin);
  return b64;
}

/*() Create JWK (json-web-key) document
 * See: https://tools.ietf.org/html/draft-ietf-jose-json-web-key-33 */

/* Called by:  zxid_mk_jwks x2 */
char* zxid_mk_jwk(zxid_conf* cf, char* pem, int enc_use)
{
  char derbuf[4096];
  X509* x = 0;  /* Forces d2i_X509() to alloc the memory. */
  RSA* rsa;
  BIGNUM* n_bn;
  BIGNUM* e_bn;
  char* buf;
  char* p;
  char* e;
  char* n_b64;
  char* e_b64;

  p = derbuf;
  e = unbase64_raw(pem, pem+strlen(pem), p, zx_std_index_64);
  OpenSSL_add_all_algorithms();
  if (!d2i_X509(&x, (const unsigned char**)&p /* *** compile warning */, e-p) || !x) {
    ERR("DER decoding of X509 certificate failed.\n%d", enc_use);
    return 0;
  }

  zx_zap_inplace_raw(pem, "\n\r \t");
  rsa = zx_get_rsa_pub_from_cert(x, "mk_jwk");
#if OPENSSL_VERSION_NUMBER >= 0x10100000
  {
    BIGNUM* d_bn;
    RSA_get0_key(rsa, &n_bn, &e_bn, &d_bn);
  }
#else
  n_bn = rsa?rsa->n:0;
  e_bn = rsa?rsa->e:0;
#endif
  n_b64 = zxid_bn2b64(cf, n_bn);
  e_b64 = zxid_bn2b64(cf, e_bn);
  X509_free(x);

  buf = zx_alloc_sprintf(cf->ctx, 0,
			 "{\"kty\":\"RSA\""
			 ",\"use\":\"%s\""
			 //",\"key_ops\":[%s]"
			 //",\"alg\":\"%s\""
			 ",\"n\":\"%s\""  /* modulus */
			 ",\"e\":\"%s\""  /* exponent */
			 ",\"x5c\":[\"%s\"]}",
			 enc_use?"enc":"sig",
			 //enc_use?"\"encrypt\",\"decrypt\"":"\"sign\",\"verify\"",
			 n_b64,
			 e_b64,
			 pem);
  ZX_FREE(cf->ctx, n_b64);
  ZX_FREE(cf->ctx, e_b64);
  return buf;
}

/*() Create JWKS (json-web-key-set) document
 * See: https://tools.ietf.org/html/draft-ietf-jose-json-web-key-33 */

/* Called by:  zxid_mk_oauth2_dyn_cli_reg_req, zxid_simple_show_jwks */
char* zxid_mk_jwks(zxid_conf* cf)
{
  char  pem_buf[4096];
  char* pem;
  char* sig_jwk;
  char* enc_jwk;
  char* buf;
  pem = zxid_read_cert_pem(cf, "sign-nopw-cert.pem", sizeof(pem_buf), pem_buf);
  sig_jwk = zxid_mk_jwk(cf, pem, 0);
  pem = zxid_read_cert_pem(cf, "enc-nopw-cert.pem", sizeof(pem_buf), pem_buf);
  enc_jwk = zxid_mk_jwk(cf, pem, 1);
  
  buf = zx_alloc_sprintf(cf->ctx, 0, "{\"keys\":[%s,%s]}", sig_jwk, enc_jwk);
  ZX_FREE(cf->ctx, sig_jwk);
  ZX_FREE(cf->ctx, enc_jwk);
  return buf;
}

/*() Create OAUTH2 Dynamic Client Registration request.
 * See: https://tools.ietf.org/html/draft-ietf-oauth-dyn-reg-20 */

/* Called by:  zxid_oauth_dynclireg_client */
char* zxid_mk_oauth2_dyn_cli_reg_req(zxid_conf* cf)
{
  char* jwks;
  char* buf;
  jwks = zxid_mk_jwks(cf);
  buf = zx_alloc_sprintf(cf->ctx, 0,
			 "{\"redirect_uris\":[\"%s%co=oauth_redir\"]"
			 ",\"token_endpoint_auth_method\":\"client_secret_post\""
			 ",\"grant_types\":[\"authorization_code\",\"implicit\",\"password\",\"client_credentials\",\"refresh_token\",\"urn:ietf:params:oauth:grant-type:jwt-bearer\",\"urn:ietf:params:oauth:grant-type:saml2-bearer\"]"
			 ",\"response_types\":[\"code\",\"token\"]"
			 ",\"client_name\":\"%s\""
			 ",\"client_uri\":\"%s\""
			 ",\"logo_uri\":\"%s\""
			 ",\"scope\":\"read read-write\""
			 ",\"contacts\":[\"%s\",\"%s\",\"%s\",\"%s\"]"
			 ",\"tos_uri\":\"%s\""
			 ",\"policy_uri\":\"%s\""
			 ",\"jwks_uri\":\"%s%co=jwks\""
			 ",\"jwks\":%s"
			 ",\"software_id\":\"ZXID\""
			 ",\"software_version\":\"" ZXID_REL "\""
			 ",\"zxid_rev\":\"" ZXID_REV "\"}",
			 cf->burl, strchr(cf->burl, '?')?'&':'?',
			 cf->nice_name,
			 "client_uri",
			 cf->button_url,
			 cf->contact_org, cf->contact_name, cf->contact_email, cf->contact_tel,
			 "tos_uri",
			 "policy_uri",
			 cf->burl, strchr(cf->burl, '?')?'&':'?',
			 jwks);
  ZX_FREE(cf->ctx, jwks);
  return buf;
}

/*() Perform the registration and create OAUTH2 Dynamic Client Registration Response.
 * The unparsed JSON for request is in the cgi->post field.
 * See: https://tools.ietf.org/html/draft-ietf-oauth-dyn-reg-20 */

/* Called by:  zxid_simple_show_dynclireg */
char* zxid_mk_oauth2_dyn_cli_reg_res(zxid_conf* cf, zxid_cgi* cgi)
{
  char* buf;
  char* iat;
  struct zx_str* client_id;
  struct zx_str* client_secret;
  int secs = time(0);

  /* *** check for valid IAT */

  if (!cgi->post) {
    ERR("Missing POST content %d",0);
    return 0;
  }

  client_id = zxid_mk_id(cf, "CI", ZXID_ID_BITS);
  client_secret = zxid_mk_id(cf, "CS", ZXID_ID_BITS);
  iat = getenv("HTTP_AUTHORIZATION");
  
  buf = zx_alloc_sprintf(cf->ctx, 0,
			 "{\"client_id\":\"%.*s\""
			 ",\"client_secret\":\"%.*s\""
			 ",\"client_id_issued_at\":%d"
			 ",\"client_secret_expires_at\":%d"
			 ",\"client_src_ip\":\"%s\""
			 ",\"client_iat\":\"%s\""
			 ",%s",
			 client_id->len, client_id->s,
			 client_secret->len, client_secret->s,
			 secs,
			 secs+86400,
			 cf->ipport,
			 STRNULLCHK(iat),
			 cgi->post+1);

  if (!write_all_path("dyn_cli_reg", "%s" ZXID_DCR_DIR "%s", cf->cpath, client_id->s, -1, buf)) {
    zxlog(cf, 0, 0, 0, 0, 0, 0, 0, "N", "S", "DCR", client_id->s, "writing dyn cli reg fail, permissions?");
  } else
    zxlog(cf, 0, 0, 0, 0, 0, 0, 0, "N", "K", "DCR", client_id->s, "ip(%s)", cf->ipport);
  ZX_FREE(cf->ctx, client_id);
  ZX_FREE(cf->ctx, client_secret);
  return buf;
}

/*() Create OAUTH2 Resource Set Registration request.
 * See: https://tools.ietf.org/html/draft-hardjono-oauth-resource-reg-03
 * The scope URL should point to scope description (created by hand
 * and put to the server in right place), e.g. at https://server/scope/scope.json
 * {"name":"Human Readable Scope Name","icon_uri":"https://server/scope/scope.png"}
 * N.B. If you want to pass more than one scope, you have to include "," in middle, e.g.
 * "https://server/scope/read.json\",\"https://server/scope/write.json" */

/* Called by:  zxid_oauth_rsrcreg_client */
char* zxid_mk_oauth2_rsrc_reg_req(zxid_conf* cf, const char* rsrc_name, const char* rsrc_icon_uri, const char* rsrc_scope_url, const char* rsrc_type)
{
  char* buf;
  buf = zx_alloc_sprintf(cf->ctx, 0,
			 "{\"name\":\"%s\""
			 ",\"icon_uri\":\"%s\""
			 ",\"scopes\":[\"%s\"]"
			 ",\"type\":\"%s\"}",
			 rsrc_name,
			 rsrc_icon_uri,
			 rsrc_scope_url,
			 rsrc_type);
  return buf;
}

/*() Perform the registration and create OAUTH2 Resource Set Registration Response.
 * The unparsed JSON for request is in the cgi->post field.
 * See: https://tools.ietf.org/html/draft-hardjono-oauth-resource-reg-03 */

/* Called by:  zxid_simple_show_rsrcreg */
char* zxid_mk_oauth2_rsrc_reg_res(zxid_conf* cf, zxid_cgi* cgi, char* rev)
{
  char* buf;
  char* pat;
  struct zx_str* rs_id;

  /* *** check for IAT */

  if (!cgi->post) {
    ERR("Missing POST content %d",0);
    return 0;
  }

  rs_id = zxid_mk_id(cf, "RS", ZXID_ID_BITS);
  pat = getenv("HTTP_AUTHORIZATION");
  strcpy(rev, "r1");
  D("rs_id(%.*s) rev(%s) pat(%s)", rs_id->len, rs_id->s, rev, pat);

  // *** TODO: Check PAT
  // *** TODO: Add registerer's (usually resource server) identity to path
  if (!write_all_path("rsrc_reg", "%s" ZXID_RSR_DIR "%s", cf->cpath, rs_id->s, -1, cgi->post)) {
    zxlog(cf, 0, 0, 0, 0, 0, 0, 0, "N", "S", "RSR", rs_id->s, "writing resource reg fail, permissions?");
  } else
    zxlog(cf, 0, 0, 0, 0, 0, 0, 0, "N", "K", "RSR", rs_id->s, "ip(%s)", cf->ipport);
  
  buf = zx_alloc_sprintf(cf->ctx, 0,
			 "{\"status\":\"created\""
			 ",\"_id\":\"%.*s\""
			 ",\"_rev\":\"%s\"",
			 ",\"policy_uri\":\"%s%co=consent\"}",
			 rs_id->len, rs_id->s,
			 rev,
			 cf->burl, strchr(cf->burl, '?')?'&':'?');
  ZX_FREE(cf->ctx, rs_id);
  return buf;
}

#endif

/*() Prepare state
 * Either deflate and safe_base64 encode state for inline passage or
 * store it in a file and return sha1_name of the file.
 *
 * See also:: zxid_decode_state() */

char* zxid_prepare_statef(zxid_conf* cf, const char* fmt, ...)
{
  int olen,len;
  char* buf;
  char* state_b64;
  va_list ap;

  va_start(ap, fmt);

  for (olen = 2047 /* just initial guess */; 1; olen=len) {
    buf = ZX_ALLOC(cf->ctx, olen+1);
    len = vsnprintf(buf, olen, fmt, ap);
    if (len <= olen)
      break;  /* fits */
    /* Did not fit, try again (second iteration will always be successful) */
    ZX_FREE(cf->ctx, buf);
  }
  buf[len] = 0;  /* MS snprintf() bug */

  va_end(ap);

  if (cf->state_opt) {
    state_b64 = ZX_ALLOC(cf->ctx, 28);
    sha1_safe_base64(state_b64, len, buf);
    state_b64[27] = 0; /* nul term */
    DD("HERE1 file(%s) state(%s)", state_b64, buf);
    write_all_path("prepare_state", "%s" ZXID_STATE_DIR "%s", cf->cpath, state_b64, len, buf);
    DD("HERE2 file(%s) state(%s)", state_b64, buf);
  } else {
    state_b64 = zxid_deflate_safe_b64_raw(cf->ctx, len, buf);
    DD("prepare deflated state(%s)", buf);
  }
  ZX_FREE(cf->ctx, buf);
  return state_b64;
}

/*() Interpret ZXID standard form fields to construct an OAuth2 Authorization request,
 * which is a redirection URL. This is also used for OpenID Connect 1.0 (OIDC),
 * Mobile Connect (2016), and Facebook Connect 2.8 (FBC). The client_id field
 * can be determined in multiple ways:
 *
 * 1. idp_meta->client_id (from Mobile Connect Discovery)
 * 2. idp_meta->ed->appId (enhanced metadata, e.g. FBC)
 * 3. (SAML2) entityID of the IdP
 *
 * Flag 0x01 triggers FBC
 * Returns URL suitable for redirection. Caller must free.
 *
 * curl -v 'http://operator-b.sandbox2.mobileconnect.io/oidc/authorize?response_type=code&client_id=a405e7fa%2Dd1bf%2D4857%2Da3fa%2D094dba847711&scope=openid+profile+email&acr_values=2&redirect_uri=https%3A%2F%2Fidsso%2Ecom%2Fidp%3fo=O&nonce=OAEIe1hMEKeaNtC45K-pDUH05S&state=Od9KINYHyHu7qE9NQxdFCYVYBhU'
 */

/* Called by:  zxid_oidc_as_call, zxid_start_sso_url */
struct zx_str* zxid_mk_oauth_az_req(zxid_conf* cf, zxid_cgi* cgi, zxid_entity* idp_meta, struct zx_str* loc, int flags)
{
  struct zx_str* ss;
  struct zx_str* nonce = 0;
  struct zx_str* eid;
  char* cli_id_url_enc;
  char* redir_url_enc;
  char* state_b64;
  const char* acr_values;
  const char* prompt;
  const char* display;
  const char* resp_type;
  const char* scope;

  if (!loc || !loc->len || !loc->s || !loc->s[0]) {
    ERR("Redirection location URL missing. %p", loc);
    return 0;
  }
  
  redir_url_enc = zx_url_encode(cf->ctx, -2, cf->burl, 0);
  if (idp_meta->client_id && idp_meta->client_id[0]) {
    /* E.g. from Mobile Connect Discovery */
    cli_id_url_enc = zx_url_encode(cf->ctx, -2, idp_meta->client_id, 0);
  } else if (idp_meta->ed && ZX_ATTR_HAS_VALUE(idp_meta->ed->appId)) {
    /* Per IdP app_id (aka client_id) instead of SP chosen eid */
    cli_id_url_enc = zx_url_encode(cf->ctx,idp_meta->ed->appId->g.len,idp_meta->ed->appId->g.s,0);
  } else {
    eid = zxid_my_ent_id(cf);
    cli_id_url_enc = zx_url_encode(cf->ctx, eid->len, eid->s, 0);
    zx_str_free(cf->ctx, eid);
  }

  /* The chosen IdP's Entity ID is in cgi->eid and we need to encode this to state
   * as OAuth2, or at least Facebook Connect, does not have any other guaranteed
   * way of receiving the issuer information (this is a defect in OAUTH2 and/or
   * Facebook Connect). */

  if (cf->idp_ena) {  /* (PXY) Middle IdP of Proxy IdP scenario */
    if (cgi->rs) {
      ERR("Ignoring RelayState(%s) supplied in middle IdP of Proxy IdP flow.", cgi->rs);
    }
    /* Carry the original authn req in state */
    state_b64 = zxid_prepare_statef(cf,
		  "e=%s&client_id=%s&client_secret=%s&token_url=%s&userinfo_url=%s&ar=%s",
		  cgi->eid, cli_id_url_enc, STRNULLCHK(idp_meta->client_secret),
                  STRNULLCHK(idp_meta->token_url), STRNULLCHK(idp_meta->userinfo_url),
                  cgi->ssoreq);
  } else {
    state_b64 = zxid_prepare_statef(cf,
                  "e=%s&client_id=%s&client_secret=%s&token_url=%s&userinfo_url=%s&rs=%s",
                  cgi->eid, cli_id_url_enc, STRNULLCHK(idp_meta->client_secret),
                  STRNULLCHK(idp_meta->token_url), STRNULLCHK(idp_meta->userinfo_url),
                  STRNULLCHK(cgi->rs));
  }
  D("state_b64(%s)", state_b64);
  if (flags & 0x01) {  /* FBC */
    nonce = 0;
    resp_type = "code%20granted_scopes";
    scope = "public_profile,email";
    acr_values = 0;
  } else {
    nonce = zxid_mk_id(cf, "OA", ZXID_ID_BITS);
    resp_type = (flags&0x02 || cgi->pr_ix == ZXID_OIDC1_CODE) ? "code" : "id_token+token";
    //scope = "openid+profile+email+address+public_profile";
    scope = "openid+profile+email";
    acr_values = "2";  /* Mobile Connect needs this */
  }
  prompt = BOOL_STR_TEST(cgi->force_authn) ? "login" : 0;
  prompt = (cgi->consent && cgi->consent[0]) ? (prompt?"login+consent":"consent") : prompt;
  display = BOOL_STR_TEST(cgi->ispassive) ? "none" : 0;
  
  ss = zx_strf(cf->ctx,
	       "%.*s%cresponse_type=%s"
	       "&scope=%s"
	       "&client_id=%s"
	       "&redirect_uri=%s%%3fo=O"
	       "%s%.*s"         /* &nonce=   (not part of FBC) */
	       "%s%s"           /* &state= */
	       "%s%s"           /* &acr_values=  (used by Mobile Connect)*/
	       "%s%s"           /* &display= */
	       "%s%s",          /* &prompt= */
	       loc->len, loc->s, (memchr(loc->s, '?', loc->len)?'&':'?'),
	       resp_type,
	       scope,
	       cli_id_url_enc,
	       redir_url_enc,
	       nonce?"&nonce=":"", nonce?nonce->len:0, nonce?nonce->s:"",
	       state_b64?"&state=":"", STRNULLCHK(state_b64),
	       acr_values?"&acr_values=":"", STRNULLCHK(acr_values),
	       display?"&display=":"", STRNULLCHK(display),
	       prompt?"&prompt=":"", STRNULLCHK(prompt)
	       );
  /* https://www.facebook.com/v2.8/dialog/oauth?response_type=code%20granted_scopes&scope=public_profile,email&client_id=1819571348286291&redirect_uri=https%3A%2F%2Fidsso%2Ecom%2Fidp%3fo=O&state=CYA0S2ZImtNiTtZ6h4SaRvRSOVg */
  D("OAUTH2 AZ REQ(%.*s)", ss->len, ss->s);
  if (errmac_debug & ERRMAC_INOUT) INFO("%.*s", ss->len, ss->s);
  if (nonce) zx_str_free(cf->ctx, nonce);
  if (state_b64) ZX_FREE(cf->ctx, state_b64);
  ZX_FREE(cf->ctx, cli_id_url_enc);
  ZX_FREE(cf->ctx, redir_url_enc);
  return ss;
}

#if 0
/*() Interpret ZXID standard form fields to construct a Facebook Connect 2.8
 * Authorization request, which is a redirection URL. */

/* Called by:  zxid_start_sso_url */
struct zx_str* zxid_mk_fbc_az_req(zxid_conf* cf, zxid_cgi* cgi, zxid_entity* idp_meta, struct zx_str* loc)
{
  struct zx_str* ss;
  //struct zx_str* nonce;
  struct zx_str* eid;
  char* eid_url_enc;
  char* redir_url_enc;
  char* state_b64;
  char* prompt;
  char* display;

  if (!loc || !loc->len || !loc->s || !loc->s[0]) {
    ERR("FBC Redirection location URL missing. %p", loc);
    return 0;
  }

  D("redir loc(%.*s) %p %p", loc->len, loc->s, loc, loc->s);
  redir_url_enc = zx_url_encode(cf->ctx, strlen(cf->burl), cf->burl, 0);
  if (idp_meta->ed && idp_meta->ed->appId && idp_meta->ed->appId->g.len && idp_meta->ed->appId->g.s && idp_meta->ed->appId->g.s[0]) {
    /* Per IdP app_id (aka client_id) instead of SP chosen eid */
    D("appId(%.*s)", idp_meta->ed->appId->g.len, idp_meta->ed->appId->g.s);
    eid_url_enc = zx_url_encode(cf->ctx, idp_meta->ed->appId->g.len, idp_meta->ed->appId->g.s, 0);
  } else {
    eid = zxid_my_ent_id(cf);
    eid_url_enc = zx_url_encode(cf->ctx, eid->len, eid->s, 0);
    zx_str_free(cf->ctx, eid);
  }

  /* The chosen IdP's Entity ID is in cgi->eid and we need to encode this to state
   * as OAuth2, or at least Facebook Connect, does not have any other guaranteed
   * way of receiving the issuer information (this is a defect in OAUTH2 and/or
   * Facebook Connect). */

  if (cf->idp_ena) {  /* (PXY) Middle IdP of Proxy IdP scenario */
    if (cgi->rs) {
      D("FBC RelayState(%s) supplied in middle IdP of Proxy IdP flow. Ignored.", cgi->rs);
    }
    /* Carry the original authn req in state */
    state_b64 = zxid_prepare_statef(cf, "e=%s&ar=%s", cgi->eid, cgi->ssoreq);
  } else {
    state_b64 = zxid_prepare_statef(cf, "e=%s&rs=%s", cgi->eid, STRNULLCHK(cgi->rs));
  }
  //nonce = zxid_mk_id(cf, "FB", ZXID_ID_BITS);
  prompt = BOOL_STR_TEST(cgi->force_authn) ? "login" : 0;
  prompt = BOOL_STR_TEST(cgi->consent && cgi->consent[0]) ? (prompt?"login+consent":"consent") : prompt;
  display = BOOL_STR_TEST(cgi->ispassive) ? "none" : 0;
  
  ss = zx_strf(cf->ctx,
	       "%.*s%cresponse_type=%s"
	       "&client_id=%s"
	       "&scope=public_profile,email"
	       "&redirect_uri=%s%%3fo=O"
	       //"&nonce=%.*s"
	       "%s%s"           /* &state= */
	       "%s%s"           /* &display= */
	       "%s%s",          /* &prompt= */
	       loc->len, loc->s, (memchr(loc->s, '?', loc->len)?'&':'?'),
	       "code%20granted_scopes",
	       eid_url_enc,
	       redir_url_enc,
	       //nonce->len, nonce->s,
	       state_b64?"&state=":"", STRNULLCHK(state_b64),
	       display?"&display=":"", STRNULLCHK(display),
	       prompt?"&prompt=":"", STRNULLCHK(prompt)
	       );
  D("FBC AZ REQ(%.*s)", ss->len, ss->s);
  if (errmac_debug & ERRMAC_INOUT) INFO("%.*s", ss->len, ss->s);
  //zx_str_free(cf->ctx, nonce);
  if (state_b64) ZX_FREE(cf->ctx, state_b64);
  ZX_FREE(cf->ctx, eid_url_enc);
  ZX_FREE(cf->ctx, redir_url_enc);
  return ss;
}
#endif

/*() Decode JWT
 * Ignores leading signature preamble and trailing signature block (separated by dots).
 * returns decoded data in allocated buffer. Caller frees. */

/* Called by:  zxid_sp_sso_finalize_jwt */
char* zxid_decode_jwt(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses, const char* jwt)
{
  int len;
  char* buf;
  char* p;
  char* q;

  if (!jwt) {
    ERR("Missing JWT %d", 0);
    return 0;
  }
  p = strchr(jwt, '.');
  if (!p) {
    ERR("Malformed JWT (missing period separating header and claims) jwt(%s)", jwt);
    return 0;
  }
  ++p;
  q = strchr(p, '.');
  len = q?q-p:strlen(p);
  buf = ZX_ALLOC(cf->ctx, SIMPLE_BASE64_PESSIMISTIC_DECODE_LEN(len));
  p = unbase64_raw(p, p+len, buf, zx_std_index_64);
  *p = 0;  /* nul termination */
  return buf;
}

/*() Construct OAUTH2 / OpenID-Connect1 id_token. */

/* Called by:  zxid_sso_issue_jwt x3 */
char* zxid_mk_jwt(zxid_conf* cf, int claims_len, const char* claims)
{
  char hash[64 /*EVP_MAX_MD_SIZE*/];
  char* jwt_hdr;
  int hdr_len;
  char* b64;
  char* p;
  int len = SIMPLE_BASE64_LEN(claims_len);
  
  switch (cf->oaz_jwt_sigenc_alg) {
  case 'n':
    jwt_hdr = "{\"typ\":\"JWT\",\"alg\":\"none\"}";
    hdr_len = strlen(jwt_hdr);
    len += SIMPLE_BASE64_LEN(hdr_len) + 1 + 1;    
    break;
  case 'h':
    jwt_hdr = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
    hdr_len = strlen(jwt_hdr);
    len += SIMPLE_BASE64_LEN(hdr_len) + 1 + 1 + 86 /* siglen conservative estimate */;    
    break;
  case 'r':
    jwt_hdr = "{\"typ\":\"JWT\",\"alg\":\"RS256\"}";
    hdr_len = strlen(jwt_hdr);
    len += SIMPLE_BASE64_LEN(hdr_len) + 1 + 1 + 500 /* siglen conservative estimate */;    
    break;
  default:
    ERR("Unrecognized OAZ_JWT_SIGENC_ALG spec(%c). See zxid-conf.pd or zxidconf.h for documentation.", cf->oaz_jwt_sigenc_alg);
    return 0;
  }
  
  b64 = ZX_ALLOC(cf->ctx, len+1);
  p = base64_fancy_raw(jwt_hdr, hdr_len, b64, safe_basis_64, 1<<31, 0, 0, 0);
  *p++ = '.';
  p = base64_fancy_raw(claims, claims_len, p, safe_basis_64, 1<<31, 0, 0, 0);
  *p = 0;
  
  switch (cf->oaz_jwt_sigenc_alg) {
  case 'n':
    *p++ = '.';
    *p = 0;
    break;
  case 'h':
    if (!cf->hmac_key[0])
      zx_get_symkey(cf, "hmac.key", cf->hmac_key);
    zx_hmac_sha256(cf->ctx, ZX_SYMKEY_LEN, cf->hmac_key, p-b64, b64, hash, &len);
    *p++ = '.';
    p = base64_fancy_raw(hash, len, p, safe_basis_64, 1<<31, 0, 0, 0);
    *p = 0;
    break;
  case 'r':
    ERR("*** RSA not implemented yet %d",0);
    zx_hmac_sha256(cf->ctx, ZX_SYMKEY_LEN, cf->hmac_key, p-b64, b64, hash, &len);
    *p++ = '.';
    p = base64_fancy_raw(hash, len, p, safe_basis_64, 1<<31, 0, 0, 0);
    *p = 0;
    break;
  }
  D("JWT(%s)", b64);
  return b64;
}

/*() Issue OAUTH2 / OpenID-Connect1 (OIDC1) id_token. logpathp is used
 * to return the path to the token so it can be remembered by AZC */

/* Called by:  zxid_oauth2_az_server_sso x3 */
char* zxid_sso_issue_jwt(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses, struct timeval* srcts, zxid_entity* sp_meta, struct zx_str* acsurl, zxid_nid** nameid, char* logop, struct zx_str** logpathp)
{
  int rawlen;
  char* buf;
  char* jwt;
  char* jwt_id; /* sha1 hash of the jwt, taken from log_path */
  struct zx_str issuer;
  struct zx_str* affil;
  char* eid;
  struct zx_str ss;
  struct zx_str nn;
  struct zx_str id;
  zxid_nid* tmpnameid;
  char sp_name_buf[ZXID_MAX_SP_NAME_BUF];

  *logpathp = 0;
  D("sp_eid(%s)", sp_meta->eid);
  if (!nameid)
    nameid = &tmpnameid;

  //if (ar && ar->IssueInstant && ar->IssueInstant->g.len && ar->IssueInstant->g.s)
  //  srcts->tv_sec = zx_date_time_to_secs(ar->IssueInstant->g.s);
  
  if (!cgi->allow_create)
    cgi->allow_create = '1';
  if (!cgi->nid_fmt || !cgi->nid_fmt[0])
    cgi->nid_fmt = "prstnt";  /* Persistent is the default implied by the specs. */

  /* Check for federation. */
  
  issuer.s = cgi->client_id; issuer.len = strlen(cgi->client_id);
  affil = &issuer;
  zxid_nice_sha1(cf, sp_name_buf, sizeof(sp_name_buf), affil, affil, 7);
  D("sp_name_buf(%s)  allow_create=%d", sp_name_buf, cgi->allow_create);

  *nameid = zxid_get_fed_nameid(cf, &issuer, affil, ses->uid, sp_name_buf, cgi->allow_create,
				(cgi->nid_fmt && !strcmp(cgi->nid_fmt, "trnsnt")),
				srcts, 0, logop);
  if (logop) { logop[3]='S';  logop[4]='S';  logop[5]='O';  logop[6]=0;  /* Patch in SSO */ }
  if (!*nameid) {
    ERR("get_fed_nameid() client_id(%s) returned NULL", cgi->client_id);
    return 0;
  }

  eid = zxid_my_ent_id_cstr(cf);
  // ,\"\":\"\"
  buf = zx_alloc_sprintf(cf->ctx, &rawlen,
		       "{\"iss\":\"%s\""
		       ",\"user_id\":\"%.*s\""
		       ",\"aud\":\"%s\""
		       ",\"exp\":%d"
		       ",\"nonce\":\"%s\"}",
		       eid,
		       ZX_GET_CONTENT_LEN(*nameid), ZX_GET_CONTENT_S(*nameid),
		       cgi->client_id,
		       time(0) + cf->timeskew + cf->a7nttl,
		       cgi->nonce);
  ZX_FREE(cf->ctx, eid);
  jwt = zxid_mk_jwt(cf, rawlen, buf);
  ZX_FREE(cf->ctx, buf);

  /* Log the issued JWT */

  ss.s = jwt; ss.len = strlen(jwt);
  *logpathp = zxlog_path(cf, &issuer, &ss, ZXLOG_ISSUE_DIR, ZXLOG_JWT_KIND, 1);
  if (!*logpathp) {
    ERR("Could not generate logpath for aud(%s) JWT(%s)", cgi->client_id, jwt);
    ZX_FREE(cf->ctx, jwt);
    return 0;
  }
  
  /* Since JWT does not have explicit ID attribute, we use the sha1 hash of the
   * contents of JWT as an ID. Since this is what logpath also does, we just
   * use the last component of the logpath. */
  for (jwt_id = (*logpathp)->s + (*logpathp)->len; jwt_id > (*logpathp)->s && jwt_id[-1] != '/'; --jwt_id) ;

  if (cf->log_issue_a7n) {
    if (zxlog_dup_check(cf, *logpathp, "sso_issue_jwt")) {
      ERR("Duplicate JWT ID(%s)", jwt_id);
      if (cf->dup_a7n_fatal) {
	ERR("FATAL (by configuration): Duplicate JWT ID(%s)", jwt_id);
	zxlog_blob(cf, 1, *logpathp, &ss, "sso_issue_JWT dup");
	zx_str_free(cf->ctx, *logpathp);
	ZX_FREE(cf->ctx, jwt);
	return 0;
      }
    }
    zxlog_blob(cf, 1, *logpathp, &ss, "sso_issue_JWT");
  }

  nn.s = cgi->nonce; nn.len = strlen(cgi->nonce);
  id.s = jwt_id; id.len = strlen(jwt_id);

  if (cf->loguser)
    zxlogusr(cf, ses->uid, 0, 0, 0, &issuer, &nn, &id,
	     ZX_GET_CONTENT(*nameid),
	     (cf->oaz_jwt_sigenc_alg!='n'?"U":"N"), "K", logop, 0, 0);
  
  zxlog(cf, 0, 0, 0, &issuer, &nn, &id,
	ZX_GET_CONTENT(*nameid),
	(cf->oaz_jwt_sigenc_alg!='n'?"U":"N"), "K", logop, 0, 0);

  return jwt;
}

/*() Issue OAUTH2 / OpenID-Connect1 (OIDC1) Authorization Code.
 * The code will be stored in /var/zxid/log/issue/azc/SHA1AZC
 * and contains pointers to actual tokens (they can be retrieved later using AZC).
 * The buffer at azc will be modified in place. */

/* Called by:  zxid_oauth2_az_server_sso */
int zxid_sso_issue_azc(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses, zxid_nid* nameid, const char* id_token_path, char* azc)
{
  int rawlen;
  char* buf;
  char* azc_id; /* sha1 hash of the azc, taken from logpath */
  struct zx_str* logpath;
  struct zx_str sp;
  struct zx_str ss;
  //struct zx_str id;

  /* Authorization code points to a file that contains paths to tokens, query string format */
  
  buf = zx_alloc_sprintf(cf->ctx, &rawlen,
			 "id_token_path=%s",
			 id_token_path);

  /* Log the issued Authorization Code */

#if 0
  sp.s = cgi->client_id;
#else
  sp.s = "fixed";  // *** since we have difficulty knowing client_id in token_endpoint, we just use fixed value
#endif
  sp.len = strlen(sp.s);
  ss.s = buf; ss.len = rawlen;
  logpath = zxlog_path(cf, &sp, &ss, ZXLOG_ISSUE_DIR, ZXLOG_AZC_KIND, 1);
  if (!logpath) {
    ERR("Could not generate logpath for aud(%s) AZC(%s)", cgi->client_id, buf);
    ZX_FREE(cf->ctx, buf);
    return 0;
  }

  /* Since AZC does not have explicit ID attribute, we use the sha1 hash of the
   * contents of AZC as an ID. Since this is what logpath also does, we just
   * use the last component of the logpath. */
  for (azc_id = logpath->s + logpath->len; azc_id > logpath->s && azc_id[-1] != '/'; --azc_id) ;

#if 1
  /* *** does it make sense to duplicate check Authorization Codes? */
  if (cf->log_issue_a7n) {
    if (zxlog_dup_check(cf, logpath, "sso_issue_azc")) {
      ERR("Duplicate AZC ID(%s)", azc_id);
      if (cf->dup_a7n_fatal) {
	ERR("FATAL (by configuration): Duplicate AZC ID(%s)", azc_id);
	zxlog_blob(cf, 1, logpath, &ss, "issue_azc dup");
	zx_str_free(cf->ctx, logpath);
	ZX_FREE(cf->ctx, buf);
	return 0;
      }
    }
    zxlog_blob(cf, 1, logpath, &ss, "issue_azc");
  }
#endif

  //id.s = azc_id; id.len = strlen(azc_id);
  if (cf->loguser)
    zxlogusr(cf, ses->uid, 0, 0, 0, 0, 0, 0, 0, "N", "K", "azc", 0, 0);
  
  zxlog(cf, 0, 0, 0, 0, 0, 0, 0, "N", "K", "azc", 0, 0);
  strcpy(azc, azc_id);
  zx_str_free(cf->ctx, logpath);
  ZX_FREE(cf->ctx, buf);
  return 1;
}

/*(i) Generate SSO assertion and ship it to SP by OAUTH2 Az redir binding. User has already
 * logged in by the time this is called. See also zxid_ssos_anreq() and zxid_idp_sso(). */

/* Called by:  zxid_idp_dispatch */
struct zx_str* zxid_oauth2_az_server_sso(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses)
{
  zxid_entity* sp_meta;
  struct zx_str* acsurl = 0;
  struct timeval srcts = {0,501000};
  zxid_nid* nameid;
  char* idtok;
  struct zx_str* jwt_logpath = 0;
  char  azc[1024];
  char logop[8];

  D_INDENT("oauth2_az_server_sso: ");
  strcpy(logop, "OAZxxxx");

  if (!cgi->client_id || !cgi->redirect_uri || !cgi->nonce) {
    ERR("Missing mandatory OAUTH2 field client_id=%p redirect_uri=%p nonce=%p", cgi->client_id, cgi->redirect_uri, cgi->nonce);
    goto err;
  }

  if (!cgi->response_type) {
    ERR("Missing mandatory OAUTH2 field response_type %d", 0);
    goto err;
  }

  if (!cgi->scope || !strstr(cgi->scope, "openid")) {
    ERR("Missing mandatory OAUTH2 field scope=%p or the scope does not contain `openid'", cgi->scope);
    goto err;
  }

  sp_meta = zxid_get_ent(cf, cgi->client_id);
  if (!sp_meta) {
    ERR("The metadata for client_id(%s) of the Az Req could not be found or fetched", cgi->client_id);
    goto err;
  }
  D("sp_eid(%s)", sp_meta->eid);

  /* Figure out the binding and url */

  acsurl = zxid_sp_loc_raw(cf, cgi, sp_meta, ZXID_ACS_SVC, OAUTH2_REDIR, 0);
  if (!acsurl) {
    ERR("sp(%s) metadata does not have SPSSODescriptor/AssertionConsumerService with Binding=\"" OAUTH2_REDIR "\". Pre-registering the SP at IdP is mandatory. redirect_uri(%s) will be ignored. (remote SP metadata problem)", sp_meta->eid, cgi->redirect_uri);
    goto err;
  }
  if (strlen(cgi->redirect_uri) != acsurl->len || memcmp(cgi->redirect_uri, acsurl->s, acsurl->len)) {
    ERR("sp(%s) metadata has SPSSODescriptor/AssertionConsumerService with Binding=\"" OAUTH2_REDIR "\" has value(%.*s), which is different from redirect_uri(%s). (remote SP problem)", sp_meta->eid, acsurl->len, acsurl->s, cgi->redirect_uri);
    goto err;
  }

  if (!cf->log_issue_a7n) {
    INFO("LOG_ISSUE_A7N must be turned on in IdP configuration for artifact profile to work. Turning on now automatically. %d", 0);
    cf->log_issue_a7n = 1;
  }

  /* User ses->uid is already logged in, now check for federation with sp */

  idtok = zxid_sso_issue_jwt(cf, cgi, ses, &srcts, sp_meta, acsurl, &nameid, logop, &jwt_logpath);
  if (!idtok) {
    ERR("Issuing JWT Failed %s", logop);
    goto err;
  }

  /* *** check that cgi->redirect_uri is authorized in metadata */

  if (strstr(cgi->response_type, "code")) {
    D("OAUTH2-ART ep(%.*s)", acsurl->len, acsurl->s);
    
    /* Assign az_code and store the tokens for future retrieval */

    if (!zxid_sso_issue_azc(cf, cgi, ses, nameid, jwt_logpath->s, azc)) {
      ERR("Issuing AZC Failed %s", logop);
      goto err;
    }

    zxlog(cf, 0, &srcts, 0, sp_meta->ed?&sp_meta->ed->entityID->g:0, 0, 0, ZX_GET_CONTENT(nameid), "N", "K", logop, ses->uid, "OAUTH2-ART code=%s", azc);
    
    /* Formulate OAUTH2 / OpenID-Connect1 Az Redir Response containing Authorization Code
     * which will later need to be dereferenced to obtain the actual tokens. */
    
    if (jwt_logpath)
      zx_str_free(cf->ctx, jwt_logpath);
    D_DEDENT("oauth2_az_server_sso: ");
    return zx_strf(cf->ctx, "Location: %s%c"
		   "code=%s"
		   "%s%s" CRLF  /* state */
		   "%s%s%s",    /* Set-Cookie */
		   cgi->redirect_uri, (strchr(cgi->redirect_uri, '?') ? '&' : '?'),
		   azc,
		   cgi->state?"&state=":"", STRNULLCHK(cgi->state),
		   ses->setcookie?"Set-Cookie: ":"", ses->setcookie?ses->setcookie:"", ses->setcookie?CRLF:"");
    
  }
  
  if (strstr(cgi->response_type, "token") && strstr(cgi->response_type, "id_token")) {
    D("OAUTH2-IMPL ep(%.*s)", acsurl->len, acsurl->s);
    zxlog(cf, 0, &srcts, 0, sp_meta->ed?&sp_meta->ed->entityID->g:0, 0, 0, ZX_GET_CONTENT(nameid), "N", "K", logop, ses->uid, "OAUTH2-IMPL");
    
    /* Formulate OAUTH2 / OpenID-Connect1 Az Redir Response directly containing tokens */
    
    if (jwt_logpath)
      zx_str_free(cf->ctx, jwt_logpath);
    D_DEDENT("oauth2_az_server_sso: ");
    return zx_strf(cf->ctx, "Location: %s%c"
		   "access_token=%s"
		   "&token_type=bearer"
		   "&id_token=%s"
		   "&expires_in=%d" CRLF
		   "%s%s%s",   /* Set-Cookie */
		   cgi->redirect_uri, (strchr(cgi->redirect_uri, '?') ? '&' : '?'),
		   idtok,
		   idtok,
		   cf->a7nttl,
		   ses->setcookie?"Set-Cookie: ":"", ses->setcookie?ses->setcookie:"", ses->setcookie?CRLF:"");
  }

  ERR("OAUTH2 field response_type(%s) missing or does not contain `code' or `token id_token'", STRNULLCHKD(cgi->response_type));
 err:
  if (jwt_logpath)
    zx_str_free(cf->ctx, jwt_logpath);
  D_DEDENT("oauth2_az_server_sso: ");
  return zx_dup_str(cf->ctx, "* ERR");
}

#define UMA_WELL_KNOWN "/.well-known/uma-configuration"

/*() Extract a metadata item from well known location.
 *
 * cf:: ZXID configuration object, for memory allocation
 * base_uri:: scheme, domain name and port of server whose metadata we are looking for.
 *     For example, the value of as_uri returned in WWW-Authenticate HTTP response header.
 * key:: Name of the metadata item, must include double quoted, e.g. "\"rpt_endpoint\""
 * return:: c string, zx allocated. Caller must free.
 *
 * N.B. This function is very simplistic as it does not cache the metadata in any way.
 */

/* Called by:  zxid_oauth_call_az_endpoint, zxid_oauth_call_rpt_endpoint, zxid_oauth_dynclireg_client, zxid_oauth_rsrcreg_client */
char* zxid_oauth_get_well_known_item(zxid_conf* cf, const char* base_uri, const char* key)
{
  int len;
  char* p;
  char endpoint[4096];
  struct zx_str* res;

  len = strlen(base_uri);
  if (len + sizeof(UMA_WELL_KNOWN) > sizeof(endpoint)-1) {
    ERR("base_uri too long %d", len);
    return 0;
  }
  memcpy(endpoint, base_uri, len);
  p = endpoint + len -1;
  if (*p != '/')
    ++p;
  strcpy(p, UMA_WELL_KNOWN);
  res = zxid_http_cli(cf, -1, endpoint, -1, 0, 0, 0, 0);
  D("base_uri(%s) endpoint(%s) res(%.*s) key(%s)", base_uri, endpoint, res?res->len:0, res?res->s:"", key);
  
  return zx_json_extract_dup(cf->ctx, res->s, key);
}

char* iat = 0;
char* _uma_authn = 0;

/* Called by:  zxid_oauth_call_az_endpoint, zxid_oauth_call_rpt_endpoint, zxumacall_main x2 */
struct zx_str* zxid_oauth_dynclireg_client(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses, const char* as_uri)
{
  struct zx_str* res;
  char* azhdr;
  char* req = zxid_mk_oauth2_dyn_cli_reg_req(cf);
  char* url = zxid_oauth_get_well_known_item(cf, as_uri, "\"dynamic_client_endpoint\"");
  char* p;
  if (iat) {
    azhdr = zx_alloc_sprintf(cf->ctx, 0, "Authorization: Bearer %s", iat);
  } else
    azhdr = 0;
  DD("url(%s) req(%s) iat(%s)", url, req, STRNULLCHKD(azhdr));
  if (_uma_authn) {
    p = url;
    url = zx_alloc_sprintf(cf->ctx, 0, "%s%c_uma_authn=%s", url, strchr(url,'?')?'&':'?', _uma_authn);
    ZX_FREE(cf->ctx, p);
  }
  D("url(%s) req(%s) iat(%s)", url, req, STRNULLCHKD(azhdr));
  res = zxid_http_cli(cf, -1, url, -1, req, ZXID_JSON_CONTENT_TYPE, azhdr, 0);
  ZX_FREE(cf->ctx, url);
  if (azhdr) ZX_FREE(cf->ctx, azhdr);
  ZX_FREE(cf->ctx, req);
  D("%.*s", res->len, res->s);
  ses->client_id = zx_json_extract_dup(cf->ctx, res->s, "\"client_id\"");
  ses->client_secret = zx_json_extract_dup(cf->ctx, res->s, "\"client_secret\"");
  return res;
}

static char* zxid_mk_oauth_az_header(zxid_conf* cf, zxid_ses* ses)
{
  char* azhdr;
  if (ses->access_token) {
    azhdr = zx_alloc_sprintf(cf->ctx, 0, "Authorization: Bearer %s", ses->access_token);
  } else if (iat) {
    azhdr = zx_alloc_sprintf(cf->ctx, 0, "Authorization: Bearer %s", iat);
  } else if (ses->client_id && ses->client_secret) {
    azhdr = zx_mk_basic_auth_b64(cf->ctx, ses->client_id, ses->client_secret);
  } else
    azhdr = 0;
  return azhdr;
}

/* Called by:  zxumacall_main */
void zxid_oauth_rsrcreg_client(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses, const char* as_uri, const char* rsrc_name, const char* rsrc_icon_uri, const char* rsrc_scope_url, const char* rsrc_type)
{
  struct zx_str* res;
  char* restful_url;
  char* azhdr;
  char* req = zxid_mk_oauth2_rsrc_reg_req(cf, rsrc_name, rsrc_icon_uri, rsrc_scope_url, rsrc_type);
  char* url = zxid_oauth_get_well_known_item(cf, as_uri, "\"resource_set_registration_endpoint\"");
  azhdr = zxid_mk_oauth_az_header(cf, ses);
  D("req(%s) azhdr(%s)", req, STRNULLCHKD(azhdr));
  
  restful_url = zx_alloc_sprintf(cf->ctx, 0, "%s/resource_set/%s", url, rsrc_name);
  ZX_FREE(cf->ctx, url);
  res = zxid_http_cli(cf, -1, restful_url, -1, req, ZXID_JSON_CONTENT_TYPE, azhdr, 0);
  ZX_FREE(cf->ctx, restful_url);
  if (azhdr) ZX_FREE(cf->ctx, azhdr);
  ZX_FREE(cf->ctx, req);
  D("%.*s", res->len, res->s);
}

/*() Call OAUTH2 / UMA1 Resource Protection Token Endpoint and return a token
 * *** still needs a lot of work to turn more generic */

/* Called by: */
char* zxid_oauth_call_rpt_endpoint(zxid_conf* cf, zxid_ses* ses, const char* host_id, const char* as_uri)
{
  struct zx_str* res;
  char* azhdr;
  char* rpt_endpoint = zxid_oauth_get_well_known_item(cf, as_uri, "\"rpt_endpoint\"");

  azhdr = zxid_mk_oauth_az_header(cf, ses);

  //if (!ses->client_id || !ses->client_secret)
  //  zxid_oauth_dynclireg_client(cf, cgi, ses, as_uri);
  // *** Client acquires AAT

#if 0
  snprintf(req, sizeof(buf),
	   "client_id=%s&client_secret=%s",
	   ses->client_id, ses->client_secret);
#endif
  D("azhdr(%s)", STRNULLCHKD(azhdr));

  res = zxid_http_cli(cf, -1, rpt_endpoint, -1, "", 0, azhdr, 0);
  D("%.*s", res->len, res->s);
  
  /* Extract the fields as if it had been implicit mode SSO */
  ses->rpt = zx_json_extract_dup(cf->ctx, res->s, "\"rpt\"");
  // *** check validity
  return "OK";
}

/*() Call OAUTH2 / UMA1 Resource Protection Token Endpoint and return a token
 * *** still needs a lot of work to turn more generic */

/* Called by: */
char* zxid_oauth_call_az_endpoint(zxid_conf* cf, zxid_ses* ses, const char* host_id, const char* as_uri, const char* ticket)
{
  char* req;
  struct zx_str* res;
  char* azhdr;
  char* az_endpoint = zxid_oauth_get_well_known_item(cf, as_uri, "\"authorization_request_endpoint\"");

  azhdr = zxid_mk_oauth_az_header(cf, ses);

  //if (!ses->client_id || !ses->client_secret)
  //  zxid_oauth_dynclireg_client(cf, cgi, ses, as_uri);
  // *** Client acquires AAT

#if 0
  snprintf(req, sizeof(buf),
	   "client_id=%s&client_secret=%s",
	   ses->client_id, ses->client_secret);
#endif
  req = zx_alloc_sprintf(cf->ctx, 0, "{\"rpt\":\"%s\",\"ticket\":\"%s\"}", ses->rpt, ticket);
  D("req(%s) azhdr(%s)", req, STRNULLCHKD(azhdr));

  res = zxid_http_cli(cf, -1, az_endpoint, -1, req, 0, azhdr, 0);
  ZX_FREE(cf->ctx, req);
  D("%.*s", res->len, res->s);
  
  /* Extract the fields as if it had been implicit mode SSO */
  ses->rpt = zx_json_extract_dup(cf->ctx, res->s, "\"rpt\"");
  // *** check validity
  return "OK";
}

/*() Get app secret from a special file.
 * The reason why we do not use metadata appSecret attribute is that
 * the usage pattern of metadata files is rather promiscuous and there
 * would be high risk of leaking the secret. By having it in its
 * own file allows it to be protected by filesystem permissions.
 * It is also located in the pem subdirectory where we keep other
 * sensitive key material. Caller must free seturned buffer.
 */

/* Called by:  zxid_oauth_call_token_endpoint */
char* zxid_get_app_secret(zxid_conf* cf, const char* idp_sha1_name, const char* logkey)
{
  fdtype fd;
  int n,siz,got;
  char* buf;
  fd = open_fd_from_path(O_RDONLY, 0, logkey, 1,
			 "%s" ZXID_PEM_DIR "%s.appsec", cf->cpath, idp_sha1_name);
  if (fd == BADFD) {
    perror("open app secret to read");
    D("No app secret file found for idp_sha1_name(%s)", idp_sha1_name);
    return 0;
  }
  siz = get_file_size(fd);
  buf = ZX_ALLOC(cf->ctx, siz+1);
  n = read_all_fd(fd, buf, siz, &got);
  DD("==========idp_sha1_name(%s)", idp_sha1_name);
  if (n == -1)
    goto readerr;
  close_file(fd, (const char*)__FUNCTION__);
  return buf;

readerr:
  perror("read app secret");
  D("%s: Failed to read app secret for idp_sha1_name(%s)", logkey, idp_sha1_name);
  close_file(fd, (const char*)__FUNCTION__);
  return 0;
}

/*() Call OAUTH2 / UMA1 / OIDC1 / Facebook Connect Token Endpoint and return a token
 * N.B. The cgi->eid was populated by caller from the information in state.
 * The token endpoint is determined from remote IdP's metadata in out cot/
 * directory. It must have IDPSSODescriptor/@tokenURL attribute (this is an
 * extension to the regular SAML metadata).
 */

/* Called by:  zxid_sp_oauth2_dispatch */
static int zxid_oauth_call_token_endpoint(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses)
{
  zxid_entity* idp_meta;
  struct zx_str surl;
  struct zx_str* url;
  struct zx_str* res;
  char* redir_url_enc;
  char* cli_id_url_enc;
  char* cli_sec_url_enc = 0;
  char* cli_sec;
  char* azhdr = 0;
  char* grant_type = 0;
  char* buf;

  D_INDENT("call_tok_ept: ");

  if (!cgi->eid || !cgi->eid[0]) {
    ERR("Entity ID missing. Corrupt state field? %p", cgi->eid);
    cgi->err = "IdP entity id missing or incorrect.";
    D_DEDENT("call_tok_ept: ");
    return 0;
  }

  ses->issuer_meta = idp_meta = zxid_get_ent(cf, cgi->eid);
  if (!idp_meta || !idp_meta->ed || !idp_meta->ed->entityID || !idp_meta->ed->IDPSSODescriptor) {
    ERR("IdP URL incorrect or IdP does not support fetching metadata from that URL. Corrupt state field? eid(%s) %p", cgi->eid, idp_meta);
    cgi->err = "IdP URL incorrect or IdP does not support fetching metadata from that URL.";
    D_DEDENT("call_tok_ept: ");
    return 0;
  }
  ses->issuer = &idp_meta->ed->entityID->g;
  ses->idpeid = zx_str_to_c(cf->ctx, ses->issuer);

  if (cgi->client_id || cgi->client_id[0]) {
    DD("HERE3 cgi->client_id(%s)",cgi->client_id);
    /* From previous steps of discovery passed via state */
    cli_id_url_enc = zx_url_encode(cf->ctx, -2, cgi->client_id, 0);
  } else if (idp_meta->ed && ZX_ATTR_HAS_VALUE(idp_meta->ed->appId)) {
    /* From metadata (the SP's appId is stored in idp_meta on SP system */
    cli_id_url_enc = zx_url_encode(cf->ctx, idp_meta->ed->appId->g.len, idp_meta->ed->appId->g.s,0);
  } else if (cgi->eid || cgi->eid[0]) {
    cli_id_url_enc = zx_url_encode(cf->ctx, -2, cgi->eid, 0);
  } else {
    ERR("IdP metadata not prepared for resolving code to access_token. appId or client_id missing. Corrupt state field? %p", cgi->eid);
    cgi->err = "IdP metadata not prepared for resolving code to access_token. appId or client_id missing.";
    D_DEDENT("call_tok_ept: ");
    return 0;
  }

#if 0  
  if (iat) {
    azhdr = zx_alloc_sprintf(cf->ctx, 0, "Authorization: Bearer %s", client_secret);
  }
#endif

  if (cgi->client_secret && cgi->client_secret[0]) {
    /* In Mobile Connect Discovery case the client_secret was discovered and
     * passed via state. In this flow, Authorization header is used and
     * client_secret is suppressed from the query string. */
    azhdr = zx_mk_basic_auth_b64(cf->ctx, cgi->client_id, cgi->client_secret);
    D("HERE6 %p azhdr(%s)", cli_id_url_enc, azhdr);
    if (cli_id_url_enc) {
      ZX_FREE(cf->ctx, cli_id_url_enc);
      cli_id_url_enc = 0;
    }
    cli_sec_url_enc = 0;
    grant_type = "authorization_code";
  } else {
    cli_sec = zxid_get_app_secret(cf, idp_meta->sha1_name, "call_tok_ept");
    D("HERE7 cli_sec(%s)",STRNULLCHKD(cli_sec));
    if (!cli_sec) {
      if (!ZX_ATTR_HAS_VALUE(idp_meta->ed->appSecret)) {
	ERR("IdP is missing app secret file (and appSecret field). eid(%s) %p", cgi->eid, idp_meta->ed->appSecret);
	cgi->err = "IdP not prepared for resolving code to access_token. Lacks app secret.";
	D_DEDENT("call_tok_ept: ");
	return 0;
      }
      cli_sec = zx_dup_len_cstr(cf->ctx, idp_meta->ed->appSecret->g.len, idp_meta->ed->appSecret->g.s);
      D("HERE8 cli_sec(%s)",STRNULLCHKD(cli_sec));
    }
    /* FBC wants client_secret in QueryString, not Authorization HTTP header */
    azhdr = 0;
    D("HERE9 cli_sec(%s)",STRNULLCHKD(cli_sec));
    cli_sec_url_enc = zx_url_encode(cf->ctx, -2, cli_sec, 0);
    ZX_FREE(cf->ctx, cli_sec);
    grant_type = 0;
  }

  if (cgi->token_url && cgi->token_url[0]) {
    D("HERE10 token_url(%s)",cgi->token_url);
    /* Mob Conn case. The token_url was discovered and passed via state so it is available here. */
    surl.s = cgi->token_url;
    surl.len = strlen(surl.s);
    url = &surl;
  } else if (ZX_ATTR_HAS_VALUE(idp_meta->ed->IDPSSODescriptor->tokenURL)) {
    /* FBC uses metadata to figure out the token url */
    url = &idp_meta->ed->IDPSSODescriptor->tokenURL->g;
    D("HERE11 FBC metadata url(%.*s)", url->len, url->s);
  } else {
    ERR("IdP metadata is missing tokenURL field. eid(%s) %p", cgi->eid, idp_meta->ed->IDPSSODescriptor->tokenURL);
    cgi->err = "IdP metadata not prepared for resolving code to access_token. Lacks tokenURL.";
    D_DEDENT("call_tok_ept: ");
    return 0;
  }
  redir_url_enc = zx_url_encode(cf->ctx, -2, cf->burl, 0);

#if 1
  /* Must use POST */
  buf = zx_alloc_sprintf(cf->ctx, 0,
			 "code=%s&redirect_uri=%s%%3fo=O"
			 "%s%s"    /* &client_id=       FBC */
			 "%s%s"    /* &client_secret=   FBC */
			 "%s%s",   /* &grant_type=      MobConn */
			 cgi->code, redir_url_enc,
			 cli_id_url_enc?"&client_id=":"", STRNULLCHK(cli_id_url_enc),
			 cli_sec_url_enc?"&client_secret=":"", STRNULLCHK(cli_sec_url_enc),
			 grant_type?"&grant_type=":"", STRNULLCHK(grant_type));

  ZX_FREE(cf->ctx, redir_url_enc);
  if (cli_sec_url_enc) ZX_FREE(cf->ctx, cli_sec_url_enc);
  if (cli_id_url_enc)  ZX_FREE(cf->ctx, cli_id_url_enc);
  res = zxid_http_cli(cf, url->len, url->s, -1, buf, 0, azhdr, 0);
#else
  /* GET is not officially supported for Mobile Connect */
  buf = zx_alloc_sprintf(cf->ctx, 0,
			 "%.*s%credirect_uri=%s%%3fo=O"
			 "&code=%s"
			 "%s%s"    /* &client_id=       FBC */
			 "%s%s"    /* &client_secret=   FBC */
			 "%s%s",   /* &grant_type=      MobConn */
			 url->len, url->s, (memchr(url->s, '?', url->len)?'&':'?'),
			 redir_url_enc,
			 cgi->code,
			 cli_id_url_enc?"&client_id=":"", STRNULLCHK(cli_id_url_enc),
			 cli_sec_url_enc?"&client_secret=":"", STRNULLCHK(cli_sec_url_enc),
			 grant_type?"&grant_type=":"", STRNULLCHK(grant_type));

  ZX_FREE(cf->ctx, redir_url_enc);
  if (cli_sec_url_enc) ZX_FREE(cf->ctx, cli_sec_url_enc);
  if (cli_id_url_enc)  ZX_FREE(cf->ctx, cli_id_url_enc);
  res = zxid_http_cli(cf, -1, buf, 0, 0, 0, azhdr, 0);
#endif
  ZX_FREE(cf->ctx, buf);
  if (azhdr)  ZX_FREE(cf->ctx, azhdr);
  D("res=%p len=%d (%.*s)", res, res->len, res->len, res->s);
  
  /* Extract the fields as if it had been implicit mode SSO
   *
   * {"access_token":"8d959b40-e001-11e6-baa0-ef6a745b61ee","token_type":"Bearer","expires_in":3600,"id_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJub25jZSI6Ik9BdmlHUGZkWXFHY0lCWUREc1QyVzFlMWY5Iiwic3ViIjoiOWMxOGI1ZDZhZDhhZjU5NmU2NzExNDUzZmU4NzhiNTciLCJhbXIiOlsiU0lNX1BJTiJdLCJhdXRoX3RpbWUiOjE0ODUwMjA3OTYsImFjciI6IjIiLCJhenAiOiJhNDA1ZTdmYS1kMWJmLTQ4NTctYTNmYS0wOTRkYmE4NDc3MTEiLCJpYXQiOjE0ODUwMjA3OTUsImV4cCI6MTQ4NTAyNDM5NSwiYXVkIjpbImE0MDVlN2ZhLWQxYmYtNDg1Ny1hM2ZhLTA5NGRiYTg0NzcxMSJdLCJpc3MiOiJodHRwOi8vb3BlcmF0b3ItYi5zYW5kYm94Mi5tb2JpbGVjb25uZWN0LmlvL29pZGMvYWNjZXNzdG9rZW4ifQ.VqbgsyBXor6CZwJOUDdHpiZg35oYgYf4CejnilDBLoc"}
   *
   * {"access_token":"8d959b40-e001-11e6-baa0-ef6a745b61ee",
      "token_type":"Bearer",
      "expires_in":3600,
      "id_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJub25jZSI6Ik9BdmlHUGZkWXFHY0lCWUREc1QyVzFlMWY5Iiwic3ViIjoiOWMxOGI1ZDZhZDhhZjU5NmU2NzExNDUzZmU4NzhiNTciLCJhbXIiOlsiU0lNX1BJTiJdLCJhdXRoX3RpbWUiOjE0ODUwMjA3OTYsImFjciI6IjIiLCJhenAiOiJhNDA1ZTdmYS1kMWJmLTQ4NTctYTNmYS0wOTRkYmE4NDc3MTEiLCJpYXQiOjE0ODUwMjA3OTUsImV4cCI6MTQ4NTAyNDM5NSwiYXVkIjpbImE0MDVlN2ZhLWQxYmYtNDg1Ny1hM2ZhLTA5NGRiYTg0NzcxMSJdLCJpc3MiOiJodHRwOi8vb3BlcmF0b3ItYi5zYW5kYm94Mi5tb2JpbGVjb25uZWN0LmlvL29pZGMvYWNjZXNzdG9rZW4ifQ.VqbgsyBXor6CZwJOUDdHpiZg35oYgYf4CejnilDBLoc"}

   */
  ses->access_token = zx_json_extract_dup(cf->ctx, res->s, "\"access_token\"");
  ses->refresh_token = zx_json_extract_dup(cf->ctx, res->s, "\"refresh_token\"");
  ses->token_type = zx_json_extract_dup(cf->ctx, res->s, "\"token_type\"");
  ses->expires_in = zx_json_extract_int(res->s, "\"expires_in\"");
  ses->id_token = zx_json_extract_dup(cf->ctx, res->s, "\"id_token\"");
  if (ses->access_token)
    cgi->access_token = ses->access_token;
  if (ses->id_token)
    cgi->id_token = ses->id_token;

  /* Typical id_token
   *
   * {"nonce":"OAviGPfdYqGcIBYDDsT2W1e1f9","sub":"9c18b5d6ad8af596e6711453fe878b57","amr":["SIM_PIN"],"auth_time":1485020796,"acr":"2","azp":"a405e7fa-d1bf-4857-a3fa-094dba847711","iat":1485020795,"exp":1485024395,"aud":["a405e7fa-d1bf-4857-a3fa-094dba847711"],"iss":"http://operator-b.sandbox2.mobileconnect.io/oidc/accesstoken"}
   *
   * {"nonce":"OAviGPfdYqGcIBYDDsT2W1e1f9",
      "sub":"9c18b5d6ad8af596e6711453fe878b57",
      "amr":["SIM_PIN"],
      "auth_time":1485020796,
      "acr":"2",
      "azp":"a405e7fa-d1bf-4857-a3fa-094dba847711",
      "iat":1485020795,
      "exp":1485024395,
      "aud":["a405e7fa-d1bf-4857-a3fa-094dba847711"],
      "iss":"http://operator-b.sandbox2.mobileconnect.io/oidc/accesstoken"}
   *
   * sub is the subject pseudonym
   */

  // *** check validity
  zx_str_free(cf->ctx, res);
  D_DEDENT("call_tok_ept: ");
  return 1;
}

/*() Call Facebook graph /me endpoint using OAUTH2 and extract
 * from the response id (the pseudonym) and other fields (if available).
 * N.B. The ses->access_token was populated by caller from response to call
 * to token endpoint, see above.
 * The graph endpoint is determined from remote IdP's metadata in out cot/
 * directory. It must have IDPSSODescriptor/@graphURL attribute (this is an
 * extension to the regular SAML metadata). */

/* Called by:  zxid_sp_oauth2_dispatch */
static int zxid_oauth_call_fb_graph_endpoint(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses, const char* graph_path, const char* more_fields)
{
  zxid_entity* idp_meta;
  struct zx_str* url;
  struct zx_str* res;
  char* azhdr;
  char* buf;
  int len,olen;
#if 0  
  if (iat) {
    azhdr = zx_alloc_sprintf(cf->ctx, 0, "Authorization: Bearer %s", client_secret);
  } else
#endif
    azhdr = 0;

  D_INDENT("call_graph_ept: ");

  idp_meta = ses->issuer_meta;  /* ses->issuer sis already populated by token end point call */
  if (!idp_meta || !idp_meta->ed || !idp_meta->ed->IDPSSODescriptor) {
    ERR("Issuer IdP not set or does not support graph API. %p", idp_meta);
    cgi->err = "Issuer IdP not set or does not support graph API";
    D_DEDENT("call_graph_ept: ");
    return 0;
  }
  
  if (!ZX_ATTR_HAS_VALUE(idp_meta->ed->IDPSSODescriptor->graphURL)) {
    ERR("IdP metadata is missing graphURL field. eid(%s) %p", cgi->eid, idp_meta->ed->IDPSSODescriptor->graphURL);
    cgi->err = "IdP metadata lacks graphURL.";
    D_DEDENT("call_graph_ept: ");
    return 0;
  }

  url = &idp_meta->ed->IDPSSODescriptor->graphURL->g;
  
  for (olen = 1023 /* just initial guess */; 1; olen=len) {
    buf = ZX_ALLOC(cf->ctx, olen+1);
    len = snprintf(buf, olen,
		   "%.*s%s%c"
		   "access_token=%s"
		   "%s",
		   url->len, url->s, graph_path, (memchr(url->s, '?', url->len)?'&':'?'),
		   ses->access_token,
		   STRNULLCHK(more_fields));
    if (len <= olen)
      break;  /* fits */
    /* Did not fit, try again (second iteration will always be successful) */
    ZX_FREE(cf->ctx, buf);
  }
  buf[len] = 0;  /* MS snprintf() bug */
  
  res = zxid_http_cli(cf, -1, buf, 0, 0, 0, azhdr, 0);
  if (!res)
    goto grapherr;
  D("%.*s", res->len, res->s);
  
  /* Extract the fields as if it had been implicit mode SSO */
  ses->nid = zx_json_extract_dup(cf->ctx, res->s, "\"id\"");  /* facebook persistent pseudonym */
  if (!ses->nid) {
 grapherr:
    ERR("Call to graph endpoint did not include id. req(%s) res(%.*s)", buf, res?res->len:1, res?res->s:"-");
    ZX_FREE(cf->ctx, buf);
    D_DEDENT("call_graph_ept: ");
    return 0;
  }
  ses->uid = zxid_mk_uid(cf, idp_meta->eid, ses->nid);
  ses->nidfmt = 1;  /* Assume federation */
  ses->tgt = ses->nid;
  ses->tgtfmt = 1;  /* Assume federation */
  ZX_FREE(cf->ctx, buf);
  D("remote idp assigned nid(%s), also used as uid", STRNULLCHKD(ses->nid));
  zxid_put_user_ses(cf, ses);
  zxid_put_user_attr(cf, ses,
		     zx_json_extract_dup(cf->ctx, res->s, "\"name\""),
		     zx_json_extract_dup(cf->ctx, res->s, "\"email\""),
		     res);

#if 0
  ses->access_token = zx_json_extract_dup(cf->ctx, res->s, "\"access_token\"");
  ses->refresh_token = zx_json_extract_dup(cf->ctx, res->s, "\"refresh_token\"");
  ses->token_type = zx_json_extract_dup(cf->ctx, res->s, "\"token_type\"");
  ses->expires_in = zx_json_extract_int(res->s, "\"expires_in\"");
  ses->id_token = zx_json_extract_dup(cf->ctx, res->s, "\"id_token\"");
  if (ses->access_token)
    cgi->access_token = ses->access_token;
  if (ses->id_token)
    cgi->id_token = ses->id_token;
  // *** check validity
#endif
  zx_str_free(cf->ctx, res);
  D_DEDENT("call_graph_ept: ");
  return 1;
}

/*() Finalize JWT based SSO, create session from the fields available in the JWT
 * See also: zxid_sp_sso_finalize() in zxidsso.c */

/* Called by:  zxid_sp_dig_oauth_sso_a7n */
int zxid_sp_sso_finalize_jwt(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses, const char* jwt)
{
  char* err = "S"; /* See: RES in zxid-log.pd, section "ZXID Log Format" */
  struct zx_str ss;
  struct timeval ourts;
  struct timeval srcts = {0,501000};
  struct zx_str* logpath;
  char* iss;
  char* claims;

  ses->jwt = (char*)jwt;
  //ses->rs = ;
  ses->ssores = 1;
  GETTIMEOFDAY(&ourts, 0);

  D_INDENT("ssof: ");

  claims = zxid_decode_jwt(cf, cgi, ses, jwt);
  if (!claims) {
    ERR("JWT decode error jwt(%s)", STRNULLCHKD(jwt));
    goto erro;
  }

  /* Typical Mobile Connect (OIDC1) id_token
   *
   * {"nonce":"OAviGPfdYqGcIBYDDsT2W1e1f9","sub":"9c18b5d6ad8af596e6711453fe878b57","amr":["SIM_PIN"],"auth_time":1485020796,"acr":"2","azp":"a405e7fa-d1bf-4857-a3fa-094dba847711","iat":1485020795,"exp":1485024395,"aud":["a405e7fa-d1bf-4857-a3fa-094dba847711"],"iss":"http://operator-b.sandbox2.mobileconnect.io/oidc/accesstoken"}
   *
   * {"nonce":"OAviGPfdYqGcIBYDDsT2W1e1f9",
      "sub":"9c18b5d6ad8af596e6711453fe878b57",
      "amr":["SIM_PIN"],
      "auth_time":1485020796,
      "acr":"2",
      "azp":"a405e7fa-d1bf-4857-a3fa-094dba847711",
      "iat":1485020795,
      "exp":1485024395,
      "aud":["a405e7fa-d1bf-4857-a3fa-094dba847711"],
      "iss":"http://operator-b.sandbox2.mobileconnect.io/oidc/accesstoken"}
   *
   * where "sub" is the subject pseudonym
   *
   * Typical FBC token content
   * {"data":{
        "app_id":"1819571348286291",
        "application":"IDSSO Proxy Identity Provider",
        "expires_at":1485686557,
        "is_valid":true,
        "issued_at":1480502557,
        "scopes":["public_profile"],
        "user_id":"336179946751868"}}
   *
   * where "user_id" is the subject pseudonym
   */
  
  ses->nid = zx_json_extract_dup(cf->ctx, claims, "\"sub\"");
  if (!ses->nid)
    ses->nid = zx_json_extract_dup(cf->ctx, claims, "\"user_id\"");
  if (!ses->nid) {
    ERR("JWT decode: no pseudonym (sub or user_id) found in jwt(%s)", STRNULLCHKD(jwt));
    goto erro;
  }
  ses->nidfmt = 1;  /* Assume federation */

  ses->tgtjwt = ses->jwt;
  ses->tgt = ses->nid;
  ses->tgtfmt = 1;  /* Assume federation */

  iss = zx_json_extract_dup(cf->ctx, claims, "\"iss\"");
  if (!iss) {
    ERR("JWT decode: no iss found in jwt(%s)", STRNULLCHKD(jwt));
    goto erro;
  }
  ses->issuer = zx_ref_str(cf->ctx, iss);
  ses->idpeid = iss;

  D("SSOJWT received. NID(%s) FMT(%d)", ses->nid, ses->nidfmt);
  
  // *** should some signature validation happen here, using issuer (idp) meta?
  cgi->sigval = "N";
  cgi->sigmsg = "Assertion was not signed.";
  ses->sigres = ZXSIG_NO_SIG;
  
  if (cf->log_rely_a7n) {
    DD("Logging rely... %d", 0);
    ss.s = (char*)jwt; ss.len = strlen(jwt);
    logpath = zxlog_path(cf, ses->issuer, &ss, ZXLOG_RELY_DIR, ZXLOG_JWT_KIND, 1);
    if (logpath) {
      ses->sso_a7n_path = ses->tgt_a7n_path = zx_str_to_c(cf->ctx, logpath);
      if (zxlog_dup_check(cf, logpath, "SSO JWT")) {
	if (cf->dup_a7n_fatal) {
	  err = "C";
	  zxlog_blob(cf, cf->log_rely_a7n, logpath, &ss, "sp_sso_finalize_jwt dup err");
	  goto erro;
	}
      }
      zxlog_blob(cf, cf->log_rely_a7n, logpath, &ss, "sp_sso_finalize_jwt");
    }
  }
  DD("Creating session... %d", 0);
  ses->uid = zxid_mk_uid(cf, iss, ses->nid);
  ses->ssores = 0;
  zxid_put_ses(cf, ses);
  //*** zxid_snarf_eprs_from_ses(cf, ses);  /* Harvest attributes and bootstrap(s) */
  cgi->msg = "SSO completed and session created.";
  cgi->op = '-';  /* Make sure management screen does not try to redispatch. */
  zxid_put_user_ses(cf, ses);
  DD("Logging... %d", 0);
  ss.s = ses->nid; ss.len = strlen(ss.s);
  zxlog(cf, &ourts, &srcts, 0, ses->issuer, 0, 0, &ss,
	cgi->sigval, "K", "NEWSESJWT", ses->sid, "sesix(%s)", STRNULLCHKD(ses->sesix));
  zxlog(cf, &ourts, &srcts, 0, ses->issuer, 0, 0, &ss,
	cgi->sigval, "K", ses->nidfmt?"FEDSSOJWT":"TMPSSOJWT", STRNULLCHKD(ses->sesix), 0);

  if (cf->idp_ena) {  /* (PXY) Middle IdP of Proxy IdP flow */
    if (cgi->ssoreq && cgi->ssoreq[0]) {
      D("ProxyIdP got ar(%s)", STRNULLCHK(cgi->ssoreq));
      cgi->saml_resp = 0;  /* Clear Response to prevent re-interpretation. We want Request. */
      zxid_decode_ssoreq(cf, cgi);
      cgi->op = 'V';
      D_DEDENT("ssof: ");
      return ZXID_IDP_REQ; /* Cause zxid_simple_idp_an_ok_do_rest() to be called from zxid_sp_dispatch(); */
    } else {
      INFO("Middle IdP of Proxy IdP flow did not receive RelayState from upstream IdP %p", cgi->rs);
    }
  }
  D_DEDENT("ssof: ");
  return ZXID_SSO_OK;

erro:
  ERR("SSOJWT fail (%s)", err);
  cgi->msg = "SSO failed. This could be due to signature, timeout, etc., technical failures, or by policy.";
  zxlog(cf, &ourts, &srcts, 0, ses->issuer, 0, 0, 0,
	cgi->sigval, err, ses->nidfmt?"FEDSSOJWT":"TMPSSOJWT", STRNULLCHKD(ses->sesix), "Error.");
  D_DEDENT("ssof: ");
  return 0;
}

/*() Extract an assertion from OAUTH2 Az response, and perform SSO */

/* Called by:  zxid_sp_oauth2_dispatch x3 */
static int zxid_sp_dig_oauth_sso_a7n(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses, char* jwt)
{
  if (jwt)
    return zxid_sp_sso_finalize_jwt(cf, cgi, ses, jwt);
  if (cf->anon_ok && cgi->rs && !strcmp(cf->anon_ok, cgi->rs))  /* Prefix match */
    return zxid_sp_anon_finalize(cf, cgi, ses);
  ERR("No Assertion found and not anon_ok in OAUTH Response %d", 0);
  zxlog(cf, 0, 0, 0, 0, 0, 0, 0, "N", "C", "ERR", 0, "sid(%s) No JWT", STRNULLCHK(ses->sid));
  return 0;
}

/*() Decode OAUTH2 state parameter
 * We use state to represent two things:
 *
 * 1. EntityID (eid) of the called IdP. This is necessary as at least Facebook
 *    does not include any issuer information in the responses.
 * 2. SSOREQ or original RelayState
 *
 * The two are represented as query string "e=EID&ar=SSOREQ" and then
 * deflated and safe_base64 encoded. Here we need to unpack this
 * and populate it back to cgi context.
 *
 * See also:: zxid_prepare_statef() */

/* Called by:  zxid_sp_oauth2_dispatch */
static int zxid_decode_state(zxid_conf* cf, zxid_cgi* cgi)
{
  int len;
  char* p;
  if (!cgi->state || !cgi->state[0])
    return 1;
  if (cf->state_opt) {
    if (strlen(cgi->state) != strspn(cgi->state, safe_basis_64)) {
      ERR("EVIL state(%s). This could indicate an attack trying to access filesystem.", cgi->state);
      return 0;
    }
    p = read_all_alloc(cf->ctx, "decode_state", 1, &len, "%s" ZXID_STATE_DIR "%s", cf->cpath, cgi->state);
  } else {
    p = zxid_unbase64_inflate(cf->ctx, -2, cgi->state, &len);
  }
  if (!p)
    return 0;
  D("state decoded(%s) len=%d", p, len);
  zxid_parse_cgi(cf, cgi, p); /* in particular this will populate cgi->eid and cgi->ssoreq */
  return 1;
}

/*() Dispatch, on RP/SP side, OAUTH2 redir or artifact binding requests.
 *
 * The state field contains eid and other information that is normally missing
 * OAUTH2 or at least Facebook Connect.
 *
 * return:: a string (such as Location: header) and let the caller output it.
 *     Sometimes a dummy string is just output to indicate status, e.g.
 *     "O" for SSO OK, "K" for normal OK no further action needed,
 *     "M" show management screen, "I" forward to IdP dispatch, or
 *     "* ERR" for error situations. These special strings
 *     are allocated from static storage and MUST NOT be freed. Other
 *     strings such as "Location: ..." should be freed by caller. */

/* Called by:  zxid_simple_no_ses_cf */
struct zx_str* zxid_sp_oauth2_dispatch(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses)
{
  int ret;
  struct zx_str ss;
  struct timeval ourts;
  struct timeval srcts = {0,501000};

  D_INDENT("sp_oauth2_dp: ");
  ret = zxid_decode_state(cf, cgi); /* Recover cgi->eid (e) and cgi->ssoreq (ar) */  
  if (cgi->code) {  /* OAUTH2 artifact / Authorization Code biding, aka OpenID-Connect1 */
    D("Dereference code(%s)", cgi->code);
    zxid_oauth_call_token_endpoint(cf, cgi, ses);
    /* populates cgi->id_token and/or cgi->access_token as well as ses->issuer_meta */
  }
  
  if (cgi->id_token) {  /* OAUTH2 implicit binding (token inline in redir), aka OpenID-Connect1 */
    ret = zxid_sp_dig_oauth_sso_a7n(cf, cgi, ses, cgi->id_token);
    D("ret=%d ses=%p", ret, ses);
    switch (ret) {
    case ZXID_OK:      D_DEDENT("sp_oauth2_dp: "); return zx_dup_str(cf->ctx, "K");
    case ZXID_SSO_OK:  D_DEDENT("sp_oauth2_dp: "); return zx_dup_str(cf->ctx, "O");
    case ZXID_IDP_REQ: /* (PXY) Middle IdP of IdP Proxy flow */
      D_DEDENT("sp_oauth2_dp: ");
      return zx_dup_str(cf->ctx, zxid_simple_ses_active_cf(cf, cgi, ses, 0, 0x1fff));
    case ZXID_FAIL:
      D("*** FAIL, should send back to IdP select %d", 0);
      D_DEDENT("sp_oauth2_dp: ");
      return zx_dup_str(cf->ctx, "* ERR");
    }
    D_DEDENT("sp_oauth2_dp: ");
    return zx_dup_str(cf->ctx, "M");  /* Management screen, please. */
  }
  
  if (cgi->access_token) {
    /* The data returned by /me will include id which can be used as pseudonym */
    if (!zxid_oauth_call_fb_graph_endpoint(cf, cgi, ses, "me", "&fields=id,name,email,first_name,last_name,gender,locale,picture,website")) {
      D("*** FAIL, should send back to IdP select %d", 0);
      D_DEDENT("sp_oauth2_dp: ");
      return zx_dup_str(cf->ctx, "* ERR");
    }

    GETTIMEOFDAY(&ourts, 0);

    // *** should some signature validation happen here, using issuer (idp) meta?
    cgi->sigval = "N";
    cgi->sigmsg = "Facebook Connect response was not signed.";
    ses->sigres = ZXSIG_NO_SIG;
  
#if 0
    if (cf->log_rely_a7n) {
      DD("Logging rely... %d", 0);
      ss.s = (char*)jwt; ss.len = strlen(jwt);
      logpath = zxlog_path(cf, ses->issuer, &ss, ZXLOG_RELY_DIR, ZXLOG_JWT_KIND, 1);
      if (logpath) {
	ses->sso_a7n_path = ses->tgt_a7n_path = zx_str_to_c(cf->ctx, logpath);
	if (zxlog_dup_check(cf, logpath, "SSO JWT")) {
	  if (cf->dup_a7n_fatal) {
	    err = "C";
	    zxlog_blob(cf, cf->log_rely_a7n, logpath, &ss, "sp_sso_finalize_fbc dup err");
	    goto erro;
	  }
	}
	zxlog_blob(cf, cf->log_rely_a7n, logpath, &ss, "sp_sso_finalize_fbc");
      }
    }
#endif
    DD("Creating session... %d", 0);
    ses->ssores = 0;
    zxid_put_ses(cf, ses);
    zxid_set_ses_cookie(cf, cgi, ses);
    //*** zxid_snarf_eprs_from_ses(cf, ses);  /* Harvest attributes and bootstrap(s) */
    cgi->msg = "SSO completed and session created.";
    cgi->op = '-';  /* Make sure management screen does not try to redispatch. */
    DD("Logging... %d", 0);
    ss.s = ses->nid; ss.len = strlen(ss.s);
    zxlog(cf, &ourts, &srcts, 0, ses->issuer, 0, 0, &ss,
	  cgi->sigval, "K", "NEWSESFBC", ses->sid, "sesix(%s)", STRNULLCHKD(ses->sesix));
    zxlog(cf, &ourts, &srcts, 0, ses->issuer, 0, 0, &ss,
	  cgi->sigval, "K", ses->nidfmt?"FEDSSOFBC":"TMPSSOFBC", STRNULLCHKD(ses->sesix), 0);

    /* See zxid_sp_sso_finalize() for similar code path */

    if (cf->idp_ena) {  /* (PXY) Middle IdP of Proxy IdP flow */
      if (cgi->ssoreq && cgi->ssoreq[0]) {
	D("ProxyIdP got ar(%s)", STRNULLCHK(cgi->ssoreq));
	cgi->saml_resp = 0;  /* Clear Response to prevent re-interpretation. We want Request. */
	zxid_decode_ssoreq(cf, cgi);
	cgi->op = 'V';
	/* case ZXID_IDP_REQ (PXY) process proxy IdP middle IdP role */
	D_DEDENT("sp_oauth2_dp: ");
	return zx_dup_str(cf->ctx, zxid_simple_ses_active_cf(cf, cgi, ses, 0, 0x1fff));
      } else {
	INFO("Middle IdP of Proxy IdP flow did not receive ssoreq from upstream IdP %p", cgi->ssoreq);
      }
    }
    D_DEDENT("sp_oauth2_dp: ");
    return zx_dup_str(cf->ctx, "O");  /* ZXID_SSO_OK */
  }
  
  if (cf->log_level > 0)
    zxlog(cf, 0, 0, 0, 0, 0, 0, ZX_GET_CONTENT(ses->nameid), "N", "C", "SPOADISP", 0, "sid(%s) unknown req or resp", STRNULLCHK(ses->sid));
  ERR("Unknown request or response %d", 0);
  D_DEDENT("sp_oauth2_dp: ");
  return zx_dup_str(cf->ctx, "* ERR");
}

/*() Handle, on IdP side, OAUTH2 / OpenID-Connect1 check_id and token requests.
 * This function is called by AS (IdP) in response to ?o=T
 *
 * return:: a string (such as Location: header) and let the caller output it.
 *     Sometimes a dummy string is just output to indicate status, e.g.
 *     "O" for SSO OK, "K" for normal OK no further action needed,
 *     "M" show management screen, "I" forward to IdP dispatch, or
 *     "* ERR" for error situations. These special strings
 *     are allocated from static storage and MUST NOT be freed. Other
 *     strings such as "Location: ..." should be freed by caller. */

/* Called by:  zxid_simple_no_ses_cf */
char* zxid_idp_oauth2_token_and_check_id(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses, int* res_len, int auto_flags)
{
  char  sha_buf[28];
  char* buf;
  char* azc_data;
  char* id_token;

  /* *** to find the azc we need to know the requester. Presumably this
   * would be available from Authorization header, or perhaps Client-TLS */
  char* sp_eid = "fixed"; // "http://sp.tas3.pt:8081/zxidhlo?=o=B";

  if (cgi->grant_type && !strcmp(cgi->grant_type, "authorization_code") && cgi->code) {
    /* OAUTH2 / OIDC1 Authorization Code / artifact binding */

    sha1_safe_base64(sha_buf, -2, sp_eid);
    sha_buf[27] = 0;
    azc_data = read_all_alloc(cf->ctx, "azc-resolve", 1, 0,
			      "%slog/" ZXLOG_ISSUE_DIR "%s" ZXLOG_AZC_KIND "%s",
			      cf->cpath, sha_buf, cgi->code);
    if (!azc_data) {
      ERR("Could not find azc_data for sp(%s) AZC(%s)", sp_eid, cgi->code);
      goto invalid_req;
    }
    
    if (memcmp(azc_data, "id_token_path=", sizeof("id_token_path=")-1)) {
      ERR("Bad azc_data for sp(%s) AZC(%s)", sp_eid, cgi->code);
    invalid_req:
      return zxid_simple_show_json(cf, "{\"error\":\"invalid_request\"}", res_len, auto_flags,
				   "Cache-Control: no-store" CRLF
				   "Pragma: no-cache" CRLF);
    }
    buf = azc_data + sizeof("id_token_path=")-1;

    id_token = read_all_alloc(cf->ctx, "azc-resolve-id_token", 1, 0, "%s", buf);
    ZX_FREE(cf->ctx, azc_data);
    
    buf = zx_alloc_sprintf(cf->ctx, 0,
			   "{\"access_token\":\"%s\""
			   ",\"token_type\":\"Bearer\""
			   ",\"refresh_token\":\"%s\""
			   ",\"expires_in\":3600"
			   ",\"id_token\":\"%s\"}",
			   cgi->code,
			   cgi->code,
			   id_token);
    if (cf->log_level > 0)
      zxlog(cf, 0, 0, 0, 0, 0, 0, 0, "N", "K", "AZC-TOK", 0, "azc(%s)", cgi->code);

    return zxid_simple_show_json(cf, buf, res_len, auto_flags,
				 "Cache-Control: no-store" CRLF
				 "Pragma: no-cache" CRLF);
  }

  if (cgi->id_token) {  /* OAUTH2 Implicit Binding, aka OpenID-Connect1 */
    /* The id_token is directly the local filename of the corresponsing assertion. */
    
    D("check_id ses=%p", ses);

    // *** TODO
    //return zxid_simple_show_page(cf, ss, ZXID_AUTO_METAC, ZXID_AUTO_METAH, "b", "text/xml", res_len, auto_flags, 0);
  }
  
  if (cf->log_level > 0)
    zxlog(cf, 0, 0, 0, 0, 0, 0, ZX_GET_CONTENT(ses->nameid), "N", "C", "IDPOACI", 0, "sid(%s) unknown req or resp", STRNULLCHK(ses->sid));
  ERR("Unknown request or response %d", 0);
  return "* ERR";
}

/* EOF  --  zxidoauth.c */
