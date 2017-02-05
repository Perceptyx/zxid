/* zxidoidc.c  -  Handwritten nitty-gritty functions for OpenID Connect 1.0 (openid-connect oidc)
 * Copyright (c) 2011-2014,2017 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
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
 *
 * 11.12.2011, created --Sampo
 * 9.10.2014, adapted from zxidoauth.c --Sampo
 * 20170119   added Mobile Connect Discovery --Sampo
 */

#include "platform.h"
#include "errmac.h"
#include "zx.h"
#include "zxid.h"
#include "zxidpriv.h"
#include "zxidutil.h"
#include "zxidconf.h"
#include "saml2.h"   /* for bindings like OAUTH2_REDIR */
#include "c/zx-data.h"

/*() Interpret ZXID standard form fields to construct a Mobile Connect 1.0
 * Discovery request, which is a redirection URL. */

/* Called by:  zxid_start_sso_url */
struct zx_str* zxid_mk_mobconn_disco_req(zxid_conf* cf, zxid_cgi* cgi, zxid_entity* idp_meta, struct zx_str* loc)
{
  struct zx_str* ss;
  char* redir_url_enc;
  char* state_b64;
  //char* basic_b64;
  char* client_id;
  char* client_secret;
  char* colon;

  if (!loc || !loc->len || !loc->s || !loc->s[0]) {
    ERR("Mobile Connect Discovery Redirection location URL missing. %p", loc);
    return 0;
  }

  D("redir loc(%.*s) %p %p", loc->len, loc->s, loc, loc->s);
  redir_url_enc = zx_url_encode(cf->ctx, strlen(cf->burl), cf->burl, 0);
  
  /* The chosen IdP's Entity ID is in cgi->eid and we need to encode this to state
   * so we can continue the flow once user is sent back from the discovery. */

  if (cf->idp_ena) {  /* (PXY) Middle IdP of Proxy IdP scenario */
    if (cgi->rs) {
      D("MobConn ignoring RelayState(%s) supplied in middle IdP of Proxy IdP flow.", cgi->rs);
    }
    /* Carry the original authn req in state */
    state_b64 = zxid_prepare_statef(cf, "e=%s&ar=%s", cgi->eid, cgi->ssoreq);
  } else {
    state_b64 = zxid_prepare_statef(cf, "e=%s&rs=%s", cgi->eid, STRNULLCHK(cgi->rs));
  }
  
  if (idp_meta->ed && idp_meta->ed->appId && idp_meta->ed->appId->g.len && idp_meta->ed->appId->g.s && idp_meta->ed->appId->g.s[0]) {
    /* Per IdP app_id (aka client_id) instead of SP chosen eid */
    D("appId(%.*s)", idp_meta->ed->appId->g.len, idp_meta->ed->appId->g.s);
    client_id = zx_str_to_c(cf->ctx, &idp_meta->ed->appId->g);
  } else {
    client_id = zxid_my_ent_id_cstr(cf);
  }
  client_secret = zxid_get_app_secret(cf, idp_meta->sha1_name, "mobconn disco req");
#if 1
  /* Apparently the only way to pass Basic auth credentials in redirect
   * is to encode them to domain name part of URL like
   *   https://user:pass@domain/rest/of/url
   * Thus this convoluted code to insert them in the middle.
   * However, due to phising danger, this method is increasingly
   * being disabled on browsers
   *   https://support.microsoft.com/en-us/help/834489/internet-explorer-does-not-support-user-names-and-passwords-in-web-site-addresses-http-or-https-urls
   *   https://bugs.chromium.org/p/chromium/issues/detail?id=82250#c7
   */
  
  colon = zx_memmem(loc->s, loc->len, "://", 3);  /* Find colon in https:// */
  if (!colon) {
    ERR("Malformed URL(%.*s)", loc->len, loc->s);
    return 0;
  }
  ss = zx_strf(cf->ctx,
	       "%.*s://%s:%s@%.*s"
	       "%cRedirect_URL=%s%%3fo=O"
	       "%s%s"           /* &state= */
	       "%s%.3s"         /* &Selected-MCC= */
	       "%s%.2s",        /* &Selected-MNC= */
	       colon - loc->s, loc->s,
	       client_id, client_secret,
	       loc->len-(colon + 3 - loc->s), colon+3,
	       (memchr(loc->s, '?', loc->len)?'&':'?'),
	       redir_url_enc,
	       state_b64?"&state=":"", STRNULLCHK(state_b64),
	       cgi->mcc_mnc?"&Selected-MCC=":"", STRNULLCHK(cgi->mcc_mnc),
	       cgi->mcc_mnc?"&Selected-MNC=":"", cgi->mcc_mnc?cgi->mcc_mnc+4:"");
  
  D("MOBCONN DISCO REQ(%.*s)", ss->len, ss->s);
  ZX_FREE(cf->ctx, client_secret);
  ZX_FREE(cf->ctx, client_id);
#else
  basic_b64 = zx_mk_basic_auth_b64(cf->ctx, client_id, client_secret);
  ZX_FREE(cf->ctx, client_secret);
  ZX_FREE(cf->ctx, client_id);
  
  ss = zx_strf(cf->ctx,
	       "%.*s%cRedirect_URL=%s%%3fo=O"
	       "%s%s"           /* &state= */
	       "%s%.3s"         /* &Selected-MCC= */
	       "%s%.2s"         /* &Selected-MNC= */
	       CRLF "Authorization: Basic %s",
	       loc->len, loc->s, (memchr(loc->s, '?', loc->len)?'&':'?'),
	       redir_url_enc,
	       state_b64?"&state=":"", STRNULLCHK(state_b64),
	       cgi->mcc_mnc?"&Selected-MCC=":"", STRNULLCHK(cgi->mcc_mnc),
	       cgi->mcc_mnc?"&Selected-MNC=":"", cgi->mcc_mnc?cgi->mcc_mnc+4:"",
	       basic_b64);
  
  D("MOBCONN DISCO REQ(%.*s)", ss->len, ss->s);
  ZX_FREE(cf->ctx, basic_b64);
#endif
  if (errmac_debug & ERRMAC_INOUT) INFO("%.*s", ss->len, ss->s);
  if (state_b64) ZX_FREE(cf->ctx, state_b64);
  //ZX_FREE(cf->ctx, eid_url_enc);
  ZX_FREE(cf->ctx, redir_url_enc);
  return ss;
}

/*() As of 20170202 Mobile Connect's discovery service
 * uses broken JavaScript escaping syntax. Fix the
 * brandamage to be compatible as it is too difficult
 * to get them to see the light. */

static void zxid_fix_inplace_mobile_connect_broken_escapes(char* href)
{
  char* p;
  char* q;
  for (p = q = href; *p; ++p) {
    if (*p != '\\')
      *q++ = *p;
  }
  *q = 0;
}

/*() Extract endpoints from Mobile Connect Discovery
 * (without really parsing the JSON). Populates info to idp_meta
 * Sample input:

 {"ttl":1484838543087,"response":{"serving_operator":"Example Operator B","country":"Spain","currency":"EUR","apis":{"operatorid":{"link":[{"href":"http://operator-b.sandbox2.mobileconnect.io/oidc/authorize","rel":"authorization"},{"href":"http://operator-b.sandbox2.mobileconnect.io/oidc/accesstoken","rel":"token"},{"href":"http://operator-b.sandbox2.mobileconnect.io/oidc/userinfo","rel":"userinfo"},{"href":"openid profile email","rel":"scope"}]}},"client_id":"a405e6fa-d1bf-4857-a3fa-094dba842211","client_secret":"885b5efe-71f7-4f9b-8dd2-f6338e393bfa"}}

 {"ttl":1484838543087,
  "response":{
   "serving_operator":"Example Operator B",
   "country":"Spain",
   "currency":"EUR",
   "apis":{
     "operatorid":{
       "link":[
         {"href":"http://operator-b.sandbox2.mobileconnect.io/oidc/authorize",
          "rel":"authorization"},
         {"href":"http://operator-b.sandbox2.mobileconnect.io/oidc/accesstoken",
          "rel":"token"},
         {"href":"http://operator-b.sandbox2.mobileconnect.io/oidc/userinfo",
          "rel":"userinfo"},{"href":"openid profile email","rel":"scope"}
       ]
     }
   },
   "client_id":"a405e7fa-d1bf-4857-a3fa-094dba842211",
   "client_secret":"885b5efe-71f7-4f9b-8dd2-f6338e393bfa"
  }
 }
 * N.B. The buffer is modified during parsing (some curlies overwritten by nuls).
 */

static void zxid_mobconn_parse_discovery(zxid_conf* cf, zxid_entity* idp_meta, char* buf)
{
  char* href;
  char* rel;
  char* p;
  char* q;

  idp_meta->client_id = zx_json_extract_dup(cf->ctx, buf, "\"client_id\"");
  idp_meta->client_secret = zx_json_extract_dup(cf->ctx, buf, "\"client_secret\"");
  p = strstr(buf, "\"link\":");
  if (!p) {
 bad:
    ERR("Malformed discovery response json(%s) p(%s)", buf, STRNULLCHK(p));
    return;
  }
  p += sizeof("\"link\":")-1;
  q = strchr(p, ']');
  if (!q) goto bad;
  *q = 0; /* nul */
  while (p) {
    q = strchr(p, '}');
    if (!q) goto bad;
    *q = 0; /* nul */
    rel = zx_json_extract_dup(cf->ctx, p, "\"rel\"");
    href = zx_json_extract_dup(cf->ctx, p, "\"href\"");
    if (rel && href) {
      zxid_fix_inplace_mobile_connect_broken_escapes(href);
      if (!strcmp(rel, "authorization")) idp_meta->az_url = href;
      if (!strcmp(rel, "token"))         idp_meta->token_url = href;
      if (!strcmp(rel, "userinfo"))      idp_meta->userinfo_url = href;
    }
    p = strchr(q+1, ',');
    if (!p)
      break;
    p = strchr(q+1, '{');
  }
}

/*() Interpret ZXID standard form fields to construct a Mobile Connect 1.0
 * Discovery call (batch mode) and follow up with Mobile Connect (OIDC)
 * Authorize call to authenticate user.
 * Returns URL suitable for redirection. Caller must free. */

/* Called by:  zxid_start_sso_url */
struct zx_str* zxid_mk_mobconn_disco_call(zxid_conf* cf, zxid_cgi* cgi, zxid_entity* idp_meta, struct zx_str* loc)
{
  struct zx_str* ss;
  struct zx_str azloc;
  char* client_id;
  char* client_secret;
  char* redir_url_enc;
  char* state_b64 = 0;
  char* hdr;
  char* url;
 
  if (!loc || !loc->len || !loc->s || !loc->s[0]) {
    ERR("Mobile Connect Discovery Redirection location URL missing. %p", loc);
    return 0;
  }

  D("redir loc(%.*s) %p %p", loc->len, loc->s, loc, loc->s);
  redir_url_enc = zx_url_encode(cf->ctx, strlen(cf->burl), cf->burl, 0);

#if 0  
  /* Since we are making a synchronous batch mode call on backchannel,
   * no state is required. Eventually state will be used in the
   * followup redirect to authorization service, see zxid_mk_oauth_az_req()
   */
  /* The chosen IdP's Entity ID is in cgi->eid and we need to encode this to state
   * so we can continue the flow once user is sent back from the discovery. */

  if (cf->idp_ena) {  /* (PXY) Middle IdP of Proxy IdP scenario */
    if (cgi->rs) {
      D("MobConn ignoring RelayState(%s) supplied in middle IdP of Proxy IdP flow.", cgi->rs);
    }
    /* Carry the original authn req in state */
    state_b64 = zxid_prepare_statef(cf, "e=%s&ar=%s", cgi->eid, cgi->ssoreq);
  } else {
    state_b64 = zxid_prepare_statef(cf, "e=%s&rs=%s", cgi->eid, STRNULLCHK(cgi->rs));
  }
#endif

  if (idp_meta->ed && idp_meta->ed->appId && idp_meta->ed->appId->g.len && idp_meta->ed->appId->g.s && idp_meta->ed->appId->g.s[0]) {
    /* Per IdP app_id (aka client_id) instead of SP chosen eid */
    D("appId(%.*s)", idp_meta->ed->appId->g.len, idp_meta->ed->appId->g.s);
    client_id = zx_str_to_c(cf->ctx, &idp_meta->ed->appId->g);
  } else {
    client_id = zxid_my_ent_id_cstr(cf);
  }
  client_secret = zxid_get_app_secret(cf, idp_meta->sha1_name, "mobconn disco call");
  hdr = zx_mk_basic_auth_b64(cf->ctx, client_id, client_secret);
  D("MOBCONN DISCO HDR(%s)", hdr);
  ZX_FREE(cf->ctx, client_secret);
  ZX_FREE(cf->ctx, client_id);
  
  url = zx_alloc_sprintf(cf->ctx, 0,
			 "%.*s%cRedirect_URL=%s%%3fo=O"
			 "%s%s"           /* &state= */
			 "%s%.3s"         /* &Selected-MCC= */
			 "%s%.2s",        /* &Selected-MNC= */
			 loc->len, loc->s, (memchr(loc->s, '?', loc->len)?'&':'?'),
			 redir_url_enc,
			 state_b64?"&state=":"", STRNULLCHK(state_b64),
			 cgi->mcc_mnc?"&Selected-MCC=":"", STRNULLCHK(cgi->mcc_mnc),
			 cgi->mcc_mnc?"&Selected-MNC=":"", cgi->mcc_mnc?cgi->mcc_mnc+4:"");
  if (state_b64) ZX_FREE(cf->ctx, state_b64);
  ZX_FREE(cf->ctx, redir_url_enc);
  if (errmac_debug & ERRMAC_INOUT) INFO("%s", url);
  
  ss = zxid_http_cli(cf, -1, url, 0, 0, 0, hdr, 0);
  
  ZX_FREE(cf->ctx, hdr);
  ZX_FREE(cf->ctx, url);
  if (!ss)
    return 0;
  if (errmac_debug & ERRMAC_INOUT) INFO("%.*s", ss->len, ss->s);

  zxid_mobconn_parse_discovery(cf, idp_meta, ss->s);
  zx_str_free(cf->ctx, ss);

  if (!idp_meta->az_url) {
    ERR("Could not determine authorization URL from the Mobile Connect Discovery %d",0);
    return 0;
  }
  azloc.s = idp_meta->az_url;
  azloc.len = strlen(azloc.s);
  ss = zxid_mk_oauth_az_req(cf, cgi, idp_meta, &azloc, 0x02);
  return ss;
}

extern char* _uma_authn;  /* See zxidoauth.c */

/*() Call OIDC Authentication (Authorization?) service in batch mode
 * Extracts access_token and id_token from the response.
 */

/* Called by:  zxumacall_main */
int zxid_oidc_as_call(zxid_conf* cf, zxid_ses* ses, zxid_entity* idp_meta, const char* _uma_authn)
{
  struct zx_md_SingleSignOnService_s* sso_svc;
  struct zx_str* ss;
  struct zx_str* req;
  struct zx_str* res; 
  struct zxid_cgi* cgi;
  struct zxid_cgi scgi;
  ZERO(&scgi, sizeof(scgi));
  cgi = &scgi;

  if (!idp_meta->ed->IDPSSODescriptor) {
    ERR("Entity(%s) does not have IdP SSO Descriptor (OAUTH2) (metadata problem)", cgi->eid);
    zxlog(cf, 0, 0, 0, 0, 0, 0, 0, "N", "B", "ERR", cgi->eid, "No IDPSSODescriptor (OAUTH2)");
    cgi->err = "Bad IdP metadata (OAUTH). Try different IdP.";
    D_DEDENT("start_sso: ");
    return 0;
  }
  for (sso_svc = idp_meta->ed->IDPSSODescriptor->SingleSignOnService;
       sso_svc;
       sso_svc = (struct zx_md_SingleSignOnService_s*)sso_svc->gg.g.n) {
    if (sso_svc->gg.g.tok != zx_md_SingleSignOnService_ELEM)
      continue;
    if (sso_svc->Binding && !memcmp(OAUTH2_REDIR,sso_svc->Binding->g.s,sso_svc->Binding->g.len))
      break;
  }
  if (!sso_svc) {
    ERR("IdP Entity(%s) does not have any IdP SSO Service with " OAUTH2_REDIR " binding (metadata problem)", cgi->eid);
    zxlog(cf, 0, 0, 0, 0, 0, 0, 0, "N", "B", "ERR", cgi->eid, "No OAUTH2 redir binding");
    cgi->err = "Bad IdP metadata. Try different IdP.";
    D_DEDENT("start_sso: ");
    return 0;
  }
  ss = &sso_svc->Location->g;
  if (_uma_authn)
    ss = zx_strf(cf->ctx, "%.*s%c_uma_authn=%s", ss->len, ss->s, (memchr(ss->s, '?', ss->len)?'&':'?'), _uma_authn);
  cgi->pr_ix = ZXID_OIDC1_ID_TOK_TOK; //"id_token token";
  D("loc(%.*s)", ss->len, ss->s);
  req = zxid_mk_oauth_az_req(cf, cgi, idp_meta, ss, 0x00);
  D("req(%.*s)", req->len, req->s);
  res = zxid_http_cli(cf, req->len, req->s, 0,0, 0, 0, 0x03);  /* do not follow redir */
  zx_str_free(cf->ctx, req);
  D("res(%.*s)", res->len, res->s);
  // *** extract token and AAT from the response
  ses->access_token = zx_qs_extract_dup(cf->ctx, res->s, "access_token=");
  ses->id_token = zx_qs_extract_dup(cf->ctx, res->s, "id_token=");
  ses->token_type = zx_qs_extract_dup(cf->ctx, res->s, "token_type=");
  //ses->expires = zx_qs_extract_dup(cf->ctx, res->s, "access_token=");
  return 1;
}

#if 0
/*() Extract an assertion from OAUTH Az response, and perform SSO */

/* Called by:  zxid_sp_oauth2_dispatch x3 */
static int zxid_sp_dig_oauth_sso_a7n(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses)
{
  //if (!zxid_chk_sig(cf, cgi, ses, &resp->gg, resp->Signature, resp->Issuer, 0, "Response")) return 0;
  
  //p = zxid_http_get(cf, url, &lim);

  ERR("*** process JWT %d", 0);

  //a7n = zxid_dec_a7n(cf, resp->Assertion, resp->EncryptedAssertion);
  //if (a7n) {
  //  zx_see_elem_ns(cf->ctx, &pop_seen, &resp->gg);
  //  return zxid_sp_sso_finalize(cf, cgi, ses, a7n, pop_seen);
  //}
  if (cf->anon_ok && cgi->rs && !strcmp(cf->anon_ok, cgi->rs))  /* Prefix match */
    return zxid_sp_anon_finalize(cf, cgi, ses);
  ERR("No Assertion found and not anon_ok in OAUTH Response %d", 0);
  zxlog(cf, 0, 0, 0, 0, 0, 0, ZX_GET_CONTENT(ses->nameid), "N", "C", "ERR", 0, "sid(%s) No assertion", ses->sid?ses->sid:"");
  return 0;
}

/*() Handle, on IdP side, OAUTH2 / OpenID-Connect1 check_id requests.
 *
 * return:: a string (such as Location: header) and let the caller output it.
 *     Sometimes a dummy string is just output to indicate status, e.g.
 *     "O" for SSO OK, "K" for normal OK no further action needed,
 *     "M" show management screen, "I" forward to IdP dispatch, or
 *     "* ERR" for error situations. These special strings
 *     are allocated from static storage and MUST NOT be freed. Other
 *     strings such as "Location: ..." should be freed by caller. */

/* Called by: */
char* zxid_idp_oauth2_check_id(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses, int auto_flags)
{
  int ret = 0;

  if (cgi->id_token) {  /* OAUTH2 artifact / redir biding, aka OpenID-Connect1 */
    /* The id_token is directly the local filename of the corresponsing assertion. */
    
    D("ret=%d ses=%p", ret, ses);

    //return zxid_simple_show_page(cf, ss, ZXID_AUTO_METAC, ZXID_AUTO_METAH, "b", "text/xml", res_len, auto_flags, 0);
  }
  
  if (cf->log_level > 0)
    zxlog(cf, 0, 0, 0, 0, 0, 0, ZX_GET_CONTENT(ses->nameid), "N", "C", "IDPOACI", 0, "sid(%s) unknown req or resp", STRNULLCHK(ses->sid));
  ERR("Unknown request or response %d", 0);
  return 0;
}
#endif

/* EOF  --  zxidoidc.c */
