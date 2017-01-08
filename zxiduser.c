/* zxiduser.c  -  Handwritten functions for SP user local account management
 * Copyright (c) 2012 Synergetics NV (sampo@synergetics.be), All Rights Reserved.
 * Copyright (c) 2009-2010,2016 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 * Copyright (c) 2007-2009 Symlabs (symlabs@symlabs.com), All Rights Reserved.
 * Author: Sampo Kellomaki (sampo@iki.fi)
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing.
 * Licensed under Apache License 2.0, see file COPYING.
 * $Id: zxiduser.c,v 1.18 2009-11-29 12:23:06 sampo Exp $
 *
 * 12.10.2007, created --Sampo
 * 7.10.2008,  added documentation --Sampo
 * 14.11.2009, added yubikey (yubico.com) support --Sampo
 * 23.9.2010,  added delegation support --Sampo
 * 1.9.2012,   distilled the authentication backend to an independent module zxpw.c --Sampo
 * 7.12.2016,  updated zxid_put_user() for FBC based proxy IdP operation --Sampo
 * 8.12.2016,  merged user/ to uid/ --Sampo
 */

#include "platform.h"  /* for dirent.h */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef USE_OPENSSL
#include <openssl/des.h>
#endif

#include "errmac.h"
#include "zxid.h"
#include "zxidutil.h"
#include "zxidconf.h"
#include "c/zx-sa-data.h"

/*() Parse a line from .mni and form a NameID, unless there is mniptr */

/* Called by:  zxid_check_fed, zxid_get_user_nameid */
zxid_nid* zxid_parse_mni(zxid_conf* cf, char* buf, char** pmniptr)
{
  zxid_nid* nameid;
  char* p;
  char* idpent = 0;
  char* spqual = 0;
  char* nid = 0;
  char* mniptr = 0;

  p = strchr(buf, '|');
  if (p) {
    *p = 0;
    idpent = ++p;
    p = strchr(p, '|');
    if (p) {
      *p = 0;
      spqual = ++p;
      p = strchr(p, '|');
      if (p) {
	*p = 0;
	nid = ++p;
	p = strchr(p, '|');
	if (p) {
	  *p = 0;
	  mniptr = ++p;
	  p = strchr(p, '|');
	  if (p)
	    *p = 0;
	}
      }
    }
  }
  
  if (mniptr && *mniptr) {
    if (pmniptr)
      *pmniptr = mniptr;
    return 0;
  }
  
  nameid = zx_NEW_sa_NameID(cf->ctx,0);
  if (spqual && *spqual) nameid->SPNameQualifier = zx_dup_attr(cf->ctx, &nameid->gg, zx_SPNameQualifier_ATTR, spqual);
  if (idpent && *idpent) nameid->NameQualifier   = zx_dup_attr(cf->ctx, &nameid->gg, zx_NameQualifier_ATTR, idpent);
  if (*buf)              nameid->Format = zx_dup_attr(cf->ctx, &nameid->gg, zx_Format_ATTR, buf);
  if (nid && *nid)       zx_add_content(cf->ctx, &nameid->gg, zx_dup_str(cf->ctx, nid));
  return nameid;
}

/*() Formulate NameID based directory name for the user. qualif is usually
 * the IdP Entity ID. It is important to separate between same nid
 * issued by different IdPs. The result is "returned" by modifying
 * sha1_name buffer, which MUST be at least 28 characters long. */

/* Called by:  zxid_get_user_nameid, zxid_put_user, zxid_ses_to_pool x2, zxid_user_change_nameid */
void zxid_user_sha1_name(zxid_conf* cf, struct zx_str* qualif, struct zx_str* nid, char* sha1_name)
{
  struct zx_str* ss;
  if (!nid) {
    ERR("*** zxid_user_sha1_name() called without nameid %p", qualif);
    ZERO(sha1_name, 28);
    return;
  }
  if (qualif) {
    ss = zx_strf(cf->ctx, "%.*s|%.*s", qualif->len, qualif->s, nid->len, nid->s);
    sha1_safe_base64(sha1_name, ss->len, ss->s);
    zx_str_free(cf->ctx, ss);
  } else {
    ERR("*** zxid_user_sha1_name(cf,0,nid(%.*s)) called without qualifier", nid->len, nid->s);
    sha1_safe_base64(sha1_name, nid->len, nid->s);
  }
  sha1_name[27] = 0;
}

/*() Formulate uid (directory name used in /var/zxid/uid/UID/ hierarchy).
 * This is used to formulate "user ids" based on pseudonymous identification.
 * This is in contrast to the local login accounts of an IdP whose uids
 * are human rememberable. Returns allocated c string of 28 bytes.
 * Version that accepts zx_strs. */

char* zxid_mk_uid_ss(zxid_conf* cf, struct zx_str* idpent, struct zx_str* idpnid)
{
  char* sha1_name;
  sha1_name = ZX_ALLOC(cf->ctx, 28);
  zxid_user_sha1_name(cf, idpent, idpnid, sha1_name);
  return sha1_name;
}

/*() Formulate uid (directory name used in /var/zxid/uid/UID/ hierarchy).
 * This is used to formulate "user ids" based on pseudonymous identification.
 * This is in contrast to the local login accounts of an IdP whose uids
 * are human rememberable. Returns allocated c string of 28 bytes. */

char* zxid_mk_uid(zxid_conf* cf, const char* idpent, const char* idpnid)
{
  struct zx_str eid;
  struct zx_str nid;
  eid.len = idpent?strlen(idpent):0;
  eid.s = (char*)idpent;
  nid.len = idpnid?strlen(idpnid):0;
  nid.s = (char*)idpnid;
  return zxid_mk_uid_ss(cf, &eid, &nid);
}

/*() Locate user file using a NameID, which may be old or current. If old,
 * chase the MNIptr fields until current is found. Mainly used to support MNI. */

/* Called by:  zxid_sp_mni_redir, zxid_sp_mni_soap, zxid_sp_slo_redir, zxid_sp_slo_soap */
zxid_nid* zxid_get_user_nameid(zxid_conf* cf, zxid_nid* oldnid)
{
  char sha1_name[28];
  char* buf;
  char* mniptr;
  int iter = 1000;
  zxid_nid* nameid;
  
  if (!cf->user_local)
    return oldnid;
  
  zxid_user_sha1_name(cf, &oldnid->NameQualifier->g, ZX_GET_CONTENT(oldnid), sha1_name);
  buf = ZX_ALLOC(cf->ctx, ZXID_MAX_USER);
  mniptr = sha1_name;

  while (--iter && mniptr && *mniptr) {
    read_all(ZXID_MAX_USER, buf, (const char*)__FUNCTION__, 1, "%s" ZXID_UID_DIR "%s/.mni", cf->cpath, mniptr);
    nameid = zxid_parse_mni(cf, buf, &mniptr);
    if (nameid)
      return nameid;
    if (!mniptr || !strcmp(mniptr, sha1_name)) {
      ERR("Infinite loop in MNI changed NameIDs in user database mniptr(%s) iter(%d)", STRNULLCHK(mniptr), iter);
      return 0;
    }
  }
  ERR("Too many mniptr indirections for oldnid(%.*s)", ZX_GET_CONTENT_LEN(oldnid), ZX_GET_CONTENT_S(oldnid));
  return 0;
}

/*() Create new user object in file system.
 * Will create user diretory (but not its subdirectories). The user name
 * is automatically formed by computing a sha1 name over idp entity id
 * and the idp assigned name id. This ensures persistent user name that
 * is unique across users from all IdPs. The end user is not supposed to
 * know this username so it is ok that it is not mnemonic or easy to remember.
 * 
 * See also zxid_ses_to_pool(), zxpasswd.c */

/* Called by:  zxid_user_change_nameid x2 */
static int zxid_put_user(zxid_conf* cf, struct zx_str* nidfmt, struct zx_str* idpent, struct zx_str* spqual, struct zx_str* idpnid, char* mniptr)
{
  char sha1_name[28];
  char dir[ZXID_MAX_BUF];
  char* buf;
  
  if (!cf->user_local)
    return 0;
  
  if (!idpnid) {
    ERR("Missing NameID %p", idpent);
    return 0;
  }
  
  /* See also zxpasswd.c:448-460 for account creation. */
  
  zxid_user_sha1_name(cf, idpent, idpnid, sha1_name);
  name_from_path(dir, sizeof(dir), "%s" ZXID_UID_DIR "%s", cf->cpath, sha1_name);
  if (MKDIR(dir, 0777) && errno != EEXIST) {
    ERR("Creating user directory(%s) failed: %d %s; euid=%d egid=%d", dir, errno, STRERROR(errno), geteuid(), getegid());
    return 0;
  }
  name_from_path(dir, sizeof(dir), "%s" ZXID_UID_DIR "%s/.bs", cf->cpath, sha1_name);
  if (MKDIR(dir, 0777) && errno != EEXIST) {
    ERR("Creating user .bs directory(%s) failed: %d %s; euid=%d egid=%d", dir, errno, STRERROR(errno), geteuid(), getegid());
    return 0;
  }
  name_from_path(dir, sizeof(dir), "%s" ZXID_UID_DIR "%s/.ps", cf->cpath, sha1_name);
  if (MKDIR(dir, 0777) && errno != EEXIST) {
    ERR("Creating user .ps directory(%s) failed: %d %s; euid=%d egid=%d", dir, errno, STRERROR(errno), geteuid(), getegid());
    return 0;
  }
  name_from_path(dir, sizeof(dir), "%s" ZXID_UID_DIR "%s/.ykspent", cf->cpath, sha1_name);
  if (MKDIR(dir, 0777) && errno != EEXIST) {
    ERR("Creating user .ykspent directory(%s) failed: %d %s; euid=%d egid=%d", dir, errno, STRERROR(errno), geteuid(), getegid());
    return 0;
  }
  
  /* *** the .mni file is rewritten every time user performs SSO */
  buf = ZX_ALLOC(cf->ctx, ZXID_MAX_USER);
  write_all_path_fmt("put_user", ZXID_MAX_USER, buf,
		     "%s" ZXID_UID_DIR "%s/.mni", cf->cpath, sha1_name,
		     "%.*s|%.*s|%.*s|%.*s|%s",
		     nidfmt?nidfmt->len:0, nidfmt?nidfmt->s:"",
		     idpent?idpent->len:0, idpent?idpent->s:"",
		     spqual?spqual->len:0, spqual?spqual->s:"",
		     idpnid->len, idpnid->s,
		     STRNULLCHK(mniptr));
  ZX_FREE(cf->ctx, buf);
  D("PUT USER idpnid(%.*s)", idpnid->len, idpnid->s);
  return 1;
}

/*() Create new user object in file system.
 * Will create user diretory (but not its subdirectories). The user name
 * is automatically formed by computing a sha1 name over idp entity id
 * and the idp assigned name id. This ensures persistent user name that
 * is unique across users from all IdPs. The end user is not supposed to
 * know this username so it is ok that it is not mnemonic or easy to remember.
 * 
 * See also zxid_ses_to_pool(), zxpasswd.c */

/* Called by:  zxid_sp_oauth2_dispatch, zxid_sp_sso_finalize, zxid_sp_sso_finalize_jwt, zxid_wsp_validate_env */
int zxid_put_user_ses(zxid_conf* cf, zxid_ses* ses)
{
  struct zx_str idpnid;
  if (!ses) {
    ERR("*** session missing %p", ses);
    return 0;
  }
  if (ses->nameid) {
    return zxid_put_user(cf,
			 &ses->nameid->Format->g,
			 &ses->nameid->NameQualifier->g,
			 &ses->nameid->SPNameQualifier->g,
			 ZX_GET_CONTENT(ses->nameid), 0);
  }
  /* Non SAML session */
  idpnid.len = ses->nid?strlen(ses->nid):0;
  idpnid.s = ses->nid;
  return zxid_put_user(cf,
		       0,
		       ses->issuer,
		       0,
		       &idpnid, 0);
}

int zxid_put_user_attr(zxid_conf* cf, zxid_ses* ses, const char* cn, const char* email, struct zx_str* fbrest)
{
  int len;
  char* buf;
  
  if (!cf->user_local) {
    D("User local storage disabled. See chonfig setting USER_LOCAL. uid(%s)", ses?STRNULLCHKD(ses->uid):"?");
    return 0;
  }
  if (!ses || !ses->uid) {
    ERR("Missing uid %p", ses);
    return 0;
  }
  
  if (email) {
    /* Facebook encodes the at sign in email addresses so we need to fix it in place. */
    buf = strstr(email, "\\u0040");
    if (buf) {
      len = strlen(buf+6);
      *((char*)buf) = '@';
      memmove((char*)buf+1, buf+6, len);
      ((char*)buf)[1+len] = 0; /* nul termination */
    }
  }
  
  /* *** the .at file is rewritten every time user performs SSO */
  buf = ZX_ALLOC(cf->ctx, ZXID_MAX_USER);
  write_all_path_fmt("put_user_attr", ZXID_MAX_USER, buf,
		     "%s" ZXID_UID_DIR "%s/.bs/.at", cf->cpath, ses->uid,
		     "cn: %s\nemail: %s\nfbrest: %.*s",
		     cn, email, fbrest->len, fbrest->s);
  ZX_FREE(cf->ctx, buf);
  D("PUT USER ATTR uid(%s)", ses->uid);
  return 1;
}

/*() Change a NameID to newnym. Old NameID's user entry is rewritten to have mniptr */

/* Called by:  zxid_mni_do */
void zxid_user_change_nameid(zxid_conf* cf, zxid_nid* oldnid, struct zx_str* newnym)
{
  char sha1_name[28];
  zxid_user_sha1_name(cf, &oldnid->NameQualifier->g, newnym, sha1_name);
  zxid_put_user(cf, &oldnid->Format->g, &oldnid->NameQualifier->g, &oldnid->SPNameQualifier->g, newnym, 0);
  zxid_put_user(cf, &oldnid->Format->g, &oldnid->NameQualifier->g, &oldnid->SPNameQualifier->g, ZX_GET_CONTENT(oldnid), sha1_name);
}

static char* login_failed = "Login failed. Check username and password. Make sure you have an active local account. Or just try some other authentication method or another IdP.<p>";

/*() Authenticate by a pairing code.
 * Pairing code is generated by an external program such as idppairing.pl
 * after user has logged in. Pairing code can be introduced in another device,
 * such as mobile phone with limited keyboard, to authenticate the user based
 * on original authentication to the pairing web site.
 */

/* Called by:  zxid_pw_authn */
static int zxid_check_mobile_pairing(zxid_conf* cf, zxid_cgi* cgi)
{
  int len, secs;
  char* uid;
  char buf[1024];
  len = read_all(sizeof(buf), (char*)buf, "pairing", 0, "%s" ZXID_PCODE_DIR "%s", cf->cpath, cgi->pcode);
  if (len <= 0) {
    ERR("Bad pairing pcode(%s)", cgi->pcode);
    return 0;
  }
  secs = atoi(buf);
  if (secs < time(0)) {
    ERR("Bad pairing pcode(%s) buf(%s) expired=%d, now=%d", cgi->pcode, buf, secs, (int)time(0));
    return 0;
  }
  uid = strchr(buf, ' ');
  if (!uid) {
    ERR("Bad pairing pcode(%s) buf(%s) uid not found", cgi->pcode, buf);
    return 0;
  }
  ++uid;
  D("Pairing OK pcode(%s) buf(%s) expired=%d, now=%d uid=%s", cgi->pcode, buf, secs, (int)time(0), uid);
  cgi->uid = zx_dup_cstr(cf->ctx, uid);
  snprintf(buf, sizeof(buf), "%s" ZXID_PCODE_DIR "%s", cf->cpath, cgi->pcode);
  unlink(buf);
  return 2;  /* *** what is good authentication context class for pairing? Password equivalent? */
}

/*() Locally authenticate user. If successful, create a session.
 * Expects to get username and password in cgi->au and cgi->ap
 * respectively. User authetication is done against local database or
 * by default using /var/zxid/uid/uid/.pw file. When filesystem
 * backend is used, for safety reasons the uid (user) component can
 * not have certain characters, such as slash (/) or sequences like "..".
 * See also: zxpasswd.c
 *
 * return:: 0 on failure and sets cgi->err; 1 on success  */

/* Called by:  zxid_idp_as_do, zxid_simple_idp_pw_authn, zxid_simple_idp_show_an */
int zxid_pw_authn(zxid_conf* cf, zxid_cgi* cgi, zxid_ses* ses)
{
  int an_level;
  struct zx_str* ss;
  struct zxid_cstr_list* ac;

  if (cgi->pcode) {
    an_level = zxid_check_mobile_pairing(cf, cgi);
  } else {
    an_level = zx_password_authn(cf->cpath, cgi->uid, cgi->pw, cgi->pin, 0);
  }
  if (!an_level) {
    cgi->err = login_failed;
    return 0;
  }

  /* Successful login. Establish session. */

  ZERO(ses, sizeof(zxid_ses));
  ses->magic = ZXID_SES_MAGIC;
  ses->an_instant = time(0);  /* This will be later used by AuthnStatement constructor. */
  
  for (ac = cf->issue_authnctx; ac && an_level > 0; ac = ac->n, --an_level) ;
  if (!ac)
    ac = cf->issue_authnctx;
  ses->an_ctx = ac->s;
  
  /* Master session. Each pairwise SSO has its own to avoid correlation, see zxid_mk_an_stmt() */
  ss = zxid_mk_id(cf, "MMSES", ZXID_ID_BITS);
  ses->sesix = ss->s;
  ZX_FREE(cf->ctx, ss);
  ses->sid = cgi->sid = ses->sesix;
  ses->uid = cgi->uid;
  zxid_put_ses(cf, ses);
  if (cf->ses_cookie_name && *cf->ses_cookie_name) {
    ses->setcookie = zx_alloc_sprintf(cf->ctx, 0, "%s=%s; path=/%s%s",
				      cf->ses_cookie_name, ses->sid,
				      cgi->mob?"; Max-Age=15481800":"",
				      ONE_OF_2(cf->burl[4], 's', 'S')?"; secure; HttpOnly":"; HttpOnly");
    ses->cookie = zx_alloc_sprintf(cf->ctx, 0, "$Version=1; %s=%s",
				   cf->ses_cookie_name, ses->sid);
  }
  INFO("LOCAL LOGIN SUCCESSFUL. sid(%s) uid(%s)", cgi->sid, cgi->uid);
  zxlog(cf, 0, 0, 0, 0, 0, 0, 0, "N", "K", "INEWSES", ses->sid, "uid(%s)", ses->uid);
  if (cf->loguser)
    zxlogusr(cf, ses->uid, 0,0,0,0,0,0,0, "N", "K", "INEWSES", ses->sid, "uid(%s)", ses->uid);
  return 1;
}

/* EOF  --  zxiduser.c */
