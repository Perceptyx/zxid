/* match.c - simple shell-style filename matcher
**
** Only does ? * and **, and multiple patterns separated by |.  Returns 1 or 0.
**
** Copyright © 1995,2000 by Jef Poskanzer <jef@acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/
/* 20131121 slightly modified by Sampo Kellomaki (sampo@zxid.org) for zxid project.
 * 20170817 generalized to strings without nul termination.
 * See also fnmatch(1). */

#include <zx/errmac.h>
#include <string.h>

/*() Helper function for filename pattern matcher */
/* Called by:  zx_match x2, zx_match_one */
static int zx_match_one(int patlen, const char* pat, int len, const char* str)
{
  const char* start = str;
  const char* p;
  int i, pl;
  
  for ( p = pat; p - pat < patlen; ++p, ++str ) {
    if ( *p == '?' && ((len==-2)?(*str != '\0'):(str < start+len)) )
      continue;
    if ( *p == '*' ) {
      ++p;
      if ( *p == '*' ) {
	/* Double-wildcard matches anything. */
	++p;
	if (len == -2)
	  i = strlen( str );
	else
	  i = start+len - str;
      } else
	/* Single-wildcard matches anything but slash. */
	if (len == -2)
	  i = strcspn( str, "/" );
	else {
	  for (i = 0; i < (start+len - str); ++i)
	    if (str[i] == '/')
	      break;
	}
      pl = patlen - ( p - pat );
      for ( ; i >= 0; --i )  /* try the rest of the pat to tails of str */
	if ( zx_match_one( pl, p, len, &(str[i]) ) )
	  return 1;
      return 0;
    }
    if ( *p != *str )
      return 0;
  }
  /* Pattern ended. If string ended as well, this is a match. */
  if (len == -2) {
    if ( *str == '\0' )
      return 1;
  } else {
    if ( start+len <= str )
      return 1;
  }
  return 0;  /* not match, some string left */
}

/*() Check if simple path glob wild card pattern matches.
 * 
 * pat:: Pattern, nul terminated string.
 * len:: Length of the string. Special value: -2 use nul termination
 *     to determine string length
 * str:: String that patterni is matched aganist. If len is positive,
 *     it expresses the string length and no nul termination is needed.
 *     If len == -2, string must be nul terminated
 * return:: 0 on failure and 1 on match.
 *
 * Only does ?, * and **, and multiple patterns separated by |.
 * Exact match, suffix match (*.wsp) and prefix match
 * (/foo/bar*) are supported. The double asterisk (**) matches
 * also slash (/). */

/* Called by:  chkuid x3, send_error_and_exit, zxid_mini_httpd_filter x3, zxid_mini_httpd_sso, zxid_sp_dig_sso_a7n, zxid_unix_grp_az_check x2 */
int zx_match(const char* pat, int len, const char* str)
{
  const char* or_clause;
  for (;;) {
    or_clause = strchr( pat, '|' );
    if (!or_clause)
      return zx_match_one( strlen(pat), pat, len, str );
    if ( zx_match_one( or_clause - pat, pat, len, str ) )
      return 1;
    pat = or_clause + 1;
  }
}

/* EOF */
