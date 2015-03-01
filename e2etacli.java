/* e2etacli.java  -  Demonstrate Web Service call from command line
 * Copyright (c) 2014-2015 Synergetics (sampo@synergetics.be), All Rights Reserved.
 * Author: Sampo Kellomaki (sampo@synergetics.be)
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing.
 * Licensed under Apache License 2.0, see file COPYING.
 * $Id: zxidappdemo.java,v 1.4 2009-11-29 12:23:06 sampo Exp $
 * 20150223, created --Sampo
 *
 * See also: zxid-java.pd, zxidwspdemo.java for server side
 * https://sp.personaldata.eu:8443/e2eTA/app-demo
 *
 * sudo apt-get install openjdk-6-jdk
 * cd syn-e2eta-connector-1.32-Linux-x86_64
 * javac -classpath . e2etacli.java
 * javac -classpath . e2etacli.java
 * javac -classpath ../syn-e2eta-connector-1.32-Linux-x86_64/e2eta.jar e2etacli.java
 *
 * Usage: java e2etacli.class
 */

import e2eta.*;
import java.io.*;
import static java.lang.System.err;
import static java.lang.System.out;

public class e2etacli {
    static e2eta_conf cf;
    static { System.loadLibrary("e2etajni"); }
    static String sid = null;
    static String idpurl = "https://ssoid.com/idp";
    static String username = "benny";
    static String password = "test123";
    
    public static void main(String argv[]) throws java.io.IOException
    {
	err.print("Start...\n");
	err.print(e2etajni.version_str());
	err.print("\nTrying to conf...\n");
	cf = e2etajni.new_conf_to_cf("CPATH=/var/e2eta/");
	err.print(e2etajni.show_conf(cf));

	e2eta_ses ses;
	
	if (sid != null) {
	    // Existing session
	    ses = e2etajni.fetch_ses(cf, sid);
	    if (ses == null) {
		err.print("No session ses_id: "+sid);
		return;
	    }
	} else {
	    // Obtain session from authentication service
	    // WARNING: The authentication service method of login should not be used
	    //    from a servlet. Use mod_auth_saml or SSO servlet approach instead.
	    // WARNING: The authentication service method only supports username+password
	    //    authentication. It is not suitable for strong authentication.
	    // Basically you should use this method only in automated test suites.
	    e2eta_entity idp_meta = e2etajni.get_ent(cf, idpurl);
	    if (idp_meta == null) {
		err.print("IdP metadata not found and could not be fetched. idp: "+idpurl);
		return;
	    }
	    ses = e2etajni.as_call(cf, idp_meta, username, password);
	    if (ses == null) {
		err.print("Login using Authentication Service failed idp: "+idpurl);
		return;
	    }
	}
	
	err.print("Output from PDS web service call rsrc=pds/flow/cardio/history:\n");
	
	String ret;
	ret = e2etajni.call(cf, ses, "urn:syn:pds:2015", null, null, "appid=CardiacFlow",
			    "{\"op\":\"read\",\"rsrc\":\"pds/flow/cardio/history\"}");
	ret = e2etajni.extract_body(cf, ret);
	out.print(ret);
	err.print("\nDone.\n");
    }
}

/* EOF */
