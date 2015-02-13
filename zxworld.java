/* zxworld.java  -  Demonstrate SSO with frontend mod_auth_saml
 * Adapted from  zxidappdemo.java
 * Copyright (c) 2014-2015 Synergetics (sampo@synergetics.be), All Rights Reserved.
 * Author: Sampo Kellomaki (sampo@synergetics.be)
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing.
 * Licensed under Apache License 2.0, see file COPYING.
 * $Id: zxidappdemo.java,v 1.4 2009-11-29 12:23:06 sampo Exp $
 * 20150211, changed to assume mod_auth_saml frontend --Sampo
 *
 * See also: zxid-java.pd, zxidwspdemo.java for server side
 * https://sp.personaldata.eu:8443/e2eTA/app-demo
 *
 * cd syn-e2eta-connector-1.22-Linux-x86_64
 * javac -classpath /usr/share/tomcat6/lib/tomcat6-servlet-2.5-api-6.0.24.jar:. world.java
 * javac -classpath /usr/share/tomcat6/lib/servlet-api.jar:. zxworld.java
 */

import zxidjava.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Enumeration;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class zxworld extends HttpServlet {

    static zxidjava.zxid_conf cf;
    static String ptm;

    public static String ReadAll(String path) throws IOException {
        FileReader in = new FileReader(path);
        StringBuilder sb = new StringBuilder();
        char[] buf = new char[4096];
        int got = 0;
        do {
            sb.append(buf, 0, got);
            got = in.read(buf);
        } while (got >= 0);
	in.close();
        return sb.toString();
    }

    static {
	System.loadLibrary("zxidjni");
	// CONFIG: You must have created /var/e2eta directory hierarchy. See `make dir'
	// CONFIG: You must create edit the URL to match your domain name and port
	// CONFIG: Usually you create and edit /var/e2eta/e2eta.conf and override the URL there
	//String conf = getServletConfig().getInitParameter("E2ETAConf"); 
	//String conf = getServletContext().getInitParameter("E2ETAConf"); 
	//cf = e2etajni.new_conf_to_cf(conf);
	//e2etajni.set_opt(cf, 1, 1);
	try {
	    ptm = ReadAll("ptm-include.html");  // in /var/lib/tomcat6/, restart tomcat for update
	} catch(IOException e) {
	    System.err.print("File not found(ptm-include.html)\n");
	    System.err.print("Working Directory(" + System.getProperty("user.dir") + ")\n");
	}
    }
    
    public void doGet(HttpServletRequest req, HttpServletResponse res)
	throws ServletException, IOException
    {
	String fullURL = req.getRequestURI();
	String qs = req.getQueryString();
	if (qs != null)
	    fullURL += "?" + req.getQueryString();
	else
	    qs = "";
	System.err.print("========= Start World GET("+fullURL+")...\n");
	HttpSession ses = req.getSession(false);  // Important: do not allow automatic session.
	if (ses == null) {                        
	    //res.sendRedirect("sso?o=E&fr=" + fullURL); // redirect to sso servlet.
	    //return;
	    ses = req.getSession(true);  // Create session
	    String hdr = req.getHeader("SAML_affid"); if (hdr != null) ses.setAttribute("affid", hdr);
	    hdr = req.getHeader("SAML_sesid"); if (hdr != null)	ses.setAttribute("sesid", hdr);
	    hdr = req.getHeader("SAML_cn");    if (hdr != null)	ses.setAttribute("cn", hdr);
	    hdr = req.getHeader("SAML_lang");  if (hdr != null)	ses.setAttribute("lang", hdr);
	    hdr = req.getHeader("SAML_role");  if (hdr != null)	ses.setAttribute("role", hdr);
	    hdr = req.getHeader("SAML_o");     if (hdr != null)	ses.setAttribute("o", hdr);
	    hdr = req.getHeader("SAML_ou");    if (hdr != null)	ses.setAttribute("ou", hdr);
	}
	
	if (cf == null) {
	    System.err.print("Running conf\n");
	    String conf = getServletConfig().getInitParameter("ZXIDConf"); 
	    cf = zxidjni.new_conf_to_cf(conf);
	    zxidjni.set_opt(cf, 1, 1);  // Debug on
	    zxidjni.set_opt(cf, 7, 3);  // Cause glibc malloc/free to dump core on error
	}
	String sid = ses.getAttribute("sesid").toString();
	ServletOutputStream out = res.getOutputStream();
	
	res.setContentType("text/html");
	out.print("<title>World</title>\n");
	out.print("<link type=\"text/css\" rel=stylesheet href=\"/idpsel.css\">\n<body>");

	if (ptm != null) {
	    out.print("<table align=right><tr><td>");
	    out.print("<a href=\"http://synergetics.be/\"><img src=\"synlogo_s.jpg\" height=67 border=0></a><br>");
	    out.print(ptm);
	    out.print("<br><iframe id=idpnav class=nav width=300 height=300 src=\"https://idp.i-dent.eu/nav.html\"><a href=\"https://idp.i-dent.eu/nav.html\">Navigation iFrame from IdP</a></iframe><br>");
	    out.print("</td></tr></table>");
	}
	
	out.print("<h1>World</h1>\n");
	out.print("<b>sesid</b>: "+sid+"<br>\n");
	out.print("<b>affid</b>: "+ses.getAttribute("affid")+" <i>(aka pairwise persistent pseudonym)</i><br>\n");
	out.print("<b>cn</b>: "+ses.getAttribute("cn")+"<br>\n");
	out.print("<b>lang</b>: "+ses.getAttribute("lang")+"<br>\n");
	out.print("<b>role</b>: "+ses.getAttribute("role")+"<br>\n");
	out.print("<b>o</b>: "+ses.getAttribute("o")+"<br>\n");
	out.print("<b>ou</b>: "+ses.getAttribute("ou")+"<br>\n");

	out.print("<p>Done.\n");
	System.err.print("^^^^^^^^^ DONE world GET("+fullURL+").\n");
    }
}

/* EOF */
