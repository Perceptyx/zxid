// zxidprovisflow.cs  - Demonstration of Single Sign-On and Provisioning flows
//
// Copyright (c) 2016 Synergetics (info@synergetics.be), All Rights Reserved.
// Author: Sampo Kellomaki (sampo@synergetics.be)
// This is confidential unpublished proprietary source code of the author.
// NO WARRANTY, not even implied warranties. Contains trade secrets.
// Distribution prohibited unless authorized in writing.
//
// mcs zxidprovisflow.cs -r:zxidcs
// #cd csharp; ln -s zxidcli.so libzxidcli.so
// #MONO_PATH=csharp LD_LIBRARY_PATH=csharp   ./zxidprovisflow.exe
// LD_LIBRARY_PATH=. ./zxidprovisflow.exe
// LD_LIBRARY_PATH=. ./zxid_httpd -c '**.exe' -p 8443 -S /var/zxid/pem/enc-nopw-cert.pem  &
// https://yourhost.example.com:8443/sso/zxidprovisflow.exe
// LD_LIBRARY_PATH=. SCRIPT_NAME='/sso/zxidprovisflow.exe' QUERY_STRING='o=E' mono --debug ./zxidprovisflow.exe
//
// This script is meant to be called as a CGI script from a web server.

using System;
using System.IO;
using System.Web;
//using System.Web.Helpers;    // Json.Decode()
//using System.Web.Script.Serialization;
using Newtonsoft.Json;    // JSON.NET, Json80r3.zip
// sudo apt-get install libnewtonsoft-json-cil-dev libnewtonsoft-json-cil monodoc-newtonsoft-json-manual
// gacutil -i ...

namespace ZXIDProvis {
  class ZXIDProvisCGI {

    static string read_post() {
      int len = int.Parse(Environment.GetEnvironmentVariable("CONTENT_LENGTH"));
      //Console.Error.WriteLine("Reading POST len="+len);
      Stream s = Console.OpenStandardInput();
      BinaryReader br = new BinaryReader(s);
      byte[] Data = new byte[len];
      br.Read(Data,0,len);
      // do not close the reader! (would close also the output side of the socket?!?)
      string post = System.Text.Encoding.Default.GetString(Data,0,len);
      Console.Error.WriteLine("Got POST("+post+") len="+len);
      return post;
    }

    static void Main(string[] argv) {
      string meth = Environment.GetEnvironmentVariable("REQUEST_METHOD");
      string uri = Environment.GetEnvironmentVariable("SCRIPT_NAME");
      string qs = Environment.GetEnvironmentVariable("QUERY_STRING");
      Console.Error.WriteLine("ZXIDProvisCGI qs("+qs+") uri("+uri+") meth("+meth+")");
      if (qs == null)
	qs = "";

      Console.Error.WriteLine(zxidcs.version());
      Console.Error.WriteLine(zxidcs.version_str());
      zxid_conf cf = zxidcs.new_conf_to_cf("CPATH=/var/zxid/&BURL=https://yourhost.example.com:8443/sso/zxidprovisflow.exe&DEBUG=0x03");
      //Console.Error.WriteLine(zxidcs.simple_show_conf(cf, null, null, 0));
      
      if (uri.StartsWith("/sso/")) {

	//
	// Anything starting by /sso/ requires Single Sign-On
	// This may be simple logged in case if session cookie is already set,
	// or it may involve SSO protocol related redirects to IdP, etc.
	// All this is handled by zxidcs.simple_cf() and the switch (res) {}
	// that follows
	//

	Console.Error.WriteLine("sso qs("+qs+") uri("+uri+")");
	if (meth == "POST")
	  qs = read_post();
	string res = zxidcs.simple_cf(cf, qs.Length, qs, null, 0x0d54);
	switch (res[0]) {
	case 'L':  /* Redirect: ret == "LOCATION: urlCRLF2" */
	  Console.Error.WriteLine("redirect("+res+") len="+res.Length);
	  Console.Write(res);  /* Location header redirect */
	  return;
	case '<':
	  switch (res[1]) {
	  case 's':  /* <se:  SOAP envelope */
	  case 'm':  /* <m20: metadata */
	    Console.Write("Content-Type: text/xml\r\nContent-Length: "+res.Length+"\r\n\r\n");
	    break;
	  default:
	    Console.Write("Content-Type: text/html\r\nContent-Length: "+res.Length+"\r\n\r\n");
	    break;
	  }
	  Console.Write(res);
	  return;
	case 'd': /* Logged in case */
	  //my_parse_ldif(ret);
	  int x = res.IndexOf("\nsesid: ");
	  int y = res.IndexOf('\n', x + 8);
	  string sid = res.Substring(x + 8, y-x-8);
	  Console.Error.WriteLine("Logged in. sid="+sid);
	  break;
	default:
	  Console.Error.WriteLine("Unknown zxid_simple() response.");
	  break;
	}

	// At this point the SSO has been handled and we are ready to process the
	// application payload data. In our case we have multistep provisioning
	// flow expressed by names of submit buttons pressed: query, provisold,
	// provisnew, ... No button pressed means beginning of the process (the last else).

	NameValueCollection cgi = HttpUtility.ParseQueryString(qs);
	if (cgi.query) {
	  // *** sanity check the cgi input to avoid evil like injection attacks
	  zx_str ret = zxidcs.call(cf, ses, "urn:syn:pds:2015", null /* url */, null, null,
				   "op=select&from=users&fields=cas,cn,addr&cnpat="+cgi.cn+"&ddnpat="+cgi.ddn+"&genderpat="+cgi.gender+"&fmt=json&count=20");
	  string res_body_json = zxidcs.zx_str_s_get(ret);
	  Console.Error.WriteLine("res("+res_body_json+") len="+res_body_json.Length);

	  // Parse response and render the choices

	  //dynamic rs = Json.Decode(res_body_json);
	  //JavaScriptSerializer jss = new JavaScriptSerializer();
	  //var rs = jss.Deserialize<dynamic>(res_body_json);
	  Rs rs = JsonConvert.DeserializeObject<Rs>(res_body_json);

	  Console.Write("Content-Type: text/html\r\n\r\n");
	  Console.WriteLine("<title>Query Exists</title><h1>Results of Query Existing Users</h1>");
	  Console.WriteLine("<form method=post>");
	  
	  if (rs == null || rs.Length == 0) {
	    Console.WriteLine("<h3>No existing users found</h3>");
	  } else if (rs.Length >= 20) {
	    Console.WriteLine("<h3>WARNING: Too many matches. You need to refine your search criteria.</h3>");
	  } else if (rs.Length == 1) {
	    Console.WriteLine("<h3>One user found. Confirm?</h3>");
	    Console.WriteLine("<input type=hidden name=cas value=\""+rs[0].cas+"\">");
	    Console.WriteLine("CN: "+rs[0].cn+" Address: "+rs[0].addr);
	    Console.WriteLine("<input type=submit name=provisold value=\" This is it \"><br>");
	  } else {
	    Console.WriteLine("<h3>Many users found: Choose one</h3>");
	    
	    for (int i=0; i < rs.Length; ++i) {
	      Console.WriteLine("<input type=radio name=cas value=\""+rs[i].cas+"\">");
	      Console.WriteLine("CN: "+rs[i].cn+" Address: "+rs[i].addr);
	    }
	    Console.WriteLine("<input type=submit name=provisold value=\" Choose Selected User \"><br>");	    
	  }
	  Console.WriteLine("Name: <input name=cn value=\""+cgi.cn+"\"><br>");
	  Console.WriteLine("Data of Birth (YYYYMMDD): <input name=ddn value=\""+cgi.ddn+"\"><br>");
	  string mselect = cgi.gender == "m" ? " selected":"";
	  string fselect = cgi.gender == "f" ? " selected":"";
	  Console.WriteLine("Gender: <input type=radio name=gender value=m"+mselect+"> Male, <input type=radio name=gender value=f"+fselect+"> Female<br>");
	  Console.WriteLine("<input type=submit name=query value=\" Search again \">");
	  Console.WriteLine("<input type=submit name=provisnew value=\" Create new user \">");
	  Console.WriteLine("</form>");
	} else if (cgi.provisnew) {
	  // *** TBW
	} else if (cgi.provisold) {
	  // *** TBW	  
	} else {
	  // Start of the provisioning flow (usually after nurse SSO)
	  Console.Write("Content-Type: text/html\r\n\r\n");
	  Console.WriteLine("<title>Protected</title><h1>Logged in, Protected Content</h1>");
	  Console.WriteLine("session id("+sid+")");
	  //Console.WriteLine("res("+res+")");
	  Console.WriteLine("<h3>Start of provisioning flow</h3>");
	  Console.WriteLine("<form method=post>");
	  Console.WriteLine("<input type=hidden name=provstep value=queryexist>");
	  Console.WriteLine("Name: <input name=cn value=\"\"><br>");
	  Console.WriteLine("Data of Birth (YYYYMMDD): <input name=ddn value=\"\"><br>");
	  Console.WriteLine("Gender: <input type=radio name=gender value=m> Male, <input type=radio name=gender value=f> Female<br>");
	  Console.WriteLine("<input type=submit name=query value=\" Query if user exists \">");
	  Console.WriteLine("</form>");
	}
	
      } else if (uri.StartsWith("/wsp/")) {

	//
	// Handle Web Service Provider interface
	//

	string post = read_post();
	zxid_ses ses = zxidcs.alloc_ses(cf);
	string idpnid = zxidcs.wsp_validate(cf, ses, "", post);
	Console.Error.WriteLine("WSP: Serving a web service call. idpnid="+idpnid+" uri="+uri);
	string resp = "OK"; // Do your web service provider payload here
	zx_str wsp_resp = zxidcs.wsp_decorate(cf, ses, "", resp);
	Console.Write("Content-Type: text/plain\r\n\r\n");
	Console.Write(zxidcs.zx_str_s_get(wsp_resp));
      } else {
	Console.Write("Content-Type: text/html\r\n\r\n");
	Console.WriteLine("<title>Unprotected</title><h1>Unprotected</h1>");
      }
    }
  }
}


/*

new Uri(url).Query

*/
