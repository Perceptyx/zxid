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
      
      if (uri.StartsWith("/clinician/1")) {
	
      } else if (uri.StartsWith("/clinician/2")) {
	
      } else if (uri.StartsWith("/sso/")) {
	Console.Error.WriteLine("sso qs("+qs+") uri("+uri+")");
	string res = zxidcs.simple_cf(cf, 0, null, null, 0x0d54);
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
	  Console.Write("Content-Type: text/html\r\n\r\n");
	  Console.WriteLine("<title>Protected</title><h1>Logged in, Protected Content</h1>");
	  Console.WriteLine("session id("+sid+")");
	  Console.WriteLine("res("+res+")");
	  Console.WriteLine("<a href=\"\">...</a>");
	  break;
	default:
	  Console.Error.WriteLine("Unknown zxid_simple() response.");
	  break;
	}
      } else if (uri.StartsWith("/wsp/")) {
	string post = read_post();
	zxid_ses ses = zxidcs.alloc_ses(cf);
	string idpnid = zxidcs.wsp_validate(cf, ses, "", post);
	Console.Error.WriteLine("WSP: Serving a web service call. idpnid="+idpnid+" uri="+uri);
	string resp = "OK"; // Do your web service provider payload here
	SWIGTYPE_p_zx_str res = zxidcs.wsp_decorate(cf, ses, "", resp);
	Console.Write("Content-Type: text/plain\r\n\r\n");
	Console.Write(zxidcs.zx_str_s_get(res));
      } else {
	Console.Write("Content-Type: text/html\r\n\r\n");
	Console.WriteLine("<title>Unprotected</title><h1>Unprotected</h1>");
      }
    }
  }
}
