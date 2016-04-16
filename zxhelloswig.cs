//#!/usr/bin/csharp
// Demonstration of calling zxid from C#
// mcs zxhelloswig.cs -r:csharp/zxidcs
// cd csharp; ln -s zxidcli.so libzxidcli.so
// MONO_PATH=csharp LD_LIBRARY_PATH=csharp   ./zxhelloswig.exe
// MONO_PATH=csharp LD_LIBRARY_PATH=csharp:. ./zxhelloswig.exe
using System;
using System.Runtime.InteropServices;
//using zxidcs;
namespace Hello {
  class HelloWorld {
    static void Main(string[] argv) {
      Console.WriteLine ("Hello, World");
      Console.WriteLine (zxidcs.version());
      Console.WriteLine (zxidcs.version_str());
    }
  }
}
