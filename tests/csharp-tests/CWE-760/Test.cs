using System;
using System.IO;
using System.Text;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Permissions;

public class StaticSalt {
  public void Test1() {
    string password = "TestPassword";

    // BAD: Static String 
    var salt = Encoding.UTF8.GetBytes("Hardcoded Salt");
    var hash = new Rfc2898DeriveBytes(password, salt);
  }
}