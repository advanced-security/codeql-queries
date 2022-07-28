using System;
using System.IO;
using System.Text;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Permissions;

public class StaticSalt
{
    public void Test1()
    {
        var key = Encoding.UTF8.GetBytes("TestPassword");

        // BAD: MD5
        var md5 = new HMACMD5();
        var md5_1 = new HMACMD5(key);

        // BAD: SHA1 (not really but worth reporting)
        var sha1 = new HMACSHA1();
        var sha1_2 = new HMACSHA1(key);

        // GOOD: SHA256
        var sha2 = new HMACSHA256(key);
        // GOOD: SHA384
        var sha3 = new HMACSHA384(key);
        // GOOD: SHA512
        var sha5 = new HMACSHA512(key);
    }
}