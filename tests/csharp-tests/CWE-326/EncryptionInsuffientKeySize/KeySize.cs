using System;
using System.IO;
using System.Text;
using System.Runtime.Serialization;
using System.Security.Cryptography;

public class StaticSalt
{
    // public void Test1()
    // {
    //     //
    //     var dsa1 = new DSACryptoServiceProvider();

    //     //
    //     var dsa2 = new DSACryptoServiceProvider(1024);

    // }

    public void TestRSA()
    {
        // BAD: Default is insecure
        var rsa1 = new RSACryptoServiceProvider();
        var rsa2 = new RSACryptoServiceProvider(1024);

        int key_size = 1024;
        var rsa3 = new RSACryptoServiceProvider(key_size);

        // Good
        var rsa_good = new RSACryptoServiceProvider(2048);
    }

    public void TestRSACng()
    {

        // BAD: Default is insecure
        var rsacng = new RSACng();
        var rsacng2 = new RSACng(1024);

        // GOOD: High
        var rsacng_good2 = new RSACng(2048);
    }
}