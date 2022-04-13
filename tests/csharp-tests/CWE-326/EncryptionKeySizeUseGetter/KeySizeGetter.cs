using System;
using System.IO;
using System.Text;
using System.Runtime.Serialization;
using System.Security.Cryptography;

public class StaticSalt
{
    public void Test1()
    {
        // BAD
        var dsa1 = new DSACryptoServiceProvider();
        dsa1.KeySize = 2048;

        // BAD
        var rsa1 = new RSACryptoServiceProvider();
        rsa1.KeySize = 2048;

        // GOOD
        var dsa2 = new DSACryptoServiceProvider(1024);

    }
}