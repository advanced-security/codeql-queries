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
        var dsa1 = new DSACryptoServiceProvider(2042);

        // GOOD
        var dsa2 = new DSACryptoServiceProvider(1024);

    }
}