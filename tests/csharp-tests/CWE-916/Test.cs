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
        string password = "TestPassword";
        var randonSalt = new byte[16];
        RandomNumberGenerator.Create().GetBytes(randonSalt);


        // BAD: Default (1000)
        var hash = new Rfc2898DeriveBytes(password, randonSalt);

        // BAD: Static int
        var hash2 = new Rfc2898DeriveBytes(password, randonSalt, 1000);

        // BAD: Static int
        int interations = 1000;
        var hash3 = new Rfc2898DeriveBytes(password, randonSalt, interations);



        // Good: High interations
        var hash_safe = new Rfc2898DeriveBytes(password, randonSalt, 100000);
    }
}