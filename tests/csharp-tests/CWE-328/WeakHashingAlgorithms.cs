using System;
using System.IO;
using System.Text;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Permissions;

public class WeakHash
{
    public static string GetMD5Hash(string str)
    {
        MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
        byte[] bytes = ASCIIEncoding.Default.GetBytes(str);
        byte[] encoded = md5.ComputeHash(bytes);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < encoded.Length; i++)
            sb.Append(encoded[i].ToString("x2"));

        return sb.ToString();
    }

    public static string GetMD5Hash2(string str)
    {
        MD5CryptoServiceProvider md5 = (MD5CryptoServiceProvider)System.Security.Cryptography.HashAlgorithm.Create("MD5");
        byte[] bytes = ASCIIEncoding.Default.GetBytes(str);
        byte[] encoded = md5.ComputeHash(bytes);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < encoded.Length; i++)
            sb.Append(encoded[i].ToString("x2"));

        return sb.ToString();
    }

    public static string GetMD5Hash3(string str)
    {
        System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create();
        byte[] bytes = Encoding.Default.GetBytes(str);
        byte[] encoded = md5.ComputeHash(bytes);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < encoded.Length; i++)
            sb.Append(encoded[i].ToString("x2"));

        return sb.ToString();
    }
}
