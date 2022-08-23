using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

/// <summary>

/// ''' Function for implementing AES Encryption-Decryption for any input

/// ''' 

/// ''' Created By: Ashish Chandra Gupta

/// ''' Created On: 31 October, 2019 01.15 AM

/// ''' </summary>

/// ''' <remarks></remarks>
public sealed class AESEncryption
{
    private AESEncryption()
    {
    }

    private static string IV = "OFRna73m*aze01xY";
    private static string PASSWORD = "SuperApp@123";
    private static string SALT = "S0#S@P@U";

    public static string EncryptAndEncode(string raw)
    {
        using (var csp = new AesCryptoServiceProvider())
        {
            ICryptoTransform e = GetCryptoTransform(csp, true);
            byte[] inputBuffer = Encoding.UTF8.GetBytes(raw);
            byte[] output = e.TransformFinalBlock(inputBuffer, 0, inputBuffer.Length);
            string encrypted = Convert.ToBase64String(output);
            return encrypted;
        }
    }

    public static string DecodeAndDecrypt(string encrypted)
    {
        using (var csp = new AesCryptoServiceProvider())
        {
            var d = GetCryptoTransform(csp, false);
            byte[] output = Convert.FromBase64String(encrypted);
            byte[] decryptedOutput = d.TransformFinalBlock(output, 0, output.Length);
            string decypted = Encoding.UTF8.GetString(decryptedOutput);
            return decypted;
        }
    }

    private static ICryptoTransform GetCryptoTransform(AesCryptoServiceProvider csp, bool encrypting)
    {
        csp.Mode = CipherMode.CBC;
        csp.Padding = PaddingMode.PKCS7;
        var spec = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(PASSWORD), Encoding.UTF8.GetBytes(SALT), 65536);
        byte[] key = spec.GetBytes(16);


        csp.IV = Encoding.UTF8.GetBytes(IV);
        csp.Key = key;
        if (encrypting)
        {
            return csp.CreateEncryptor();
        }
        return csp.CreateDecryptor();
    }
    /// <summary>
    ///     ''' Encrypts a string
    ///     ''' </summary>
    ///     ''' <param name="PlainText">Text to be encrypted</param>
    ///     ''' <param name="Password">Password to encrypt with</param>
    ///     ''' <param name="Salt">Salt to encrypt with</param>
    ///     ''' <param name="HashAlgorithm">Can be either SHA1 or MD5</param>
    ///     ''' <param name="PasswordIterations">Number of iterations to do</param>
    ///     ''' <param name="InitialVector">Needs to be 16 ASCII characters long</param>
    ///     ''' <param name="KeySize">Can be 128, 192, or 256</param>
    ///     ''' <returns>An encrypted string</returns>
    public static string Encrypt(string PlainText, string Password, string Salt = "S0#S@P", string HashAlgorithm = "SHA1", int PasswordIterations = 2, string InitialVector = "OFRna73m*aze01xY", int KeySize = 256)
    {
        if (string.IsNullOrEmpty(PlainText))
            return "";
        byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(InitialVector);
        byte[] SaltValueBytes = Encoding.ASCII.GetBytes(Salt);
        byte[] PlainTextBytes = Encoding.UTF8.GetBytes(PlainText);
        PasswordDeriveBytes DerivedPassword = new PasswordDeriveBytes(Password, SaltValueBytes, HashAlgorithm, PasswordIterations);
        byte[] KeyBytes = DerivedPassword.GetBytes(KeySize / 8);
        RijndaelManaged SymmetricKey = new RijndaelManaged();
        SymmetricKey.Mode = CipherMode.CBC;
        byte[] CipherTextBytes = null;
        using (ICryptoTransform Encryptor = SymmetricKey.CreateEncryptor(KeyBytes, InitialVectorBytes))
        {
            using (MemoryStream MemStream = new MemoryStream())
            {
                using (CryptoStream CryptoStream = new CryptoStream(MemStream, Encryptor, CryptoStreamMode.Write))
                {
                    CryptoStream.Write(PlainTextBytes, 0, PlainTextBytes.Length);
                    CryptoStream.FlushFinalBlock();
                    CipherTextBytes = MemStream.ToArray();
                    MemStream.Close();
                    CryptoStream.Close();
                }
            }
        }
        SymmetricKey.Clear();
        return Convert.ToBase64String(CipherTextBytes);
    }

    /// <summary>
    ///     ''' Decrypts a string
    ///     ''' </summary>
    ///     ''' <param name="CipherText">Text to be decrypted</param>
    ///     ''' <param name="Password">Password to decrypt with</param>
    ///     ''' <param name="Salt">Salt to decrypt with</param>
    ///     ''' <param name="HashAlgorithm">Can be either SHA1 or MD5</param>
    ///     ''' <param name="PasswordIterations">Number of iterations to do</param>
    ///     ''' <param name="InitialVector">Needs to be 16 ASCII characters long</param>
    ///     ''' <param name="KeySize">Can be 128, 192, or 256</param>
    ///     ''' <returns>A decrypted string</returns>
    public static string Decrypt(string CipherText, string Password, string Salt = "S0#S@P", string HashAlgorithm = "SHA1", int PasswordIterations = 2, string InitialVector = "OFRna73m*aze01xY", int KeySize = 256)
    {
        if (string.IsNullOrEmpty(CipherText))
            return "";
        byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(InitialVector);
        byte[] SaltValueBytes = Encoding.ASCII.GetBytes(Salt);
        byte[] CipherTextBytes = Convert.FromBase64String(CipherText);
        PasswordDeriveBytes DerivedPassword = new PasswordDeriveBytes(Password, SaltValueBytes, HashAlgorithm, PasswordIterations);
        byte[] KeyBytes = DerivedPassword.GetBytes(KeySize / 8);
        RijndaelManaged SymmetricKey = new RijndaelManaged();
        SymmetricKey.Mode = CipherMode.CBC;
        byte[] PlainTextBytes = new byte[CipherTextBytes.Length - 1 + 1];
        int ByteCount = 0;
        using (ICryptoTransform Decryptor = SymmetricKey.CreateDecryptor(KeyBytes, InitialVectorBytes))
        {
            using (MemoryStream MemStream = new MemoryStream(CipherTextBytes))
            {
                using (CryptoStream CryptoStream = new CryptoStream(MemStream, Decryptor, CryptoStreamMode.Read))
                {
                    ByteCount = CryptoStream.Read(PlainTextBytes, 0, PlainTextBytes.Length);
                    MemStream.Close();
                    CryptoStream.Close();
                }
            }
        }
        SymmetricKey.Clear();
        return Encoding.UTF8.GetString(PlainTextBytes, 0, ByteCount);
    }
}
