using System;

namespace BouncyCastle.AesGcmEncryption
{
    public interface IAesGcmStreamCipher : IDisposable
    {
        void Encrypt(string inputToEncrypt);
        void EncryptLine(string inputToEncrypt);
        string Decrypt();
    }
}
