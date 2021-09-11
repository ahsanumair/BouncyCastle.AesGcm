
using System;

namespace BouncyCastle.AesGcm
{
    public interface IAesGcm : IDisposable
    {
        void Write(string text);
        void WriteLine(string text);
        string ReadAllText();
    }
}
