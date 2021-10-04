using System;
using System.IO;
using System.Reflection;
using System.Text;
using BouncyCastle.AesGcmEncryption;
using FluentAssertions;
using NUnit.Framework;

namespace BouncyCastle.AesGcm.Tests
{
    [Parallelizable]
    public class AesGcmStreamCipherTests
    {
        private StreamingSettings _settings;
        private MemoryStream _writeStream;

        [SetUp]
        public void Setup()
        {
            _writeStream = new MemoryStream();
            _settings = new StreamingSettings
            {
                Nonce = AesGcmStreamCipher.GetCryptedRandom(32),
                Key = AesGcmStreamCipher.GetCryptedRandom(32)
            };
        }

        [Test]
        public void InitializeAesGcmStreamCipher_IfStreamIsNull_ItShouldThrowArgumentNullException()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => new AesGcmStreamCipher(null, _settings, StreamingMode.Write));

            exception.ParamName.Should().Be("stream");
        }

        [Test]
        public void InitializeAesGcmStreamCipher_IfStreamSettingsIsNull_ItShouldThrowArgumentNullException()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => new AesGcmStreamCipher(_writeStream, null, StreamingMode.Write));

            exception.ParamName.Should().Be("streamingSettings");
        }

        [Test]
        [TestCase("")]
        [TestCase("    ")]
        [TestCase(null)]
        public void InitializeAesGcmStreamCipher_IfKeyIsNullEmptyOrWhiteSpace_ItShouldThrowArgumentNullException(string key)
        {
            _settings.Key = key;

            var exception = Assert.Throws<ArgumentNullException>(() => new AesGcmStreamCipher(_writeStream, _settings, StreamingMode.Write));

            exception.ParamName.Should().Be("streamingSettings.Key");
        }

        [Test]
        [TestCase("")]
        [TestCase("    ")]
        [TestCase(null)]
        public void InitializeAesGcmStreamCipher_IfNonceIsNullEmptyOrWhiteSpace_ItShouldThrowArgumentNullException(string nonce)
        {
            _settings.Nonce = nonce;

            var exception = Assert.Throws<ArgumentNullException>(() => new AesGcmStreamCipher(_writeStream, _settings, StreamingMode.Write));

            exception.ParamName.Should().Be("streamingSettings.Nonce");
        }

        [Test]
        public void InitializeAesGcmStreamCipher_InvalidNonBase64EncodedKeyUsed_ItShouldThrowArgumentException()
        {
            _settings.Key = "invalid_key";
            _settings.Nonce = AesGcmStreamCipher.GetCryptedRandom(32);

            var exception = Assert.Throws<ArgumentException>(() => new AesGcmStreamCipher(_writeStream, _settings, StreamingMode.Write));

            exception.ParamName.Should().Be("streamingSettings.Key");

            exception.Message.Should().Be("Key needs to be a valid base64 encoded string (Parameter 'streamingSettings.Key')");
        }

        [Test]
        public void InitializeAesGcmStreamCipher_Base64EncodedKeyWithInvalidLengthUsed_ItShouldThrowArgumentException()
        {
            _settings.Key = "MTNiNDBmMTZhOQ==";
            _settings.Nonce = AesGcmStreamCipher.GetCryptedRandom(32);

            var exception = Assert.Throws<ArgumentException>(() =>  new AesGcmStreamCipher(_writeStream, _settings, StreamingMode.Write));

            exception.ParamName.Should().Be("streamingSettings.Key");

            exception.Message.Should().Be("Key needs to be 256 bit. Actual:80 (Parameter 'streamingSettings.Key')");
        }

        [Test]
        public void InitializeAesGcmStreamCipher_InvalidNonBase64EncodedNonceUsed_ItShouldThrowArgumentException()
        {
            _settings.Key = AesGcmStreamCipher.GetCryptedRandom(32);
            _settings.Nonce = "invalid_Nonce";

            var exception = Assert.Throws<ArgumentException>(() => new AesGcmStreamCipher(_writeStream, _settings, StreamingMode.Write));

            exception.ParamName.Should().Be("streamingSettings.Nonce");

            exception.Message.Should().Be("Nonce needs to be a valid base64 encoded string (Parameter 'streamingSettings.Nonce')");
        }

        [Test]
        public void InitializeAesGcmStreamCipher_Base64EncodedNonceWithInvalidLengthUsed__ItShouldThrowArgumentException()
        {
            _settings.Key = AesGcmStreamCipher.GetCryptedRandom(32);
            _settings.Nonce = "MTNiNDBmMTZhOQ==";

            var exception = Assert.Throws<ArgumentException>(() => new AesGcmStreamCipher(_writeStream, _settings, StreamingMode.Write));

            exception.ParamName.Should().Be("streamingSettings.Nonce");

            exception.Message.Should().Be("Nonce needs to be 256 bit. Actual:80 (Parameter 'streamingSettings.Nonce')");
        }

        [Test]
        [TestCase("")]
        [TestCase("   ")]
        [TestCase(null)]
        public void Encrypt_TextIsNullEmptyOrWhiteSpace_ItShouldThrowArgumentNullException(string text)
        {
            _settings.Key = AesGcmStreamCipher.GetCryptedRandom(32);
            _settings.Nonce = AesGcmStreamCipher.GetCryptedRandom(32);

            using var _aesGcmStreamCipher = new AesGcmStreamCipher(_writeStream, _settings, StreamingMode.Write);

            var exception = Assert.Throws<ArgumentNullException>(() => _aesGcmStreamCipher.Encrypt(text));

            exception.ParamName.Should().Be("inputToEncrypt");
        }

        [Test]
        public void EncryptAndDecrypt_ValidUTF8InputProvidedToEncrypt_SuccessfullyDecrypted()
        {
            var text = "Δ, Й, ק, ‎ م, ๗, あ, 叶, 葉, and 말. ABC";

            var decryptedText = EncryptDecrypt(text,"UTF8File.txt", Encoding.UTF8);

            decryptedText.Should().Be(text + "\r\n" + text + "\r\n" + text);
        }

        [Test]
        public void EncryptAndDecrypt_ValidASCIIInputProvidedToEncrypt_SuccessfullyDecrypted()
        {
            var text = "Hello World, This text needs to be encrypted";

            var decryptedText = EncryptDecrypt(text,"ASCIIEncodedFile.txt", Encoding.ASCII);

            decryptedText.Should().Be(text + "\r\n" + text + "\r\n" + text);
        }

        private string EncryptDecrypt(string text, string fileName, Encoding encoding)
        {
            _settings.Key = AesGcmStreamCipher.GetCryptedRandom(32);
            _settings.Nonce = AesGcmStreamCipher.GetCryptedRandom(32);

            var path = $"{Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)}\\{fileName}";

            FileInfo fileInfo = new FileInfo(path);

            var writeStream = fileInfo.Open(FileMode.Create, FileAccess.Write);

            using (var _aesGcmStreamEncryptCipher = new AesGcmStreamCipher(writeStream, _settings, StreamingMode.Write, encoding))
            {
                _aesGcmStreamEncryptCipher.EncryptLine(text);
                _aesGcmStreamEncryptCipher.EncryptLine(text);
                _aesGcmStreamEncryptCipher.Encrypt(text);
            }

            string decryptedText;
            var readStream = fileInfo.OpenRead();

            using (var _aesGcmStreamDecryptCipher = new AesGcmStreamCipher(readStream, _settings, StreamingMode.Read, encoding))
            {
                decryptedText = _aesGcmStreamDecryptCipher.Decrypt();
            }

            if (fileInfo.Exists)
            {
                fileInfo.Delete();
            }

            return decryptedText;
        }
    }
}
