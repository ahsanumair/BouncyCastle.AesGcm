using System;
using System.IO;
using System.Reflection;
using BouncyCastle.AesGcmEncryption;
using FluentAssertions;
using NUnit.Framework;

namespace BouncyCastle.AesGcm.Tests
{
    [Parallelizable]
    public class AesGcmStreamCipherTests
    {
        private string _keyBase64 = "MTNiNDBmMTZhOTg0NGIxMGFjOTdiOGY4YTExMDhiY2Q=";

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
        public void InitializeAesGcmStreamCipher_InvalidPlainTextKeySize_ItShouldThrowArgumentException()
        {
            _settings.Key = "invalidkey";

            var exception = Assert.Throws<ArgumentException>(() => new AesGcmStreamCipher(_writeStream, _settings, StreamingMode.Write));

            exception.ParamName.Should().Be("key");

            exception.Message.Should().Be("Key needs to be 256 bit. Actual:80 (Parameter 'key')");
        }

        [Test]
        public void InitializeAesGcmStreamCipher_InvalidBase64EncodedKeySize_ItShouldThrowArgumentException()
        {
            _settings.Key = "MTNiNDBmMTZhOQ==";

            var exception = Assert.Throws<ArgumentException>(() => new AesGcmStreamCipher(_writeStream, _settings, StreamingMode.Write));

            exception.ParamName.Should().Be("key");

            exception.Message.Should().Be("Key needs to be 256 bit. Actual:80 (Parameter 'key')");
        }

        [Test]
        [TestCase("")]
        [TestCase("   ")]
        [TestCase(null)]
        public void Encrypt_TextIsNullEmptyOrWhiteSpace_ItShouldThrowArgumentNullException(string text)
        {
            _settings.Key = _keyBase64;

            using var _aesGcmStreamCipher = new AesGcmStreamCipher(_writeStream, _settings, StreamingMode.Write);

            var exception = Assert.Throws<ArgumentNullException>(() => _aesGcmStreamCipher.Encrypt(text));

            exception.ParamName.Should().Be("inputToEncrypt");
        }

        [Test]
        [TestCase("")]
        [TestCase("    ")]
        [TestCase(null)]
        public void EncryptLine_TextIsNullEmptyOrWhiteSpace_ItShouldThrowArgumentNullException(string text)
        {
            _settings.Key = _keyBase64;

            using var _aesGcmStreamCipher = new AesGcmStreamCipher(_writeStream, _settings, StreamingMode.Write);

            var exception = Assert.Throws<ArgumentNullException>(() => _aesGcmStreamCipher.EncryptLine(text));

            exception.ParamName.Should().Be("inputToEncrypt");
        }

        [Test]
        public void EncryptAndDecrypt_ValidInputTextToEncrypt_SuccessfullyDecrypted()
        {
            _settings.Key = _keyBase64;

            var text = "Hello World, This text needs to be encrypted";

            var path = $"{Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)}\\EncryptedFile.txt";

            FileInfo fileInfo = new FileInfo(path);

            var writeStream = fileInfo.Open(FileMode.Create, FileAccess.Write);

            using (var _aesGcmStreamEncryptCipher = new AesGcmStreamCipher(writeStream, _settings, StreamingMode.Write))
            {
                _aesGcmStreamEncryptCipher.EncryptLine(text);
                _aesGcmStreamEncryptCipher.EncryptLine(text);
                _aesGcmStreamEncryptCipher.Encrypt(text);
            }

            string decryptedText;
            var readStream = fileInfo.OpenRead();

            using (var _aesGcmStreamDecryptCipher = new AesGcmStreamCipher(readStream, _settings, StreamingMode.Read))
            {
                decryptedText = _aesGcmStreamDecryptCipher.Decrypt();
            }

            if (fileInfo.Exists)
            {
                fileInfo.Delete();
            }

            decryptedText.Should().Be(text + "\r\n" + text + "\r\n" + text);
        }
    }
}
