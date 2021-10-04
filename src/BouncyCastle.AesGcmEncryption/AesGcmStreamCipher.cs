using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BouncyCastle.AesGcmEncryption
{
	public enum StreamingMode
	{
		Read = 0,
		Write = 1
	}

	public class StreamingSettings
	{
		public int KeySize = 256;
		public int MacSize = 128;
		public string Key;
		public string Nonce;
	}

	public class AesGcmStreamCipher : IAesGcmStreamCipher
	{
		private CipherStream writeCipherStream = null;

		private CipherStream readCipherStream = null;

		private StreamingSettings _streamingSettings = null;

		private Encoding _encoding;

		private long _streamLength = 0;

		private bool _isDisposed;

		private const string Algorithm = "AES/GCM/NoPadding";

		public AesGcmStreamCipher(Stream stream, StreamingSettings streamingSettings, StreamingMode streamingMode, Encoding encoding = null)
		{
			if (encoding == null)
			{
				encoding = Encoding.UTF8;
			}

			_encoding = encoding;
			_streamingSettings = streamingSettings;

			if (stream == null)
			{
				throw new ArgumentNullException(nameof(stream));
			}

			if (streamingSettings == null)
			{
				throw new ArgumentNullException(nameof(streamingSettings));
			}

			if (string.IsNullOrWhiteSpace(streamingSettings.Key))
			{
				throw new ArgumentNullException("streamingSettings.Key");
			}

			if (string.IsNullOrWhiteSpace(streamingSettings.Nonce))
			{
				throw new ArgumentNullException("streamingSettings.Nonce");
			}

			if (TryGetFromBase64String(streamingSettings.Key, out byte[] keyBytes))
			{
				CheckKeyIsValid(keyBytes);
			}
			else
			{
				keyBytes = _encoding.GetBytes(streamingSettings.Key);
				CheckKeyIsValid(keyBytes);
			}

			if (!TryGetFromBase64String(streamingSettings.Nonce, out byte[] nonceBytes))
			{
				nonceBytes = _encoding.GetBytes(streamingSettings.Nonce);
			}

			KeyParameter key = ParameterUtilities.CreateKeyParameter("AES", keyBytes);

			if (streamingMode == StreamingMode.Write)
			{
				IBufferedCipher writeCipher = CipherUtilities.GetCipher(Algorithm);

				writeCipher.Init(true, new AeadParameters(key, _streamingSettings.MacSize, nonceBytes));

				writeCipherStream = new CipherStream(stream, null, writeCipher);
			}
			else if (streamingMode == StreamingMode.Read)
			{
				IBufferedCipher readCipher = CipherUtilities.GetCipher(Algorithm);

				readCipher.Init(false, new AeadParameters(key, _streamingSettings.MacSize, nonceBytes));

				_streamLength = stream.Length;

				readCipherStream = new CipherStream(stream, readCipher, null);
			}
		}

		public void Encrypt(string inputToEncrypt)
		{
			if (string.IsNullOrWhiteSpace(inputToEncrypt))
			{
				throw new ArgumentNullException(nameof(inputToEncrypt));
			}

			EncryptBytes(_encoding.GetBytes(inputToEncrypt));
		}

		public void EncryptLine(string inputToEncrypt)
		{
			if (string.IsNullOrWhiteSpace(inputToEncrypt))
			{
				throw new ArgumentNullException(nameof(inputToEncrypt));
			}

			EncryptBytes(_encoding.GetBytes(inputToEncrypt + "\r\n"));
		}

		public string Decrypt()
		{
			if (_streamLength > 0)
			{
				var length = _streamLength - (_streamingSettings.MacSize / 8);

				using (BinaryReader reader = new BinaryReader(readCipherStream, _encoding))
				{
					return _encoding.GetString(DecryptBytes(reader, length));
				}
			}

			return string.Empty;
		}

		private void EncryptBytes(byte[] input)
		{
			for (int i = 0; i != input.Length / 2; i++)
			{
				writeCipherStream.WriteByte(input[i]);
			}
			writeCipherStream.Write(input, input.Length / 2, input.Length - input.Length / 2);
		}

		private byte[] DecryptBytes(BinaryReader reader, long length)
		{
			var bytes = new byte[length];

			for (int i = 0; i != length / 2; i++)
			{
				bytes[i] = reader.ReadByte();
			}

			int remaining = bytes.Length - (int)length / 2;

			byte[] extra = reader.ReadBytes(remaining);

			if (extra.Length < remaining)
			{
				throw new EndOfStreamException();
			}

			extra.CopyTo(bytes, length / 2);

			return bytes;
		}

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (_isDisposed) return;

			if (disposing)
			{
				if (writeCipherStream != null)
				{
					if (writeCipherStream.CanSeek)
					{
						writeCipherStream.Flush();
					}

					writeCipherStream.Dispose();
					writeCipherStream = null;
				}

				if (readCipherStream != null)
				{
					if (readCipherStream.CanSeek)
					{
						readCipherStream.Flush();
					}

					readCipherStream.Dispose();
					readCipherStream = null;
				}
			}

			_isDisposed = true;
		}

		private bool TryGetFromBase64String(string input, out byte[] output)
		{
			output = null;
			try
			{
				output = Convert.FromBase64String(input);
				return true;
			}
			catch
			{
				return false;
			}
		}

		private void CheckKeyIsValid(byte[] key)
		{
			if (key == null || key.Length != _streamingSettings.KeySize / 8)
			{
				throw new ArgumentException($"Key needs to be {_streamingSettings.KeySize} bit. Actual:{key?.Length * 8}", nameof(key));
			}
		}

		public static string GetCryptedRandom(int size, bool encodeBase64 = true)
		{
			using (var cryptoRandom = new RNGCryptoServiceProvider())
			{
				var key = new byte[size];
				cryptoRandom.GetBytes(key);

				if (encodeBase64)
				{
					return Convert.ToBase64String(key);
				}
				else
				{
					return Encoding.UTF8.GetString(key, 0, key.Length);
				}
			}
		}
	}
}
