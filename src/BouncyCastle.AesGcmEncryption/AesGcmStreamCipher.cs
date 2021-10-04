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
		public int NonceSize = 256;
		public string Key;
		public string Nonce;
	}

	public class AesGcmStreamCipher : IAesGcmStreamCipher
	{
		private CipherStream _cipherStream = null;
		
		private StreamingSettings _streamingSettings = null;

		private Encoding _encoding;

		private long _streamLength = 0;

		private bool _isDisposed;

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
				throw new ArgumentException($"Key needs to be a valid base64 encoded string", "streamingSettings.Key");
			}

			if (TryGetFromBase64String(streamingSettings.Nonce, out byte[] nonceBytes))
			{
				CheckNonceIsValid(nonceBytes);
			}
			else
			{
				throw new ArgumentException($"Nonce needs to be a valid base64 encoded string", "streamingSettings.Nonce");
			}

			KeyParameter key = ParameterUtilities.CreateKeyParameter("AES", keyBytes);
			IBufferedCipher bufferedCipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");

			if (streamingMode == StreamingMode.Write)
			{
				bufferedCipher.Init(true, new AeadParameters(key, _streamingSettings.MacSize, nonceBytes));

				_cipherStream = new CipherStream(stream, null, bufferedCipher);
			}
			else if (streamingMode == StreamingMode.Read)
			{
				bufferedCipher.Init(false, new AeadParameters(key, _streamingSettings.MacSize, nonceBytes));

				_streamLength = stream.Length;

				_cipherStream = new CipherStream(stream, bufferedCipher, null);
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
			Encrypt(inputToEncrypt + "\r\n");
		}

		public string Decrypt()
		{
			if (_streamLength > 0)
			{
				var length = _streamLength - (_streamingSettings.MacSize / 8);
				
				using (BinaryReader reader = new BinaryReader(_cipherStream, _encoding))
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
				_cipherStream.WriteByte(input[i]);
			}
			_cipherStream.Write(input, input.Length / 2, input.Length - input.Length / 2);
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
				if (_cipherStream != null)
				{
					if (_cipherStream.CanSeek)
					{
						_cipherStream.Flush();
					}

					_cipherStream.Dispose();
					_cipherStream = null;
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
				throw new ArgumentException($"Key needs to be {_streamingSettings.KeySize} bit. Actual:{key?.Length * 8}", "streamingSettings.Key");
			}
		}

		private void CheckNonceIsValid(byte[] nonce)
		{
			if (nonce == null || nonce.Length != _streamingSettings.NonceSize / 8)
			{
				throw new ArgumentException($"Nonce needs to be {_streamingSettings.NonceSize} bit. Actual:{nonce?.Length * 8}", "streamingSettings.Nonce");
			}
		}

		public static string GetCryptedRandom(int size)
		{
			using (var cryptoRandom = new RNGCryptoServiceProvider())
			{
				var key = new byte[size];
				cryptoRandom.GetBytes(key);
				return Convert.ToBase64String(key);
			}
		}
	}
}
