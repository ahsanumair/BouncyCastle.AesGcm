using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BouncyCastle.AesGcm
{
	public enum AesGcmStreamMode
	{ 
		Read = 0,
		Write = 1
	}

	public class StreamSettings
	{
		public int MacSize = 32;
		public byte[] Key;
		public byte[] Nonce;
	}

	public class AesGcm
	{
		private CipherStream writeCipherStream = null;
		
		private CipherStream readCipherStream = null;
		
		private StreamSettings settings = null;
		
		private long streamLength;

		private const string Algorithm = "AES/GCM/NoPadding";
		public AesGcm(Stream stream, StreamSettings cryptoSettings, AesGcmStreamMode mode)
		{
			settings = cryptoSettings;
			streamLength = 0;

			KeyParameter key = ParameterUtilities.CreateKeyParameter("AES", settings.Key);

			if (mode == AesGcmStreamMode.Write)
			{
				IBufferedCipher writeCipher = CipherUtilities.GetCipher(Algorithm);
				
				writeCipher.Init(true, new AeadParameters(key, settings.MacSize, settings.Nonce));

				this.writeCipherStream = new CipherStream(stream, null, writeCipher);
			}
			else if (mode == AesGcmStreamMode.Read)
			{
				IBufferedCipher readCipher = CipherUtilities.GetCipher(Algorithm);
				
				readCipher.Init(false, new AeadParameters(key, settings.MacSize, settings.Nonce));

				streamLength = stream.Length;

				readCipherStream = new CipherStream(stream, readCipher, null);
			}
		}
		public void Write(string text)
		{
			EncryptBytes(Encoding.UTF8.GetBytes(text));
		}

		public void WriteLine(string text)
		{
			EncryptBytes(Encoding.UTF8.GetBytes(text + "\n"));
		}

		public string ReadAllText()
		{
			if (streamLength > 0)
			{
				var length = streamLength - (settings.MacSize / 8);
				
				using (BinaryReader reader = new BinaryReader(readCipherStream, Encoding.UTF8))
                {
					return Encoding.UTF8.GetString(DecryptBytes(reader, length));
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
