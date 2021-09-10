using System;
using System.IO;
using System.Text;

namespace BouncyCastle.AesGcm
{
    class Program
    {
        static void Main(string[] args)
        {
            var settings = new StreamSettings
            {
                Nonce = Encoding.UTF8.GetBytes("13b40f16a9844b10ac97b8f8a1108bcd"), // this should be same when encrypting and decrypting, use a random nonce each time.
                Key = Encoding.UTF8.GetBytes("629f221c5369477ea0060ca962e1ce92") // this should be same when encrypting and decrypting, use a random key each time.
            };

            var path = @"C:\test.txt";

            FileInfo fileInfo = new FileInfo(path);

            ////Encrypt content to file
            var writeStream = fileInfo.Open(FileMode.Create, FileAccess.Write);

            var writeCrypto = new AesGcm(writeStream, settings, AesGcmStreamMode.Write);

            Console.WriteLine("Encrypting Text...");

            writeCrypto.WriteLine("This text needs to be encrypted using AES GCM encryption.");
            writeCrypto.WriteLine("This text needs to be encrypted using AES GCM encryption.");

            writeCrypto.Dispose(); //must call dispose to release resources

            Console.WriteLine($"Encrypting finished...\n\n");

            //Decrypt content from file
            var readStream = fileInfo.OpenRead();

            var readCrypto = new AesGcm(readStream, settings, AesGcmStreamMode.Read);
            
            Console.WriteLine("Decrypting Text...");

            var decryptedText = readCrypto.ReadAllText();

            readCrypto.Dispose(); //must call dispose to release resources

            Console.WriteLine("Decrytion finished...\n\n");

            Console.WriteLine(decryptedText);
            
            Console.ReadKey();
        }
    }
}
