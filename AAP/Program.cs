using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using MessagePack;
using SharpCompress.Common;
using SharpCompress.Writers;
using ZstdSharp;

namespace AAP
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("Usage: ./AAP <private_key_pem_file_path> <resource_folder_path> <output_aap_file_path>");
                return;
            }

            string privateKeyPath = args[0];
            string resourceFolderPath = args[1];
            string outputPath = args[2];

            // Load the private key
            AsymmetricCipherKeyPair keyPair;
            using (var reader = File.OpenText(privateKeyPath))
            {
                keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();
            }

            // Prepare the data
            string appSettingsPath = Path.Combine(resourceFolderPath, "AppSettings.xml");
            byte[] appSettingsData = MessagePackSerializer.Serialize(File.ReadAllText(appSettingsPath));
            ushort appSettingsSize = (ushort)appSettingsData.Length;

            string[] assetFolders = { "content", "PlatformContent", "shaders" };
            byte[] archiveData = CreateZstdArchive(resourceFolderPath, assetFolders);
            ulong archiveSize = (ulong)archiveData.Length;

            // Create the signature
            ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
            signer.Init(true, keyPair.Private);
            signer.BlockUpdate(appSettingsData, 0, appSettingsData.Length);
            signer.BlockUpdate(archiveData, 0, archiveData.Length);
            byte[] signature = signer.GenerateSignature();

            // Write the output file
            using (var stream = File.OpenWrite(outputPath))
            {
                stream.Write(new byte[] { 0x61, 0x61, 0x70, 0x25, 0x25 }, 0, 5);  // Magic header
                stream.Write(signature, 0, 128);  // Signature
                stream.Write(BitConverter.GetBytes(appSettingsSize), 0, 2);  // AppSettings.xml size
                stream.Write(appSettingsData, 0, appSettingsData.Length);  // AppSettings.xml data
                stream.Write(BitConverter.GetBytes(archiveSize), 0, 8);  // Archive size
                stream.Write(archiveData, 0, archiveData.Length);  // Archive data
            }
        }

        private static byte[] CreateZstdArchive(string basePath, string[] folders)
        {
            using var memoryStream = new MemoryStream();
            using (var writer = WriterFactory.Open(memoryStream, ArchiveType.Tar, CompressionType.None))
            {
                foreach (var folder in folders)
                {
                    writer.Write(folder, Path.Combine(basePath, folder));
                }
            }

            byte[] tarData = memoryStream.ToArray();

            using var compressor = new Compressor();
            byte[] compressedData = compressor.Wrap(tarData).ToArray();

            return compressedData;
        }
    }
}