using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BatchVirusScanner
{
    internal class Quarantiner
    {
        private static Helpers _helpers = new Helpers();

        public void QuarantineFile(string filePath, string? quarantineDir = null)
        {
            try
            {

                if (string.IsNullOrEmpty(quarantineDir))
                {
                    quarantineDir = @"C:\Quarantine\";
                }

                if (!Directory.Exists(quarantineDir))
                {
                    Directory.CreateDirectory(quarantineDir);
                }

                byte[] fileBytes = File.ReadAllBytes(filePath);

                string fileHash = _helpers.Sha256Hash(fileBytes);

                string header = $"Timestamp: {DateTime.UtcNow}\n" +
                    $"SHA-256: {fileHash}\n\n";

                byte[] headerBytes = Encoding.UTF8.GetBytes(header);

                string quarantineFilePath = Path.Combine(quarantineDir, $"{Path.GetFileName(filePath)}.quarantine");
                using (FileStream fs = new FileStream(quarantineFilePath, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(headerBytes, 0, headerBytes.Length);
                    fs.Write(fileBytes, 0, fileBytes.Length);
                }

                SecureDelete(filePath);

                Console.WriteLine($"File quarantined successfully: {quarantineFilePath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private void SecureDelete(string filePath)
        {
            try
            {
                FileInfo fileInfo = new FileInfo(filePath);
                if (!fileInfo.Exists)
                {
                    Console.WriteLine($"File: {filePath} does not exist!");
                    return;
                }

                int length = (int)fileInfo.Length;
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Write))
                {
                    byte[] randomData = new byte[length];
                    new Random().NextBytes(randomData);
                    fs.Write(randomData, 0, length);
                }

                File.Delete(filePath);
                Console.WriteLine($"Securely Deleted File: {filePath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error Deleting File: ",ex.Message);
            }
        }
    }
}
