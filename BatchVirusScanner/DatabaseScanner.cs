using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BatchVirusScanner
{
    internal class DatabaseScanner : Scanner
    {
        private static Helpers _helpers = new Helpers();
        private static Dictionary<string, string> _virusDatabase = new Database().getVirusDatabase();

        public override FileScanResult ScanFile(string filePath)
        {
            ScannedFiles++;                    
            string fileHash = _helpers.Sha256Hash(filePath);
            _virusDatabase.TryGetValue(fileHash, out string? detectionName);
            if (detectionName != null) {
                Console.WriteLine($"Threat detected: {detectionName} in file: {filePath}");
                Threats++;
                return FileScanResult.Threat;
            }
            return FileScanResult.Safe;
        }

    }
}
