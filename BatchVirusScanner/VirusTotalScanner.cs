using Microsoft.Extensions.Configuration;
using VirusTotalNet;
using VirusTotalNet.Objects;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;

namespace BatchVirusScanner
{
    internal class VirusTotalScanner : Scanner
    {
        private static VirusTotal _virusTotal;
        private static FileReport _fileReport;

        public VirusTotalScanner()
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true).Build();

            string? apiKey = configuration["VIRUS_TOTAL_API_KEY"] 
                ?? throw new Exception("Missing VirusTotal api key");

            _virusTotal = new VirusTotal(apiKey);
            _virusTotal.UseTLS = true;
        }

        public override FileScanResult ScanFile(string filePath)
        {
            return ScanFileAsync(filePath).GetAwaiter().GetResult();
        }

        public async Task<FileScanResult> ScanFileAsync(string filePath)
        {
            ScannedFiles++;
            byte[] bytes = File.ReadAllBytes(filePath);
            _fileReport = await _virusTotal.GetFileReportAsync(bytes);

            bool scannedBefore = _fileReport.ResponseCode == FileReportResponseCode.Present;
            if (scannedBefore)
            {
                PrintScan();
            }
            else
            {
                ScanResult scanResult = await _virusTotal.ScanFileAsync(bytes, Path.GetFileName(filePath));
                _fileReport = await _virusTotal.GetFileReportAsync(scanResult.Resource);
                PrintScan();
            }

            if (_fileReport.Positives > 0)
            {
                Threats++;
                return FileScanResult.Threat;
            }

            return FileScanResult.Safe;
        }

        private static void PrintScan()
        {
            Console.WriteLine("Scan ID: " + _fileReport.ScanId);
            Console.WriteLine("Message: " + _fileReport.VerboseMsg);

            foreach (KeyValuePair<string, ScanEngine> scan in _fileReport.Scans)
            {
                Console.WriteLine("{0,-25} Detected: {1}", scan.Key, scan.Value.Detected);
            }

            Console.WriteLine();
        }

    }
}
