using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace BatchVirusScanner
{
    internal class PatternScanner : Scanner
    {

        private readonly List<string> patterns = new List<string>
        {
            @"del\s+/f\s+/s\s+/q",
            @"rd\s+/s\s+/q",
            @"shutdown\s+/s\s+/t\s+\d+",
            @"shutdown\s+/r\s+/t\s+\d+",
            @"reg\s+add",
            @"reg\s+delete",
            @"ipconfig\s+/release",
            @"format\s+C:",
            @"echo\s+.*?>\s*.+",
            @"goto\s+:loop",
            @"netsh\s+interface\s+set.*disable",
            @"attrib\s+\+h\s+\+s",
            @"powershell\s+-Command.*Invoke-WebRequest"
        };
        private readonly List<string> FlaggedFiles = new();

        public List<string> GetFlaggedFiles() => FlaggedFiles;

        public override FileScanResult ScanFile(string filePath)
        {
            ScannedFiles++;
            string fileContent = File.ReadAllText(filePath);

            foreach(string pattern in patterns)
            {
                Regex regex = new Regex(pattern, RegexOptions.IgnoreCase);
                Match match = regex.Match(fileContent);

                if (match.Success)
                {
                    Threats++;
                    FlaggedFiles.Add(filePath);
                    return FileScanResult.Threat;
                }
            }

            return FileScanResult.Safe;
        }
    }
}
