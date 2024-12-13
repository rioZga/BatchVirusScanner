using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BatchVirusScanner
{
    abstract class Scanner
    {
        public int ScannedFiles = 0;
        public int Threats = 0;

        public abstract FileScanResult ScanFile(string path);
        public void PrintReport(string stage)
        {
            Console.WriteLine($"{stage} Stage Scan Finished: \n" +
                $"  Files Scanned: {ScannedFiles}\n" +
                $"  Threats Found: {Threats}\n");
        }
    }
}
