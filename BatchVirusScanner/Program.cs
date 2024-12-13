using BatchVirusScanner;
using System.Diagnostics;
using System.IO;

internal class Program
{
    private static Quarantiner quarantiner = new Quarantiner();
    private static void Main(string[] args)
    {
        Console.Title = "Batch Virus Scanner";

        List<string> batFiles = new List<string>();
        try
        {
            Console.WriteLine("Scanning system for .bat files...\n");
            batFiles = GetSystemBatFiles();
            Console.WriteLine($"Found {batFiles.Count} .bat files.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error occurred: {ex.Message}");
        }

        if (batFiles.Count == 0)
        {
            Console.WriteLine("No .bat files found in the system.\n");
            return;
        }

        DatabaseScanner databaseScanner = new DatabaseScanner();
        Console.WriteLine("First Stage Scan:");

        ScanBatFiles(batFiles, databaseScanner, quarantiner);
        databaseScanner.PrintReport("First");
        Console.WriteLine();

        PatternScanner patternScanner = new PatternScanner();
        Console.WriteLine("Second Stage Scan:");

        ScanBatFiles(batFiles, patternScanner);
        patternScanner.PrintReport("Second");
        Console.WriteLine();


        List<string> flaggedFiles = patternScanner.GetFlaggedFiles();

        if (flaggedFiles.Count == 0) return;

        Console.WriteLine("Last Stage Scan:");

        VirusTotalScanner virusTotalScanner = new VirusTotalScanner();
        foreach(string flaggedFile in flaggedFiles)
        {
            var scanResult = virusTotalScanner.ScanFile(flaggedFile);
            if (scanResult == FileScanResult.Threat)
            {
                quarantiner.QuarantineFile(flaggedFile);
            }
        }

        virusTotalScanner.PrintReport("Third");
        Console.WriteLine();
    }

    static void ScanBatFiles(List<string> files, Scanner scanner, Quarantiner? quarantiner = null)
    {
        foreach (var file in files.ToList())
        {
            var scanResult = scanner.ScanFile(file);

            if (scanResult == FileScanResult.Threat && quarantiner != null)
            {
                quarantiner.QuarantineFile(file);
                files.Remove(file);
            }
        }
    }

    static List<string> GetSystemBatFiles()
    {
        string[] rootDirectories = { @"C:\", @"D:\" };

        var batFiles = new List<string>();

        foreach (var directory in rootDirectories)
        {
            try
            {
                batFiles.AddRange(Directory.GetFiles(directory, "*.bat", SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"Access denied to: {directory}");
            }
            catch (PathTooLongException)
            {
                Console.WriteLine($"Path too long: {directory}");
            }
            catch (IOException ex)
            {
                Console.WriteLine($"I/O error in {directory}: {ex.Message}");
            }
        }

        return batFiles;
    }

}