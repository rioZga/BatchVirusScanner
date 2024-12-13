# BatchVirusScanner

BatchVirusScanner is a C# console application designed to scan and quarantine potentially malicious batch (.bat) files on your system. The scanner uses a multi-stage process to detect and handle threats effectively.

## Features

1. **File Locator**

   - Automatically scans the system to locate all `.bat` files.

2. **Multi-Stage Scanning**

   - **Stage 1: Hash-Based Detection**
     - Calculates the SHA-256 hash of each file.
     - Compares the hash against a database of known malicious hashes.
     - Files matching a hash are immediately quarantined.
   - **Stage 2: Pattern Matching**
     - Analyzes the content of each file using pre-defined regex patterns.
     - Flags files with suspicious content for further inspection.
   - **Stage 3: TotalVirus API Integration**
     - Submits flagged files to the TotalVirus API for a final malware verdict.
     - Files confirmed as malware are quarantined.

3. **Quarantine System**

   - Creates a new file with a header (timestamp and file hash) and appends the malicious file content to prevent execution by accident.
   - Saves the quarantined file in the `quarantine/` directory with a `.quarantine` extension.
   - Securely deletes the original malicious file by randomizing its bits before deletion.

## Prerequisites

- .NET SDK 6.0 or later.
- Access to the TotalVirus API (API key required).

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/rioZga/BatchVirusScanner.git
   cd BatchVirusScanner
   ```

2. Build the project:

   ```bash
   dotnet build
   ```

3. Configure the application:

   - Add your TotalVirus API key to the configuration file or as an environment variable.
   - Update the hash database file (`BatchDatabase.bav`) with known malicious hashes and detection names.

## Usage

1. Run the application:

   ```bash
   dotnet run
   ```

2. The scanner will:

   - Locate all `.bat` files on your system.
   - Execute the three-stage scanning process.
   - Quarantine any malicious or suspicious files.

3. Review the logs for details on scanned files and detected threats.

## File Structure

- `Program.cs`: Entry point of the application.
- `DatabaseScanner.cs`: Implements Stage 1 hash-based detection.
- `PatternScanner.cs`: Implements Stage 2 regex pattern scanning.
- `VirusTotalScanner.cs`: Implements Stage 3 TotalVirus API integration.
- `Quarantine.cs`: Handles quarantining of malicious files.
- `BatchDatabase.bav`: Contains known malicious hashes and their detection names.

## Contributing

Contributions are welcome! If you have suggestions, bug reports, or feature requests, please open an issue or submit a pull request.