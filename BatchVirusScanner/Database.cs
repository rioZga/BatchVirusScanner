using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BatchVirusScanner
{
    internal class Database
    {
        private Dictionary<string, string> _database = new Dictionary<string, string>();
        private string _databasePath = @"BatchDatabase.bav";

        public Database()
        {
            LoadDatabase(_databasePath);
        }

        private void LoadDatabase(string databasePath)
        {
            if (!File.Exists(databasePath))
            {
                Console.WriteLine("Virus database file not found!");
                return;
            }

            foreach (var line in File.ReadLines(databasePath))
            {
                var parts = line.Split(':');
                if (parts.Length == 2)
                {
                    string hash = parts[0].Trim();
                    string detectionName = parts[1].Trim();
                    _database[hash] = detectionName;
                }
            }
        }

        public Dictionary<string, string> getVirusDatabase()
        {
            return _database;
        }
    }
}
