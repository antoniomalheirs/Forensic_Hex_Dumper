using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.AccessControl;

namespace Hex_Dumper
{
    /// <summary>
    /// Comprehensive metadata extractor for forensic file analysis.
    /// Extracts file system info, hashes, hex dump, entropy, strings,
    /// PE headers, EXIF (via MetadataExtractor NuGet), PDF metadata, and ZIP contents.
    /// </summary>
    public static class MetadataExtractorModule
    {
        // ANSI color shortcuts
        private const string CYAN = "\u001b[1;36m";
        private const string YELLOW = "\u001b[1;33m";
        private const string GREEN = "\u001b[1;32m";
        private const string RED = "\u001b[1;31m";
        private const string WHITE = "\u001b[1;37m";
        private const string DIM = "\u001b[1;30m";
        private const string ORANGE = "\u001b[38;5;208m";
        private const string MAGENTA = "\u001b[1;35m";
        private const string RESET = "\u001b[0m";

        private const string TOOL_VERSION = "v2.0-FORENSIC";

        // Report buffer for export
        private static StringBuilder _reportBuffer = new StringBuilder();
        private static bool _captureReport = false;

        /// <summary>
        /// Run full forensic metadata extraction on a file.
        /// </summary>
        public static void ExtractAll(string filePath, string caseId = "", string examiner = "")
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"{RED}[!] File not found: {filePath}{RESET}");
                return;
            }

            _reportBuffer.Clear();
            _captureReport = true;

            // === FORENSIC REPORT HEADER ===
            PrintLine($"\n{YELLOW}{new string('=', 80)}{RESET}");
            PrintLine($"{CYAN}  SENTINEL DATA SOLUTIONS — FORENSIC FILE ANALYSIS REPORT{RESET}");
            PrintLine($"{YELLOW}{new string('=', 80)}{RESET}");
            PrintLine($"  {DIM}Tool Version  :{RESET} {WHITE}Hex Dumper {TOOL_VERSION}{RESET}");
            PrintLine($"  {DIM}Analysis Time :{RESET} {WHITE}{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC{RESET}");
            PrintLine($"  {DIM}               {RESET} {DIM}{DateTime.Now:yyyy-MM-dd HH:mm:ss zzz} (Local){RESET}");
            PrintLine($"  {DIM}Machine       :{RESET} {WHITE}{Environment.MachineName}{RESET}");
            PrintLine($"  {DIM}OS            :{RESET} {WHITE}{System.Runtime.InteropServices.RuntimeInformation.OSDescription}{RESET}");
            PrintLine($"  {DIM}User          :{RESET} {WHITE}{Environment.UserName}{RESET}");

            if (!string.IsNullOrWhiteSpace(caseId))
                PrintLine($"  {YELLOW}Case ID       :{RESET} {WHITE}{caseId}{RESET}");
            if (!string.IsNullOrWhiteSpace(examiner))
                PrintLine($"  {YELLOW}Examiner      :{RESET} {WHITE}{examiner}{RESET}");

            PrintLine($"  {DIM}Target File   :{RESET} {WHITE}{filePath}{RESET}");
            PrintLine($"{YELLOW}{new string('=', 80)}{RESET}");

            // Module 1: File System Info
            ExtractFileSystemInfo(filePath);

            // Module 2: Cryptographic Hashes
            ExtractHashes(filePath);

            // Module 3: Hex Dump (first 256 bytes)
            ExtractHexDump(filePath);

            // Module 4: Entropy Analysis
            ExtractEntropy(filePath);

            // Module 5: String Extraction
            ExtractStrings(filePath);

            // Module 6: PE Header (EXE/DLL)
            ExtractPEHeader(filePath);

            // Module 7: Embedded Metadata (EXIF, XMP, IPTC, ICC — runs on ALL files)
            ExtractEmbeddedMetadata(filePath);

            // Module 8: PDF Metadata
            ExtractPDFMetadata(filePath);

            // Module 9: ZIP/Archive Contents
            ExtractZipContents(filePath);

            // Module 10: Signature vs Extension Mismatch (FORENSIC)
            ExtractSignatureMismatch(filePath);

            // Module 11: NTFS Alternate Data Streams (FORENSIC)
            ExtractNTFSStreams(filePath);

            // Module 12: Byte Frequency Analysis (FORENSIC)
            ExtractByteFrequency(filePath);

            PrintLine($"\n{YELLOW}{new string('=', 80)}{RESET}");
            PrintLine($"{GREEN}  FORENSIC ANALYSIS COMPLETE{RESET}");
            PrintLine($"  {DIM}End Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC{RESET}");
            PrintLine($"{YELLOW}{new string('=', 80)}{RESET}");

            _captureReport = false;
        }

        /// <summary>
        /// Export the last analysis as a plain-text forensic report.
        /// </summary>
        public static string ExportReport(string filePath, string caseId, string examiner)
        {
            if (_reportBuffer.Length == 0)
                return null;

            // Strip ANSI codes for plain text
            string plainText = Regex.Replace(_reportBuffer.ToString(), @"\u001b\[[0-9;]*m", "");

            string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            string safeFileName = Path.GetFileNameWithoutExtension(filePath);
            string reportDir = Path.GetDirectoryName(filePath) ?? ".";
            string reportPath = Path.Combine(reportDir, $"FORENSIC_REPORT_{safeFileName}_{timestamp}.txt");

            var sb = new StringBuilder();
            sb.AppendLine(new string('=', 80));
            sb.AppendLine("  SENTINEL DATA SOLUTIONS — FORENSIC FILE ANALYSIS REPORT");
            sb.AppendLine(new string('=', 80));
            sb.AppendLine($"  Report Generated : {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"  Tool Version     : Hex Dumper {TOOL_VERSION}");
            sb.AppendLine($"  Case ID          : {(string.IsNullOrWhiteSpace(caseId) ? "N/A" : caseId)}");
            sb.AppendLine($"  Examiner         : {(string.IsNullOrWhiteSpace(examiner) ? "N/A" : examiner)}");
            sb.AppendLine($"  Machine          : {Environment.MachineName}");
            sb.AppendLine($"  OS               : {System.Runtime.InteropServices.RuntimeInformation.OSDescription}");
            sb.AppendLine($"  Operator         : {Environment.UserName}");
            sb.AppendLine($"  Target File      : {filePath}");
            sb.AppendLine(new string('=', 80));
            sb.AppendLine();
            sb.AppendLine("DISCLAIMER: This report was generated by an automated forensic analysis tool.");
            sb.AppendLine("The information contained herein should be verified by a qualified examiner.");
            sb.AppendLine("Chain of custody must be maintained for evidentiary purposes.");
            sb.AppendLine();
            sb.AppendLine(new string('-', 80));
            sb.AppendLine();
            sb.Append(plainText);
            sb.AppendLine();
            sb.AppendLine(new string('=', 80));
            sb.AppendLine("  END OF FORENSIC REPORT");
            sb.AppendLine(new string('=', 80));

            File.WriteAllText(reportPath, sb.ToString(), Encoding.UTF8);
            return reportPath;
        }

        // =====================================================================
        // MODULE 1: FILE SYSTEM INFO
        // =====================================================================
        private static void ExtractFileSystemInfo(string filePath)
        {
            PrintSectionHeader("FILE SYSTEM INFO", "1");

            try
            {
                var fi = new FileInfo(filePath);
                string sizeFormatted = FormatFileSize(fi.Length);

                PrintField("File Name", fi.Name);
                PrintField("Full Path", fi.FullName);
                PrintField("Directory", fi.DirectoryName ?? "N/A");
                PrintField("Size", $"{fi.Length:N0} bytes ({sizeFormatted})");
                PrintField("Created (Local)", fi.CreationTime.ToString("yyyy-MM-dd HH:mm:ss (zzz)"));
                PrintField("Created (UTC)", $"{fi.CreationTimeUtc:yyyy-MM-dd HH:mm:ss} UTC");
                PrintField("Modified (Local)", fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss (zzz)"));
                PrintField("Modified (UTC)", $"{fi.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC");
                PrintField("Accessed (Local)", fi.LastAccessTime.ToString("yyyy-MM-dd HH:mm:ss (zzz)"));
                PrintField("Accessed (UTC)", $"{fi.LastAccessTimeUtc:yyyy-MM-dd HH:mm:ss} UTC");
                PrintField("Extension", string.IsNullOrEmpty(fi.Extension) ? "(none)" : fi.Extension);

                // File Owner (NTFS)
                try
                {
                    var security = fi.GetAccessControl();
                    var owner = security.GetOwner(typeof(NTAccount));
                    PrintField("Owner (NTFS)", owner?.ToString() ?? "Unknown");
                }
                catch
                {
                    PrintField("Owner (NTFS)", $"{DIM}(not available){RESET}");
                }

                // Attributes
                var attrs = new List<string>();
                if ((fi.Attributes & FileAttributes.ReadOnly) != 0) attrs.Add("ReadOnly");
                if ((fi.Attributes & FileAttributes.Hidden) != 0) attrs.Add("Hidden");
                if ((fi.Attributes & FileAttributes.System) != 0) attrs.Add("System");
                if ((fi.Attributes & FileAttributes.Archive) != 0) attrs.Add("Archive");
                if ((fi.Attributes & FileAttributes.Compressed) != 0) attrs.Add("Compressed");
                if ((fi.Attributes & FileAttributes.Encrypted) != 0) attrs.Add("Encrypted");
                if ((fi.Attributes & FileAttributes.Temporary) != 0) attrs.Add("Temporary");
                if ((fi.Attributes & FileAttributes.Offline) != 0) attrs.Add("Offline");
                if ((fi.Attributes & FileAttributes.ReparsePoint) != 0) attrs.Add("ReparsePoint/Symlink");
                PrintField("Attributes", attrs.Count > 0 ? string.Join(", ", attrs) : "Normal");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  {RED}Error: {ex.Message}{RESET}");
            }
        }

        // =====================================================================
        // MODULE 2: CRYPTOGRAPHIC HASHES
        // =====================================================================
        private static void ExtractHashes(string filePath)
        {
            PrintSectionHeader("CRYPTOGRAPHIC HASHES", "2");

            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);

                using (var md5 = MD5.Create())
                    PrintField("MD5", BitConverter.ToString(md5.ComputeHash(fileBytes)).Replace("-", "").ToLowerInvariant());

                using (var sha1 = SHA1.Create())
                    PrintField("SHA-1", BitConverter.ToString(sha1.ComputeHash(fileBytes)).Replace("-", "").ToLowerInvariant());

                using (var sha256 = SHA256.Create())
                    PrintField("SHA-256", BitConverter.ToString(sha256.ComputeHash(fileBytes)).Replace("-", "").ToLowerInvariant());

                using (var sha512 = SHA512.Create())
                {
                    string hash = BitConverter.ToString(sha512.ComputeHash(fileBytes)).Replace("-", "").ToLowerInvariant();
                    // SHA-512 is long, wrap it
                    PrintField("SHA-512", hash.Substring(0, 64));
                    Console.WriteLine($"  {"",20}{DIM}{hash.Substring(64)}{RESET}");
                }

                // CRC32
                uint crc = Crc32(fileBytes);
                PrintField("CRC32", crc.ToString("X8"));

                // VirusTotal lookup
                string sha256hash = BitConverter.ToString(SHA256.Create().ComputeHash(fileBytes)).Replace("-", "").ToLowerInvariant();
                PrintLine($"\n  {CYAN}[VIRUSTOTAL LOOKUP]{RESET}");
                PrintLine($"  {DIM}Search this hash on VirusTotal to check for known malware:{RESET}");
                PrintLine($"  {GREEN}https://www.virustotal.com/gui/file/{sha256hash}{RESET}");
            }
            catch (OutOfMemoryException)
            {
                Console.WriteLine($"  {YELLOW}[!] File too large to hash in memory. Using stream mode...{RESET}");
                ExtractHashesStreamed(filePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  {RED}Error: {ex.Message}{RESET}");
            }
        }

        private static void ExtractHashesStreamed(string filePath)
        {
            try
            {
                using (var stream = File.OpenRead(filePath))
                {
                    using (var md5 = MD5.Create())
                    {
                        stream.Position = 0;
                        PrintField("MD5", BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "").ToLowerInvariant());
                    }
                    using (var sha1 = SHA1.Create())
                    {
                        stream.Position = 0;
                        PrintField("SHA-1", BitConverter.ToString(sha1.ComputeHash(stream)).Replace("-", "").ToLowerInvariant());
                    }
                    using (var sha256 = SHA256.Create())
                    {
                        stream.Position = 0;
                        PrintField("SHA-256", BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant());
                    }
                    using (var sha512 = SHA512.Create())
                    {
                        stream.Position = 0;
                        string hash = BitConverter.ToString(sha512.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                        PrintField("SHA-512", hash.Substring(0, 64));
                        Console.WriteLine($"  {"",20}{DIM}{hash.Substring(64)}{RESET}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  {RED}Error in streamed hashing: {ex.Message}{RESET}");
            }
        }

        private static uint Crc32(byte[] data)
        {
            uint[] table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint crc = i;
                for (int j = 0; j < 8; j++)
                    crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
                table[i] = crc;
            }
            uint result = 0xFFFFFFFF;
            foreach (byte b in data)
                result = table[(result ^ b) & 0xFF] ^ (result >> 8);
            return result ^ 0xFFFFFFFF;
        }

        // =====================================================================
        // MODULE 3: HEX DUMP
        // =====================================================================
        private static void ExtractHexDump(string filePath)
        {
            PrintSectionHeader("HEX DUMP (First 256 bytes)", "3");

            try
            {
                byte[] buffer = new byte[256];
                int bytesRead;
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    bytesRead = fs.Read(buffer, 0, buffer.Length);
                }

                if (bytesRead == 0)
                {
                    Console.WriteLine($"  {DIM}(empty file){RESET}");
                    return;
                }

                // Classic forensic hex dump format
                Console.WriteLine($"  {DIM}Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII{RESET}");
                Console.WriteLine($"  {DIM}{new string('-', 75)}{RESET}");

                for (int offset = 0; offset < bytesRead; offset += 16)
                {
                    StringBuilder hexPart = new StringBuilder();
                    StringBuilder asciiPart = new StringBuilder();

                    for (int i = 0; i < 16; i++)
                    {
                        if (i == 8) hexPart.Append(' ');

                        if (offset + i < bytesRead)
                        {
                            byte b = buffer[offset + i];
                            hexPart.Append($"{b:X2} ");
                            asciiPart.Append(b >= 32 && b < 127 ? (char)b : '.');
                        }
                        else
                        {
                            hexPart.Append("   ");
                            asciiPart.Append(' ');
                        }
                    }

                    Console.WriteLine($"  {ORANGE}{offset:X8}{RESET}  {hexPart}  {GREEN}{asciiPart}{RESET}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  {RED}Error: {ex.Message}{RESET}");
            }
        }

        // =====================================================================
        // MODULE 4: ENTROPY ANALYSIS
        // =====================================================================
        private static void ExtractEntropy(string filePath)
        {
            PrintSectionHeader("ENTROPY ANALYSIS", "4");

            try
            {
                byte[] data;
                long fileSize = new FileInfo(filePath).Length;

                if (fileSize == 0)
                {
                    PrintField("Entropy", "N/A (empty file)");
                    return;
                }

                // For very large files, sample first 1MB
                if (fileSize > 1024 * 1024)
                {
                    data = new byte[1024 * 1024];
                    using (var fs = File.OpenRead(filePath))
                        fs.Read(data, 0, data.Length);
                    Console.WriteLine($"  {DIM}(Sampled first 1 MB of {FormatFileSize(fileSize)} file){RESET}");
                }
                else
                {
                    data = File.ReadAllBytes(filePath);
                }

                double entropy = CalculateShannonEntropy(data);
                string classification = ClassifyEntropy(entropy);

                PrintField("Shannon Entropy", $"{entropy:F4} / 8.0000");
                PrintField("Classification", classification);

                // Visual entropy bar
                int barLength = 40;
                int filled = (int)Math.Round((entropy / 8.0) * barLength);
                string bar = new string('█', filled) + new string('░', barLength - filled);
                string barColor = entropy < 3.0 ? GREEN : entropy < 6.0 ? YELLOW : entropy < 7.5 ? ORANGE : RED;
                Console.WriteLine($"  {"Entropy Bar",-20}{barColor}[{bar}]{RESET} {entropy / 8.0 * 100:F1}%");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  {RED}Error: {ex.Message}{RESET}");
            }
        }

        private static double CalculateShannonEntropy(byte[] data)
        {
            int[] frequency = new int[256];
            foreach (byte b in data)
                frequency[b]++;

            double entropy = 0.0;
            double length = data.Length;

            for (int i = 0; i < 256; i++)
            {
                if (frequency[i] == 0) continue;
                double p = frequency[i] / length;
                entropy -= p * Math.Log(p, 2);
            }

            return entropy;
        }

        private static string ClassifyEntropy(double entropy)
        {
            if (entropy < 1.0) return $"{GREEN}Very Low{RESET} — Likely uniform/repetitive data (empty, null-padded)";
            if (entropy < 3.5) return $"{GREEN}Low{RESET} — Plain text, source code, structured data";
            if (entropy < 5.0) return $"{YELLOW}Medium{RESET} — Mixed content, some binary data";
            if (entropy < 6.5) return $"{YELLOW}Medium-High{RESET} — Binary executable, native code";
            if (entropy < 7.5) return $"{ORANGE}High{RESET} — Compressed data (ZIP, GZIP, PNG)";
            return $"{RED}Very High{RESET} — Encrypted or highly compressed (AES, random data)";
        }

        // =====================================================================
        // MODULE 5: STRING EXTRACTION
        // =====================================================================
        private static void ExtractStrings(string filePath)
        {
            PrintSectionHeader("STRING EXTRACTION (printable strings >= 4 chars)", "5");

            try
            {
                long fileSize = new FileInfo(filePath).Length;
                int maxBytesToScan = (int)Math.Min(fileSize, 512 * 1024); // Scan first 512KB

                byte[] data = new byte[maxBytesToScan];
                using (var fs = File.OpenRead(filePath))
                    fs.Read(data, 0, data.Length);

                if (fileSize > maxBytesToScan)
                    Console.WriteLine($"  {DIM}(Scanning first 512 KB of {FormatFileSize(fileSize)} file){RESET}");

                var strings = new List<(int Offset, string Value)>();
                StringBuilder current = new StringBuilder();
                int startOffset = 0;

                for (int i = 0; i < data.Length; i++)
                {
                    byte b = data[i];
                    if (b >= 32 && b < 127) // Printable ASCII
                    {
                        if (current.Length == 0) startOffset = i;
                        current.Append((char)b);
                    }
                    else
                    {
                        if (current.Length >= 4)
                        {
                            strings.Add((startOffset, current.ToString()));
                        }
                        current.Clear();
                    }
                }
                if (current.Length >= 4)
                    strings.Add((startOffset, current.ToString()));

                PrintField("Strings Found", strings.Count.ToString());

                if (strings.Count == 0)
                {
                    Console.WriteLine($"  {DIM}(no printable strings found){RESET}");
                    return;
                }

                // Show first 30 unique strings, sorted by length (most interesting first)
                int displayCount = Math.Min(30, strings.Count);
                var displayed = strings
                    .GroupBy(s => s.Value)
                    .Select(g => g.First())
                    .OrderByDescending(s => s.Value.Length)
                    .Take(displayCount)
                    .OrderBy(s => s.Offset)
                    .ToList();

                Console.WriteLine($"\n  {DIM}{"OFFSET",-10} {"STRING"}{RESET}");
                Console.WriteLine($"  {DIM}{new string('-', 60)}{RESET}");

                foreach (var s in displayed)
                {
                    string display = s.Value.Length > 70 ? s.Value.Substring(0, 67) + "..." : s.Value;
                    Console.WriteLine($"  {ORANGE}0x{s.Offset:X6}{RESET}   {WHITE}{display}{RESET}");
                }

                if (strings.Count > displayCount)
                    Console.WriteLine($"\n  {DIM}... and {strings.Count - displayCount} more strings{RESET}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  {RED}Error: {ex.Message}{RESET}");
            }
        }

        // =====================================================================
        // MODULE 6: PE HEADER (EXE/DLL)
        // =====================================================================
        private static void ExtractPEHeader(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (ext != ".exe" && ext != ".dll" && ext != ".sys" && ext != ".ocx" && ext != ".scr")
                return;

            PrintSectionHeader("PE HEADER ANALYSIS", "6");

            try
            {
                byte[] data;
                long fileSize = new FileInfo(filePath).Length;
                int readSize = (int)Math.Min(fileSize, 4096);
                data = new byte[readSize];
                using (var fs = File.OpenRead(filePath))
                    fs.Read(data, 0, data.Length);

                // Check MZ signature
                if (data.Length < 64 || data[0] != 0x4D || data[1] != 0x5A)
                {
                    Console.WriteLine($"  {RED}Not a valid PE file (missing MZ header){RESET}");
                    return;
                }

                // PE offset is at 0x3C
                int peOffset = BitConverter.ToInt32(data, 0x3C);
                if (peOffset < 0 || peOffset + 24 >= data.Length)
                {
                    Console.WriteLine($"  {RED}Invalid PE offset{RESET}");
                    return;
                }

                // Verify PE\0\0 signature
                if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45 ||
                    data[peOffset + 2] != 0x00 || data[peOffset + 3] != 0x00)
                {
                    Console.WriteLine($"  {RED}Invalid PE signature{RESET}");
                    return;
                }

                PrintField("PE Signature", "Valid (PE\\0\\0)");

                // COFF Header (20 bytes starting at peOffset+4)
                int coffOffset = peOffset + 4;
                ushort machine = BitConverter.ToUInt16(data, coffOffset);
                ushort numSections = BitConverter.ToUInt16(data, coffOffset + 2);
                uint timestamp = BitConverter.ToUInt32(data, coffOffset + 4);
                ushort optionalSize = BitConverter.ToUInt16(data, coffOffset + 16);
                ushort characteristics = BitConverter.ToUInt16(data, coffOffset + 18);

                string machineStr = machine switch
                {
                    0x014C => "x86 (i386)",
                    0x0200 => "IA64 (Itanium)",
                    0x8664 => "x64 (AMD64)",
                    0xAA64 => "ARM64",
                    0x01C0 => "ARM",
                    0x01C4 => "ARMv7 Thumb-2",
                    _ => $"Unknown (0x{machine:X4})"
                };

                PrintField("Architecture", machineStr);
                PrintField("Sections", numSections.ToString());

                // Timestamp
                DateTimeOffset compileTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
                PrintField("Compile Time", compileTime.ToString("yyyy-MM-dd HH:mm:ss UTC"));

                // Characteristics
                var chars = new List<string>();
                if ((characteristics & 0x0002) != 0) chars.Add("EXECUTABLE");
                if ((characteristics & 0x0020) != 0) chars.Add("LARGE_ADDRESS_AWARE");
                if ((characteristics & 0x2000) != 0) chars.Add("DLL");
                if ((characteristics & 0x0100) != 0) chars.Add("32BIT_MACHINE");
                if ((characteristics & 0x0001) != 0) chars.Add("RELOCS_STRIPPED");
                if ((characteristics & 0x0004) != 0) chars.Add("LINE_NUMS_STRIPPED");
                if ((characteristics & 0x0200) != 0) chars.Add("DEBUG_STRIPPED");
                PrintField("Characteristics", string.Join(" | ", chars));

                // Optional Header
                int optOffset = coffOffset + 20;
                if (optionalSize > 0 && optOffset + 2 < data.Length)
                {
                    ushort magic = BitConverter.ToUInt16(data, optOffset);
                    string peType = magic switch
                    {
                        0x10B => "PE32 (32-bit)",
                        0x20B => "PE32+ (64-bit)",
                        0x107 => "ROM Image",
                        _ => $"Unknown (0x{magic:X4})"
                    };
                    PrintField("PE Type", peType);

                    // Entry point
                    if (optOffset + 20 < data.Length)
                    {
                        uint entryPoint = BitConverter.ToUInt32(data, optOffset + 16);
                        PrintField("Entry Point", $"0x{entryPoint:X8}");
                    }

                    // Subsystem
                    int subsysOffset = magic == 0x20B ? optOffset + 68 : optOffset + 68;
                    if (subsysOffset + 2 <= data.Length)
                    {
                        ushort subsystem = BitConverter.ToUInt16(data, subsysOffset);
                        string subsysStr = subsystem switch
                        {
                            1 => "Native",
                            2 => "Windows GUI",
                            3 => "Windows Console (CUI)",
                            5 => "OS/2 Console",
                            7 => "POSIX Console",
                            9 => "Windows CE GUI",
                            10 => "EFI Application",
                            11 => "EFI Boot Service Driver",
                            12 => "EFI Runtime Driver",
                            13 => "EFI ROM",
                            14 => "Xbox",
                            16 => "Windows Boot Application",
                            _ => $"Unknown ({subsystem})"
                        };
                        PrintField("Subsystem", subsysStr);
                    }
                }

                // Section table
                int sectionTableOffset = coffOffset + 20 + optionalSize;
                if (numSections > 0 && sectionTableOffset + (numSections * 40) <= data.Length)
                {
                    Console.WriteLine($"\n  {DIM}{"SECTION",-10} {"VirtSize",10} {"VirtAddr",10} {"RawSize",10} {"RawAddr",10} {"Flags"}{RESET}");
                    Console.WriteLine($"  {DIM}{new string('-', 65)}{RESET}");

                    for (int i = 0; i < numSections && i < 20; i++) // Cap at 20
                    {
                        int secOff = sectionTableOffset + (i * 40);
                        if (secOff + 40 > data.Length) break;

                        string name = Encoding.ASCII.GetString(data, secOff, 8).TrimEnd('\0');
                        uint virtualSize = BitConverter.ToUInt32(data, secOff + 8);
                        uint virtualAddr = BitConverter.ToUInt32(data, secOff + 12);
                        uint rawSize = BitConverter.ToUInt32(data, secOff + 16);
                        uint rawAddr = BitConverter.ToUInt32(data, secOff + 20);
                        uint flags = BitConverter.ToUInt32(data, secOff + 36);

                        var flagList = new List<string>();
                        if ((flags & 0x20) != 0) flagList.Add("CODE");
                        if ((flags & 0x40) != 0) flagList.Add("IDATA");
                        if ((flags & 0x80) != 0) flagList.Add("UDATA");
                        if ((flags & 0x20000000) != 0) flagList.Add("EXEC");
                        if ((flags & 0x40000000) != 0) flagList.Add("READ");
                        if ((flags & 0x80000000u) != 0) flagList.Add("WRITE");

                        Console.WriteLine($"  {WHITE}{name,-10}{RESET} {virtualSize,10:X8} {virtualAddr,10:X8} {rawSize,10:X8} {rawAddr,10:X8} {DIM}{string.Join("|", flagList)}{RESET}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  {RED}Error: {ex.Message}{RESET}");
            }
        }

        // =====================================================================
        // MODULE 7: IMAGE / EXIF METADATA (via MetadataExtractor NuGet)
        // =====================================================================
        private static void ExtractEmbeddedMetadata(string filePath)
        {
            PrintSectionHeader("EMBEDDED METADATA (EXIF / XMP / IPTC / ICC / ID3 / QuickTime)", "7");
            Console.WriteLine($"  {DIM}Using MetadataExtractor library — supports JPEG, PNG, GIF, TIFF, WebP,{RESET}");
            Console.WriteLine($"  {DIM}HEIF, AVIF, MP4, MOV, AVI, WAV, MP3, PDF, PSD, ICO, PCX, and more.{RESET}");

            try
            {
                var directories = MetadataExtractor.ImageMetadataReader.ReadMetadata(filePath);

                // === GPS HIGHLIGHT ===
                var gpsDir = directories.OfType<MetadataExtractor.Formats.Exif.GpsDirectory>().FirstOrDefault();
                if (gpsDir != null)
                {
                    Console.WriteLine($"\n  {RED}{'=',0}{new string('=', 50)}{RESET}");
                    Console.WriteLine($"  {RED}  !! GEOLOCATION DATA FOUND !!{RESET}");
                    Console.WriteLine($"  {RED}{new string('=', 50)}{RESET}");

                    var location = gpsDir.GetGeoLocation();
                    if (location != null)
                    {
                        PrintField("  Latitude", $"{location.Latitude:F6}°");
                        PrintField("  Longitude", $"{location.Longitude:F6}°");
                        PrintField("  Google Maps", $"{GREEN}https://www.google.com/maps?q={location.Latitude:F6},{location.Longitude:F6}{RESET}");
                    }

                    foreach (var tag in gpsDir.Tags)
                    {
                        string desc = tag.Description ?? "(null)";
                        PrintField($"  GPS {tag.Name}", desc);
                    }
                    Console.WriteLine($"  {RED}{new string('=', 50)}{RESET}");
                }
                else
                {
                    Console.WriteLine($"\n  {DIM}GPS/Geolocation: Not present in this file{RESET}");
                }

                // === KEY CAMERA/MEDIA INFO SUMMARY ===
                var exifIfd0 = directories.OfType<MetadataExtractor.Formats.Exif.ExifIfd0Directory>().FirstOrDefault();
                var exifSub = directories.OfType<MetadataExtractor.Formats.Exif.ExifSubIfdDirectory>().FirstOrDefault();

                if (exifIfd0 != null || exifSub != null)
                {
                    Console.WriteLine($"\n  {CYAN}[KEY CAMERA INFO]{RESET}");

                    if (exifIfd0 != null)
                    {
                        PrintTagIfPresent(exifIfd0, "Make", "Camera Make");
                        PrintTagIfPresent(exifIfd0, "Model", "Camera Model");
                        PrintTagIfPresent(exifIfd0, "Software", "Software");
                        PrintTagIfPresent(exifIfd0, "Date/Time", "Date/Time");
                        PrintTagIfPresent(exifIfd0, "Artist", "Artist/Author");
                        PrintTagIfPresent(exifIfd0, "Copyright", "Copyright");
                        PrintTagIfPresent(exifIfd0, "Image Description", "Description");
                    }
                    if (exifSub != null)
                    {
                        PrintTagIfPresent(exifSub, "Date/Time Original", "Date Taken");
                        PrintTagIfPresent(exifSub, "ISO Speed Ratings", "ISO");
                        PrintTagIfPresent(exifSub, "Exposure Time", "Exposure Time");
                        PrintTagIfPresent(exifSub, "F-Number", "F-Number");
                        PrintTagIfPresent(exifSub, "Focal Length", "Focal Length");
                        PrintTagIfPresent(exifSub, "Flash", "Flash");
                        PrintTagIfPresent(exifSub, "White Balance Mode", "White Balance");
                        PrintTagIfPresent(exifSub, "Exposure Program", "Exposure Program");
                        PrintTagIfPresent(exifSub, "Metering Mode", "Metering Mode");
                        PrintTagIfPresent(exifSub, "Lens Model", "Lens Model");
                        PrintTagIfPresent(exifSub, "Lens Make", "Lens Make");
                        PrintTagIfPresent(exifSub, "Image Width", "Image Width");
                        PrintTagIfPresent(exifSub, "Image Height", "Image Height");
                        PrintTagIfPresent(exifSub, "Exif Image Width", "Exif Image Width");
                        PrintTagIfPresent(exifSub, "Exif Image Height", "Exif Image Height");
                        PrintTagIfPresent(exifSub, "Color Space", "Color Space");
                        PrintTagIfPresent(exifSub, "Unique Image ID", "Unique Image ID");
                    }
                }

                // === FULL TAG DUMP ===
                int totalTags = 0;
                foreach (var directory in directories)
                {
                    if (!directory.Tags.Any()) continue;
                    // Skip GPS (already shown above)
                    if (directory is MetadataExtractor.Formats.Exif.GpsDirectory) continue;

                    Console.WriteLine($"\n  {CYAN}[{directory.Name}]{RESET}");

                    foreach (var tag in directory.Tags)
                    {
                        string desc = tag.Description ?? "(null)";
                        if (desc.Length > 80) desc = desc.Substring(0, 77) + "...";
                        Console.WriteLine($"    {WHITE}{tag.Name,-35}{RESET} {desc}");
                        totalTags++;
                    }
                }

                if (totalTags == 0)
                {
                    Console.WriteLine($"  {DIM}(no EXIF/metadata tags found){RESET}");
                }
                else
                {
                    Console.WriteLine($"\n  {GREEN}Total metadata tags extracted: {totalTags}{RESET}");
                }
            }
            catch (MetadataExtractor.ImageProcessingException)
            {
                Console.WriteLine($"  {DIM}(format not recognized by MetadataExtractor — no embedded metadata){RESET}");
            }
            catch (IOException)
            {
                Console.WriteLine($"  {DIM}(unable to read file for metadata extraction){RESET}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  {DIM}(no embedded metadata found: {ex.Message}){RESET}");
            }
        }

        private static void PrintTagIfPresent(MetadataExtractor.Directory dir, string tagName, string displayName)
        {
            var tag = dir.Tags.FirstOrDefault(t => t.Name == tagName);
            if (tag != null && !string.IsNullOrWhiteSpace(tag.Description))
            {
                PrintField($"  {displayName}", tag.Description);
            }
        }

        // =====================================================================
        // MODULE 8: PDF METADATA
        // =====================================================================
        private static void ExtractPDFMetadata(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (ext != ".pdf") return;

            PrintSectionHeader("PDF METADATA", "8");

            try
            {
                byte[] rawBytes = File.ReadAllBytes(filePath);
                string content = Encoding.Latin1.GetString(rawBytes);

                // --- PDF Version ---
                var versionMatch = Regex.Match(content, @"%PDF-(\d+\.\d+)");
                PrintField("PDF Version", versionMatch.Success ? versionMatch.Groups[1].Value : $"{DIM}Not found{RESET}");

                // --- All Info Dictionary Fields ---
                string[] pdfFields = { "Title", "Author", "Subject", "Keywords", "Creator",
                                       "Producer", "CreationDate", "ModDate", "Trapped" };

                foreach (string field in pdfFields)
                {
                    string value = ExtractPDFField(content, field);
                    if (value != null)
                    {
                        if ((field == "CreationDate" || field == "ModDate") && value.StartsWith("D:"))
                            value = FormatPDFDate(value);
                        PrintField(field, value);
                    }
                    else
                    {
                        PrintField(field, $"{DIM}(not present in this PDF){RESET}");
                    }
                }

                // --- Page Count ---
                var pageCountMatch = Regex.Match(content, @"/Count\s+(\d+)");
                if (pageCountMatch.Success)
                    PrintField("Pages", pageCountMatch.Groups[1].Value);
                else
                {
                    var pageMatches = Regex.Matches(content, @"/Type\s*/Page[^s]");
                    PrintField("Pages (approx)", pageMatches.Count > 0 ? pageMatches.Count.ToString() : $"{DIM}Unknown{RESET}");
                }

                // --- Page Dimensions (MediaBox) ---
                var mediaBoxMatch = Regex.Match(content, @"/MediaBox\s*\[([^\]]+)\]");
                if (mediaBoxMatch.Success)
                {
                    string mb = mediaBoxMatch.Groups[1].Value.Trim();
                    var parts = mb.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 4)
                    {
                        if (double.TryParse(parts[2], System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out double w) &&
                            double.TryParse(parts[3], System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out double h))
                        {
                            double widthMM = w * 25.4 / 72.0;
                            double heightMM = h * 25.4 / 72.0;
                            PrintField("Page Size", $"{w} x {h} pts ({widthMM:F0} x {heightMM:F0} mm)");
                        }
                        else
                        {
                            PrintField("MediaBox", mb);
                        }
                    }
                }

                // --- Security & Features ---
                PrintField("Encryption", content.Contains("/Encrypt")
                    ? $"{RED}File is encrypted/password-protected{RESET}"
                    : $"{GREEN}None{RESET}");

                PrintField("Linearized", content.Contains("/Linearized")
                    ? $"{GREEN}Yes (optimized for fast web view){RESET}"
                    : "No");

                PrintField("Tagged PDF", content.Contains("/MarkInfo")
                    ? $"{GREEN}Yes (accessible){RESET}"
                    : "No");

                PrintField("Has Forms", content.Contains("/AcroForm")
                    ? $"{YELLOW}Yes (contains AcroForm){RESET}"
                    : "No");

                PrintField("JavaScript", content.Contains("/JavaScript") || content.Contains("/JS ")
                    ? $"{RED}Yes (contains executable scripts!){RESET}"
                    : "No");

                PrintField("Embedded Files", content.Contains("/EmbeddedFiles")
                    ? $"{YELLOW}Yes (file attachments present){RESET}"
                    : "No");

                // --- Font list ---
                var fontMatches = Regex.Matches(content, @"/BaseFont\s*/([^\s/\]>]+)");
                if (fontMatches.Count > 0)
                {
                    var fonts = fontMatches.Cast<Match>()
                        .Select(m => m.Groups[1].Value.Replace("+", " → "))
                        .Distinct()
                        .ToList();
                    PrintField("Fonts", $"{fonts.Count} font(s)");
                    foreach (var font in fonts.Take(15))
                        Console.WriteLine($"  {DIM}                     • {font}{RESET}");
                    if (fonts.Count > 15)
                        Console.WriteLine($"  {DIM}                     ... and {fonts.Count - 15} more{RESET}");
                }

                PrintField("File Size", FormatFileSize(rawBytes.Length));

                // --- XMP Extraction via MetadataExtractor NuGet (bonus) ---
                try
                {
                    Console.WriteLine($"\n  {CYAN}[XMP / EXTENDED METADATA via MetadataExtractor]{RESET}");
                    var directories = MetadataExtractor.ImageMetadataReader.ReadMetadata(filePath);
                    int xmpTags = 0;
                    foreach (var directory in directories)
                    {
                        if (!directory.Tags.Any()) continue;
                        Console.WriteLine($"\n  {CYAN}[{directory.Name}]{RESET}");
                        foreach (var tag in directory.Tags)
                        {
                            string desc = tag.Description ?? "(null)";
                            if (desc.Length > 80) desc = desc.Substring(0, 77) + "...";
                            Console.WriteLine($"    {WHITE}{tag.Name,-35}{RESET} {desc}");
                            xmpTags++;
                        }
                    }
                    if (xmpTags == 0)
                        Console.WriteLine($"  {DIM}(no XMP metadata found){RESET}");
                    else
                        Console.WriteLine($"\n  {GREEN}Extended metadata tags: {xmpTags}{RESET}");
                }
                catch
                {
                    Console.WriteLine($"  {DIM}(XMP extraction not available for this PDF){RESET}");
                }
            }
            catch (OutOfMemoryException)
            {
                Console.WriteLine($"  {YELLOW}[!] PDF too large to parse in memory{RESET}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  {RED}Error: {ex.Message}{RESET}");
            }
        }

        /// <summary>
        /// Extract a field value from PDF Info dictionary.
        /// Handles both literal string /Field (value) and hex string /Field <FEFF...> patterns.
        /// </summary>
        private static string? ExtractPDFField(string content, string field)
        {
            // Try literal string: /Author (Some Value)
            var match = Regex.Match(content, @"/" + field + @"\s*\(([^)]*)\)");
            if (match.Success)
                return match.Groups[1].Value;

            // Try hex string: /Author <FEFF0041...>
            var hexMatch = Regex.Match(content, @"/" + field + @"\s*<([^>]+)>");
            if (hexMatch.Success)
            {
                string hexVal = hexMatch.Groups[1].Value;
                try
                {
                    byte[] bytes = Enumerable.Range(0, hexVal.Length / 2)
                        .Select(i => Convert.ToByte(hexVal.Substring(i * 2, 2), 16))
                        .ToArray();
                    if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
                        return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);
                    else
                        return Encoding.UTF8.GetString(bytes);
                }
                catch { return $"(hex) {hexVal}"; }
            }

            return null;
        }

        private static string FormatPDFDate(string pdfDate)
        {
            try
            {
                string d = pdfDate.Replace("D:", "").Replace("'", "");
                if (d.Length >= 14)
                {
                    string formatted = $"{d.Substring(0, 4)}-{d.Substring(4, 2)}-{d.Substring(6, 2)} " +
                                       $"{d.Substring(8, 2)}:{d.Substring(10, 2)}:{d.Substring(12, 2)}";
                    if (d.Length > 14)
                        formatted += $" ({d.Substring(14)})";
                    return formatted;
                }
                return pdfDate;
            }
            catch { return pdfDate; }
        }

        // =====================================================================
        // MODULE 9: ZIP / ARCHIVE CONTENTS
        // =====================================================================
        private static void ExtractZipContents(string filePath)
        {
            // Check if the file is a ZIP-based format
            try
            {
                byte[] header = new byte[4];
                using (var fs = File.OpenRead(filePath))
                    fs.Read(header, 0, 4);

                // PK signature
                if (header[0] != 0x50 || header[1] != 0x4B)
                    return;
            }
            catch { return; }

            PrintSectionHeader("ZIP / ARCHIVE CONTENTS", "9");

            try
            {
                using (var zip = ZipFile.OpenRead(filePath))
                {
                    PrintField("Total Entries", zip.Entries.Count.ToString());

                    long totalUncompressed = 0;
                    long totalCompressed = 0;
                    int directories = 0;
                    int files = 0;

                    foreach (var entry in zip.Entries)
                    {
                        if (string.IsNullOrEmpty(entry.Name))
                            directories++;
                        else
                        {
                            files++;
                            totalUncompressed += entry.Length;
                            totalCompressed += entry.CompressedLength;
                        }
                    }

                    PrintField("Files", files.ToString());
                    PrintField("Directories", directories.ToString());
                    PrintField("Uncompressed", FormatFileSize(totalUncompressed));
                    PrintField("Compressed", FormatFileSize(totalCompressed));

                    if (totalUncompressed > 0)
                    {
                        double ratio = (1.0 - (double)totalCompressed / totalUncompressed) * 100;
                        PrintField("Compression Ratio", $"{ratio:F1}%");
                    }

                    // List entries (cap at 40 for readability)
                    Console.WriteLine($"\n  {DIM}{"#",-5} {"SIZE",10} {"COMPRESSED",12} {"RATIO",7} {"NAME"}{RESET}");
                    Console.WriteLine($"  {DIM}{new string('-', 75)}{RESET}");

                    int shown = 0;
                    foreach (var entry in zip.Entries.OrderBy(e => e.FullName))
                    {
                        if (string.IsNullOrEmpty(entry.Name)) continue; // Skip directories
                        if (shown >= 40)
                        {
                            Console.WriteLine($"  {DIM}... and {files - 40} more files{RESET}");
                            break;
                        }

                        string ratio = entry.Length > 0
                            ? $"{(1.0 - (double)entry.CompressedLength / entry.Length) * 100:F0}%"
                            : "-";

                        string name = entry.FullName;
                        if (name.Length > 45) name = "..." + name.Substring(name.Length - 42);

                        Console.WriteLine($"  {shown + 1,-5} {FormatFileSize(entry.Length),10} {FormatFileSize(entry.CompressedLength),12} {ratio,7} {WHITE}{name}{RESET}");
                        shown++;
                    }
                }
            }
            catch (InvalidDataException)
            {
                Console.WriteLine($"  {YELLOW}[!] Archive appears corrupted or uses unsupported compression{RESET}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  {RED}Error: {ex.Message}{RESET}");
            }
        }

        // =====================================================================
        // MODULE 10: SIGNATURE VS EXTENSION MISMATCH (FORENSIC)
        // =====================================================================
        private static void ExtractSignatureMismatch(string filePath)
        {
            PrintSectionHeader("SIGNATURE vs EXTENSION MISMATCH DETECTION", "10");
            PrintLine($"  {DIM}Anti-forensic technique: renaming files to hide their true type{RESET}");

            try
            {
                string actualExt = Path.GetExtension(filePath).ToLowerInvariant();

                byte[] buffer = new byte[4096];
                int bytesRead;
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    bytesRead = fs.Read(buffer, 0, buffer.Length);

                if (bytesRead == 0)
                {
                    PrintLine($"  {DIM}(empty file — no signature to check){RESET}");
                    return;
                }

                // Build hex string of first bytes for matching
                string hexHeader = BitConverter.ToString(buffer, 0, Math.Min(bytesRead, 32)).Replace("-", "");

                // Known signatures to check against
                var signatureDB = new List<(string Name, string Hex, string[] Extensions)>
                {
                    ("JPEG Image", "FFD8FF", new[] { ".jpg", ".jpeg", ".jfif" }),
                    ("PNG Image", "89504E47", new[] { ".png" }),
                    ("GIF Image", "474946383", new[] { ".gif" }),
                    ("PDF Document", "25504446", new[] { ".pdf" }),
                    ("ZIP Archive", "504B0304", new[] { ".zip", ".apk", ".epub", ".docx", ".xlsx", ".pptx", ".jar", ".odt", ".ods", ".kwgt", ".klwp", ".mtz", ".xpi", ".nupkg" }),
                    ("RAR Archive", "526172211A07", new[] { ".rar" }),
                    ("7-Zip Archive", "377ABCAF271C", new[] { ".7z" }),
                    ("GZIP Archive", "1F8B", new[] { ".gz", ".tgz" }),
                    ("PE Executable", "4D5A", new[] { ".exe", ".dll", ".sys", ".scr", ".ocx", ".drv" }),
                    ("ELF Binary", "7F454C46", new[] { "", ".so", ".o", ".elf" }),
                    ("Mach-O Binary", "FEEDFACE", new[] { "", ".dylib" }),
                    ("BMP Image", "424D", new[] { ".bmp", ".dib" }),
                    ("TIFF Image", "49492A00", new[] { ".tif", ".tiff" }),
                    ("TIFF Image (BE)", "4D4D002A", new[] { ".tif", ".tiff" }),
                    ("WebP Image", "52494646", new[] { ".webp", ".wav", ".avi" }),
                    ("MP3 Audio (ID3)", "494433", new[] { ".mp3" }),
                    ("MP3 Audio (Sync)", "FFFB", new[] { ".mp3" }),
                    ("FLAC Audio", "664C6143", new[] { ".flac" }),
                    ("OGG Container", "4F676753", new[] { ".ogg", ".oga", ".ogv", ".opus" }),
                    ("WAV Audio", "52494646", new[] { ".wav" }),
                    ("MP4 Video", "00000018667479706D70", new[] { ".mp4", ".m4a", ".m4v" }),
                    ("MP4/MOV", "66747970", new[] { ".mp4", ".mov", ".m4a", ".m4v", ".3gp" }),
                    ("SQLite DB", "53514C69746520666F726D6174", new[] { ".sqlite", ".db", ".sqlite3" }),
                    ("Windows Shortcut", "4C00000001140200", new[] { ".lnk" }),
                    ("ISO Disc Image", "4344303031", new[] { ".iso" }),
                };

                string detectedType = null;
                string[] expectedExts = null;
                bool mismatchFound = false;

                foreach (var sig in signatureDB)
                {
                    if (hexHeader.StartsWith(sig.Hex, StringComparison.OrdinalIgnoreCase))
                    {
                        detectedType = sig.Name;
                        expectedExts = sig.Extensions;

                        if (!sig.Extensions.Contains(actualExt))
                        {
                            mismatchFound = true;
                        }
                        break;
                    }
                }

                // Special check for ftyp at offset 4 (MP4/MOV)
                if (detectedType == null && bytesRead > 8)
                {
                    string offset4 = BitConverter.ToString(buffer, 4, Math.Min(4, bytesRead - 4)).Replace("-", "");
                    if (offset4.StartsWith("66747970", StringComparison.OrdinalIgnoreCase))
                    {
                        detectedType = "MP4/MOV Video";
                        expectedExts = new[] { ".mp4", ".mov", ".m4a", ".m4v", ".3gp", ".avif", ".heic" };
                        if (!expectedExts.Contains(actualExt))
                            mismatchFound = true;
                    }
                }

                PrintField("File Extension", string.IsNullOrEmpty(actualExt) ? "(none)" : actualExt);
                PrintField("Detected Signature", detectedType ?? $"{DIM}(not in mismatch database){RESET}");

                if (mismatchFound)
                {
                    PrintLine($"\n  {RED}{new string('!', 60)}{RESET}");
                    PrintLine($"  {RED}  !! MISMATCH DETECTED — POSSIBLE ANTI-FORENSIC ACTIVITY !!{RESET}");
                    PrintLine($"  {RED}{new string('!', 60)}{RESET}");
                    PrintLine($"  {RED}  File claims to be  : {actualExt}{RESET}");
                    PrintLine($"  {RED}  Actually contains  : {detectedType}{RESET}");
                    PrintLine($"  {RED}  Expected extensions: {string.Join(", ", expectedExts)}{RESET}");
                    PrintLine($"  {RED}{new string('!', 60)}{RESET}");
                }
                else if (detectedType != null)
                {
                    PrintLine($"\n  {GREEN}[✓] MATCH — File extension is consistent with its signature.{RESET}");
                    PrintLine($"  {GREEN}    No anti-forensic file renaming detected.{RESET}");
                }
                else
                {
                    PrintLine($"\n  {YELLOW}[?] Signature not in mismatch database — manual verification recommended.{RESET}");
                }
            }
            catch (Exception ex)
            {
                PrintLine($"  {RED}Error: {ex.Message}{RESET}");
            }
        }

        // =====================================================================
        // MODULE 11: NTFS ALTERNATE DATA STREAMS (FORENSIC)
        // =====================================================================
        private static void ExtractNTFSStreams(string filePath)
        {
            PrintSectionHeader("NTFS ALTERNATE DATA STREAMS (ADS)", "11");
            PrintLine($"  {DIM}ADS can hide data within files on NTFS volumes without changing file size.{RESET}");
            PrintLine($"  {DIM}Technique used by malware, steganography, and anti-forensic tools.{RESET}");

            try
            {
                // Use dir /R to detect ADS on Windows
                if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                    System.Runtime.InteropServices.OSPlatform.Windows))
                {
                    PrintLine($"  {DIM}(ADS detection only available on Windows/NTFS){RESET}");
                    return;
                }

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c dir /R \"{filePath}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit(5000);

                    // Parse for ADS entries (lines containing :$DATA that aren't the main stream)
                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    var adsEntries = new List<string>();

                    string fileName = Path.GetFileName(filePath);
                    foreach (var line in lines)
                    {
                        string trimmed = line.Trim();
                        // ADS lines typically show as:  size filename:streamname:$DATA
                        if (trimmed.Contains(":$DATA") && !trimmed.EndsWith("::$DATA"))
                        {
                            adsEntries.Add(trimmed);
                        }
                    }

                    if (adsEntries.Count > 0)
                    {
                        PrintLine($"\n  {RED}{new string('!', 60)}{RESET}");
                        PrintLine($"  {RED}  !! ALTERNATE DATA STREAMS DETECTED !!{RESET}");
                        PrintLine($"  {RED}{new string('!', 60)}{RESET}");
                        PrintField("ADS Count", adsEntries.Count.ToString());

                        foreach (var ads in adsEntries)
                        {
                            PrintLine($"  {RED}  → {ads}{RESET}");
                        }
                        PrintLine($"  {RED}{new string('!', 60)}{RESET}");
                        PrintLine($"  {YELLOW}  To read ADS content: more < \"{filePath}:stream_name\"{RESET}");
                    }
                    else
                    {
                        PrintLine($"\n  {GREEN}[✓] No Alternate Data Streams found.{RESET}");
                        PrintLine($"  {GREEN}    File contains only its primary data stream.{RESET}");
                    }
                }

                // Also check Zone.Identifier (Download origin marker)
                string zoneFile = filePath + ":Zone.Identifier";
                try
                {
                    if (File.Exists(zoneFile) || File.OpenRead(zoneFile) != null)
                    {
                        // This won't work via File.Exists, let's try reading
                    }
                }
                catch { /* Zone.Identifier not accessible, normal */ }

                // Try reading Zone.Identifier directly
                try
                {
                    using (var fs = new FileStream(filePath + ":Zone.Identifier", FileMode.Open, FileAccess.Read))
                    {
                        byte[] zoneData = new byte[512];
                        int read = fs.Read(zoneData, 0, zoneData.Length);
                        if (read > 0)
                        {
                            string zoneContent = Encoding.UTF8.GetString(zoneData, 0, read);
                            PrintLine($"\n  {YELLOW}[ZONE IDENTIFIER — Download Origin]{RESET}");

                            var zoneLines = zoneContent.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                            foreach (var zl in zoneLines)
                            {
                                string zt = zl.Trim();
                                if (zt.StartsWith("ZoneId="))
                                {
                                    string zoneId = zt.Replace("ZoneId=", "");
                                    string zoneName = zoneId switch
                                    {
                                        "0" => "Local Machine",
                                        "1" => "Local Intranet",
                                        "2" => "Trusted Sites",
                                        "3" => "Internet",
                                        "4" => "Restricted Sites",
                                        _ => $"Unknown ({zoneId})"
                                    };
                                    PrintField("  Zone ID", $"{zoneId} ({zoneName})");
                                }
                                else if (zt.StartsWith("ReferrerUrl="))
                                    PrintField("  Referrer URL", zt.Replace("ReferrerUrl=", ""));
                                else if (zt.StartsWith("HostUrl="))
                                    PrintField("  Download URL", zt.Replace("HostUrl=", ""));
                            }
                        }
                    }
                }
                catch { /* No Zone.Identifier — file wasn't downloaded from internet or was unblocked */ }
            }
            catch (Exception ex)
            {
                PrintLine($"  {RED}Error: {ex.Message}{RESET}");
            }
        }

        // =====================================================================
        // MODULE 12: BYTE FREQUENCY ANALYSIS (FORENSIC)
        // =====================================================================
        private static void ExtractByteFrequency(string filePath)
        {
            PrintSectionHeader("BYTE FREQUENCY ANALYSIS", "12");
            PrintLine($"  {DIM}Byte distribution profile reveals file content characteristics.{RESET}");

            try
            {
                long fileSize = new FileInfo(filePath).Length;
                if (fileSize == 0)
                {
                    PrintLine($"  {DIM}(empty file){RESET}");
                    return;
                }

                int sampleSize = (int)Math.Min(fileSize, 1024 * 1024); // 1MB sample
                byte[] data = new byte[sampleSize];
                using (var fs = File.OpenRead(filePath))
                    fs.Read(data, 0, data.Length);

                if (fileSize > sampleSize)
                    PrintLine($"  {DIM}(Sampled first 1 MB of {FormatFileSize(fileSize)} file){RESET}");

                // Count frequencies
                int[] freq = new int[256];
                foreach (byte b in data)
                    freq[b]++;

                // Statistics
                int nullBytes = freq[0];
                int printableBytes = 0;
                int controlBytes = 0;
                int highBytes = 0;

                for (int i = 0; i < 256; i++)
                {
                    if (i >= 32 && i < 127) printableBytes += freq[i];
                    else if (i < 32) controlBytes += freq[i];
                    else highBytes += freq[i];
                }

                double nullPct = (double)nullBytes / sampleSize * 100;
                double printPct = (double)printableBytes / sampleSize * 100;
                double ctrlPct = (double)controlBytes / sampleSize * 100;
                double highPct = (double)highBytes / sampleSize * 100;

                int uniqueBytes = freq.Count(f => f > 0);

                PrintField("Sample Size", FormatFileSize(sampleSize));
                PrintField("Unique Bytes", $"{uniqueBytes} / 256 ({uniqueBytes / 256.0 * 100:F1}%)");
                PrintField("Null (0x00)", $"{nullBytes:N0} ({nullPct:F1}%)");
                PrintField("Printable ASCII", $"{printableBytes:N0} ({printPct:F1}%)");
                PrintField("Control (0-31)", $"{controlBytes:N0} ({ctrlPct:F1}%)");
                PrintField("High (128-255)", $"{highBytes:N0} ({highPct:F1}%)");

                // Content classification based on byte distribution
                string classification;
                if (printPct > 85)
                    classification = $"{GREEN}Plain Text / Source Code{RESET} — Predominantly printable ASCII";
                else if (printPct > 50)
                    classification = $"{YELLOW}Mixed Content{RESET} — Text with embedded binary (e.g., rich document)";
                else if (nullPct > 30)
                    classification = $"{ORANGE}Null-padded Binary{RESET} — Executable, firmware, or disk image";
                else if (uniqueBytes > 240 && highPct > 30)
                    classification = $"{RED}Encrypted / Compressed{RESET} — Near-uniform byte distribution";
                else
                    classification = $"{YELLOW}Binary Data{RESET} — Structured binary format";

                PrintField("Classification", classification);

                // Visual histogram (16 rows × 16 columns = all 256 byte values)
                PrintLine($"\n  {CYAN}[BYTE FREQUENCY HEATMAP]{RESET}");
                PrintLine($"  {DIM}Each cell: brightness = frequency (darker = less common){RESET}");

                // Header row
                StringBuilder hdr = new StringBuilder("  {DIM}     ");
                for (int c = 0; c < 16; c++)
                    hdr.Append($" {c:X1}  ");
                PrintLine(hdr.ToString() + RESET);

                int maxFreq = freq.Max();

                for (int row = 0; row < 16; row++)
                {
                    StringBuilder line = new StringBuilder($"  {ORANGE}{row:X1}x{RESET}   ");
                    for (int col = 0; col < 16; col++)
                    {
                        int idx = row * 16 + col;
                        int level = maxFreq > 0 ? (int)((double)freq[idx] / maxFreq * 8) : 0;
                        string block = level switch
                        {
                            0 => $"{DIM} · {RESET}",
                            1 => $"{DIM} ░ {RESET}",
                            2 => $"\u001b[38;5;242m ▒ {RESET}",
                            3 => $"\u001b[38;5;246m ▒ {RESET}",
                            4 => $"\u001b[38;5;250m ▓ {RESET}",
                            5 => $"{WHITE} ▓ {RESET}",
                            6 => $"{YELLOW} █ {RESET}",
                            7 => $"{ORANGE} █ {RESET}",
                            _ => $"{RED} █ {RESET}",
                        };
                        line.Append(block);
                    }
                    PrintLine(line.ToString());
                }

                // Top 10 most frequent bytes
                PrintLine($"\n  {CYAN}[TOP 10 MOST FREQUENT BYTES]{RESET}");
                PrintLine($"  {DIM}{"BYTE",-8} {"HEX",-6} {"COUNT",-10} {"%",-8} {"CHAR"}{RESET}");
                PrintLine($"  {DIM}{new string('-', 50)}{RESET}");

                var topBytes = Enumerable.Range(0, 256)
                    .OrderByDescending(i => freq[i])
                    .Take(10);

                foreach (int b in topBytes)
                {
                    string ch = b >= 32 && b < 127 ? $"'{(char)b}'" : b == 0 ? "NULL" : b == 10 ? "LF" : b == 13 ? "CR" : b == 9 ? "TAB" : b == 32 ? "SPACE" : "·";
                    double pct = (double)freq[b] / sampleSize * 100;
                    PrintLine($"  {b,-8} {"0x" + b.ToString("X2"),-6} {freq[b],-10:N0} {pct,-8:F2}% {WHITE}{ch}{RESET}");
                }
            }
            catch (Exception ex)
            {
                PrintLine($"  {RED}Error: {ex.Message}{RESET}");
            }
        }

        // =====================================================================
        // HELPERS
        // =====================================================================
        private static void PrintSectionHeader(string title, string number)
        {
            PrintLine($"\n{DIM}{new string('-', 80)}{RESET}");
            PrintLine($" {CYAN}[MODULE {number}]{RESET} {YELLOW}{title}{RESET}");
            PrintLine($"{DIM}{new string('-', 80)}{RESET}");
        }

        private static void PrintField(string label, string value)
        {
            PrintLine($"  {WHITE}{label,-20}{RESET} {value}");
        }

        /// <summary>
        /// Print to console AND capture to report buffer if active.
        /// </summary>
        private static void PrintLine(string text)
        {
            Console.WriteLine(text);
            if (_captureReport)
                _reportBuffer.AppendLine(text);
        }

        private static string FormatFileSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F2} KB";
            if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F2} MB";
            return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
        }
    }
}
