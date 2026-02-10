using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Hex_Dumper
{
    public class FileSignature
    {
        public string Description { get; set; }
        public string Extension { get; set; }
        public byte[] Signature { get; set; }
        public int Offset { get; set; } = 0;

        public FileSignature(string description, string extension, string hexSignature, int offset = 0)
        {
            Description = description;
            Extension = extension;
            Signature = StringToByteArray(hexSignature);
            Offset = offset;
        }

        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }

    class Program
    {
        private static List<FileSignature> _signatures = new List<FileSignature>();

        static void Main(string[] args)
        {
            EnableANSI();
            InitializeSignatures();

            // === CLI MODE (when arguments are passed) ===
            if (args.Length > 0)
            {
                string command = args[0].ToLowerInvariant().TrimStart('-');

                switch (command)
                {
                    case "test-all":
                        RunSelfTest();
                        return;

                    case "help":
                    case "h":
                    case "?":
                        PrintHelp();
                        return;

                    case "version":
                    case "v":
                        PrintVersion();
                        return;

                    case "analyze":
                    case "scan":
                    case "a":
                        if (args.Length < 2)
                        {
                            Console.WriteLine("\u001b[1;31m[!] Uso: HexDumper analyze <arquivo>\u001b[0m");
                            return;
                        }
                        {
                            string filePath = args[1].Trim('"');
                            if (File.Exists(filePath))
                            {
                                IdentifyFile(filePath);
                            }
                            else
                            {
                                Console.WriteLine($"\u001b[1;31m[!] Arquivo nao encontrado: {filePath}\u001b[0m");
                            }
                        }
                        return;

                    case "forensic":
                    case "metadata":
                    case "meta":
                    case "f":
                    case "m":
                        if (args.Length < 2)
                        {
                            Console.WriteLine("\u001b[1;31m[!] Uso: HexDumper forensic <arquivo> [--case-id ID] [--examiner NOME] [--export]\u001b[0m");
                            return;
                        }
                        {
                            string filePath = args[1].Trim('"');
                            string caseId = GetArgValue(args, "--case-id") ?? GetArgValue(args, "-c") ?? "";
                            string examiner = GetArgValue(args, "--examiner") ?? GetArgValue(args, "-e") ?? "";
                            bool autoExport = HasFlag(args, "--export") || HasFlag(args, "-x");

                            if (!File.Exists(filePath))
                            {
                                Console.WriteLine($"\u001b[1;31m[!] Arquivo nao encontrado: {filePath}\u001b[0m");
                                return;
                            }

                            MetadataExtractorModule.ExtractAll(filePath, caseId, examiner);

                            if (autoExport)
                            {
                                string reportPath = MetadataExtractorModule.ExportReport(filePath, caseId, examiner);
                                if (reportPath != null)
                                    Console.WriteLine($"\u001b[1;32m[+] Relatorio salvo em: {reportPath}\u001b[0m");
                                else
                                    Console.WriteLine("\u001b[1;31m[!] Erro ao exportar relatorio.\u001b[0m");
                            }
                        }
                        return;

                    case "batch":
                    case "b":
                        if (args.Length < 2)
                        {
                            Console.WriteLine("\u001b[1;31m[!] Uso: HexDumper batch <pasta>\u001b[0m");
                            return;
                        }
                        {
                            string dirPath = args[1].Trim('"');
                            if (Directory.Exists(dirPath))
                            {
                                string[] files = Directory.GetFiles(dirPath);
                                Console.WriteLine($"\u001b[1;33m[*] Analisando {files.Length} arquivos em: {dirPath}\u001b[0m\n");
                                foreach (string f in files)
                                {
                                    IdentifyFile(f);
                                    Console.WriteLine();
                                }
                            }
                            else
                            {
                                Console.WriteLine($"\u001b[1;31m[!] Pasta nao encontrada: {dirPath}\u001b[0m");
                            }
                        }
                        return;

                    case "identify":
                    case "id":
                    case "i":
                        if (args.Length < 2)
                        {
                            Console.WriteLine("\u001b[1;31m[!] Uso: HexDumper identify <arquivo>\u001b[0m");
                            return;
                        }
                        {
                            string filePath = args[1].Trim('"');
                            if (File.Exists(filePath))
                            {
                                byte[] buffer = new byte[4096];
                                int bytesRead;
                                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                                    bytesRead = fs.Read(buffer, 0, buffer.Length);

                                var matches = MatchSignatures(buffer, bytesRead, filePath);
                                if (matches.Count > 0)
                                {
                                    foreach (var match in matches)
                                        Console.WriteLine($"{match.Description} ({match.Extension})");
                                }
                                else
                                {
                                    Console.WriteLine("Unknown");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"\u001b[1;31m[!] Arquivo nao encontrado: {filePath}\u001b[0m");
                            }
                        }
                        return;

                    default:
                        // If first arg is a file path, auto-analyze it
                        if (File.Exists(args[0]))
                        {
                            IdentifyFile(args[0]);
                            return;
                        }
                        Console.WriteLine($"\u001b[1;31m[!] Comando desconhecido: {args[0]}\u001b[0m");
                        Console.WriteLine("\u001b[1;30mUse 'HexDumper --help' para ver os comandos disponiveis.\u001b[0m");
                        return;
                }
            }

            // === INTERACTIVE MODE (no arguments) ===
            int choice;
            do
            {
                Console.Clear();
                DrawBanner();
                Console.ResetColor();

                Console.WriteLine("\n\u001b[1;33m=== MODO DE ANALISE ===\u001b[0m");
                Console.WriteLine("\u001b[1;30m------------------------------------------------\u001b[0m");
                Console.WriteLine("\u001b[1;37m1.\u001b[0m Analisar Arquivo Unico");
                Console.WriteLine("\u001b[1;37m2.\u001b[0m Analisar Multiplos Arquivos (Pasta/Lista)");
                Console.WriteLine("\u001b[1;37m3.\u001b[0m Extrair Metadados Completos");
                Console.WriteLine("\u001b[1;31m0.\u001b[0m Sair");
                Console.WriteLine("\u001b[1;30m------------------------------------------------\u001b[0m");
                Console.Write("\u001b[1;33mEscolha: \u001b[0m");

                string choiceInput = Console.ReadLine();
                if (!int.TryParse(choiceInput, out choice))
                {
                    choice = -1;
                }

                if (choice == 0) break;

                switch (choice)
                {
                    case 1:
                        RunSingleFileMode();
                        break;
                    case 2:
                        RunMultiFileMode();
                        break;
                    case 3:
                        RunMetadataMode();
                        break;
                    default:
                        Console.WriteLine("\u001b[1;31m[!] Opcao invalida.\u001b[0m");
                        PressEnterToContinue();
                        break;
                }
            } while (choice != 0);
        }

        // === CLI HELPER METHODS ===
        static string GetArgValue(string[] args, string flag)
        {
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i].Equals(flag, StringComparison.OrdinalIgnoreCase))
                    return args[i + 1];
            }
            return null;
        }

        static bool HasFlag(string[] args, string flag)
        {
            return args.Any(a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));
        }

        static void PrintHelp()
        {
            DrawBanner();
            Console.WriteLine(@"
  USAGE:
    HexDumper                              Modo interativo (menu)
    HexDumper <arquivo>                    Analise rapida do arquivo
    HexDumper <comando> [args] [opcoes]    Modo CLI

  COMMANDS:
    analyze, scan, a    <arquivo>          Analise completa (hex + assinatura)
    forensic, meta, f   <arquivo>          Extracao forense completa (12 modulos)
    batch, b            <pasta>            Analisar todos os arquivos de uma pasta
    identify, id, i     <arquivo>          Identificar tipo (saida simples)
    help, h, ?                             Mostrar esta ajuda
    version, v                             Mostrar versao

  OPTIONS (for forensic command):
    --case-id, -c <ID>                     Numero do caso / referencia
    --examiner, -e <NOME>                  Nome do examinador
    --export, -x                           Exportar relatorio .txt automaticamente

  EXAMPLES:
    HexDumper forensic ""C:\evidence\file.pdf"" --case-id ""CASE-2026-001"" --examiner ""Perito Silva"" --export
    HexDumper analyze ""C:\Users\file.exe""
    HexDumper batch ""C:\evidence\folder""
    HexDumper identify ""C:\suspect.jpg""
    HexDumper ""C:\file.pdf""
");
        }

        static void PrintVersion()
        {
            Console.WriteLine("Hex Dumper v2.0-FORENSIC");
            Console.WriteLine("Developed by Zeca | Sentinel Data Solutions");
            Console.WriteLine("Forensic Analysis Tool | For Didactic Use Only");
        }

        static void PressEnterToContinue()
        {
            Console.Write("\n\u001b[1;30mPressione ENTER para continuar...\u001b[0m");
            Console.ReadLine();
        }

        static void RunSingleFileMode()
        {
            while (true)
            {
                Console.ResetColor();
                Console.WriteLine("\n\u001b[1;36m[MODO 1]\u001b[0m Insira o caminho do arquivo (ou '\u001b[1;31mexit\u001b[0m' para voltar):");
                string input = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(input)) continue;
                if (input.Trim().Equals("exit", StringComparison.OrdinalIgnoreCase)) break;

                string filePath = input.Trim().Trim('"');

                if (File.Exists(filePath))
                {
                    IdentifyFile(filePath);
                }
                else
                {
                    Console.WriteLine("\u001b[1;31m[!] Erro: Arquivo nao encontrado.\u001b[0m");
                }
            }
        }

        static void RunMetadataMode()
        {
            // Forensic case info
            Console.ResetColor();
            Console.WriteLine("\n\u001b[1;33m=== FORENSIC ANALYSIS SETUP ===\u001b[0m");
            Console.WriteLine("\u001b[1;30m(Leave blank to skip)\u001b[0m");

            Console.Write("\u001b[1;37mCase ID / Reference Number: \u001b[0m");
            string caseId = Console.ReadLine()?.Trim() ?? "";

            Console.Write("\u001b[1;37mExaminer Name: \u001b[0m");
            string examiner = Console.ReadLine()?.Trim() ?? "";

            Console.WriteLine("\u001b[1;30m------------------------------------------------\u001b[0m");

            while (true)
            {
                Console.ResetColor();
                Console.WriteLine("\n\u001b[1;36m[MODO 3]\u001b[0m Insira o caminho do arquivo para analise forense (ou '\u001b[1;31mexit\u001b[0m' para voltar):");
                string input = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(input)) continue;
                if (input.Trim().Equals("exit", StringComparison.OrdinalIgnoreCase)) break;

                string filePath = input.Trim().Trim('"');

                if (File.Exists(filePath))
                {
                    MetadataExtractorModule.ExtractAll(filePath, caseId, examiner);

                    // Offer report export
                    Console.WriteLine("\n\u001b[1;33mDeseja exportar relatorio forense em .txt? (S/N): \u001b[0m");
                    string exportChoice = Console.ReadLine()?.Trim().ToUpperInvariant() ?? "";
                    if (exportChoice == "S" || exportChoice == "Y" || exportChoice == "SIM" || exportChoice == "YES")
                    {
                        string reportPath = MetadataExtractorModule.ExportReport(filePath, caseId, examiner);
                        if (reportPath != null)
                        {
                            Console.WriteLine($"\u001b[1;32m[+] Relatorio salvo em: {reportPath}\u001b[0m");
                        }
                        else
                        {
                            Console.WriteLine("\u001b[1;31m[!] Erro ao exportar relatorio.\u001b[0m");
                        }
                    }

                    PressEnterToContinue();
                }
                else
                {
                    Console.WriteLine("\u001b[1;31m[!] Erro: Arquivo nao encontrado.\u001b[0m");
                }
            }
        }

        static void RunMultiFileMode()
        {
            Console.WriteLine("\n\u001b[1;36m[MODO 2]\u001b[0m Analisar Multiplos Arquivos");
            Console.WriteLine("\u001b[1;30m------------------------------------------------\u001b[0m");
            Console.WriteLine("\u001b[1;37mA.\u001b[0m Inserir caminho de uma \u001b[1;33mPASTA\u001b[0m (analisa todos os arquivos dentro)");
            Console.WriteLine("\u001b[1;37mB.\u001b[0m Inserir \u001b[1;33mvarios caminhos\u001b[0m separados por virgula");
            Console.WriteLine("\u001b[1;30m------------------------------------------------\u001b[0m");
            Console.Write("\u001b[1;33mEscolha (A/B): \u001b[0m");

            string subChoice = Console.ReadLine()?.Trim().ToUpperInvariant();

            List<string> filesToAnalyze = new List<string>();

            if (subChoice == "A")
            {
                Console.Write("\nInsira o caminho da pasta: ");
                string dirPath = Console.ReadLine()?.Trim().Trim('"');

                if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath))
                {
                    Console.WriteLine("\u001b[1;31m[!] Erro: Pasta nao encontrada.\u001b[0m");
                    PressEnterToContinue();
                    return;
                }

                filesToAnalyze.AddRange(Directory.GetFiles(dirPath));

                if (filesToAnalyze.Count == 0)
                {
                    Console.WriteLine("\u001b[1;31m[!] Nenhum arquivo encontrado na pasta.\u001b[0m");
                    PressEnterToContinue();
                    return;
                }

                Console.WriteLine($"\n\u001b[1;32m[OK]\u001b[0m {filesToAnalyze.Count} arquivo(s) encontrado(s) na pasta.\n");
            }
            else if (subChoice == "B")
            {
                Console.Write("\nInsira os caminhos separados por virgula:\n> ");
                string pathsInput = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(pathsInput))
                {
                    Console.WriteLine("\u001b[1;31m[!] Nenhum caminho fornecido.\u001b[0m");
                    PressEnterToContinue();
                    return;
                }

                string[] paths = pathsInput.Split(',');
                foreach (string p in paths)
                {
                    string trimmed = p.Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(trimmed))
                        filesToAnalyze.Add(trimmed);
                }
            }
            else
            {
                Console.WriteLine("\u001b[1;31m[!] Opcao invalida.\u001b[0m");
                PressEnterToContinue();
                return;
            }

            // Analyze all files and collect results for summary
            var results = new List<(string FileName, string Status, string Types)>();

            Console.WriteLine("\u001b[1;30m================================================\u001b[0m");
            Console.WriteLine("\u001b[1;36m  INICIANDO ANALISE EM LOTE...\u001b[0m");
            Console.WriteLine("\u001b[1;30m================================================\u001b[0m");

            int fileNum = 0;
            foreach (string filePath in filesToAnalyze)
            {
                fileNum++;
                Console.WriteLine($"\n\u001b[1;30m[{fileNum}/{filesToAnalyze.Count}]\u001b[0m");

                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"\u001b[1;31m[!] NAO ENCONTRADO:\u001b[0m {filePath}");
                    results.Add((Path.GetFileName(filePath), "NOT FOUND", "-"));
                    continue;
                }

                var matches = IdentifyFileWithResults(filePath);
                string fileName = Path.GetFileName(filePath);

                if (matches != null && matches.Count > 0)
                {
                    string types = string.Join(", ", matches.Select(m => $"{m.Description} ({m.Extension})"));
                    results.Add((fileName, "IDENTIFIED", types));
                }
                else
                {
                    results.Add((fileName, "UNKNOWN", "Signature not in database"));
                }
            }

            // Print summary table
            Console.WriteLine("\n\u001b[1;33m" + new string('=', 80) + "\u001b[0m");
            Console.WriteLine("\u001b[1;36m  RESUMO DA ANALISE EM LOTE\u001b[0m");
            Console.WriteLine("\u001b[1;33m" + new string('=', 80) + "\u001b[0m");

            int identified = results.Count(r => r.Status == "IDENTIFIED");
            int unknown = results.Count(r => r.Status == "UNKNOWN");
            int notFound = results.Count(r => r.Status == "NOT FOUND");

            Console.WriteLine($"\n  Total: \u001b[1;37m{results.Count}\u001b[0m | "
                + $"\u001b[1;32mIdentificados: {identified}\u001b[0m | "
                + $"\u001b[1;31mDesconhecidos: {unknown}\u001b[0m | "
                + $"\u001b[1;35mNao Encontrados: {notFound}\u001b[0m\n");

            // Table header
            Console.WriteLine("\u001b[1;30m" + new string('-', 80) + "\u001b[0m");
            Console.WriteLine($"  {"#",-4} {"ARQUIVO",-30} {"STATUS",-12} {"TIPO(S)"}");
            Console.WriteLine("\u001b[1;30m" + new string('-', 80) + "\u001b[0m");

            for (int i = 0; i < results.Count; i++)
            {
                var r = results[i];
                string statusColor = r.Status == "IDENTIFIED" ? "\u001b[1;32m" : r.Status == "UNKNOWN" ? "\u001b[1;31m" : "\u001b[1;35m";
                string shortName = r.FileName.Length > 28 ? r.FileName.Substring(0, 25) + "..." : r.FileName;
                string shortTypes = r.Types.Length > 35 ? r.Types.Substring(0, 32) + "..." : r.Types;
                Console.WriteLine($"  {i + 1,-4} {shortName,-30} {statusColor}{r.Status,-12}\u001b[0m {shortTypes}");
            }

            Console.WriteLine("\u001b[1;30m" + new string('-', 80) + "\u001b[0m");

            PressEnterToContinue();
        }

        static void EnableANSI()
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                var handle = GetStdHandle(-11); // STD_OUTPUT_HANDLE
                int mode;
                GetConsoleMode(handle, out mode);
                SetConsoleMode(handle, mode | 0x4); // ENABLE_VIRTUAL_TERMINAL_PROCESSING
            }
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetStdHandle(int nStdHandle);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern bool GetConsoleMode(IntPtr hConsoleHandle, out int lpMode);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern bool SetConsoleMode(IntPtr hConsoleHandle, int dwMode);

        static void DrawBanner()
        {
             Console.WriteLine("\n\u001b[1;36m  SENTINEL DATA \u001b[1;30m| \u001b[1;32mSTATUS: ACTIVE \u001b[1;30m| \u001b[1;34mENGINE: v1.0-HEX-ANALYZER\u001b[0m");
             
             // HEX DUMPER ASCII Art
             Console.WriteLine("\u001b[1;36m  _   _ _______  __  \u001b[1;33m ____  _   _ __  __ ____  _____ ____  ");
             Console.WriteLine("\u001b[1;36m | | | | ____\\ \\/ /  \u001b[1;33m|  _ \\| | | |  \\/  |  _ \\| ____|  _ \\ ");
             Console.WriteLine("\u001b[1;36m | |_| |  _|  \\  /   \u001b[1;33m| | | | | | | |\\/| | |_) |  _| | |_) |");
             Console.WriteLine("\u001b[1;36m |  _  | |___ /  \\   \u001b[1;33m| |_| | |_| | |  | |  __/| |___|  _ < ");
             Console.WriteLine("\u001b[1;36m |_| |_|_____/_/\\_\\  \u001b[1;33m|____/ \\___/|_|  |_|_|   |_____|_| \\_\\");
             Console.WriteLine("\u001b[0m");

             Console.WriteLine("\u001b[1;30m  ----------------------------------------------------------------------------\u001b[0m");
             Console.WriteLine("  \u001b[1;37mFORENSIC ANALYSIS TOOL \u001b[1;30m>> \u001b[38;5;208mDEVELOPED BY ZECA \u001b[1;30m>> \u001b[1;31mFOR DIDACTIC USE ONLY\u001b[0m");
             Console.WriteLine("\u001b[1;30m  ----------------------------------------------------------------------------\u001b[0m");
        }

        static void InitializeSignatures()
        {
            // --- IMAGES ---
            _signatures.Add(new FileSignature("JPEG Image", ".jpg", "FFD8FF"));
            _signatures.Add(new FileSignature("PNG Image", ".png", "89504E470D0A1A0A"));
            _signatures.Add(new FileSignature("GIF Image (87a)", ".gif", "474946383761"));
            _signatures.Add(new FileSignature("GIF Image (89a)", ".gif", "474946383961"));
            _signatures.Add(new FileSignature("Bitmap", ".bmp", "424D"));
            _signatures.Add(new FileSignature("TIFF (Intel)", ".tif", "49492A00"));
            _signatures.Add(new FileSignature("TIFF (Motorola)", ".tif", "4D4D002A"));
            _signatures.Add(new FileSignature("WebP", ".webp", "52494646", 0)); // RIFF...WEBP
            _signatures.Add(new FileSignature("Icon File", ".ico", "00000100"));
            _signatures.Add(new FileSignature("Photoshop Document", ".psd", "38425053"));
            _signatures.Add(new FileSignature("Canon RAW (CR2)", ".cr2", "49492A00100000004352"));
            _signatures.Add(new FileSignature("Canon RAW (CR3)", ".cr3", "49492A00100000004352"));
            _signatures.Add(new FileSignature("Nikon RAW (NEF)", ".nef", "4D4D002A"));
            _signatures.Add(new FileSignature("Fujifilm RAW (RAF)", ".raf", "46554A4946494C4D4343442D524157"));
            _signatures.Add(new FileSignature("Sony RAW (ARW)", ".arw", "49492A00"));
            _signatures.Add(new FileSignature("High Efficiency Image (HEIC)", ".heic", "000000186674797068656963"));
            _signatures.Add(new FileSignature("Targa Image", ".tga", "0000020000")); // Simple check
            _signatures.Add(new FileSignature("Kodak Cineon", ".cin", "802A5F")); 
            _signatures.Add(new FileSignature("OpenEXR Image", ".exr", "762F3101"));
            _signatures.Add(new FileSignature("BPG Image", ".bpg", "425047FB"));
            _signatures.Add(new FileSignature("JPEG 2000 Codestream", ".j2k", "FF4FFF51"));
            _signatures.Add(new FileSignature("JPEG 2000 Image", ".jp2", "0000000C6A5020200D0A870A"));
            _signatures.Add(new FileSignature("DirectDraw Surface", ".dds", "44445320"));

            // --- AUDIO ---
            _signatures.Add(new FileSignature("MP3 Audio (ID3v2)", ".mp3", "494433"));
            _signatures.Add(new FileSignature("MP3 Audio (MPEG-1)", ".mp3", "FFFB"));
            _signatures.Add(new FileSignature("WAV Audio", ".wav", "52494646")); // RIFF...WAVE
            _signatures.Add(new FileSignature("FLAC Audio", ".flac", "664C6143"));
            _signatures.Add(new FileSignature("Ogg Vorbis/Theora", ".ogg", "4F676753"));
            _signatures.Add(new FileSignature("MIDI Audio", ".mid", "4D546864"));
            _signatures.Add(new FileSignature("AAC Audio", ".aac", "FFF1"));
            _signatures.Add(new FileSignature("AAC Audio (MPEG-4)", ".aac", "FFF9"));
            _signatures.Add(new FileSignature("Apple Lossless (ALAC)", ".m4a", "00000020667479704D3441"));
            _signatures.Add(new FileSignature("AIFF Audio", ".aiff", "464F524D")); // FORM...AIFF
            _signatures.Add(new FileSignature("Sun Microsystems Audio", ".au", "2E736E64"));
            _signatures.Add(new FileSignature("Adaptive Multi-Rate", ".amr", "2321414D52"));
            _signatures.Add(new FileSignature("RealAudio", ".ra", "2E7261FD"));

            // --- VIDEO ---
            _signatures.Add(new FileSignature("MP4 Video", ".mp4", "0000001866747970")); 
            _signatures.Add(new FileSignature("MP4 Video (QuickTime)", ".mov", "0000001466747970"));
            _signatures.Add(new FileSignature("Matroska Video", ".mkv", "1A45DFA3"));
            _signatures.Add(new FileSignature("WebM Video", ".webm", "1A45DFA3")); // Shares sig with MKV, often distinguished by doctype but simple sig match is ok
            _signatures.Add(new FileSignature("AVI Video", ".avi", "52494646"));
            _signatures.Add(new FileSignature("Flash Video", ".flv", "464C56"));
            _signatures.Add(new FileSignature("MPEG Video", ".mpg", "000001BA"));
            _signatures.Add(new FileSignature("MPEG Video", ".mpg", "000001B3"));
            _signatures.Add(new FileSignature("Windows Media Video", ".wmv", "3026B2758E66CF11"));
            _signatures.Add(new FileSignature("3GP Mobile Video", ".3gp", "00000014667479703367"));
            _signatures.Add(new FileSignature("RealMedia", ".rm", "2E524D46"));

            // --- DOCUMENTS ---
            _signatures.Add(new FileSignature("PDF Document", ".pdf", "25504446"));
            _signatures.Add(new FileSignature("Rich Text Format", ".rtf", "7B5C72746631"));
            _signatures.Add(new FileSignature("Microsoft Office (Legacy)", ".doc", "D0CF11E0A1B11AE1"));
            _signatures.Add(new FileSignature("Microsoft Office (OpenXML)", ".docx", "504B030414000600"));
            _signatures.Add(new FileSignature("PostScript", ".ps", "25215053"));
            _signatures.Add(new FileSignature("Encapsulated PostScript", ".eps", "C5D0D3C6"));
            _signatures.Add(new FileSignature("DjVu Document", ".djvu", "41542654464F524D")); // AT&TFORM
            _signatures.Add(new FileSignature("Mobipocket eBook", ".mobi", "424F4F4B4D4F4249", 60)); // BOOKMOBI at offset 60 (approx check)
            
            // --- ARCHIVES & COMPRESSION ---
            _signatures.Add(new FileSignature("ZIP Archive", ".zip", "504B0304"));
            _signatures.Add(new FileSignature("ZIP Archive (Empty)", ".zip", "504B0506"));
            _signatures.Add(new FileSignature("ZIP Archive (Spanned)", ".zip", "504B0708"));
            _signatures.Add(new FileSignature("RAR Archive v1.5", ".rar", "526172211A0700"));
            _signatures.Add(new FileSignature("RAR Archive v5.0", ".rar", "526172211A070100"));
            _signatures.Add(new FileSignature("7-Zip Archive", ".7z", "377ABCAF271C"));
            _signatures.Add(new FileSignature("GZIP Archive", ".gz", "1F8B"));
            _signatures.Add(new FileSignature("BZIP2 Archive", ".bz2", "425A68"));
            _signatures.Add(new FileSignature("XZ Archive", ".xz", "FD377A585A00"));
            _signatures.Add(new FileSignature("LZIP Archive", ".lz", "4C5A4950"));
            _signatures.Add(new FileSignature("TAR Archive", ".tar", "7573746172", 257));
            _signatures.Add(new FileSignature("LZH Archive", ".lzh", "2D6C68"));
            _signatures.Add(new FileSignature("ARJ Archive", ".arj", "60EA"));
            _signatures.Add(new FileSignature("Z Archive (Unix)", ".z", "1F9D"));
            _signatures.Add(new FileSignature("Cabinet File", ".cab", "4D534346"));
            _signatures.Add(new FileSignature("Windows Installer", ".msi", "D0CF11E0A1B11AE1")); // OLE Compound File
            _signatures.Add(new FileSignature("Debian Package", ".deb", "213C617263683E")); // !<arch>
            _signatures.Add(new FileSignature("RedHat Package (RPM)", ".rpm", "EDABEEDB"));
            _signatures.Add(new FileSignature("ISO Disk Image", ".iso", "4344303031", 32769)); 
            _signatures.Add(new FileSignature("VMDK Disk Image", ".vmdk", "4B444D56"));
            _signatures.Add(new FileSignature("VirtualBox Disk (VDI)", ".vdi", "3C3C3C204F7261636C6520564D"));
            _signatures.Add(new FileSignature("QCOW2 Disk Image", ".qcow2", "514649FB")); 
            _signatures.Add(new FileSignature("Toast Disc Image", ".toast", "455202000000"));
            _signatures.Add(new FileSignature("Apple Disk Image", ".dmg", "7801730D626260"));
            _signatures.Add(new FileSignature("Nintendo N64 ROM", ".z64", "80371240"));
            _signatures.Add(new FileSignature("Game Boy Color ROM", ".gbc", "CEED6666CC0D000B", 260));
            _signatures.Add(new FileSignature("Game Boy Advance ROM", ".gba", "24FFFF0351C9"));

            // --- EXECUTABLES & LIBS ---
            _signatures.Add(new FileSignature("Windows Executable", ".exe", "4D5A")); 
            _signatures.Add(new FileSignature("ELF Executable", "", "7F454C46"));
            _signatures.Add(new FileSignature("Java Class", ".class", "CAFEBABE"));
            _signatures.Add(new FileSignature("Mach-O (32-bit)", "", "FEEDFACE"));
            _signatures.Add(new FileSignature("Mach-O (64-bit)", "", "FEEDFACF"));
            _signatures.Add(new FileSignature("Dalvik Executable", ".dex", "6465780A30333500"));
            _signatures.Add(new FileSignature("Lua Bytecode", ".luc", "1B4C7561"));
            _signatures.Add(new FileSignature("Python .pyc", ".pyc", "610D0D0A"));
            _signatures.Add(new FileSignature("WebAssembly", ".wasm", "0061736D"));
            _signatures.Add(new FileSignature("SWF Flash", ".swf", "435753"));
            _signatures.Add(new FileSignature("SWF Flash", ".swf", "465753"));

            // --- FONTS ---
            _signatures.Add(new FileSignature("TrueType Font", ".ttf", "0001000000"));
            _signatures.Add(new FileSignature("OpenType Font", ".otf", "4F54544F"));
            _signatures.Add(new FileSignature("Web Open Font Format", ".woff", "774F4646"));
            _signatures.Add(new FileSignature("WOFF2", ".woff2", "774F4632"));

            // --- DATABASES & MISC ---
            _signatures.Add(new FileSignature("SQLite Database", ".sqlite", "53514C69746520666F726D6174203300")); 
            _signatures.Add(new FileSignature("Microsoft Outlook PST", ".pst", "2142444E"));
            _signatures.Add(new FileSignature("Microsoft Access (Standard)", ".mdb", "000100005374616E64617264204A6574"));
            _signatures.Add(new FileSignature("BitTorrent File", ".torrent", "64383A616E6E6F756E6365"));
            _signatures.Add(new FileSignature("Windows Shortcut", ".lnk", "4C00000001140200"));
            _signatures.Add(new FileSignature("Windows Minidump", ".dmp", "5041474544554D50"));
            _signatures.Add(new FileSignature("Windows Registry Hive", ".dat", "72656766"));
            _signatures.Add(new FileSignature("FLIC Animation", ".fli", "AF11"));
            _signatures.Add(new FileSignature("FLIC Animation", ".flc", "AF12"));
            _signatures.Add(new FileSignature("PDB (PalmOS)", ".pdb", "00000000000000000000000000000000", 11)); // offset check

            // --- TEXT-BASED FORMATS (Magic Bytes) ---
            _signatures.Add(new FileSignature("XML Document", ".xml", "3C3F786D6C")); // <?xml
            _signatures.Add(new FileSignature("HTML Document", ".html", "3C21444F4354595045")); // <!DOCTYPE
            _signatures.Add(new FileSignature("HTML Document", ".html", "3C68746D6C")); // <html
            _signatures.Add(new FileSignature("SVG Image", ".svg", "3C73766720")); // <svg 
            _signatures.Add(new FileSignature("Shell Script", ".sh", "23212F")); // #!/
            _signatures.Add(new FileSignature("Windows Batch Script", ".bat", "40656368")); // @ech

            // --- MODERN IMAGE FORMATS ---
            _signatures.Add(new FileSignature("AVIF Image", ".avif", "0000001C66747970"));
            _signatures.Add(new FileSignature("JPEG XL (Codestream)", ".jxl", "FF0A"));
            _signatures.Add(new FileSignature("JPEG XL (Container)", ".jxl", "0000000C4A584C20"));

            // --- MODERN COMPRESSION ---
            _signatures.Add(new FileSignature("Zstandard Archive", ".zst", "28B52FFD"));
            _signatures.Add(new FileSignature("LZ4 Frame", ".lz4", "04224D18"));
            _signatures.Add(new FileSignature("Brotli Compressed", ".br", "CE")); // Common first byte

            // --- PROGRAMMING / DATA ---
            _signatures.Add(new FileSignature("UTF-8 BOM Text", "", "EFBBBF")); // UTF-8 BOM
            _signatures.Add(new FileSignature("UTF-16 LE Text", "", "FFFE")); // UTF-16 Little Endian BOM
            _signatures.Add(new FileSignature("UTF-16 BE Text", "", "FEFF")); // UTF-16 Big Endian BOM
            _signatures.Add(new FileSignature("PCap Network Capture", ".pcap", "D4C3B2A1"));
            _signatures.Add(new FileSignature("PCap-NG Capture", ".pcapng", "0A0D0D0A"));
            _signatures.Add(new FileSignature("Google Protobuf (compiled)", ".pb", "0A"));
            _signatures.Add(new FileSignature("FlatBuffers Binary", ".bfbs", "46425300")); // FBS\0

            // --- PLAYLISTS & STREAMING ---
            _signatures.Add(new FileSignature("M3U Playlist", ".m3u", "23455854")); // #EXT
            _signatures.Add(new FileSignature("M3U8 Playlist", ".m3u8", "23455854")); // #EXT
            _signatures.Add(new FileSignature("PLS Playlist", ".pls", "5B706C61796C6973745D")); // [playlist]
            _signatures.Add(new FileSignature("ASX Playlist", ".asx", "3C617378")); // <asx
        }

        static (byte[] buffer, int bytesRead) ReadFileBuffer(string filePath)
        {
            byte[] buffer = new byte[4096];
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                int bytesRead = fs.Read(buffer, 0, buffer.Length);
                return (buffer, bytesRead);
            }
        }

        static List<FileSignature> MatchSignatures(byte[] buffer, int bytesRead, string filePath)
        {
            var matches = _signatures.Where(sig => IsMatch(buffer, sig)).ToList();

            // Heuristic detection for text-based formats
            if (bytesRead > 0)
            {
                string ext = Path.GetExtension(filePath).ToLowerInvariant();
                string firstChars = System.Text.Encoding.UTF8.GetString(buffer, 0, Math.Min(bytesRead, 256)).TrimStart();

                // JSON heuristic: starts with { or [
                if ((firstChars.StartsWith("{") || firstChars.StartsWith("[")) && 
                    (ext == ".json" || ext == ".geojson" || ext == ".jsonl"))
                {
                    matches.Add(new FileSignature("JSON Document (Heuristic)", ext, "00") { Offset = -1 });
                }

                // YAML heuristic: starts with --- or key: value
                if ((firstChars.StartsWith("---") || (firstChars.Contains(":") && !firstChars.StartsWith("<"))) &&
                    (ext == ".yml" || ext == ".yaml"))
                {
                    matches.Add(new FileSignature("YAML Document (Heuristic)", ext, "00") { Offset = -1 });
                }

                // Markdown heuristic: starts with # or common MD patterns
                if ((firstChars.StartsWith("#") || firstChars.StartsWith("---\n") || firstChars.StartsWith("---\r\n")) &&
                    (ext == ".md" || ext == ".markdown" || ext == ".mkd"))
                {
                    matches.Add(new FileSignature("Markdown Document (Heuristic)", ext, "00") { Offset = -1 });
                }

                // CSV/TSV heuristic by extension
                if (ext == ".csv")
                    matches.Add(new FileSignature("CSV Data File (Heuristic)", ".csv", "00") { Offset = -1 });
                if (ext == ".tsv")
                    matches.Add(new FileSignature("TSV Data File (Heuristic)", ".tsv", "00") { Offset = -1 });

                // INI/Config heuristic
                if ((firstChars.StartsWith("[") || firstChars.StartsWith(";")) &&
                    (ext == ".ini" || ext == ".cfg" || ext == ".conf"))
                {
                    matches.Add(new FileSignature("Config/INI File (Heuristic)", ext, "00") { Offset = -1 });
                }

                // Log file heuristic
                if (ext == ".log")
                    matches.Add(new FileSignature("Log File (Heuristic)", ".log", "00") { Offset = -1 });

                // Plain text heuristic
                if (ext == ".txt")
                    matches.Add(new FileSignature("Plain Text File (Heuristic)", ".txt", "00") { Offset = -1 });

                // M3U heuristic (for m3u files that don't match #EXT signature)
                if ((ext == ".m3u" || ext == ".m3u8") && !matches.Any(m => m.Extension == ".m3u" || m.Extension == ".m3u8"))
                    matches.Add(new FileSignature("M3U Playlist (Heuristic)", ext, "00") { Offset = -1 });
            }

            // --- ZIP-based format refinement ---
            // Many modern formats are ZIP containers. Refine by extension.
            if (matches.Any(m => m.Description.Contains("ZIP")))
            {
                string ext = Path.GetExtension(filePath).ToLowerInvariant();
                var zipRefinements = new Dictionary<string, string>
                {
                    { ".apk",  "Android Package (APK)" },
                    { ".xapk", "Android XAPK Bundle" },
                    { ".aab",  "Android App Bundle" },
                    { ".epub", "EPUB eBook" },
                    { ".docx", "Microsoft Word (OOXML)" },
                    { ".xlsx", "Microsoft Excel (OOXML)" },
                    { ".pptx", "Microsoft PowerPoint (OOXML)" },
                    { ".odt",  "OpenDocument Text" },
                    { ".ods",  "OpenDocument Spreadsheet" },
                    { ".odp",  "OpenDocument Presentation" },
                    { ".jar",  "Java Archive (JAR)" },
                    { ".war",  "Web Application Archive (WAR)" },
                    { ".ear",  "Enterprise Application Archive" },
                    { ".kwgt", "Kustom Widget (KWGT)" },
                    { ".klwp", "Kustom Wallpaper (KLWP)" },
                    { ".mtz",  "MIUI Theme (MTZ)" },
                    { ".ipa",  "iOS Application (IPA)" },
                    { ".xpi",  "Firefox Extension (XPI)" },
                    { ".crx",  "Chrome Extension (CRX)" },
                    { ".nupkg","NuGet Package" },
                    { ".sketch","Sketch Design File" },
                    { ".kml",  "Google Earth KMZ" },
                };

                if (zipRefinements.ContainsKey(ext))
                {
                    // Add the specific format as the first match
                    matches.Insert(0, new FileSignature(zipRefinements[ext], ext, "504B0304"));
                }
            }

            return matches;
        }

        static void IdentifyFile(string filePath)
        {
            try
            {
                var (buffer, bytesRead) = ReadFileBuffer(filePath);
                if (bytesRead == 0)
                {
                    Console.WriteLine("File is empty.");
                    return;
                }

                Console.WriteLine($"\n\u001b[1;37mAnalysis for:\u001b[0m \u001b[1;36m{Path.GetFileName(filePath)}\u001b[0m");
                Console.WriteLine($"\u001b[1;30mFull Path:\u001b[0m {filePath}");
                Console.WriteLine($"\u001b[1;30mHex Signature (first 16 bytes):\u001b[0m {BitConverter.ToString(buffer.Take(Math.Min(bytesRead, 16)).ToArray()).Replace("-", " ")}");

                var matches = MatchSignatures(buffer, bytesRead, filePath);

                if (matches.Any())
                {
                    Console.WriteLine("\n\u001b[1;32mPossible File Types:\u001b[0m");
                    foreach (var match in matches)
                    {
                        string tag = match.Offset == -1 ? "\u001b[1;33m[HEURISTIC]\u001b[0m " : "";
                        Console.WriteLine($"  {tag}\u001b[1;37m-\u001b[0m {match.Description} ({match.Extension})");
                    }
                }
                else
                {
                    Console.WriteLine("\n\u001b[1;31mUnknown file type (signature not in database).\u001b[0m");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\u001b[1;31mError reading file:\u001b[0m {ex.Message}");
            }
        }

        /// <summary>
        /// Same as IdentifyFile but returns the match list for batch summary.
        /// </summary>
        static List<FileSignature> IdentifyFileWithResults(string filePath)
        {
            try
            {
                var (buffer, bytesRead) = ReadFileBuffer(filePath);
                if (bytesRead == 0)
                {
                    Console.WriteLine($"\u001b[1;37m{Path.GetFileName(filePath)}\u001b[0m — \u001b[1;31mempty file\u001b[0m");
                    return new List<FileSignature>();
                }

                Console.WriteLine($"\n\u001b[1;37mAnalysis for:\u001b[0m \u001b[1;36m{Path.GetFileName(filePath)}\u001b[0m");
                Console.WriteLine($"\u001b[1;30mHex Signature (first 16 bytes):\u001b[0m {BitConverter.ToString(buffer.Take(Math.Min(bytesRead, 16)).ToArray()).Replace("-", " ")}");

                var matches = MatchSignatures(buffer, bytesRead, filePath);

                if (matches.Any())
                {
                    Console.WriteLine("\u001b[1;32m  Possible File Types:\u001b[0m");
                    foreach (var match in matches)
                    {
                        string tag = match.Offset == -1 ? "\u001b[1;33m[HEURISTIC]\u001b[0m " : "";
                        Console.WriteLine($"    {tag}\u001b[1;37m-\u001b[0m {match.Description} ({match.Extension})");
                    }
                }
                else
                {
                    Console.WriteLine("  \u001b[1;31mUnknown file type.\u001b[0m");
                }

                return matches;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\u001b[1;31mError reading file:\u001b[0m {ex.Message}");
                return null;
            }
        }

        static bool IsMatch(byte[] fileHeader, FileSignature signature)
        {
            if (fileHeader.Length < signature.Offset + signature.Signature.Length)
                return false;

            for (int i = 0; i < signature.Signature.Length; i++)
            {
                if (fileHeader[signature.Offset + i] != signature.Signature[i])
                    return false;
            }
            return true;
        }

        static void RunSelfTest()
        {
            Console.WriteLine("Running Self-Test Sequence...");
            string tempDir = Path.Combine(Path.GetTempPath(), "HexDumperTest");
            Directory.CreateDirectory(tempDir);

            int passed = 0;
            int failed = 0;

            foreach (var sig in _signatures)
            {
                string testFile = Path.Combine(tempDir, $"test_{Guid.NewGuid()}{sig.Extension.Split('/')[0]}");
                try
                {
                    // Create a valid file for this signature
                    byte[] content = new byte[sig.Offset + sig.Signature.Length + 10]; // Padding
                    Array.Copy(sig.Signature, 0, content, sig.Offset, sig.Signature.Length);
                    File.WriteAllBytes(testFile, content);

                    // Test identification logic locally without console output spam
                    // (We are duplicating logic slightly for self-test verification)
                    if (IsMatch(content, sig))
                    {
                        // Double check identity call would find it
                        // Console.WriteLine($"[PASS] {sig.Description}");
                        passed++;
                    }
                    else
                    {
                        Console.WriteLine($"[FAIL] {sig.Description} (Logic Error)");
                        failed++;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[FAIL] {sig.Description} - {ex.Message}");
                    failed++;
                }
                finally
                {
                    if (File.Exists(testFile)) File.Delete(testFile);
                }
            }

            try
            {
                Directory.Delete(tempDir, true);
            }
            catch { /* Ignore cleanup errors */ }

            Console.WriteLine($"\nTest Results: {passed} Passed, {failed} Failed.");
            if (failed == 0)
                Console.WriteLine("All systems operational.");
            else
                Console.WriteLine("Some items failed validation.");
        }
    }
}
