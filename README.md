<div align="center">

```
  _   _ _______  __   ____  _   _ __  __ ____  _____ ____
 | | | | ____\ \/ /  |  _ \| | | |  \/  |  _ \| ____|  _ \
 | |_| |  _|  \  /   | | | | | | | |\/| | |_) |  _| | |_) |
 |  _  | |___ /  \   | |_| | |_| | |  | |  __/| |___|  _ <
 |_| |_|_____/_/\_\  |____/ \___/|_|  |_|_|   |_____|_| \_\
```

### 🔬 Forensic File Analysis Tool

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0--FORENSIC-blue?style=for-the-badge)]()
[![Signatures](https://img.shields.io/badge/Signatures-130+-orange?style=for-the-badge)]()
[![Status](https://img.shields.io/badge/Tests-130%20Passed-brightgreen?style=for-the-badge)]()

**A powerful, zero-dependency\* forensic file analysis tool built in C#.**
<br>
Identify file types by magic bytes, extract deep metadata, detect anti-forensic techniques,
<br>
and generate court-ready reports — all from the command line.

<sub>\* Only external dependency: MetadataExtractor NuGet for EXIF/XMP parsing</sub>

---

[Features](#-features) •
[Installation](#-installation) •
[Usage](#-usage) •
[Forensic Modules](#-forensic-modules) •
[CLI Reference](#-cli-reference) •
[Screenshots](#-screenshots) •
[License](#-license)

</div>

---

## 🚀 Features

<table>
<tr>
<td width="50%">

### 🔎 File Identification
- **130+ file signatures** via magic bytes
- ZIP-based format refinement (APK, EPUB, DOCX, etc.)
- Heuristic detection for text-based formats
- Extension vs signature **mismatch detection**

</td>
<td width="50%">

### 🧬 Forensic Analysis
- **12 analysis modules** in a single scan
- Cryptographic hashes (MD5, SHA-1, SHA-256, SHA-512, CRC32)
- Shannon entropy analysis
- NTFS Alternate Data Streams detection

</td>
</tr>
<tr>
<td>

### 📊 Deep Metadata Extraction
- **EXIF / XMP / IPTC / ICC / ID3** via MetadataExtractor
- GPS geolocation with **Google Maps link**
- PDF metadata, fonts, security analysis
- PE header parsing (EXE/DLL architecture, imports)

</td>
<td>

### 📋 Report Generation
- Professional forensic report export (.txt)
- Case ID & Examiner tracking
- UTC timestamps (international standard)
- Chain of custody disclaimer
- VirusTotal hash lookup link

</td>
</tr>
</table>

---

## 📦 Installation

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later

### Clone & Build

```bash
git clone https://github.com/YOUR_USERNAME/HEX_Dumper.git
cd HEX_Dumper
dotnet build -c Release
```

### Add to PATH (optional)

```powershell
# PowerShell (run as Administrator)
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\path\to\HEX_Dumper\bin\Release\net8.0", "User")
```

Then open a new terminal and run `Hex_Dumper` from anywhere.

---

## 💻 Usage

### Interactive Mode

Run without arguments to open the interactive menu:

```bash
Hex_Dumper
```

```
  SENTINEL DATA | STATUS: ACTIVE | ENGINE: v1.0-HEX-ANALYZER

  === MODO DE ANALISE ===
  ------------------------------------------------
  1. Analisar Arquivo Unico
  2. Analisar Multiplos Arquivos (Pasta/Lista)
  3. Extrair Metadados Completos
  0. Sair
  ------------------------------------------------
```

### CLI Mode

Run with commands for direct, scriptable analysis:

```bash
# Quick file type identification
Hex_Dumper identify "C:\evidence\suspect_file.jpg"
# Output: JPEG Image (.jpg)

# Full forensic analysis with report export
Hex_Dumper forensic "C:\evidence\file.pdf" --case-id "CASE-2026-001" --examiner "Perito Silva" --export

# Analyze a single file (hex dump + signature)
Hex_Dumper analyze "C:\Users\file.exe"

# Batch analyze all files in a folder
Hex_Dumper batch "C:\evidence\folder"

# Just pass a file path for quick analysis
Hex_Dumper "C:\file.pdf"
```

---

## 🔬 Forensic Modules

When running a full forensic extraction (`forensic` command or Option 3), the tool runs **12 analysis modules** sequentially:

| # | Module | Description |
|:-:|--------|-------------|
| 1 | **File System Info** | Name, path, size, timestamps (Local + UTC), NTFS owner, attributes |
| 2 | **Cryptographic Hashes** | MD5, SHA-1, SHA-256, SHA-512, CRC32 + **VirusTotal** lookup link |
| 3 | **Hex Dump** | First 256 bytes in hex + ASCII side-by-side view |
| 4 | **Entropy Analysis** | Shannon entropy with visual bar — detects encryption/compression |
| 5 | **String Extraction** | All printable strings ≥ 4 chars with hex offsets |
| 6 | **PE Header** | EXE/DLL analysis: architecture, sections, imports, timestamps |
| 7 | **Embedded Metadata** | Universal EXIF/XMP/IPTC/ICC/ID3/QuickTime via MetadataExtractor NuGet — works on JPEG, PNG, MP4, MP3, PDF, TIFF, WebP, HEIF, AVI, WAV, PSD, and more |
| 8 | **PDF Metadata** | Version, author, producer, fonts, page count/dimensions, security flags (JavaScript, encryption, forms, embedded files) + XMP |
| 9 | **ZIP Contents** | Archive listing with compressed sizes and compression ratios |
| 10 | **Signature Mismatch** | ⚠️ Compares magic bytes vs file extension — **detects renamed/disguised files** |
| 11 | **NTFS ADS** | 🔒 Detects Alternate Data Streams + **Zone.Identifier** (download origin URL) |
| 12 | **Byte Frequency** | 📊 256-byte heatmap, printable/null/high ratios, top 10 bytes, content classification |

### GPS / Geolocation Detection

When GPS data is found in images, the tool highlights it with a red alert and provides a direct **Google Maps** link:

```
  ==================================================
    !! GEOLOCATION DATA FOUND !!
  ==================================================
    Latitude             -23.550520°
    Longitude            -46.633308°
    Google Maps          https://www.google.com/maps?q=-23.550520,-46.633308
  ==================================================
```

### Anti-Forensic Detection

Module 10 detects **file extension spoofing** — the most common anti-forensic technique:

```
  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !! MISMATCH DETECTED — POSSIBLE ANTI-FORENSIC ACTIVITY !!
  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    File claims to be  : .jpg
    Actually contains  : PE Executable
    Expected extensions: .exe, .dll, .sys, .scr, .ocx, .drv
  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

---

## 📖 CLI Reference

```
USAGE:
  Hex_Dumper                              Interactive mode (menu)
  Hex_Dumper <file>                       Quick analysis
  Hex_Dumper <command> [args] [options]    CLI mode

COMMANDS:
  analyze, scan, a    <file>              Full analysis (hex + signature)
  forensic, meta, f   <file>              Complete forensic extraction (12 modules)
  batch, b            <folder>            Analyze all files in a folder
  identify, id, i     <file>              Identify file type (simple output)
  help, h, ?                              Show help
  version, v                              Show version

OPTIONS (forensic command):
  --case-id, -c <ID>                      Case number / reference
  --examiner, -e <NAME>                   Examiner name
  --export, -x                            Auto-export .txt report
```

---

## 🗂️ Supported File Types

<details>
<summary><b>130+ file signatures organized by category (click to expand)</b></summary>

| Category | Formats |
|----------|---------|
| **Images** | JPEG, PNG, GIF, BMP, TIFF, WebP, HEIF, AVIF, ICO, PSD, SVG, JXL, CR2, CR3, NEF, ARW, DNG, ORF |
| **Video** | MP4, AVI, MKV, MOV, FLV, WebM, WMV, 3GP, MPEG-TS, VOB |
| **Audio** | MP3, WAV, FLAC, OGG, AAC, WMA, MIDI, AIFF, APE, Opus, M4A |
| **Documents** | PDF, DOCX, XLSX, PPTX, ODT, ODS, ODP, RTF, EPUB |
| **Archives** | ZIP, RAR, 7Z, GZIP, TAR, BZ2, XZ, ZSTD, LZ4 |
| **Executables** | EXE/DLL (PE), ELF, Mach-O, DEX, .class, WASM |
| **Databases** | SQLite, Access (MDB), Outlook (PST) |
| **Disk Images** | ISO 9660, VMDK, VDI, QCOW2, VHD |
| **Fonts** | TTF, OTF, WOFF, WOFF2 |
| **3D/CAD** | STL (binary), glTF (GLB), Blender (.blend) |
| **Crypto** | Bitcoin Wallet (wallet.dat) |
| **Mobile** | APK, IPA, KWGT, KLWP, MTZ |
| **Network** | PCAP, PCAP-NG |
| **Playlists** | M3U, M3U8, PLS, ASX |
| **Misc** | LNK, Torrent, Protobuf, FlatBuffers |

</details>

---

## 🧪 Self-Test

The tool includes a built-in self-test that validates all 130 file signatures:

```bash
Hex_Dumper --test-all
```

```
Running Self-Test Sequence...

Test Results: 130 Passed, 0 Failed.
All systems operational.
```

---

## 🏗️ Project Structure

```
HEX_Dumper/
├── Program.cs              # Main program, CLI parser, menu, 130+ signatures
├── MetadataExtractor.cs    # 12 forensic analysis modules + report export
├── Hex_Dumper.csproj       # .NET 8.0 project configuration
├── Hex_Dumper.sln          # Solution file
├── LICENSE                 # MIT License
└── README.md               # This file
```

---

## 📝 Report Export

Forensic reports are exported as plain-text `.txt` files with the following structure:

```
================================================================================
  SENTINEL DATA SOLUTIONS — FORENSIC FILE ANALYSIS REPORT
================================================================================
  Report Generated : 2026-02-10 18:13:19 UTC
  Tool Version     : Hex Dumper v2.0-FORENSIC
  Case ID          : CASE-2026-001
  Examiner         : Perito Silva
  Machine          : WORKSTATION-01
  OS               : Microsoft Windows 10.0.22631
  Target File      : C:\evidence\suspect_file.pdf
================================================================================

DISCLAIMER: This report was generated by an automated forensic analysis tool.
The information contained herein should be verified by a qualified examiner.
Chain of custody must be maintained for evidentiary purposes.

--------------------------------------------------------------------------------

[MODULE 1] FILE SYSTEM INFO
...
[MODULE 12] BYTE FREQUENCY ANALYSIS
...

================================================================================
  END OF FORENSIC REPORT
================================================================================
```

---

## ⚠️ Disclaimer

This tool is developed **for educational and didactic purposes only**. It is intended to be used in controlled environments such as classrooms, labs, and CTF challenges. The authors are not responsible for any misuse of this software.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
Copyright (c) 2026 Antônio Malheiros
```

---

<div align="center">

**Built with ❤️ by [Zeca](https://github.com/YOUR_USERNAME)**

*SENTINEL DATA SOLUTIONS • Forensic Analysis Tool*

</div>
