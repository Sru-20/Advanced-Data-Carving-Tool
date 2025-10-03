# Advanced File Carver for Corrupted Storag

A professional digital forensics tool that recovers files from corrupted drives, damaged media, and formatted storage using file signature carving technology.

## Features

- **Raw Data Carving**: Recovers files without file system metadata
- **Multiple File Formats**: JPEG, PNG, PDF, ZIP, GIF, MP3
- **Batch Processing**: Handle multiple files and folders
- **Forensic Logging**: Detailed JSON logs with timestamps and MD5 hashes
- **Professional GUI**: User-friendly interface with progress tracking
- **Selective Recovery**: Choose specific file types to recover

## Installation

```bash
git clone https://github.com/yourusername/advanced-file-carver.git
cd advanced-file-carver
python data_carver.py
```

## Usage

1. Run `python data_carver.py`
2. Select input files or folder
3. Choose output directory
4. Select file types to recover
5. Click "Start Recovery"

## Technologies Used

- **Python** - Core programming language
- **Tkinter** - GUI framework
- **Hashlib** - MD5 hashing for file integrity
- **Regex** - Pattern matching for file signatures
- **Threading** - Background processing

## Supported File Types

| Format | Header | Footer | Extension |
|--------|--------|--------|-----------|
| JPEG | `FF D8 FF` | `FF D9` | .jpg |
| PNG | `89 50 4E 47` | `49 45 4E 44` | .png |
| PDF | `25 50 44 46` | `25 25 45 4F 46` | .pdf |
| ZIP | `50 4B 03 04` | `50 4B 05 06` | .zip |
| GIF | `47 49 46 38` | `00 3B` | .gif |
| MP3 | `FF FB` | None | .mp3 |

## Project Structure

```
advanced-file-carver/
├── data_carver.py
├── requirements.txt
├── README.md
└── recovery_logs/
```

## How It Works

The tool scans raw binary data for known file signatures (headers and footers) and extracts the data between them, effectively recovering files even when file system structures are damaged or missing.

## Use Cases

- Data recovery from corrupted drives
- Forensic analysis of damaged media
- File extraction from formatted storage
- Digital evidence recovery

## Requirements

- Python 3.6+
- Tkinter (usually included with Python)

No additional dependencies required.
