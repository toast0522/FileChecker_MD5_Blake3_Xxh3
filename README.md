Md5Checker GUI Project

Overview

Md5Checker GUI is a high‑performance file hash verification tool built
with Python and PySide6.
It is designed to efficiently scan, hash, verify, and manage very large
collections of files while keeping the user interface responsive.

The application supports multiple hashing algorithms, sidecar hash
files, export/import verification workflows, and database snapshot
baselines.
It is optimized for large-scale file validation, backup verification,
software integrity checks, and archival auditing.

Core Features

• Fast, non‑blocking folder scanning
• Multi‑threaded hashing engine
• Large dataset support (tens or hundreds of thousands of files)
• Sidecar hash file support (.md5)
• Import and export of hash lists (.txt)
• SQLite database snapshot storage
• Multiple hashing algorithms: - MD5 - SHA1 - SHA256 - BLAKE3
(optional) - XXH3‑128 (optional)

Status System

Each file is categorized into one of the following states:

New – File exists but has no saved hash
Loaded – Saved hash loaded but not yet verified
Passed – Current hash matches saved hash
Failed – Current hash differs from saved hash
Unknown – File path does not exist
N/A – File cannot be processed or parsed

Main Workflows

Baseline Creation: 1. Add files or folders 2. Start hashing 3. Export
hashes or generate sidecar files

Verification: 1. Load saved hashes or database snapshot 2. Run Check 3.
Review Passed / Failed results

Database Usage: 1. Save snapshots of hash tables 2. Reload snapshots for
future verification 3. Maintain historical file integrity records

Performance Design

• Model/View architecture for scalable tables
• Time‑sliced UI insertion to prevent freezing
• Thread pool hashing workers
• Smart hash caching using file size and timestamp
• Optimized proxy filtering for fast tab switching

Configuration Files

ui_settings.json Stores application configuration and performance
settings.

hash_databases.sqlite Stores database snapshots and saved hashes.

Requirements

Python 3.10+

Required: - PySide6

Optional: - blake3 - xxhash

Typical Use Cases

• Backup verification
• Software archive validation
• Large file repository auditing
• Data integrity monitoring
• Malware or corruption detection workflows

Credits

This project was VibeCoded with ChatGPT.

Release download:
https://github.com/toast0522/FileChecker_MD5_Blake3_Xxh3/releases/tag/v19
