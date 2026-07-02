# exlibrys

Python reimplementation of the checksum algorithm used by `Exl_win.exe`
("Ex Libris" / "Екслібрис"), reverse-engineered from the binary. Produces
the same `XXXX-XXXX` codes as the original program.

## Usage

### Command line

```bash
uv run exlibrys.py path/to/file.txt
```

Prints `path: CHECKSUM` for each file given. Multiple files at once:

```bash
uv run exlibrys.py file1.txt file2.docx "C:\path\with spaces\file3.epub"
```

On real Windows, no extra flags are needed - the real file metadata
(timestamp, attributes) is read automatically via the actual Win32 APIs,
and the result matches `Exl_win.exe` exactly.

#### Overriding file metadata

The checksum depends on four inputs: file content, file size, the file's
last-write timestamp, Win32 file attributes, and the filename. Each of the
metadata inputs can be overridden explicitly:

```bash
uv run exlibrys.py --file-age "2024-06-15 14:30:22" --attributes 0x20 file.txt
```

| Flag | Purpose |
|---|---|
| `--file-age` | Override the last-write timestamp. Accepts a human-readable datetime (`"2024-06-15 14:30:22"`, local time) **or** a raw packed DOS FileAge integer (decimal or `0x`-prefixed hex). |
| `--attributes` | Override the Win32 file attributes value (decimal or `0x`-prefixed hex). See table below. |
| `--name` | Override the filename used in the checksum's name-sum term (default: the file's basename). Use this if the file was renamed since the checksum was generated. |
| `--file-size` | Override the file size in bytes. Rarely needed. |

All overrides apply to every path given in that invocation.

**Why this matters:** on Linux/macOS, real Windows file attributes and
timestamps can't be read directly, so the script falls back to
best-effort guesses that won't reliably match `Exl_win.exe`'s real
output. Passing the real values explicitly (read off the original
Windows machine once, e.g. with `Get-Item file | Format-List *`) makes
the result exact regardless of what OS the script runs on.

##### Win32 attribute values

Attributes are bitflags - combine by adding the values (or pass the
combined value directly):

| Value | Name | Meaning |
|---|---|---|
| `0x01` | READONLY | Read-only file |
| `0x02` | HIDDEN | Hidden file |
| `0x04` | SYSTEM | Operating system file |
| `0x10` | DIRECTORY | Is a directory |
| `0x20` | ARCHIVE | Archive bit - the default Windows sets on ordinary files; the most common single value you'll need |
| `0x80` | NORMAL | No other attributes set (only valid alone) |
| `0x100` | TEMPORARY | Temporary file |
| `0x400` | REPARSE_POINT | Symlink or junction |
| `0x800` | COMPRESSED | NTFS-compressed file |
| `0x2000` | ENCRYPTED | NTFS-encrypted file |

Examples: `--attributes 0x20` (plain file), `--attributes 0x21` (archive +
read-only, `0x20 + 0x01`), `--attributes 32` (same as `0x20`, decimal
form).

Full details: `uv run exlibrys.py --help`

### Programmatic usage

Import `compute_checksum` directly to use `exlibrys` as a library rather
than a CLI tool:

```python
from exlibrys import compute_checksum

checksum = compute_checksum("path/to/file.txt")
print(checksum)  # e.g. "54T8-E0TL"
```

`compute_checksum` accepts the same overrides as the CLI flags, as keyword
arguments - useful for batch-processing many files with metadata you've
already collected (e.g. from a manifest, a database, or an earlier scan of
the original Windows machine), without touching the filesystem's real
timestamp/attributes at all:

```python
from exlibrys import compute_checksum, file_age_dos_from_mtime
import datetime

checksum = compute_checksum(
    "file.txt",
    name_for_sum="original-filename.docx",   # overrides the basename
    file_age=1558028784,                     # raw packed DOS FileAge int
    attributes=0x20,                         # Win32 attributes
    file_size=23309,                         # bytes, rarely needed
)

# --file-age also accepts a datetime - the equivalent helper for
# programmatic use is file_age_dos_from_mtime(), which takes a Unix
# timestamp (e.g. from datetime.timestamp()):
dt = datetime.datetime(2024, 6, 15, 14, 30, 22)
checksum = compute_checksum("file.txt", file_age=file_age_dos_from_mtime(dt.timestamp()))
```

Processing every file in a directory:

```python
import os
from exlibrys import compute_checksum

for entry in os.scandir("some/directory"):
    if entry.is_file():
        print(entry.name, "->", compute_checksum(entry.path))
```

A failed checksum for one file shouldn't usually stop a batch job - wrap
each call:

```python
results = {}
for entry in os.scandir("some/directory"):
    if entry.is_file():
        try:
            results[entry.name] = compute_checksum(entry.path)
        except Exception as e:
            results[entry.name] = f"ERROR: {e}"
```

### Diagnostics

A few helper functions are available for troubleshooting a mismatch
against real `Exl_win.exe` output:

```python
from exlibrys import debug_accumulator, debug_attributes_source, debug_fileage_seconds

debug_accumulator("file.txt")          # every intermediate value + final checksum
debug_attributes_source("file.txt")    # real Win32 API vs. fallback guess, side by side
debug_fileage_seconds("file.txt")      # raw mtime seconds, for ruling out rounding issues
```

Or from the command line:

```bash
uv run python -c "from exlibrys import debug_accumulator; debug_accumulator('file.txt')"
```
