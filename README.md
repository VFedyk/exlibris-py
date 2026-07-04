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
| `--format` | Output format: `text` (default), `table`, or `json`. See below. |

All overrides apply to every path given in that invocation.

#### Output formats

```bash
uv run exlibrys.py --format text file1.txt file2.txt    # default
uv run exlibrys.py --format table file1.txt file2.txt
uv run exlibrys.py --format json file1.txt file2.txt
```

**text** (default) - one line per file:

```
file1.txt: 54T8-E0TL
file2.txt: 54V1-G100
```

**table** - aligned columns:

```
Path        Checksum
----------  ---------
file1.txt   54T8-E0TL
file2.txt   54V1-G100
```

**json** - an array of objects, useful for piping into other tools:

```json
[
  {"path": "file1.txt", "checksum": "54T8-E0TL", "error": null},
  {"path": "file2.txt", "checksum": "54V1-G100", "error": null}
]
```

In all three formats, a file that fails (e.g. doesn't exist, or a real
error during computation) is reported inline rather than stopping the
whole run - `checksum` is `null` and `error` holds the message in JSON
mode, or an `ERROR - ...` string in text/table mode. The process exits
with status 1 if any file failed, 0 if all succeeded.

#### Checksum-only output (`-q` / `--quiet`)

Strips the path/filename from the output entirely, in any format - just
the checksum value(s):

```bash
uv run exlibrys.py -q file.txt
# 54T8-E0TL

uv run exlibrys.py -q file1.txt file2.txt
# 54T8-E0TL
# 54V1-G100
```

Handy for capturing a single checksum straight into a shell variable:

```bash
CHECKSUM=$(uv run exlibrys.py -q file.txt)
```

Combines with `--format`: `-q --format json` gives a plain JSON array of
checksum strings (no `path`/`error` keys), `-q --format table` gives a
single-column table. Note that if a file fails, the error message itself
may still mention its path (that's just what the underlying OS error
says) - `--quiet` only omits the `path: ` prefix we add ourselves, so
it's most useful for batches you don't expect to fail, or a single file
at a time.

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

## Development

Install with dev dependencies and run the test suite:

```bash
uv pip install -e ".[dev]"
pytest
```

The test suite (`tests/test_exlibrys.py`) covers:

- Full checksum matches against real, previously-confirmed `Exl_win.exe`
  output (content + explicit FileAge/attributes together).
- Content-only matches for larger synthetic fixtures, regenerated
  deterministically from a fixed seed (no binary files are committed to
  the repo - see below).
- A regression test confirming the entire file is processed rather than
  capped at 65535 bytes (a real bug caught during reconstruction).
- Unit tests for the individual building blocks: filename byte-summing
  (including the cp1251 Cyrillic case), base32 packing, the Borland
  `Str(Extended)` float formatter, DOS date/time packing, and CLI argument
  parsing/error handling.

### Regenerating test fixtures for manual testing

The 1KB/1MB/5MB files used in tests are generated in-memory from a fixed
seed - they aren't committed to the repo as binary files. If you want a
local copy to manually run against the real `Exl_win.exe` on Windows:

```bash
python scripts/generate_fixtures.py [output_dir]
```

This writes byte-identical copies of what the test suite generates
in-memory, so any checksum you get from the real program on these files
can be added back into `tests/test_exlibrys.py` as a new confirmed test
case.

