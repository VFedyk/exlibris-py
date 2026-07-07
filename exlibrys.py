"""
Reconstruction of the "Екслібрис" (Ex Libris) / Exl_win.exe checksum algorithm.

Derived via static analysis (disassembly of Exl_win.exe, a Delphi/Borland Win32 binary)
plus targeted x86 emulation (Unicorn) to verify the exact Borland RTL `Str(Extended)`
formatting behaviour.

ALGORITHM SUMMARY
------------------
1. An integer accumulator is built from file + filename metadata:

       acc = FileAge(path) + GetFileAttributes(path)
           + (FileSize(path) // 128)
           + sum(ord(c) for c in path)      # the exact string passed to the
                                             # underlying WinAPI calls - see CAVEATS

2. The file's first min(FileSize, 65535) bytes are read. For each 1-indexed
   byte position i (1..bytesRead) with value `b`:

       N = FileSize // 128                  # same blockCount as above
       P = round(N * 0.618)                  # golden-ratio split point

       bucket = round(b * (pi/128) / 0.01746)   # NOTE: 0.01746 is a hand-typed
                                                  # imprecise stand-in for pi/180
                                                  # actually used by the binary -
                                                  # must be reproduced exactly.

       if i <= P:
           weight = (i * 0.236) / P
       else:
           weight = ((N - i + 1) * 0.236) / (N - P + 1)

       histogram[bucket] += weight          # 360 buckets (0..359), float accum

3. After processing all bytes, every histogram bucket is folded back into the
   accumulator, weighted by (2*bucket + 1), and the buckets are cleared:

       acc_float = float(acc) + sum(histogram[k] * (2*k + 1) for k in range(360))

4. acc_float is formatted exactly as Borland's default `Str(Extended)` would:

       " D.DDDDDDDDDDDDDDE+EEEE"   (sign-or-space, 1 digit, '.', 14 digits,
                                    'E', sign, 4-digit exponent) - 23 chars total.

   Characters 8..17 (1-indexed, i.e. python slice [7:17]) are extracted - this
   window always lands entirely inside the 14 fractional mantissa digits.

5. Those 10 decimal digits are treated as 10 independent 4-bit nibbles
   (each digit 0-9 fits in 4 bits), concatenated MSB-first into a 40-bit
   stream, and re-sliced into 8 groups of 5 bits (40 / 5 = 8). Each 5-bit
   value (0-31) indexes into the custom alphabet:

       "0123456789ABCDEFGHKLMNPRSTUVWXYZ"     (32 chars; no I, O, Q)

   producing an 8-character string. A '-' is inserted at position 5,
   yielding the final "XXXX-XXXX" checksum.

CAVEATS / UNVERIFIED PIECES
----------------------------
* FileAge()/GetFileAttributes() depend on filesystem metadata (last-write
  time, archive/hidden/readonly bits) that isn't recoverable from file
  content alone. The histogram/bit-packing engine IS independently
  verified against real Exl_win.exe output across many test files - that
  part reproduces exactly given the correct accumulator.
* The exact string passed into FileAge/GetFileAttributes/ASCII-sum (full
  path vs. bare filename, and whether it's the path as typed/selected by
  the user or some normalized form) was not 100% pinned down; bare filename
  is used below as the best-supported guess from the disassembly context.
* Str(Extended) general-format behaviour was verified by direct emulation of
  Borland's RTL routine inside the actual binary for a range of inputs
  (zero, positive, negative, fractional, large exponent) - that mapping is
  solid. Round() uses round-half-to-even (matches Python's `round()`).
"""

import math
import os
import struct
import sys
import time

ALPHABET = "0123456789ABCDEFGHKLMNPRSTUVWXYZ"
PI_OVER_128 = math.pi / 128
HAND_PI_OVER_180 = 0.01746  # exact hand-typed constant found in the binary - NOT math.pi/180
GOLDEN = 0.618
GOLDEN_COMPLEMENT = 0.236
NUM_BUCKETS = 360
READ_LIMIT = 0xFFFF  # 65535 bytes max read by the histogram pass


def name_sum_bytes(name: str) -> int:
    """
    Sum of the filename's BYTE values as the real Win32 ANSI application
    would see them - NOT Python's raw Unicode ord() values. Confirmed via
    real-world testing: a Cyrillic filename summed via plain ord() (full
    Unicode codepoints, e.g. 1072 for 'а') produced a wildly wrong
    accumulator. Encoding as Windows-1251 (the codepage implied by this
    program's own Ukrainian-language UI strings, found embedded in the
    binary as cp1251 bytes) and summing the resulting BYTE values is the
    correct approach for any non-ASCII filename. For plain ASCII filenames
    this is identical to summing ord() values, so no prior test case is
    affected.
    """
    try:
        encoded = name.encode("cp1251")
    except UnicodeEncodeError:
        encoded = name.encode("cp1251", errors="replace")
    return sum(encoded)


def file_age_dos_from_mtime(mtime: float) -> int:
    """
    Pack a Unix timestamp (seconds since epoch, as from os.path.getmtime())
    into Delphi's FileAge() format: 32-bit DOS date/time, matching
    FileTimeToDosDateTime() (local time).
    """
    t = time.localtime(mtime)
    dos_time = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    dos_date = ((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    return (dos_date << 16) | dos_time


def debug_win32_timesource(path: str) -> None:
    """
    Historical diagnostic - checks whether a direct CreateFile+GetFileTime
    Win32 call returns a different value than os.path.getmtime(). Kept for
    reference, but confirmed via real-world testing that the two paths
    always agree - this was a dead end (see file_age_dos() HISTORY for the
    fix that actually worked).
    """
    print(f"path = {path!r}")
    mtime_result = file_age_dos_from_mtime(os.path.getmtime(path))
    print(f"os.path.getmtime()-based result: {mtime_result} (0x{mtime_result:08X})")

    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
            os.path.abspath(path), 0x80000000, 0x1 | 0x2 | 0x4,
            None, 3, 0x02000000, None,
        )
        if handle == wintypes.HANDLE(-1).value or not handle:
            raise OSError(f"CreateFileW failed (error {ctypes.get_last_error()})")
        try:
            ft_write = wintypes.FILETIME()
            ok = kernel32.GetFileTime(handle, None, None, ctypes.byref(ft_write))
            if not ok:
                raise OSError(f"GetFileTime failed (error {ctypes.get_last_error()})")
        finally:
            kernel32.CloseHandle(handle)
        ft_local = wintypes.FILETIME()
        kernel32.FileTimeToLocalFileTime(ctypes.byref(ft_write), ctypes.byref(ft_local))
        dos_date, dos_time = wintypes.WORD(), wintypes.WORD()
        kernel32.FileTimeToDosDateTime(ctypes.byref(ft_local), ctypes.byref(dos_date), ctypes.byref(dos_time))
        win32_result = (dos_date.value << 16) | dos_time.value
        print(f"direct CreateFile+GetFileTime result: {win32_result} (0x{win32_result:08X})")
        print("agree" if win32_result == mtime_result else "DISAGREE", "with os.path.getmtime()")
    except Exception as e:
        print(f"direct Win32 call failed or unavailable: {type(e).__name__}: {e}")

    actual = file_age_dos(path)
    print(f"file_age_dos() (with the confirmed -2s correction) returned: {actual} (0x{actual:08X})")


def file_age_dos(path: str) -> int:
    """
    Reproduce the timestamp Exl_win.exe actually uses for FileAge.

    CONFIRMED VIA REAL-WORLD TESTING across five independent files (plain
    ASCII names, a Cyrillic name, different drives/filesystems including
    both NTFS and FAT32): Exl_win.exe's effective last-write time is
    consistently exactly 2 real seconds EARLIER than what every Windows
    timestamp API reports (os.path.getmtime(), a direct
    CreateFile+GetFileTime handle, and .NET's LastWriteTime/LastWriteTimeUtc
    all agree with each other and all disagree with Exl_win.exe by the same
    fixed 2 seconds, every time, regardless of drive/filesystem). This
    ruled out: filesystem timestamp precision (FAT32 vs NTFS - identical
    behaviour on both), which Win32 API reads the timestamp (enumeration
    vs. handle-based - both agree with each other), DST/timezone handling
    (hour and minute always matched exactly - only seconds were ever off,
    by the same fixed amount), and live clock drift (reproduced even on a
    freshly-created file checked immediately, no time gap at all).

    The likely explanation is that Delphi/Borland's own internal RTL
    timestamp-conversion routines (whatever FileAge() or the equivalent
    code in Exl_win.exe actually calls) don't go through the real Win32
    API's FileTimeToLocalFileTime/FileTimeToDosDateTime at all, but use
    their own reimplementation with this 2-second bias baked in - this
    wasn't independently verified against the disassembly after the
    discovery, only against real Exl_win.exe output across the five files
    that exposed and then confirmed it.

    HISTORY: two earlier attempts at this function did NOT fix the issue
    and were reverted:
      1. Switching from last-write time to creation time (os.path.getctime())
         - based on one file where creation time coincidentally matched.
         Further testing showed creation time is unreliable in general.
      2. Calling CreateFile+GetFileTime directly via ctypes instead of
         os.path.getmtime() - confirmed via direct testing that both paths
         return the IDENTICAL raw value, so this bought nothing; the
         discrepancy is not about which Win32 API reads the timestamp.
    The actual fix is the empirically-confirmed flat -2 second correction
    applied here.
    """
    return file_age_dos_from_mtime(os.path.getmtime(path) - 2.0)


def debug_attributes_source(path: str) -> None:
    """
    Report whether file_attributes() actually used the real Win32 API or
    fell back to the Unix-stat guess, and what each would individually
    return - to distinguish "API succeeded with value X" from "API failed,
    fallback happened to also compute X" (which look identical from the
    final number alone).
    """
    abs_path = os.path.abspath(path)
    api_result = None
    api_error = None
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.GetFileAttributesA.restype = ctypes.c_uint32
        kernel32.GetFileAttributesA.argtypes = [ctypes.c_char_p]
        api_result = kernel32.GetFileAttributesA(abs_path.encode("mbcs", errors="replace"))
        if api_result == 0xFFFFFFFF:
            api_error = "INVALID_FILE_ATTRIBUTES (call failed)"
            api_result = None
    except Exception as e:
        api_error = f"{type(e).__name__}: {e}"

    fallback_result = None
    try:
        import stat
        st = os.stat(path)
        attr = 0x20
        if stat.S_ISDIR(st.st_mode):
            attr |= 0x10
        if not (st.st_mode & 0o200):
            attr |= 0x01
        fallback_result = attr
    except OSError as e:
        fallback_result = f"error: {e}"

    print(f"abs_path        = {abs_path!r}")
    print(f"real API result = {api_result}  (0x{api_result:08X})" if api_result is not None else f"real API result = FAILED ({api_error})")
    print(f"fallback result = {fallback_result}  (0x{fallback_result:08X})" if isinstance(fallback_result, int) else f"fallback result = {fallback_result}")
    print(f"actually used   = {'REAL API' if api_result is not None else 'FALLBACK GUESS'}")


def file_attributes(path: str) -> int:
    """
    Get Win32 file attributes for `path`.

    On real Windows: calls the actual GetFileAttributesA - exact, no
    approximation needed.

    On non-Windows (Linux/macOS) or if the API call fails for any reason:
    falls back to a best-effort guess from Unix stat() bits
    (FILE_ATTRIBUTE_ARCHIVE | _DIRECTORY | _READONLY). This fallback is NOT
    guaranteed to match the real Windows value - Windows attribute bits
    (hidden, system, archive) don't have a clean Unix equivalent. Use
    --attributes on the CLI to supply the real value directly if you know it
    (e.g. by checking the file's properties on the original Windows machine,
    or via a WSL-mounted NTFS path where the real API can be reached).
    """
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.GetFileAttributesA.restype = ctypes.c_uint32
        kernel32.GetFileAttributesA.argtypes = [ctypes.c_char_p]
        # Use the absolute path - GetFileAttributesA resolves relative paths
        # against the process's current directory, which should match here,
        # but being explicit avoids any ambiguity.
        abs_path = os.path.abspath(path)
        result = kernel32.GetFileAttributesA(abs_path.encode("mbcs", errors="replace"))
        if result != 0xFFFFFFFF:  # INVALID_FILE_ATTRIBUTES, now compared correctly as unsigned
            return result
    except (AttributeError, OSError, UnicodeError):
        pass  # not on Windows, or the call failed - fall through to the guess

    try:
        import stat
        st = os.stat(path)
        attr = 0x20  # FILE_ATTRIBUTE_ARCHIVE is the common default Windows sets
        if stat.S_ISDIR(st.st_mode):
            attr |= 0x10
        if not (st.st_mode & 0o200):
            attr |= 0x01
        return attr
    except OSError:
        return 0


def borland_str_extended(value: float) -> str:
    """
    Exact reproduction (verified via x86 emulation of the real binary) of
    Borland/Delphi's `Str(Value: Extended; var S: string)` with no explicit
    width/decimals: fixed-format scientific notation,
        "<sign-or-space><1 digit>.<14 digits>E<sign><4-digit exponent>"
    23 characters total.
    """
    if value == 0:
        mantissa_str = "0." + "0" * 14
        exp = 0
        sign = " "
    else:
        sign = "-" if value < 0 else " "
        av = abs(value)
        exp = math.floor(math.log10(av))
        mantissa = av / (10 ** exp)
        mantissa_str = f"{mantissa:.14f}"
        # handle rounding pushing mantissa to 10.000...
        if float(mantissa_str) >= 10.0:
            exp += 1
            mantissa = av / (10 ** exp)
            mantissa_str = f"{mantissa:.14f}"
    exp_sign = "+" if exp >= 0 else "-"
    return f"{sign}{mantissa_str}E{exp_sign}{abs(exp):04d}"


def pack_digits_to_base32(digit_string: str, alphabet: str = ALPHABET) -> str:
    """
    Treat each decimal digit char as a 4-bit nibble, concatenate MSB-first
    into a single bitstream, slice into 5-bit groups, map each through
    `alphabet`. len(digit_string) * 4 must be divisible by 5 (10 digits -> 8
    symbols, as used by this algorithm).
    """
    bits = "".join(format(int(c), "04b") for c in digit_string)
    assert len(bits) % 5 == 0, f"bit length {len(bits)} not divisible by 5"
    out = []
    for i in range(0, len(bits), 5):
        out.append(alphabet[int(bits[i:i + 5], 2)])
    return "".join(out)


def delphi_round(x: float) -> int:
    """Round-half-to-even, matching the FPU default rounding mode used by Round()."""
    return round(x)


def compute_checksum(
    path: str,
    name_for_sum: str = None,
    file_age: int = None,
    attributes: int = None,
    file_size: int = None,
) -> str:
    """
    Compute the Exl_win.exe-style checksum for the file at `path`.

    All metadata inputs can be overridden explicitly, which is what makes
    this usable cross-platform: on real Windows the defaults (real
    GetFileAttributesA, real FileAge from mtime) are exact. On Linux/macOS,
    or for a file whose original Windows metadata you know from elsewhere
    (e.g. you read it off the source machine before copying), pass the real
    values in directly instead of relying on the fallback guesses.

    name_for_sum: the string whose byte values (Windows-1251 encoded) get
        summed into the accumulator. Defaults to os.path.basename(path).
    file_age: pre-packed Delphi FileAge() value (32-bit DOS date/time). If
        None, computed from the file's actual mtime via file_age_dos().
        Use file_age_dos_from_mtime() to pack a known Unix timestamp, or
        pass the raw DOS-packed integer directly if you have it.
    attributes: Win32 file attributes integer. If None, uses the real
        GetFileAttributesA on Windows, or a best-effort Unix-stat-based
        guess otherwise (see file_attributes() docstring for caveats).
    file_size: file size in bytes. If None, uses os.path.getsize(path).
        Override only if you're computing a checksum for content that isn't
        literally on disk at `path` in its original form.
    """
    if name_for_sum is None:
        name_for_sum = os.path.basename(path)

    if file_size is None:
        file_size = os.path.getsize(path)  # N (the histogram's golden-ratio variable).
        # This is the RAW byte count, confirmed both empirically AND now from the
        # disassembly. The stream's Size() method (0x405958) computes
        # FileSizeInBytes / [obj+0x8], where [obj+0x8] is a record-size field.
        # The constructor (0x405816) sets that field to 128, which briefly made
        # it look like Size() returns FileSize/128 - but the file-open call
        # (0x405ae9) that runs *between* construction and the Size() read
        # overwrites the field with 1 (byte-granular record size). So Size()
        # returns FileSize / 1 = FileSize. An earlier draft stopped the trace at
        # the constructor and missed that intervening overwrite.

    acc = 0
    if file_age is not None:
        acc += file_age
    elif os.path.exists(path):
        acc += file_age_dos(path)

    if attributes is not None:
        acc += attributes
    else:
        acc += file_attributes(path)

    acc += file_size
    acc += name_sum_bytes(name_for_sum)

    # ACCUMULATOR_FUDGE (+1): an empirically-confirmed constant, deliberately
    # kept as-is. The accumulator built above (FileAge + attributes + FileSize
    # + filename-byte-sum) comes out consistently 1 too low versus the real
    # Exl_win.exe result, across every file tested (many files, varied content,
    # size, filename, and both odd/even mtime-seconds).
    #
    # Its exact origin in the binary was investigated but not pinned down. The
    # checksum function (0x472d40) builds the accumulator [ebp-0x2c] from
    # exactly four contributions - FileAge (0x4086a4), GetFileAttributes
    # (0x4086f4), FileSize (0x405958), and the filename byte-sum loop - with no
    # explicit "+1" instruction among them, and each of those was traced and
    # matches this reimplementation. The +1 therefore lives in some RTL
    # nuance inside one of the helper calls (a likely candidate is a semantic
    # difference in how the original obtains file attributes vs. our
    # GetFileAttributesA, or the handle open/close path) rather than in the
    # checksum routine itself. Chasing it further was judged not worth the
    # effort: it's a fixed offset, so the worst plausible failure mode is an
    # obvious off-by-a-small-integer that would be trivial to spot and re-tune,
    # not a silent subtle corruption. FileAge seconds-rounding was specifically
    # ruled out as the cause. If a file ever needs a correction other than +1,
    # that's the signal the real source is not a flat constant after all.
    acc += 1

    # --- histogram / golden-ratio pass ---
    # Confirmed via real-world testing against three files >65535 bytes: the
    # ENTIRE file is processed, not just the first 65535 bytes. An earlier
    # draft assumed a single TFileStream.Read(buf, 0xFFFF) call capped the
    # data seen by this loop - that 0xFFFF really is the request size of one
    # Read() call, but the real code evidently loops until EOF (processing
    # the file in 65535-byte chunks) rather than stopping after one read.
    # N = file_size throughout, matching every verified test file regardless
    # of size.
    with open(path, "rb") as f:
        data = f.read()

    bytes_read = len(data)
    N = file_size
    P = delphi_round(N * GOLDEN)
    histogram = [0.0] * NUM_BUCKETS

    if bytes_read > 0:
        for i in range(1, bytes_read + 1):  # 1-indexed, matches the original loop
            b = data[i - 1]
            bucket = delphi_round(b * PI_OVER_128 / HAND_PI_OVER_180)
            bucket = max(0, min(NUM_BUCKETS - 1, bucket))

            if P != 0 and i <= P:
                weight = (i * GOLDEN_COMPLEMENT) / P
            else:
                denom = (N - P + 1)
                weight = ((N - i + 1) * GOLDEN_COMPLEMENT) / denom if denom != 0 else 0.0

            histogram[bucket] += weight

    # fold histogram back into the accumulator
    acc_float = float(acc)
    for k in range(NUM_BUCKETS):
        acc_float += histogram[k] * (2 * k + 1)

    # --- Str() formatting + digit extraction ---
    s = borland_str_extended(acc_float)
    digit_window = s[7:17]  # Copy(S, 8, 10), 1-indexed -> python [7:17]

    if not (len(digit_window) == 10 and digit_window.isdigit()):
        raise ValueError(
            f"Unexpected digit window {digit_window!r} from Str() output {s!r} - "
            "value magnitude pushed non-digit chars into the extraction window; "
            "the formula or formatting assumption needs revisiting for this input."
        )

    # --- base32 bit-packing + dash insertion ---
    encoded = pack_digits_to_base32(digit_window)
    checksum = encoded[:4] + "-" + encoded[4:]
    return checksum


def _parse_datetime_to_dos(s: str) -> int:
    """Parse a human-readable datetime string into a packed DOS FileAge value."""
    import datetime
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(s, fmt)
            return file_age_dos_from_mtime(dt.timestamp())
        except ValueError:
            continue
    raise ValueError(
        f"Could not parse '{s}' as a datetime. Use 'YYYY-MM-DD HH:MM:SS' "
        f"(or a bare integer for a raw packed DOS FileAge value)."
    )


def _parse_int_auto(s: str) -> int:
    """Accept a plain int, or 0x-prefixed hex, for --attributes / --file-age."""
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        description="Compute Exl_win.exe-style checksums for one or more files.",
        epilog=(
            "Cross-platform notes:\n"
            "  On real Windows, file metadata (timestamp, attributes) is read via\n"
            "  the real Win32 APIs automatically - no overrides needed.\n"
            "  On Linux/macOS, or for a file whose ORIGINAL Windows metadata you\n"
            "  know from elsewhere, supply it explicitly:\n\n"
            "    --file-age \"2024-06-15 14:30:22\"   (human-readable local time)\n"
            "    --file-age 1558028784                (raw packed DOS FileAge int)\n"
            "    --attributes 0x20                    (Win32 attributes, hex or decimal)\n"
            "    --name \"original-filename.docx\"      (overrides the basename used\n"
            "                                           in the checksum's name-sum term)\n"
            "    --format table                       (or 'json' - see --format below)\n\n"
            "  Without these, results on non-Windows hosts will only match the real\n"
            "  Exl_win.exe output by coincidence - see file_attributes()/file_age_dos()\n"
            "  docstrings for exactly what's being approximated and why.\n\n"
            "Win32 file attribute values (for --attributes):\n"
            "  These are bitflags - combine by adding the values together (or pass the\n"
            "  combined hex directly). The value shown on a real Windows machine via\n"
            "  'Get-Item file | Format-List Attributes' or the debug_attributes_source()\n"
            "  helper is the one to use for an exact match.\n\n"
            "    0x01   READONLY     read-only file\n"
            "    0x02   HIDDEN       hidden file\n"
            "    0x04   SYSTEM       operating system file\n"
            "    0x10   DIRECTORY    is a directory\n"
            "    0x20   ARCHIVE      archive bit (the default Windows sets on ordinary\n"
            "                        files after creation/modification - most common\n"
            "                        single value you'll need)\n"
            "    0x80   NORMAL       no other attributes set (only valid alone)\n"
            "    0x100  TEMPORARY    temporary file (kept in cache, written on close)\n"
            "    0x400  REPARSE_POINT  symlink or junction point\n"
            "    0x800  COMPRESSED   NTFS-compressed file\n"
            "    0x2000 ENCRYPTED    NTFS-encrypted file\n\n"
            "  Examples:\n"
            "    --attributes 0x20        plain file, archive bit set (most common case)\n"
            "    --attributes 0x21        archive + read-only (0x20 + 0x01)\n"
            "    --attributes 32          same as 0x20, decimal form\n"
            "    --attributes 0x23        archive + hidden + read-only (0x20+0x02+0x01)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="+", help="File(s) to checksum.")
    parser.add_argument(
        "--name", dest="name_for_sum", default=None,
        help="Filename string to use in the name-sum term (default: basename of each path). "
             "Use this if the file was renamed and you need to match the checksum under its "
             "original Windows filename.",
    )
    parser.add_argument(
        "--file-age", dest="file_age", default=None, type=str,
        help="Override the FileAge value: either a human-readable datetime "
             "('2024-06-15 14:30:22', local time) or a raw packed DOS FileAge "
             "integer (decimal or 0x-prefixed hex). Applies to ALL paths given.",
    )
    parser.add_argument(
        "--attributes", dest="attributes", default=None, type=str,
        help="Override the Win32 file attributes value: decimal or 0x-prefixed hex. "
             "Common value: 0x20 (FILE_ATTRIBUTE_ARCHIVE, the default for an ordinary "
             "file). Combine flags by adding them, e.g. 0x21 = archive + read-only. "
             "See the bottom of --help for the full list of named values. "
             "Applies to ALL paths given.",
    )
    parser.add_argument(
        "--file-size", dest="file_size", default=None, type=int,
        help="Override the file size in bytes (rarely needed; default: actual size on disk). "
             "Applies to ALL paths given - only useful with a single path.",
    )
    parser.add_argument(
        "--format", dest="output_format", default="text",
        choices=["text", "table", "json"],
        help="Output format: 'text' (default) prints 'path: CHECKSUM' per line; "
             "'table' prints an aligned table; 'json' prints a JSON array of "
             "{\"path\", \"checksum\", \"error\"} objects, suitable for piping to "
             "other tools.",
    )
    parser.add_argument(
        "-q", "--quiet", dest="quiet", action="store_true",
        help="Print checksums only, with no path/filename attached - one per "
             "line for 'text'/'table', a plain JSON array of strings for "
             "'json'. Useful for capturing a single checksum straight into a "
             "shell variable, e.g. CHECKSUM=$(exlibrys -q file.txt). A failed "
             "file still reports its error (with no path to identify it by, "
             "so this is best combined with a single input file).",
    )
    args = parser.parse_args(argv)

    file_age = None
    if args.file_age is not None:
        try:
            file_age = _parse_int_auto(args.file_age)
        except ValueError:
            try:
                file_age = _parse_datetime_to_dos(args.file_age)
            except ValueError as e:
                parser.error(str(e))

    attributes = None
    if args.attributes is not None:
        try:
            attributes = _parse_int_auto(args.attributes)
        except ValueError:
            parser.error(f"--attributes value '{args.attributes}' is not a valid integer (decimal or 0x-hex).")

    results = []
    for p in args.paths:
        try:
            checksum = compute_checksum(
                p,
                name_for_sum=args.name_for_sum,
                file_age=file_age,
                attributes=attributes,
                file_size=args.file_size,
            )
            results.append({"path": p, "checksum": checksum, "error": None})
        except Exception as e:
            results.append({"path": p, "checksum": None, "error": str(e)})

    _print_results(results, args.output_format, quiet=args.quiet)

    if any(r["error"] is not None for r in results):
        sys.exit(1)


def _print_results(results, output_format, quiet=False):
    if output_format == "json":
        import json
        if quiet:
            values = [r["checksum"] if r["checksum"] is not None else f"ERROR - {r['error']}" for r in results]
            print(json.dumps(values, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    if output_format == "table":
        if quiet:
            value_w = max(
                [len("Checksum")]
                + [len(r["checksum"]) if r["checksum"] else len(f"ERROR - {r['error']}") for r in results]
            )
            print(f"{'Checksum':<{value_w}}")
            print("-" * value_w)
            for r in results:
                value = r["checksum"] if r["checksum"] else f"ERROR - {r['error']}"
                print(f"{value:<{value_w}}")
            return
        path_w = max([len("Path")] + [len(r["path"]) for r in results])
        value_w = max(
            [len("Checksum")]
            + [len(r["checksum"]) if r["checksum"] else len(f"ERROR - {r['error']}") for r in results]
        )
        header = f"{'Path':<{path_w}}  {'Checksum':<{value_w}}"
        print(header)
        print("-" * path_w + "  " + "-" * value_w)
        for r in results:
            value = r["checksum"] if r["checksum"] else f"ERROR - {r['error']}"
            print(f"{r['path']:<{path_w}}  {value:<{value_w}}")
        return

    # text (default)
    for r in results:
        if quiet:
            if r["checksum"] is not None:
                print(r["checksum"])
            else:
                print(f"ERROR - {r['error']}")
        else:
            if r["checksum"] is not None:
                print(f"{r['path']}: {r['checksum']}")
            else:
                print(f"{r['path']}: ERROR - {r['error']}")


if __name__ == "__main__":
    main()


def calibrate_accumulator_constant(known_checksum: str, file_size: int, filename: str):
    """
    Given a REAL checksum produced by Exl_win.exe for a file you control, and that
    file's size + the filename string used, search for the (FileAge + GetFileAttributes)
    constant that would reproduce it. Only meaningful when block_count==0 (file < 128
    bytes), so the histogram pass contributes nothing and acc_float == acc (a plain
    integer) - this lets you brute-force/verify the FileAge encoding on a real machine.

    This is a DIAGNOSTIC helper, not part of the core algorithm.
    """
    target = known_checksum.replace("-", "")
    name_sum = name_sum_bytes(filename)
    block_count = file_size // 128
    base = block_count + name_sum

    # FileAge (DOS packed date/time) realistically spans roughly 1980-2107,
    # i.e. raw values roughly 0 .. ~0x7FFFFFFF. GetFileAttributes is small (<0x1000
    # for ordinary files). Brute-forcing the full range is too slow in pure Python;
    # this function instead demonstrates HOW to check a candidate quickly so you can
    # plug in the real FileAge value computed on your Windows machine directly.
    def quick_check(file_age, attrs):
        acc = file_age + attrs + base
        s = borland_str_extended(float(acc))
        digits = s[7:17]
        if not digits.isdigit():
            return None
        return pack_digits_to_base32(digits)

    return quick_check


def debug_accumulator(path: str, name_for_sum: str = None) -> None:
    """
    Print every intermediate value feeding the accumulator, for diagnosing
    mismatches against real Exl_win.exe output. Run this on Windows with the
    real file_attributes() (ctypes GetFileAttributesA) wired in.
    """
    if name_for_sum is None:
        name_for_sum = os.path.basename(path)

    file_size = os.path.getsize(path)
    age = file_age_dos(path) if os.path.exists(path) else 0
    attrs = file_attributes(path)
    namesum = name_sum_bytes(name_for_sum)
    acc = age + attrs + file_size + namesum

    print(f"path           = {path!r}")
    print(f"name_for_sum   = {name_for_sum!r}")
    print(f"file_size      = {file_size}")
    print(f"file_age_dos   = {age}  (0x{age:08X})")
    print(f"file_attributes= {attrs}  (0x{attrs:08X})")
    print(f"namesum        = {namesum}")
    print(f"acc (sum)      = {acc}")
    print(f"checksum       = {compute_checksum(path, name_for_sum)}")


def debug_fileage_seconds(path: str) -> None:
    """
    Print the raw last-write-time seconds value to check whether DOS-time
    seconds rounding (floor vs round vs ceil) is the source of a +1
    discrepancy. Also shows creation time for comparison - see
    debug_fileage_source() if the two might be genuinely different and you
    need to know which one is actually driving a mismatch.
    """
    import time
    mtime = os.path.getmtime(path)
    t = time.localtime(mtime)
    print(f"mtime (raw float)   = {mtime!r}   (last-write time - what file_age_dos() uses)")
    print(f"seconds (int)       = {t.tm_sec}")
    print(f"sub-second fraction = {mtime - int(mtime):.6f}")
    print(f"floor(sec/2)        = {t.tm_sec // 2}")
    print(f"round(sec/2)        = {round(t.tm_sec / 2)}")
    print(f"ceil(sec/2)         = {-(-t.tm_sec // 2)}")
    print()
    ctime = os.path.getctime(path)
    if ctime != mtime:
        print(f"NOTE: creation time differs from last-write time by {ctime - mtime:+.6f}s")
        print(f"      (ctime={ctime!r}) - see debug_fileage_source() to compare both fully")
    else:
        print("(creation time is identical to last-write time for this file)")


def debug_fileage_source(path: str, name_for_sum: str = None) -> None:
    """
    Compute the full checksum under both the creation-time and
    last-write-time hypotheses for FileAge, side by side.

    HISTORY: creation time was briefly believed to be the correct field,
    based on a single file where it happened to match exactly while
    last-write time was off by one DOS-time tick. Further testing (see
    file_age_dos() docstring) showed that was a coincidence - last-write
    time is the field that's actually correct, matching Delphi's documented
    FileAge() semantics. Small residual mismatches under last-write time are
    ordinary clock drift (the file was touched again after a reference
    checksum was captured), not a deeper bug. This diagnostic still checks
    both, in case a future file genuinely needs creation time after all -
    but treat a clean small offset under last-write time as drift, not
    evidence for switching back to creation time on the strength of one
    file alone.
    """
    if name_for_sum is None:
        name_for_sum = os.path.basename(path)

    ctime = os.path.getctime(path)
    mtime = os.path.getmtime(path)
    attrs = file_attributes(path)

    print(f"creation time (ctime)   = {ctime!r}")
    print(f"last-write time (mtime) = {mtime!r}")
    print(f"difference              = {mtime - ctime:+.6f}s")
    print()

    for label, ts in [("creation time", ctime), ("last-write time", mtime)]:
        age = file_age_dos_from_mtime(ts)
        cs = compute_checksum(path, name_for_sum=name_for_sum, file_age=age, attributes=attrs)
        print(f"{label:16s}: file_age_dos={age:12d} (0x{age:08X})  checksum={cs}")


def debug_N_hypotheses(path: str, name_for_sum: str = None) -> None:
    """
    Compute the checksum under several different hypotheses for what N (the
    golden-ratio histogram variable) and the read range actually are, to
    determine empirically which one matches real Exl_win.exe output for
    large files (>65535 bytes).
    """
    if name_for_sum is None:
        name_for_sum = os.path.basename(path)

    file_size = os.path.getsize(path)
    with open(path, "rb") as f:
        capped_data = f.read(READ_LIMIT)
    bytes_read = len(capped_data)

    with open(path, "rb") as f:
        full_data = f.read()

    acc = 0
    if os.path.exists(path):
        acc += file_age_dos(path)
    acc += file_attributes(path)
    acc += file_size
    acc += name_sum_bytes(name_for_sum)
    acc += 1  # the confirmed universal fudge

    def hist_sum_for(data, N):
        P = delphi_round(N * GOLDEN)
        histogram = [0.0] * NUM_BUCKETS
        for i in range(1, len(data) + 1):
            b = data[i - 1]
            bucket = delphi_round(b * PI_OVER_128 / HAND_PI_OVER_180)
            bucket = max(0, min(NUM_BUCKETS - 1, bucket))
            if P != 0 and i <= P:
                weight = (i * GOLDEN_COMPLEMENT) / P
            else:
                denom = (N - P + 1)
                weight = ((N - i + 1) * GOLDEN_COMPLEMENT) / denom if denom != 0 else 0.0
            histogram[bucket] += weight
        return sum(histogram[k] * (2 * k + 1) for k in range(NUM_BUCKETS))

    hypotheses = {
        "N=bytes_read(capped@65535)": (capped_data, bytes_read),
        "N=file_size(capped read)": (capped_data, file_size),
        "N=file_size//128(capped read)": (capped_data, file_size // 128),
        "N=bytes_read//128(capped read)": (capped_data, bytes_read // 128),
        "N=file_size(FULL file read)": (full_data, file_size),
    }

    print(f"file_size={file_size}  bytes_read(capped)={bytes_read}  acc(integer part)={acc}")
    print()
    for label, (data, N) in hypotheses.items():
        h = hist_sum_for(data, N)
        acc_float = float(acc) + h
        s = borland_str_extended(acc_float)
        digits = s[7:17]
        if digits.isdigit():
            enc = pack_digits_to_base32(digits)
            cs = enc[:4] + "-" + enc[4:]
        else:
            cs = f"(non-digit window: {s!r})"
        print(f"{label:35s} N={N:8d}  hist_sum={h:15.4f}  checksum={cs}")
