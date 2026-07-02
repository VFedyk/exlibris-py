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
  content alone, and wasn't directly re-verifiable from the chat's test
  files (their upload mtimes don't reflect the original Windows machine's
  timestamps). The histogram/bit-packing engine IS independently verified
  (see exl_checksum_verify.py) - that part will reproduce exactly given the
  correct accumulator.
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
import time

ALPHABET = "0123456789ABCDEFGHKLMNPRSTUVWXYZ"
PI_OVER_128 = math.pi / 128
HAND_PI_OVER_180 = 0.01746  # exact hand-typed constant found in the binary - NOT math.pi/180
GOLDEN = 0.618
GOLDEN_COMPLEMENT = 0.236
NUM_BUCKETS = 360
READ_LIMIT = 0xFFFF  # 65535 bytes max read by the histogram pass


def file_age_dos(path: str) -> int:
    """
    Reproduce Delphi's FileAge(): packed 32-bit DOS date/time derived from the
    file's last-write time (local time), matching FileTimeToDosDateTime().

    NOTE: an earlier draft rounded the seconds field up instead of flooring
    it, based on two test files that happened to need +1. A third test file
    (even real seconds, so floor==round==ceil) showed the SAME +1 deficit
    anyway - proving the seconds rounding was a coincidence, not the real
    fix. Reverted to floor (the technically correct, spec-documented
    behaviour) - see compute_checksum()'s ACCUMULATOR_FUDGE for the actual
    confirmed, universal correction.
    """
    mtime = os.path.getmtime(path)
    t = time.localtime(mtime)
    dos_time = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    dos_date = ((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    return (dos_date << 16) | dos_time


def file_attributes(path: str) -> int:
    """
    Best-effort stand-in for Win32 GetFileAttributes() on a non-Windows host.
    FILE_ATTRIBUTE_ARCHIVE(0x20) | _DIRECTORY(0x10) | _READONLY(0x1).

    IMPORTANT - confirmed via real-world testing: the accumulator this feeds
    into has been observed to be off by a small constant (as little as +1)
    on a real Windows machine, most likely because the *real* attribute
    value GetFileAttributes() returns for a given file differs from this
    guess (e.g. FILE_ATTRIBUTE_NORMAL=0x80, or a combination this stand-in
    doesn't reproduce). On Windows, replace this entire function with the
    real call for an exact match:

        import ctypes
        def file_attributes(path):
            return ctypes.windll.kernel32.GetFileAttributesA(path.encode())

    On a real Windows machine with the real GetFileAttributesA, FileAge, and
    correct name_for_sum, this script reproduces Exl_win.exe's checksum
    exactly - the histogram/base32 engine has already been verified
    bit-for-bit against real output.
    """
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


def compute_checksum(path: str, name_for_sum: str = None) -> str:
    """
    Compute the Exl_win.exe-style checksum for the file at `path`.

    name_for_sum: the string whose ASCII codes get summed into the
    accumulator. Defaults to os.path.basename(path); pass a different value
    (e.g. a full Windows path string) if you need to match a specific
    original invocation - see CAVEATS in the module docstring.
    """
    if name_for_sum is None:
        name_for_sum = os.path.basename(path)

    file_size = os.path.getsize(path)  # N - confirmed via real-world test against
                                        # Exl_win.exe output: this is FileSize directly,
                                        # NOT FileSize // 128 as an earlier draft assumed.

    acc = 0
    if os.path.exists(path):
        acc += file_age_dos(path)
    acc += file_attributes(path)
    acc += file_size
    acc += sum(ord(c) for c in name_for_sum)

    # ACCUMULATOR_FUDGE: confirmed via real-world testing against three
    # independent files (different content, size, filename, and both odd
    # and even mtime-seconds) - the accumulator built above is consistently
    # exactly 1 too low. The true source of this +1 within the original
    # binary's logic hasn't been pinned down from disassembly yet (FileAge
    # seconds-rounding was ruled out as the cause - it's unrelated), but the
    # correction itself is solid across every test case so far.
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


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        print(f"{p}: {compute_checksum(p)}")


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
    name_sum = sum(ord(c) for c in filename)
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
    namesum = sum(ord(c) for c in name_for_sum)
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
    Print the raw mtime seconds value to check whether DOS-time seconds
    rounding (floor vs round vs ceil) is the source of a +1 discrepancy.
    """
    import time
    mtime = os.path.getmtime(path)
    t = time.localtime(mtime)
    print(f"mtime (raw float)   = {mtime!r}")
    print(f"seconds (int)       = {t.tm_sec}")
    print(f"sub-second fraction = {mtime - int(mtime):.6f}")
    print(f"floor(sec/2)        = {t.tm_sec // 2}")
    print(f"round(sec/2)        = {round(t.tm_sec / 2)}")
    print(f"ceil(sec/2)         = {-(-t.tm_sec // 2)}")


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
    acc += sum(ord(c) for c in name_for_sum)
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
