"""
Unit tests for exlibrys.

Test cases fall into two categories:

1. Full checksum matches: content + explicit file_age/attributes overrides
   that reproduce a checksum actually confirmed against real Exl_win.exe
   output. These are the strongest tests - both the content/histogram half
   and the metadata half are verified simultaneously.

2. Content-only ("second half") matches: for larger synthetic fixtures we
   don't have a captured real file_age/attributes pair, so only the
   content-dependent half of the checksum (after the dash) is asserted.
   IMPORTANT: the placeholder file_age used for these must be a realistic
   ~1.5-2 billion magnitude (same order as a genuine Windows FileAge value,
   which determines the float's exponent) - an unrealistic value like 0
   shifts which digits land in the extraction window and breaks the
   "content half is independent of metadata" property these tests rely on.
   See compute_checksum()'s digit-window extraction for why.
"""
import os
import random
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import exlibrys as ex


# A realistic FileAge-scale placeholder (same exponent/magnitude as a real
# Windows FileAge value) - see module docstring above for why this matters.
REALISTIC_PLACEHOLDER_AGE = 1558028797


# ---------------------------------------------------------------------------
# Full checksum matches (content + metadata both verified against real
# Exl_win.exe output)
# ---------------------------------------------------------------------------

FULL_MATCH_CASES = [
    # (filename, content, file_age, attributes, expected_checksum)
    ("empty.txt", b"", 1558028784, 0x20, "55VM-0000"),
    ("1.txt", b"test", 1558028662, 0x20, "54T8-E0TL"),
    ("b.txt", b"b", 1558085190, 0x20, "GNW5-6WG0"),
]


@pytest.mark.parametrize("filename,content,file_age,attributes,expected", FULL_MATCH_CASES)
def test_full_checksum_matches_real_exlibris(tmp_path, filename, content, file_age, attributes, expected):
    p = tmp_path / filename
    p.write_bytes(content)
    result = ex.compute_checksum(str(p), file_age=file_age, attributes=attributes)
    assert result == expected


# ---------------------------------------------------------------------------
# Content-only ("second half") matches - larger files where only the
# content/histogram half was independently confirmed.
# ---------------------------------------------------------------------------

def _generate_1kb_fixture() -> bytes:
    random.seed(42)
    return bytes(random.randint(32, 126) for _ in range(1024))


def _generate_1mb_fixture() -> bytes:
    # NOTE: continues the SAME random stream as the 1KB fixture, without
    # re-seeding - this must match exactly how the original fixtures were
    # generated for the second-half values below to be correct.
    random.seed(42)
    _ = bytes(random.randint(32, 126) for _ in range(1024))
    return bytes(random.randint(0, 255) for _ in range(1024 * 1024))


def _generate_5mb_fixture() -> bytes:
    np = pytest.importorskip("numpy", reason="numpy needed to regenerate the 5MB fixture deterministically")
    rng = np.random.default_rng(42)
    return rng.integers(0, 256, size=5 * 1024 * 1024, dtype="uint8").tobytes()


CONTENT_ONLY_CASES = [
    ("test_1kb.txt", _generate_1kb_fixture, "CWHT"),
    ("test_1mb.bin", _generate_1mb_fixture, "4HW7"),
    ("test_5mb.bin", _generate_5mb_fixture, "H43S"),
]


@pytest.mark.parametrize("filename,generator,expected_second_half", CONTENT_ONLY_CASES)
def test_large_file_content_half_matches_real_exlibris(tmp_path, filename, generator, expected_second_half):
    content = generator()
    p = tmp_path / filename
    p.write_bytes(content)
    result = ex.compute_checksum(str(p), file_age=REALISTIC_PLACEHOLDER_AGE, attributes=0x20)
    assert result.split("-")[1] == expected_second_half


def test_entire_file_is_processed_not_capped_at_65535_bytes(tmp_path):
    """
    Regression test for a real reconstruction bug: an earlier draft assumed
    only the first 65535 bytes of a file were read/hashed. Two files that
    are identical for their first 65535 bytes but differ afterward MUST
    produce different checksums if the whole file is genuinely processed.
    """
    base = bytes((i % 256) for i in range(70000))
    tail_a = base + b"AAAA"
    tail_b = base + b"BBBB"

    p_a = tmp_path / "a70k.bin"
    p_b = tmp_path / "b70k.bin"
    p_a.write_bytes(tail_a)
    p_b.write_bytes(tail_b)

    cs_a = ex.compute_checksum(str(p_a), file_age=REALISTIC_PLACEHOLDER_AGE, attributes=0x20)
    cs_b = ex.compute_checksum(str(p_b), file_age=REALISTIC_PLACEHOLDER_AGE, attributes=0x20)
    assert cs_a != cs_b


# ---------------------------------------------------------------------------
# Helper function units
# ---------------------------------------------------------------------------

def test_name_sum_bytes_ascii():
    # 'a'=97 + '.'=46 + 't'=116 + 'x'=120 + 't'=116 = 495
    assert ex.name_sum_bytes("a.txt") == 495


def test_name_sum_bytes_cyrillic_cp1251():
    # Confirmed against a real reconstruction bug: summing raw Unicode
    # codepoints (Python's plain ord()) instead of cp1251 byte values gave
    # a wildly wrong result for non-ASCII filenames.
    assert ex.name_sum_bytes("аліса.docx") == 1579


def test_name_sum_bytes_cp1251_fallback_does_not_raise():
    # A character outside cp1251 should not crash the whole computation.
    result = ex.name_sum_bytes("日本語.txt")
    assert isinstance(result, int)


def test_pack_digits_to_base32_length_and_alphabet():
    digits = "1234567890"
    packed = ex.pack_digits_to_base32(digits)
    assert len(packed) == 8
    assert all(c in ex.ALPHABET for c in packed)


def test_pack_digits_to_base32_alphabet_excludes_ambiguous_chars():
    # The custom alphabet deliberately excludes I, O, Q to avoid confusion
    # with 1, 0. Guard against a future edit accidentally reintroducing them.
    assert "I" not in ex.ALPHABET
    assert "O" not in ex.ALPHABET
    assert "Q" not in ex.ALPHABET
    assert len(ex.ALPHABET) == 32


def test_borland_str_extended_format():
    s = ex.borland_str_extended(1558028784.0)
    # " D.DDDDDDDDDDDDDDE+EEEE" - sign/space, 1 digit, '.', 14 digits, E, sign, 4-digit exp
    assert len(s) == 23
    assert s[0] == " "  # positive sign is a space
    assert s[2] == "."
    assert s[17] == "E"
    assert s[18] in "+-"


def test_borland_str_extended_zero():
    s = ex.borland_str_extended(0.0)
    digits = s[7:17]
    assert digits == "0000000000"


def test_delphi_round_matches_python_round_half_to_even():
    assert ex.delphi_round(2.5) == 2
    assert ex.delphi_round(3.5) == 4
    assert ex.delphi_round(0.4) == 0
    assert ex.delphi_round(0.6) == 1


def test_file_age_dos_from_mtime_roundtrip_fields():
    import datetime
    dt = datetime.datetime(2024, 6, 15, 14, 30, 22)
    packed = ex.file_age_dos_from_mtime(dt.timestamp())

    dos_time = packed & 0xFFFF
    dos_date = (packed >> 16) & 0xFFFF
    hour = (dos_time >> 11) & 0x1F
    minute = (dos_time >> 5) & 0x3F
    sec2 = dos_time & 0x1F
    day = dos_date & 0x1F
    month = (dos_date >> 5) & 0xF
    year = ((dos_date >> 9) & 0x7F) + 1980

    assert (year, month, day) == (2024, 6, 15)
    assert (hour, minute) == (14, 30)
    assert sec2 == 22 // 2  # DOS time stores seconds at half resolution, floored


# ---------------------------------------------------------------------------
# CLI argument parsing helpers
# ---------------------------------------------------------------------------

def test_parse_int_auto_decimal():
    assert ex._parse_int_auto("32") == 32


def test_parse_int_auto_hex():
    assert ex._parse_int_auto("0x20") == 32
    assert ex._parse_int_auto("0X20") == 32


def test_parse_int_auto_invalid_raises():
    with pytest.raises(ValueError):
        ex._parse_int_auto("not-a-number")


def test_parse_datetime_to_dos_valid():
    packed = ex._parse_datetime_to_dos("2024-06-15 14:30:22")
    assert isinstance(packed, int)
    assert packed > 0


def test_parse_datetime_to_dos_invalid_raises():
    with pytest.raises(ValueError):
        ex._parse_datetime_to_dos("not a date")


def test_cli_reports_clean_error_for_bad_file_age(tmp_path, capsys):
    p = tmp_path / "f.txt"
    p.write_bytes(b"x")
    with pytest.raises(SystemExit) as exc_info:
        ex.main(["--file-age", "garbage", str(p)])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "Could not parse" in captured.err


def test_cli_reports_clean_error_for_bad_attributes(tmp_path, capsys):
    p = tmp_path / "f.txt"
    p.write_bytes(b"x")
    with pytest.raises(SystemExit) as exc_info:
        ex.main(["--attributes", "garbage", str(p)])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "not a valid integer" in captured.err


def test_cli_computes_checksum_for_valid_input(tmp_path, capsys):
    p = tmp_path / "1.txt"
    p.write_bytes(b"test")
    ex.main(["--file-age", "1558028662", "--attributes", "0x20", str(p)])
    captured = capsys.readouterr()
    assert "54T8-E0TL" in captured.out


def test_cli_accepts_human_readable_datetime(tmp_path, capsys):
    p = tmp_path / "1.txt"
    p.write_bytes(b"test")
    ex.main(["--file-age", "2026-06-29 20:15:56", "--attributes", "0x20", str(p)])
    captured = capsys.readouterr()
    # Just confirm it runs and produces a well-formed checksum - the exact
    # value depends on DOS-time rounding of an arbitrary chosen datetime.
    assert ":" in captured.out
    printed_checksum = captured.out.strip().split(": ")[1]
    assert len(printed_checksum) == 9
    assert printed_checksum[4] == "-"


# ---------------------------------------------------------------------------
# General properties (not tied to a specific known-good value)
# ---------------------------------------------------------------------------

def test_compute_checksum_is_deterministic(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"some content")
    a = ex.compute_checksum(str(p), file_age=REALISTIC_PLACEHOLDER_AGE, attributes=0x20)
    b = ex.compute_checksum(str(p), file_age=REALISTIC_PLACEHOLDER_AGE, attributes=0x20)
    assert a == b


def test_compute_checksum_changes_with_content(tmp_path):
    p1 = tmp_path / "f1.txt"
    p2 = tmp_path / "f2.txt"
    p1.write_bytes(b"content A")
    p2.write_bytes(b"content B")
    cs1 = ex.compute_checksum(str(p1), file_age=REALISTIC_PLACEHOLDER_AGE, attributes=0x20, name_for_sum="same.txt")
    cs2 = ex.compute_checksum(str(p2), file_age=REALISTIC_PLACEHOLDER_AGE, attributes=0x20, name_for_sum="same.txt")
    assert cs1 != cs2


def test_compute_checksum_changes_with_name_override(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"identical content")
    cs1 = ex.compute_checksum(str(p), file_age=REALISTIC_PLACEHOLDER_AGE, attributes=0x20, name_for_sum="alpha.txt")
    cs2 = ex.compute_checksum(str(p), file_age=REALISTIC_PLACEHOLDER_AGE, attributes=0x20, name_for_sum="beta.txt")
    assert cs1 != cs2


def test_compute_checksum_changes_with_file_age(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"identical content")
    cs1 = ex.compute_checksum(str(p), file_age=REALISTIC_PLACEHOLDER_AGE, attributes=0x20)
    cs2 = ex.compute_checksum(str(p), file_age=REALISTIC_PLACEHOLDER_AGE + 1, attributes=0x20)
    assert cs1 != cs2


def test_compute_checksum_output_format(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"anything")
    result = ex.compute_checksum(str(p), file_age=REALISTIC_PLACEHOLDER_AGE, attributes=0x20)
    assert len(result) == 9
    assert result[4] == "-"
    assert all(c in ex.ALPHABET for c in result[:4] + result[5:])
