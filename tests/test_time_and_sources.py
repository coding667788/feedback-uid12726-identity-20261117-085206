"""Tests for time parsing/formatting and byte-exact line slicing."""

from __future__ import annotations

import unittest

from _support import ROOT  # noqa: F401

from solution.sources import SourceBytes, split_lines
from solution.timeutil import (
    TimestampError,
    format_rfc3339_ns,
    parse_rfc3339_ns,
)


class TimestampTests(unittest.TestCase):
    def test_epoch_and_offsets(self):
        self.assertEqual(parse_rfc3339_ns("1970-01-01T00:00:00Z"), 0)
        self.assertEqual(
            parse_rfc3339_ns("2026-01-01T01:00:00+01:00"),
            parse_rfc3339_ns("2026-01-01T00:00:00Z"),
        )
        self.assertEqual(
            parse_rfc3339_ns("2026-01-01T00:00:00.123456789Z") % 1_000_000_000,
            123_456_789,
        )

    def test_round_trip(self):
        for text in (
            "2026-01-01T00:00:00Z",
            "2026-02-28T23:59:59.5Z",
            "2024-02-29T12:00:00.000000001Z",
            "1969-12-31T23:59:59.999999999Z",
        ):
            with self.subTest(text=text):
                self.assertEqual(format_rfc3339_ns(parse_rfc3339_ns(text)), text)

    def test_rejects_malformed(self):
        for text in (
            "2026-01-01 00:00:00",        # missing offset
            "2026-13-01T00:00:00Z",       # bad month
            "2026-02-30T00:00:00Z",       # impossible date
            "2026-01-01T24:00:00Z",       # hour out of range
            "2026-01-01T00:00:60Z",       # leap second is not accepted
            "2026-01-01T00:00:00+24:00",  # offset out of range
            "2026-01-01T00:00:00.1234567890Z",  # too many fraction digits
            "2026-01-01T00:00:00Z\n",
        ):
            with self.subTest(text=text):
                with self.assertRaises(TimestampError):
                    parse_rfc3339_ns(text)

    def test_rejects_non_ascii_digits(self):
        with self.assertRaises(TimestampError):
            parse_rfc3339_ns("２０２６-01-01T00:00:00Z")


class LineSliceTests(unittest.TestCase):
    def test_offsets_cover_every_byte_exactly(self):
        payload = b'{"a":1}\n{"b":2}\r\n{"c":3}'
        lines = split_lines(payload)
        self.assertEqual([l.line for l in lines], [1, 2, 3])
        self.assertEqual([l.byte_start for l in lines], [0, 8, 17])
        self.assertEqual([l.byte_end for l in lines], [8, 17, 24])
        self.assertEqual(b"".join(l.data for l in lines), payload)

    def test_line_text_strips_one_terminator(self):
        payload = b"one\r\ntwo\nthree"
        text = [l.text for l in split_lines(payload)]
        self.assertEqual(text, [b"one", b"two", b"three"])

    def test_multibyte_utf8_stays_within_one_line(self):
        payload = '{"note":"中文"}\n'.encode("utf-8")
        lines = split_lines(payload)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].byte_end - lines[0].byte_start, len(payload))
        self.assertEqual(lines[0].text.decode("utf-8"), '{"note":"中文"}')

    def test_blank_final_line_is_not_invented(self):
        self.assertEqual(len(split_lines(b"a\n\n")), 2)
        self.assertEqual(len(split_lines(b"")), 0)

    def test_source_bytes_size_matches_payload(self):
        source = SourceBytes("s", "path", b"abc\ndef", "digest")
        self.assertEqual(source.size, 7)


if __name__ == "__main__":
    unittest.main()
