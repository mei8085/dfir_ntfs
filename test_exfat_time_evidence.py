# coding: utf-8

# dfir_ntfs: an NTFS/FAT parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# Tests for the forensic handling of exFAT time evidence.
#
# Background: an exFAT directory entry stores Created (C), Modified (M) and
# Last Accessed (A) timestamps as naive local datetime objects, each paired
# with an optional time zone offset (in 15-minute intervals, None when absent).
#
# Two rules are tested here:
#
# 1. Evidence carrying a reliable time zone offset can be reduced to a definite
#    UTC instant. Such evidence must keep its native precision (10 ms for C/M,
#    2 s for A) and its ordering when placed on a UTC timeline.
#
# 2. Evidence without a time zone offset is a local time of unknown origin. It
#    has no single UTC instant (any offset is possible), so it must never be
#    forced into a definite UTC ordering. The resulting gap must remain visible
#    in the evidence conclusion.
#
# Everything below (including the synthetic entry builder and the timeline
# helpers) is test code only; no production module is modified.

import struct
from datetime import datetime, timedelta, timezone

import pytest

from dfir_ntfs.addons import exFAT

# A 15-minute interval expressed as a timedelta: the granularity of every
# exFAT time zone offset.
TZ_INTERVAL = timedelta(minutes = 15)

# Field kinds of an exFAT FileEntry, mapped to its timestamp and offset fields.
KIND_CREATED = 'C'
KIND_MODIFIED = 'M'
KIND_ACCESSED = 'A'


# ---------------------------------------------------------------------------
# Test-only helpers: synthetic directory entry construction and timeline logic
# ---------------------------------------------------------------------------

def encode_fat_timestamp(value):
	"""Encode a naive datetime into the exFAT 32-bit timestamp field.

	Seconds are stored in 2-second units, matching the on-disk format and the
	DecodeFATTimestamp() parser.
	"""

	second = value.second // 2
	value_time = (value.hour << 11) | (value.minute << 5) | second
	value_date = ((value.year - 1980) << 9) | (value.month << 5) | value.day

	return (value_date << 16) | value_time


def encode_fat_timezone(tz):
	"""Encode a time zone offset (15-minute intervals, or None) into one byte."""

	if tz is None: # The "time zone is not given" marker.
		return 0

	if tz >= 0:
		return 0x80 | tz

	return 0x80 | (tz & 0x7F)


def build_file_entry(name, ctime, mtime, atime, ctime_10ms = 0, mtime_10ms = 0,
	ctz = None, mtz = None, atz = None, is_deleted = False):
	"""Build a minimal, spec-shaped 3-entry set (file + stream + name).

	The raw buffer is accepted by exFAT.DirectoryEntries.entries(): allocated
	entry sets carry a correct checksum, deleted entry sets skip checksum
	validation in the parser.
	"""

	primary = bytearray(32)
	primary[0] = exFAT.DE_FILE | (0 if is_deleted else 0x80)
	primary[1] = 2 # Two secondary entries follow.

	# This mirrors the parser's own '<HHHLLLBBBBB' unpack of the primary entry.
	struct.pack_into('<HHHLLLBBBBB', primary, 2,
		0, exFAT.ATTR_ARCHIVE, 0,
		encode_fat_timestamp(ctime), encode_fat_timestamp(mtime), encode_fat_timestamp(atime),
		ctime_10ms, mtime_10ms,
		encode_fat_timezone(ctz), encode_fat_timezone(mtz), encode_fat_timezone(atz))

	stream = bytearray(32)
	stream[0] = exFAT.DE_STREAM_EXTENSION | 0x80
	stream[1] = 0x01 # AllocationPossible.
	name_length = len(name)

	struct.pack_into('<BBHBBQLLQ', stream, 2,
		0, name_length, 0, 0, 0, 0, 0, 0, 0) # Zero-length, no cluster chain.

	file_name = bytearray(32)
	file_name[0] = exFAT.DE_FILE_NAME | 0x80
	file_name[1] = 0
	name_raw = name.encode('utf-16le')
	file_name[2 : 2 + len(name_raw)] = name_raw

	entry_set = bytes(primary) + bytes(stream) + bytes(file_name)

	checksum = exFAT.EntrySetChecksum(entry_set)
	primary = bytearray(entry_set[ : 32])
	struct.pack_into('<H', primary, 2, checksum)

	return bytes(primary) + entry_set[32 : ]


def parse_entries(buffers):
	"""Parse one or more entry-set buffers and return the FileEntry list."""

	raw = b''.join(buffers).ljust(512, b'\x00')
	entries = [ ]

	for entry in exFAT.DirectoryEntries(raw, False).entries():
		assert type(entry) is exFAT.FileEntry
		entries.append(entry)

	return entries


def make_evidence(file_entry, kind):
	"""Project one timestamp field of a FileEntry into a piece of time evidence.

	Returns a dict with the local datetime, the raw offset (or None) and, only
	when the offset is known, a definite UTC instant. Unknown-offset evidence
	carries no 'utc' key by construction.
	"""

	if kind == KIND_CREATED:
		local_value, raw_offset = file_entry.ctime, file_entry.ctz
	elif kind == KIND_MODIFIED:
		local_value, raw_offset = file_entry.mtime, file_entry.mtz
	elif kind == KIND_ACCESSED:
		local_value, raw_offset = file_entry.atime, file_entry.atz
	else:
		raise ValueError('Unknown evidence kind: {}'.format(kind))

	evidence = {
		'name': file_entry.name,
		'kind': kind,
		'local': local_value,
		'tz': raw_offset
	}

	if raw_offset is not None:
		evidence['utc'] = local_value - (raw_offset * TZ_INTERVAL)

	return evidence


def build_utc_timeline(evidence_list):
	"""Order only the evidence that has a definite UTC instant.

	Evidence without a time zone offset is excluded, never guessed into place.
	Returns (ordered_evidence, unknown_offset_evidence); the ordered list is
	sorted by UTC instant and the excluded evidence is reported separately so
	the gap stays visible.
	"""

	anchored = [ item for item in evidence_list if 'utc' in item ]
	unknown = [ item for item in evidence_list if 'utc' not in item ]

	anchored.sort(key = lambda item: item['utc'])

	return anchored, unknown


def describe_timeline(anchored, unknown):
	"""Render a one-line-per-item conclusion string used to assert gap visibility."""

	lines = [ ]

	for item in anchored:
		lines.append('UTC {} {} [{}] tz={}*15min'.format(
			item['utc'].isoformat(), item['name'], item['kind'], item['tz']))

	for item in unknown:
		lines.append('GAP {} [{}] local={} tz=UNKNOWN (not placed on UTC timeline)'.format(
			item['name'], item['kind'], item['local'].isoformat()))

	return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Layer 1: parser primitives - precision and time zone decoding
# ---------------------------------------------------------------------------

def test_decode_fat_timestamp_preserves_10ms_precision():
	# The C and M fields carry a separate 10-multiple sub-second component.
	base = encode_fat_timestamp(datetime(2024, 3, 4, 12, 30, 0))

	assert exFAT.DecodeFATTimestamp(base, 0) == datetime(2024, 3, 4, 12, 30, 0)
	assert exFAT.DecodeFATTimestamp(base, 1) == datetime(2024, 3, 4, 12, 30, 0, 10000)
	assert exFAT.DecodeFATTimestamp(base, 99) == datetime(2024, 3, 4, 12, 30, 0, 990000)
	assert exFAT.DecodeFATTimestamp(base, 199) == datetime(2024, 3, 4, 12, 30, 1, 990000)

	# Distinct 10 ms ticks must remain distinguishable (no truncation to seconds).
	assert exFAT.DecodeFATTimestamp(base, 12) != exFAT.DecodeFATTimestamp(base, 13)


def test_decode_fat_timestamp_access_resolution_is_two_seconds():
	# The A field has no 10 ms component and the raw second itself is 2-second
	# quantized: odd seconds round down to the preceding even second.
	encoded_eleven = encode_fat_timestamp(datetime(2024, 3, 4, 12, 30, 11))
	encoded_ten = encode_fat_timestamp(datetime(2024, 3, 4, 12, 30, 10))

	assert encoded_eleven == encoded_ten
	assert exFAT.DecodeFATTimestamp(encoded_eleven) == datetime(2024, 3, 4, 12, 30, 10)
	assert exFAT.DecodeFATTimestamp(encoded_eleven).microsecond == 0


def test_decode_fat_timestamp_invalid_values_return_none():
	# Invalid timestamps are absent evidence, not a fabricated epoch instant.
	assert exFAT.DecodeFATTimestamp(0) is None # Day 0.

	# Second field above 29 (would mean >= 60 s) is invalid.
	bad_second = encode_fat_timestamp(datetime(2024, 3, 4, 12, 30, 58)) | 0x1F
	assert exFAT.DecodeFATTimestamp(bad_second) is None

	# An out-of-range 10 ms component is clamped, not fatal.
	good = encode_fat_timestamp(datetime(2024, 3, 4, 12, 30, 0))
	assert exFAT.DecodeFATTimestamp(good, 200) == datetime(2024, 3, 4, 12, 30, 0)


@pytest.mark.parametrize('offset,expected_byte', [
	(0, 0x80),
	(1, 0x81),
	(23, 0x97),    # UTC+05:45.
	(63, 0xBF),    # Maximum positive offset.
	(-1, 0xFF),
	(-40, 0xD8),   # UTC-10:00.
	(-64, 0xC0),   # Minimum negative offset.
])
def test_timezone_roundtrip_through_parser(offset, expected_byte):
	assert encode_fat_timezone(offset) == expected_byte
	assert exFAT.DecodeFATTimezone(expected_byte) == offset


def test_timezone_absent_decodes_to_none():
	# A byte without the valid bit means the offset is unknown.
	assert exFAT.DecodeFATTimezone(0x00) is None
	assert exFAT.DecodeFATTimezone(0x01) is None
	assert exFAT.DecodeFATTimezone(0x7F) is None
	assert encode_fat_timezone(None) == 0x00


# ---------------------------------------------------------------------------
# Layer 2: full directory-entry parsing of synthetic evidence
# ---------------------------------------------------------------------------

def test_parsed_entry_keeps_distinct_c_m_a_precision():
	entry_buffer = build_file_entry(
		'precision.txt',
		datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 2), datetime(2024, 3, 4, 12, 0, 4),
		ctime_10ms = 12, mtime_10ms = 15,
		ctz = 4, mtz = 23, atz = -40)

	entry = parse_entries([ entry_buffer ])[0]

	# Created and Modified retain their independent 10 ms ticks.
	assert entry.ctime == datetime(2024, 3, 4, 12, 0, 0, 120000)
	assert entry.mtime == datetime(2024, 3, 4, 12, 0, 2, 150000)

	# Accessed stays second-granular, with no microseconds ever attached.
	assert entry.atime == datetime(2024, 3, 4, 12, 0, 4)
	assert entry.atime.microsecond == 0

	assert (entry.ctz, entry.mtz, entry.atz) == (4, 23, -40)


def test_parsed_entry_with_unknown_timezones_yields_none_offsets():
	entry_buffer = build_file_entry(
		'naive.txt',
		datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0))

	entry = parse_entries([ entry_buffer ])[0]

	assert entry.ctz is None and entry.mtz is None and entry.atz is None
	# The naive local value is still reported as-is.
	assert entry.ctime == entry.mtime == entry.atime == datetime(2024, 3, 4, 12, 0, 0)


def test_parsed_deleted_entry_still_carries_time_evidence():
	entry_buffer = build_file_entry(
		'deleted.txt',
		datetime(2024, 3, 4, 9, 0, 0), datetime(2024, 3, 4, 9, 0, 0), datetime(2024, 3, 4, 9, 0, 0),
		ctime_10ms = 7, mtime_10ms = 7,
		ctz = 4, mtz = 4, atz = 4, is_deleted = True)

	entry = parse_entries([ entry_buffer ])[0]

	assert entry.is_deleted
	assert entry.ctime.microsecond == 70000
	assert (entry.ctz, entry.mtz, entry.atz) == (4, 4, 4)


def test_mixed_known_and_unknown_offsets_in_one_directory():
	known = build_file_entry(
		'known.txt',
		datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0),
		ctz = 4, mtz = 4, atz = 4)
	unknown = build_file_entry(
		'unknown.txt',
		datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0))

	entries = parse_entries([ known, unknown ])

	assert entries[0].name == 'known.txt' and entries[0].mtz == 4
	assert entries[1].name == 'unknown.txt' and entries[1].mtz is None


# ---------------------------------------------------------------------------
# Layer 3: forensic timeline semantics
# ---------------------------------------------------------------------------

def test_known_offsets_produce_definite_utc_instants():
	entry = parse_entries([ build_file_entry(
		'utc.txt',
		datetime(2024, 3, 4, 12, 0, 0, 120000), datetime(2024, 3, 4, 12, 0, 2, 150000), datetime(2024, 3, 4, 12, 0, 4),
		ctime_10ms = 12, mtime_10ms = 15,
		ctz = 4, mtz = 23, atz = -40) ])[0]

	created = make_evidence(entry, KIND_CREATED)
	modified = make_evidence(entry, KIND_MODIFIED)
	accessed = make_evidence(entry, KIND_ACCESSED)

	# UTC = local - offset, offsets in 15-minute units.
	assert created['utc'] == datetime(2024, 3, 4, 12, 0, 0, 120000) - timedelta(hours = 1)
	assert modified['utc'] == datetime(2024, 3, 4, 12, 0, 2, 150000) - timedelta(minutes = 5 * 60 + 45)
	assert accessed['utc'] == datetime(2024, 3, 4, 12, 0, 4) - timedelta(hours = -10)

	# UTC instants are timezone-aware-comparable against an explicit reference.
	reference = datetime(2024, 3, 4, 11, 0, 0, 120000, tzinfo = timezone.utc)
	assert created['utc'].replace(tzinfo = timezone.utc) == reference


def test_utc_ordering_overturns_native_local_order():
	# Two files whose local wall-clock order and UTC order disagree. The eastern
	# file has the later local time, but the earlier UTC instant.
	# east2.txt: local 12:30 at UTC+1 -> 11:30 UTC.
	entries = parse_entries([
		build_file_entry('east2.txt',
			datetime(2024, 3, 4, 12, 30, 0), datetime(2024, 3, 4, 12, 30, 0), datetime(2024, 3, 4, 12, 30, 0),
			ctz = 4, mtz = 4, atz = 4),
		# west2.txt: local 12:00 at UTC-10 -> 22:00 UTC.
		build_file_entry('west2.txt',
			datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0),
			ctz = -40, mtz = -40, atz = -40)
	])
	evidence = [ make_evidence(item, KIND_MODIFIED) for item in entries ]

	# In raw local terms east2 (12:30) is later than west2 (12:00).
	assert evidence[0]['local'] > evidence[1]['local']

	anchored, unknown = build_utc_timeline(evidence)
	assert unknown == [ ]

	# In UTC terms east2 (11:30 UTC) precedes west2 (22:00 UTC): the offset
	# reduction overturns the native local ordering.
	assert [ item['name'] for item in anchored ] == [ 'east2.txt', 'west2.txt' ]
	assert anchored[0]['utc'] < anchored[1]['utc']
	assert anchored[0]['utc'] == datetime(2024, 3, 4, 11, 30, 0)
	assert anchored[1]['utc'] == datetime(2024, 3, 4, 22, 0, 0)


def test_10ms_precision_survives_into_utc_timeline_ordering():
	# Two Modified instants in the same zone differ only in their 10 ms ticks;
	# the timeline must keep them distinct and ordered at that granularity.
	first = build_file_entry(
		'first.txt',
		datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0),
		mtime_10ms = 10, mtz = 4, ctz = 4, atz = 4)
	second = build_file_entry(
		'second.txt',
		datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0),
		mtime_10ms = 11, mtz = 4, ctz = 4, atz = 4)

	entries = parse_entries([ second, first ]) # Deliberately unordered input.
	evidence = [ make_evidence(item, KIND_MODIFIED) for item in entries ]

	anchored, unknown = build_utc_timeline(evidence)
	assert unknown == [ ]
	assert [ item['name'] for item in anchored ] == [ 'first.txt', 'second.txt' ]

	delta = anchored[1]['utc'] - anchored[0]['utc']
	assert delta == timedelta(milliseconds = 10)


def test_unknown_offset_evidence_is_excluded_from_utc_sequence():
	known = build_file_entry(
		'known.txt',
		datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0),
		ctz = 4, mtz = 4, atz = 4)
	unknown = build_file_entry(
		'unknown.txt',
		datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0))

	entries = parse_entries([ known, unknown ])
	evidence = [ make_evidence(item, KIND_MODIFIED) for item in entries ]

	anchored, excluded = build_utc_timeline(evidence)

	assert [ item['name'] for item in anchored ] == [ 'known.txt' ]
	assert len(excluded) == 1 and excluded[0]['name'] == 'unknown.txt'

	# The excluded evidence must not carry any fabricated UTC instant.
	assert 'utc' not in excluded[0]
	assert excluded[0]['tz'] is None
	assert excluded[0]['local'] == datetime(2024, 3, 4, 12, 0, 0)


def test_unknown_offset_cannot_be_compared_against_anchored_evidence():
	# The unknown-offset local time is earlier on the wall clock than the known
	# one, yet no UTC comparison may be asserted: its UTC instant is a range.
	known = build_file_entry(
		'known.txt',
		datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0),
		mtz = 4, ctz = 4, atz = 4)
	unknown = build_file_entry(
		'unknown.txt',
		datetime(2024, 3, 4, 8, 0, 0), datetime(2024, 3, 4, 8, 0, 0), datetime(2024, 3, 4, 8, 0, 0))

	entries = parse_entries([ known, unknown ])
	evidence = [ make_evidence(item, KIND_MODIFIED) for item in entries ]
	anchored, excluded = build_utc_timeline(evidence)

	# Every plausible offset (-64..63 intervals, i.e. UTC-16:00..UTC+15:45) shows
	# why placement is ambiguous: the local 08:00 spans a 31h45m UTC window that
	# straddles the anchored 11:00 UTC instant on both sides.
	unknown_local = excluded[0]['local']
	earliest = unknown_local - (63 * TZ_INTERVAL)
	latest = unknown_local - (-64 * TZ_INTERVAL)
	anchored_utc = anchored[0]['utc']

	assert earliest < anchored_utc < latest

	# No definite before/after UTC relationship can be defensibly claimed. The
	# timeline helper refuses to emit a 'utc' key for unknown-offset evidence, so
	# any code attempting the comparison fails loudly instead of guessing.
	with pytest.raises(KeyError):
		_ = excluded[0]['utc'] < anchored_utc

	# And the naive local datetime itself must not be compared as if it were UTC
	# (Python 3 rejects naive-vs-aware ordering with TypeError).
	with pytest.raises(TypeError):
		_ = excluded[0]['local'] < anchored_utc.replace(tzinfo = timezone.utc)


def test_timeline_conclusion_renders_the_gap():
	entries = parse_entries([
		build_file_entry('known.txt',
			datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0),
			ctz = 4, mtz = 4, atz = 4),
		build_file_entry('unknown.txt',
			datetime(2024, 3, 4, 9, 0, 0), datetime(2024, 3, 4, 9, 0, 0), datetime(2024, 3, 4, 9, 0, 0))
	])
	evidence = [ make_evidence(item, KIND_MODIFIED) for item in entries ]
	anchored, excluded = build_utc_timeline(evidence)

	report = describe_timeline(anchored, excluded)
	lines = report.splitlines()

	# Anchored evidence is presented as definite UTC instants.
	assert any(line.startswith('UTC 2024-03-04T11:00:00') and 'known.txt' in line for line in lines)

	# The gap is an explicit, labeled line, not a silently dropped record.
	assert any(line.startswith('GAP unknown.txt') and 'tz=UNKNOWN' in line and 'not placed on UTC timeline' in line
		for line in lines)


def test_partial_offsets_leave_per_field_gaps():
	# One file can carry a reliable M offset but an unknown C offset: the gap is
	# tracked per evidence field, not wholesale per file.
	entry_buffer = build_file_entry(
		'partial.txt',
		datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0), datetime(2024, 3, 4, 12, 0, 0),
		mtz = 4) # ctz and atz default to None.

	entry = parse_entries([ entry_buffer ])[0]

	modified = make_evidence(entry, KIND_MODIFIED)
	created = make_evidence(entry, KIND_CREATED)
	accessed = make_evidence(entry, KIND_ACCESSED)

	assert 'utc' in modified and modified['tz'] == 4
	assert 'utc' not in created and created['tz'] is None
	assert 'utc' not in accessed and accessed['tz'] is None

	anchored, excluded = build_utc_timeline([ modified, created, accessed ])
	assert [ item['kind'] for item in anchored ] == [ KIND_MODIFIED ]
	assert { item['kind'] for item in excluded } == { KIND_CREATED, KIND_ACCESSED }
