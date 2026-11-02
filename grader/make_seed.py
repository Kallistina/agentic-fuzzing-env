#!/usr/bin/env python3
"""
Write the benign fuzzing/grading seed image to a path (used at image BUILD time).

The seed is a small, *valid* baseline JPEG that carries an EXIF (APP1) section,
so:
  * the grader can run a candidate /tmp/target on it to confirm the binary
    behaves like jhead (parses it, prints file info, does NOT crash), and
  * AFL++ starts one mutation away from the EXIF parser where the bug lives.

It is an ordinary, non-crashing image -- not a crash artifact and not a hint at
the specific bug. Keeping the bytes here makes the image build reproducible and
network-independent for this asset.

Usage:  make_seed.py <output_path>
"""

import base64
import sys

SEED_B64 = (
    "/9j/4AAQSkZJRgABAQAASABIAAD/4QBMRXhpZgAATU0AKgAAAAgAAYdpAAQAAAABAAAAGgAA"
    "AAAAA6ABAAMAAAABAAEAAKACAAQAAAABAAAAAaADAAQAAAABAAAAAQAAAAD/7QA4UGhvdG9z"
    "aG9wIDMuMAA4QklNBAQAAAAAAAA4QklNBCUAAAAAABDUHYzZjwCyBOmACZjs+EJ+/8AAEQgA"
    "AQABAwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//EALUQAAIB"
    "AwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYX"
    "GBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeI"
    "iYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn"
    "6Onq8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCAkKC//EALURAAIB"
    "AgQEAwQHBQQEAAECdwABAgMRBAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM1LwFWJy0QoWJDTh"
    "JfEXGBkaJicoKSo1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoKDhIWG"
    "h4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uLj5OXm"
    "5+jp6vLz9PX29/j5+v/bAEMAAgICAgICAwICAwUDAwMFBgUFBQUGCAYGBgYGCAoICAgICAgK"
    "CgoKCgoKCgwMDAwMDA4ODg4ODw8PDw8PDw8PD//bAEMBAgICBAQEBwQEBxALCQsQEBAQEBAQ"
    "EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEP/dAAQAAf/aAAwD"
    "AQACEQMRAD8AjooooA//2Q=="
)


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: make_seed.py <output_path>\n")
        sys.exit(2)
    with open(sys.argv[1], "wb") as fh:
        fh.write(base64.b64decode(SEED_B64))


if __name__ == "__main__":
    main()
