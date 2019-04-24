#!/usr/bin/env python3

import os
import re
import sys

import warcio.archiveiterator
import warcio.warcwriter

def main():
    if len(sys.argv) != 3:
        print(("Usage: %s INPUT_WARC OUTPUT_WARC < URL_REGEXES"
               % os.path.basename(sys.argv[0])),
              file=sys.stderr)
        sys.exit(1)

    target_rxs = [re.compile(r.strip()) for r in sys.stdin]

    total = 0
    kept = 0

    with open(sys.argv[1], 'rb') as warc_if, open(sys.argv[2], 'wb') as warc_of:
        warc_out = warcio.warcwriter.WARCWriter(warc_of)

        for record in warcio.archiveiterator.WARCIterator(warc_if):
            total += 1

            http_headers = record.http_headers
            if not http_headers:
                continue

            rec_type = record.rec_type
            if rec_type != 'request' and rec_type != 'response':
                continue

            url = record.rec_headers.get_header('WARC-Target-URI')
            if any(rx.match(url) for rx in target_rxs):
                kept += 1
                warc_out.write_record(record)

    print("Kept %d of %d records." % (kept, total), file=sys.stderr)

if __name__ == '__main__':
    main()
