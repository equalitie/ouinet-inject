#!/usr/bin/env python3
"""Sign content to be published using Ouinet.
"""

import argparse
import os
import re
import sys


DATA_DIR_NAME = '.ouinet'
DESC_FILE_EXT = '.desc'


_uri_hash_path_re = r'^.*/([0-9A-Fa-f]{2})/([0-9A-Fa-f]{38})\.uri$'.replace('/', os.path.sep)
_uri_hash_path_rx = re.compile(_uri_hash_path_re)

def uri_hash_from_path(path):
    """Return the URI hash encoded in the `path`.

    The result is a full SHA1 hexadecimal string, or the empty string if the
    hash can not be extracted.

    >>> path = os.path.join('path', 'to', '64', '6503c01c841c04e3c0cbc8f6edcc737da466ef.uri')
    >>> uri_hash_from_path(path)
    '646503c01c841c04e3c0cbc8f6edcc737da466ef'
    """
    m = _uri_hash_path_rx.match(path)
    return ''.join(m.groups()).lower() if m else ''

def desc_path_from_uri_hash(uri_hash, output_dir):
    return os.path.join(output_dir, DATA_DIR_NAME, uri_hash + DESC_FILE_EXT)

def inject_dir(input_dir, output_dir):
    # Look for URI files not yet having a descriptor file in the output directory.
    for (dirpath, dirnames, filenames) in os.walk(input_dir):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            uri_hash = uri_hash_from_path(fp)
            if not uri_hash:
                continue  # not a URI file
            descp = desc_path_from_uri_hash(uri_hash, output_dir)
            if os.path.exists(descp):
                continue  # a descriptor for the URI already exists
            print("TODO: handle URI file:", fp)  # XXXX

def main():
    parser = argparse.ArgumentParser(
        description="Sign content to be published using Ouinet.")
    parser.add_argument(
        # Normalize to avoid confusing ``os.path.{base,dir}name()``.
        'input_directory', metavar="INPUT_DIR", type=os.path.normpath,
        help="the directory where HTTP exchanges are read from")
    parser.add_argument(
        # Normalize to avoid confusing ``os.path.{base,dir}name()``.
        'output_directory', metavar="OUTPUT_DIR", type=os.path.normpath,
        help="the directory where content data, descriptors and insertion data will be saved to")
    args = parser.parse_args()

    inject_dir(input_dir=args.input_directory, output_dir=args.output_directory)

if __name__ == '__main__':
    sys.exit(main())
