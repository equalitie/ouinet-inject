#!/usr/bin/env python3
"""Sign content to be published using Ouinet.
"""

import argparse
import os
import re
import sys


DATA_DIR_NAME = '.ouinet'
DESC_FILE_EXT = '.desc'
HTTP_RPH_FILE_EXT = '.http-rph'


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
    """Sign content from `input_dir`, put insertion data in `output_dir`.

    Limitations:

    - Only a single injection per URI is supported.
    - Only injection of HTTP exchanges is supported.

    For each injection to be performed for a given URI, with ``URI_HASH``
    being the hexadecimal, lower-case SHA1 hash of the URI, in `input_dir`
    there must exist:

    - ``URI_HASH[:2]/URI_HASH[2:].uri`` with the URI itself;
      the hash of the *whole content* of the file must be ``URI_HASH``
    - ``URI_HASH[:2]/URI_HASH[2:].http-rph`` with the head of the HTTP response
    - ``URI_HASH[:2]/URI_HASH[2:].data`` with the body of the HTTP response
      (after transfer decoding if a non-identity transfer encoding was used)

    If a ``.ouinet/URI_HASH.desc`` file already exists in the `output_dir`,
    the injection for that URI is skipped.

    The HTTP response head will be processed, thus the head in the resulting
    descriptor may differ from that in the ``.http-rph`` file.
    """
    # Look for URI files not yet having a descriptor file in the output directory.
    for (dirpath, dirnames, filenames) in os.walk(input_dir):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            uri_hash = uri_hash_from_path(fp)
            if not uri_hash:
                continue  # not a URI file
            http_rphp = os.path.splitext(fp)[0] + HTTP_RPH_FILE_EXT
            if not os.path.exists(http_rphp):
                continue  # only handle HTTP insertion for the moment

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
