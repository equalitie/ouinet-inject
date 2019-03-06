#!/usr/bin/env python3
"""Sign content to be published using Ouinet.
"""

import argparse
import hashlib
import logging
import os
import re
import sys


DATA_DIR_NAME = '.ouinet'
URI_FILE_EXT = '.uri'
DATA_FILE_EXT = '.data'
HTTP_RPH_FILE_EXT = '.http-rph'
DESC_FILE_EXT = '.desc'


_logger = logging.getLogger('ouinet.inject')

_uri_hash_path_re = r'^.*/([0-9A-Fa-f]{2})/([0-9A-Fa-f]{38})\.uri$'.replace('/', os.path.sep)
_uri_hash_path_rx = re.compile(_uri_hash_path_re)

def uri_hash_from_path(path):
    """Return the URI hash encoded in the `path`.

    The result is a full SHA1 hexadecimal string, or the empty string if the
    hash can not be extracted.

    >>> path = os.path.join('path', 'to', 'b5', '59c7edd3fb67374c1a25e739cdd7edd1d79949.uri')
    >>> uri_hash_from_path(path)
    'b559c7edd3fb67374c1a25e739cdd7edd1d79949'
    """
    # The hash above is for ``https://example.com/``.
    m = _uri_hash_path_rx.match(path)
    return ''.join(m.groups()).lower() if m else ''

def desc_path_from_uri_hash(uri_hash, output_dir):
    return os.path.join(output_dir, DATA_DIR_NAME, uri_hash + DESC_FILE_EXT)

def inject_uri(uri, data_path, **kwargs):
    print("TODO: inject URI:", uri)  # XXXX

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
            uri_prefix = os.path.splitext(fp)[0]

            urip = uri_prefix + URI_FILE_EXT
            datap = uri_prefix + DATA_FILE_EXT
            http_rphp = uri_prefix + HTTP_RPH_FILE_EXT

            if not os.path.exists(http_rphp):
                _logger.warning("skipping URI with missing HTTP response head: hash=%s", uri_hash)
                continue  # only handle HTTP insertion for the moment

            descp = desc_path_from_uri_hash(uri_hash, output_dir)
            if os.path.exists(descp):
                _logger.debug("skipping URI with existing descriptor: hash=%s", uri_hash)
                continue  # a descriptor for the URI already exists

            with open(urip, 'rb') as urif, open(http_rphp, 'rb') as http_rphf:
                uri = urif.read()
                if hashlib.sha1(uri).hexdigest() != uri_hash:
                    _logger.error("skipping URI with invalid hash: hash=%s", uri_hash)
                    continue
                http_rph = http_rphf.read()
                inject_uri(uri, datap, meta_http_rph=http_rph)

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
