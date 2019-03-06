#!/usr/bin/env python3
"""Sign content to be published using Ouinet.
"""

import argparse
import hashlib
import io
import json
import logging
import os
import re
import subprocess
import uuid
import sys
import time
import zlib

from http.client import HTTPResponse


DATA_DIR_NAME = '.ouinet'
URI_FILE_EXT = '.uri'
DATA_FILE_EXT = '.data'
HTTP_RPH_FILE_EXT = '.http-rph'
DESC_FILE_EXT = '.desc'
INS_FILE_EXT_PFX = '.ins-'


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

# From Ouinet's ``src/http_util.h:to_cache_response()``.
# The order and format of the headers is respected in the output.
# The alphabetical order has no particular reason.
# The camel case format only makes the resulting head look more natural.
_cache_http_response_headers = [
    'Accept-Ranges',
    'Access-Control-Allow-Credentials',
    'Access-Control-Allow-Headers',
    'Access-Control-Allow-Methods',
    'Access-Control-Allow-Origin',
    'Access-Control-Expose-Headers',
    'Access-Control-Max-Age',
    'Age',
    'Cache-Control',
    'Content-Encoding',
    'Content-Language',
    'Content-Length',
    'Content-Type',
    'Date',
    'Etag',
    'Expires',
    'Last-Modified',
    'Location',
    'Retry-After',
    'Server',
    'Transfer-Encoding',
    'Vary',
    'Via',
    'Warning',
]

def process_http_response(resp_str):
    """Return a filtered version of `resp_str` as another response string."""

    # Parse response head from string.
    rpf = io.BytesIO(resp_str.encode('iso-8859-1'))  # RFC 7230#3.2.4
    rpf.makefile = lambda *a, **k: rpf  # monkey-patch as a socket
    rp = HTTPResponse(rpf)
    rp.begin()

    # Build a new response head string with selected headers.
    v = int(rp.version)
    version = 'HTTP/%d.%d' % (v // 10, v % 10)
    out_rp_str = '%s %s %s\r\n' % (version, rp.status, rp.reason)
    for hdrn in _cache_http_response_headers:
        hdrv = rp.getheader(hdrn)  # concatenates repeated headers
        if hdrv is not None:
            out_rp_str += '%s: %s\r\n' % (hdrn, hdrv)
    out_rp_str += '\r\n'
    return out_rp_str

def descriptor_from_ipfs(canonical_uri, data_ipfs_cid, **kwargs):
    # v0 descriptors only support HTTP exchanges,
    # with compulsory response head metadata,
    # and a single IPFS CID pointing to the body.
    meta_http_rph = process_http_response(kwargs['meta_http_rph'])
    desc = {
        '!ouinet_version': 0,
        'url': canonical_uri,
        'id': str(uuid.uuid4()),
        'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'head': meta_http_rph,
        'body_link': data_ipfs_cid,
    }
    return desc

def descriptor_from_file(canonical_uri, data_path, **kwargs):
    # This only computes and returns the CID, without seeding.
    # The daemon need not be running.
    # We may want to instead use native Python packages for this.
    ipfs_add = subprocess.run(['ipfs', 'add', '-qn', data_path],
                              capture_output=True, check=True)
    data_ipfs_cid = ipfs_add.stdout.decode().strip()
    return descriptor_from_ipfs(canonical_uri, data_ipfs_cid, **kwargs)

def bep44_insert(desc_link, desc_inline):
    """Return a signed BEP44 mutable data item (as bytes)."""
    print("TODO: insert BEP44 data")  # XXXX
    return b''  # TODO

def get_canonical_uri(uri):
    return uri  # TODO

def inject_uri(uri, data_path, **kwargs):
    """Create descriptor and insertion data for the injection of the `uri`.

    A tuple is returned with the serialized descriptor (as bytes)
    and a dictionary mapping the different index names to
    their respective serialized insertion data (as bytes).
    """

    # Generate the descriptor.
    curi = get_canonical_uri(uri)
    desc = descriptor_from_file(curi, data_path, **kwargs)

    # Serialize the descriptor for index insertion.
    desc_data = json.dumps(desc, separators=(',', ':')).encode('utf-8')  # RFC 8259#8.1
    ipfs_add = subprocess.run(['ipfs', 'add', '-qn'],
                              input=desc_data, capture_output=True, check=True)
    desc_link = b'/ipfs/' + ipfs_add.stdout.strip()
    desc_inline = b'/zlib/' + zlib.compress(desc_data)

    # Prepare insertion of the descriptor into indexes.
    bep44_ins_data = bep44_insert(desc_link, desc_inline)

    return (desc_data, {'bep44': bep44_ins_data})

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

    TODO: describe output files
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

            if not os.path.exists(datap):
                _logger.warning("skipping URI with missing data file: hash=%s", uri_hash)
                continue  # data file must exist even if empty

            if not os.path.exists(http_rphp):
                _logger.warning("skipping URI with missing HTTP response head: hash=%s", uri_hash)
                continue  # only handle HTTP insertion for the moment

            descp = desc_path_from_uri_hash(uri_hash, output_dir)
            if os.path.exists(descp):
                _logger.debug("skipping URI with existing descriptor: hash=%s", uri_hash)
                continue  # a descriptor for the URI already exists

            with open(urip, 'rb') as urif, open(http_rphp, 'rb') as http_rphf:
                uri = urif.read().decode()  # only ASCII, RFC 3986#1.2.1
                if hashlib.sha1(uri.encode()).hexdigest() != uri_hash:
                    _logger.error("skipping URI with invalid hash: hash=%s", uri_hash)
                    continue
                http_rph = http_rphf.read().decode('iso-8859-1')  # RFC 7230#3.2.4

            # After all the previous checks, proceed to the real injection.
            (desc_data, inj_data) = inject_uri(uri, datap, meta_http_rph=http_rph)

            # Write descriptor and insertion data to the output directory.
            desc_dir = os.path.dirname(descp)
            if not os.path.exists(desc_dir):
                os.makedirs(desc_dir, exist_ok=True)
            # TODO: handle exceptions
            with open(descp, 'wb') as descf:
                descf.write(desc_data)
            desc_prefix = os.path.splitext(descp)[0]
            for (idx, idx_inj_data) in inj_data.items():
                with open(desc_prefix + INS_FILE_EXT_PFX + idx, 'wb') as injf:
                    injf.write(idx_inj_data)
            # TODO: copy data file

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
