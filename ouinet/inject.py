#!/usr/bin/env python3
"""Sign content to be published using Ouinet.
"""

import argparse
import hashlib
import http.client
import io
import json
import logging
import os
import subprocess
import uuid
import sys
import time
import zlib

import bencoder
import nacl.encoding
import nacl.signing


OUINET_DIR_NAME = '.ouinet'
URI_FILE_EXT = '.uri'
DATA_FILE_EXT = '.data'
HTTP_RPH_FILE_EXT = '.http-rph'
DESC_FILE_EXT = '.desc'
INS_FILE_EXT_PFX = '.ins-'
DATA_DIR_NAME = 'ouinet-data'

logger = logging.getLogger(__name__)


def desc_path_from_uri_hash(uri_hash, output_dir):
    return os.path.join(output_dir, OUINET_DIR_NAME, uri_hash + DESC_FILE_EXT)

def data_path_from_data_mhash(data_mhash, output_dir):
    """Return the output path for a file with the given `data_mhash`.

    >>> mhash = 'QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH'
    >>> data_path_from_data_mhash(mhash, '.').split(os.path.sep)
    ['.', 'data', 'b4', 'bafybeif7ztnhq65lumvvtr4ekcwd2ifwgm3awq4zfr3srh462rwyinlb4y']
    """
    # The hash above is for an empty (zero-length) file.
    #
    # Use a Base32 hash since it is case-insensitive,
    # so we avoid collisions on platforms like Windows.
    #
    # Also, since ASCII-encoded multihashes have prefix bytes indicating things like
    # the encoding base, hash function code, hash size etc.,
    # we prefer end digits for the parent directory,
    # but not the last one since it may be affected by padding.
    # The [-3:-1] digits are used as in IPFS v7 repository format,
    # though our hashes are for the whole file and not just for blocks.
    ipfs_cid = subprocess.run(['ipfs', 'cid', 'base32'],
                              input=data_mhash.encode(),
                              capture_output=True, check=True)
    b32_mhash = ipfs_cid.stdout.decode().strip()
    return os.path.join(output_dir, DATA_DIR_NAME, b32_mhash[-3:-1], b32_mhash)

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
    rp = http.client.HTTPResponse(rpf)
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
    """Returns the descriptor and a hash of the data.

    The descriptor is a mapping.  The hash is a string containing
    the ASCII-encoded multihash provided by IPFS.
    """

    # This only computes and returns the CID, without seeding.
    # The daemon need not be running.
    # We may want to instead use native Python packages for this.
    ipfs_add = subprocess.run(['ipfs', 'add', '-qn', data_path],
                              capture_output=True, check=True)
    data_ipfs_cid = ipfs_add.stdout.decode().strip()
    desc = descriptor_from_ipfs(canonical_uri, data_ipfs_cid, **kwargs)
    return (desc, data_ipfs_cid)

def index_key_from_http_url(canonical_url):
    return canonical_url

def bep44_insert(index_key, desc_link, desc_inline, priv_key):
    """Return a signed BEP44 mutable data item (as bytes)."""

    # It is not safe to assume that storing more than 1000 bytes will succeed,
    # according to <http://bittorrent.org/beps/bep_0044.html#messages>.
    v = desc_inline
    if len(bencoder.bencode(desc_inline)) > 1000:
        v = desc_link

    salt = hashlib.sha1(index_key.encode()).digest()  # SHA1 hash of the index key
    seq = int(time.time())  # integer Unix time stamp

    # Low-level signature buffer computation is mandated by
    # <http://bittorrent.org/beps/bep_0044.html#signature-verification>.
    sigbuf = b''
    sigbuf += b'4:salt%d:%s' % (len(salt), salt)
    sigbuf += b'3:seqi%de' % seq
    sigbuf += b'1:v%d:%s' % (len(v), v)

    # Sign, build exported message fields and encode the result.
    # We follow the names used in the BEP44 document.
    sig = priv_key.sign(sigbuf)[:-len(sigbuf)]  # remove trailing signed message
    return bencoder.bencode(dict(
        # cas is not compulsory
        # id depends on the publishing node
        k=priv_key.verify_key.encode(),
        salt=salt,
        seq=seq,
        # token depends on the insertion
        sig=sig,
        v=v
    ))

def get_canonical_uri(uri):
    return uri  # TODO

def inject_uri(uri, data_path, bep44_priv_key=None, **kwargs):
    """Create descriptor and insertion data for the injection of the `uri`.

    A tuple is returned with the serialized descriptor (as bytes),
    a multihash of the data (as a string),
    and a dictionary mapping the different index names to
    their respective serialized insertion data (as bytes).
    """

    # Generate the descriptor.
    curi = get_canonical_uri(uri)
    (desc, data_mhash) = descriptor_from_file(curi, data_path, **kwargs)

    # Serialize the descriptor for index insertion.
    desc_data = json.dumps(desc, separators=(',', ':')).encode('utf-8')  # RFC 8259#8.1
    ipfs_add = subprocess.run(['ipfs', 'add', '-qn'],
                              input=desc_data, capture_output=True, check=True)
    desc_link = b'/ipfs/' + ipfs_add.stdout.strip()
    desc_inline = b'/zlib/' + zlib.compress(desc_data)

    # Prepare insertion of the descriptor into indexes.
    index_key = index_key_from_http_url(curi)
    ins_data = {}
    if bep44_priv_key:
        ins_data['bep44'] = bep44_insert(index_key, desc_link, desc_inline, bep44_priv_key)

    return (desc_data, data_mhash, ins_data)

def inject_dir(input_dir, output_dir, bep44_priv_key=None):
    """Sign content from `input_dir`, put insertion data in `output_dir`.

    `bep44_priv_key` is the Ed25519 private key to be used to
    sign insertions into the BEP44 index.

    Limitations:

    - Only a single injection per URI is supported.
    - Only injection of HTTP exchanges is supported.

    For each injection to be performed for a given URI,
    somewhere under `input_dir` there must exist:

    - ``NAME.uri`` with the URI itself; the ``NAME`` is not relevant
    - ``NAME.http-rph`` with the head of the HTTP response
    - ``NAME.data`` with the body of the HTTP response
      (after transfer decoding if a non-identity transfer encoding was used)

    The resulting descriptor for a URI is saved to
    ``.ouinet/URI_HASH.desc`` in the `output_dir`,
    where ``URI_HASH`` is the hexadecimal, lower-case SHA1 hash of the URI.
    If such a file already exists in the `output_dir`,
    the injection for that URI is skipped.

    The HTTP response head will be processed, thus the head in the resulting
    descriptor may differ from that in the ``.http-rph`` file.

    TODO: describe output files
    """
    # Look for URI files not yet having a descriptor file in the output directory.
    for (dirpath, dirnames, filenames) in os.walk(input_dir):
        for fn in filenames:
            if not fn.endswith(URI_FILE_EXT):
                continue  # not a URI file
            fp = os.path.join(dirpath, fn)
            uri_prefix = os.path.splitext(fp)[0]

            urip = uri_prefix + URI_FILE_EXT
            datap = uri_prefix + DATA_FILE_EXT
            http_rphp = uri_prefix + HTTP_RPH_FILE_EXT

            if not os.path.exists(datap):
                logger.warning("skipping URI with missing data file: %s", urip)
                continue  # data file must exist even if empty

            if not os.path.exists(http_rphp):
                logger.warning("skipping URI with missing HTTP response head: %s", urip)
                continue  # only handle HTTP insertion for the moment

            with open(urip, 'rb') as urif, open(http_rphp, 'rb') as http_rphf:
                uri = urif.read().decode()  # only ASCII, RFC 3986#1.2.1
                http_rph = http_rphf.read().decode('iso-8859-1')  # RFC 7230#3.2.4

            save_uri_injection(uri, datap, output_dir,
                               bep44_priv_key=bep44_priv_key,
                               meta_http_rph=http_rph)

def save_uri_injection(uri, data_path, output_dir, bep44_priv_key=None, **kwargs):
    """Inject the `uri` and save insertion data to `output_dir`.

    This is only done if insertion data is not already present for the `uri`
    in `output_dir`.
    """
    uri_hash = hashlib.sha1(uri.encode()).hexdigest()
    descp = desc_path_from_uri_hash(uri_hash, output_dir)
    if os.path.exists(descp):
        logger.info("skipping URI with existing descriptor: %s", urip)
        return  # a descriptor for the URI already exists

    # After all the previous checks, proceed to the real injection.
    (desc_data, data_mhash, inj_data) = inject_uri(
        uri, data_path, bep44_priv_key=bep44_priv_key, **kwargs
    )

    # Write descriptor and insertion data to the output directory.
    # TODO: handle exceptions
    desc_dir = os.path.dirname(descp)
    if not os.path.exists(desc_dir):
        logger.info("creating output directory for descriptor data: %s", desc_dir)
        os.makedirs(desc_dir, exist_ok=True)
    with open(descp, 'wb') as descf:
        logger.debug("writing descriptor: uri_hash=%s", uri_hash)
        descf.write(desc_data)
    desc_prefix = os.path.splitext(descp)[0]
    for (idx, idx_inj_data) in inj_data.items():
        with open(desc_prefix + INS_FILE_EXT_PFX + idx, 'wb') as injf:
            logger.debug("writing insertion data (%s): uri_hash=%s", idx, uri_hash)
            injf.write(idx_inj_data)

    # Hard-link the data file (if not already there).
    # TODO: look for better options
    # TODO: handle exceptions
    out_data_path = data_path_from_data_mhash(data_mhash, output_dir)
    if not os.path.exists(out_data_path):
        out_data_dir = os.path.dirname(out_data_path)
        if not os.path.exists(out_data_dir):
            os.makedirs(out_data_dir, exist_ok=True)
        logger.debug("linking data file: uri_hash=%s", uri_hash)
        os.link(data_path, out_data_path)

def main():
    parser = argparse.ArgumentParser(
        description="Sign content to be published using Ouinet.")
    parser.add_argument(
        '--bep44-private-key', metavar="KEY", default='',
        help=("hex-encoded private key for BEP44 index insertion; "
              "if KEY contains '{0}' (e.g. '.{0}bep44.key'), "
              "handle as a file containing the encoded key".format(
                  os.path.sep
              )))
    parser.add_argument(
        # Normalize to avoid confusing ``os.path.{base,dir}name()``.
        'input_directory', metavar="INPUT_DIR", type=os.path.normpath,
        help="the directory where HTTP exchanges are read from")
    parser.add_argument(
        # Normalize to avoid confusing ``os.path.{base,dir}name()``.
        'output_directory', metavar="OUTPUT_DIR", type=os.path.normpath,
        help="the directory where content data, descriptors and insertion data will be saved to")
    args = parser.parse_args()

    # Retrieve the BEP44 private key from disk or argument.
    bep44_priv_key = args.bep44_private_key
    if os.path.sep in bep44_priv_key:  # path to file with key
        logger.debug("loading BEP44 private key from file: %s", bep44_priv_key)
        with open(bep44_priv_key) as b44kf:
            bep44_priv_key = b44kf.read().strip()
    if bep44_priv_key:  # decode key
        bep44_priv_key = nacl.signing.SigningKey(
            nacl.signing.SignedMessage.fromhex(bep44_priv_key))
        bep44_pub_key = bep44_priv_key.verify_key
        logger.info("BEP44 index public key: %s",
                    bep44_pub_key.encode(nacl.encoding.HexEncoder).decode())

    inject_dir(input_dir=args.input_directory, output_dir=args.output_directory,
               bep44_priv_key=bep44_priv_key)

if __name__ == '__main__':
    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=logging.INFO)
    sys.exit(main())
