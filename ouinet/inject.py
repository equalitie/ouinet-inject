#!/usr/bin/env python3
"""Sign content to be published using Ouinet.
"""

import argparse
import base64
import codecs
import glob
import hashlib
import io
import json
import logging
import mimetypes
import os
import subprocess
import uuid
import re
import shutil
import sys
import tempfile
import time
import urllib.parse
import zlib

import bencoder
import nacl.encoding
import nacl.signing
import warcio.archiveiterator
import warcio.bufferedreaders as _warcbuf
import warcio.statusandheaders as _warchead

from ouinet.util import http_signature


OUINET_DIR_NAME = '.ouinet'
URI_FILE_EXT = '.uri'
DATA_FILE_EXT = '.data'
HTTP_RES_H_FILE_EXT = '.http-res-h'

DESC_TAG = 'desc'
INS_TAG_PFX = 'ins-'
HTTP_SIG_TAG = 'http-res-h'
BLOCK_SIGS_TAG = 'bsigs'

DATA_DIR_NAME = 'ouinet-data'

OUINET_DIR_INFO = """\
This directory contains control data for reinserting URI content using a
Ouinet client and the `ouinet-upload` tool.

Please run `ouinet-upload` on the parent directory.

For each injected URI the following files can be found, where `<XY><REST>` is
the lower-case, hexadecimal SHA1 hash of the URI:

  - `<XY>/<REST>.desc`: the Ouinet descriptor for the URI; the descriptor
    contains the IPFS CID hash to content data (in the `%s` directory)

  - `<XY>/<REST>.ins-<INDEX>`: insertion data for the URI on the given INDEX

  - `<XY>/<REST>.http-res-h`: the signed head of the HTTP GET response

  - `<XY>/<REST>.bsigs`: signature and hash of each data block: block offset
    (hex), block signature (Base64), chained hash (Base64)
""" % DATA_DIR_NAME

DATA_DIR_INFO = """\
This directory contains content data for seeding using a Ouinet client and
`ouinet-upload`.  (You may also seed the files directly using IPFS.)

Please run `ouinet-upload` on the parent directory.

Each data file is `<XY>/<REST>`, where `<XY><REST>` is the lower-case,
hexadecimal SHA-256 hash of its contents.

To get the hexadecimal hash from the Base64 one used by descriptors in the
`%s` directory, use:

    echo 'SHA-256=...' | cut -d= -f2- | base64 -d | hexdump -e '/1 "%%02x"'

""" % OUINET_DIR_NAME

logger = logging.getLogger(__name__)


def _maybe_add_readme(readme_dir, text):
    readme_path = os.path.join(readme_dir, 'readme.txt')
    if os.path.exists(readme_path):
        return
    logger.debug("creating readme: %s", readme_path)
    os.makedirs(readme_dir, exist_ok=True)
    with open(readme_path, 'w') as f:
        f.write(text)

def inj_prefix_from_uri_hash(uri_hash, output_dir):
    # The splitting mimics that of Git object storage:
    # we use the initial two digits since
    # with SHA1 all bytes vary more or less uniformly.
    return os.path.join(output_dir, OUINET_DIR_NAME, uri_hash[:2], uri_hash[2:])

def data_path_from_data_digest(data_digest, output_dir):
    """Return the output path for a file with the given `data_digest`.

    >>> import base64
    >>> b64digest = b'47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
    >>> digest = base64.b64decode(b64digest)
    >>> data_path_from_data_digest(digest, '.').split(os.path.sep)
    ['.', 'ouinet-data', 'e3', 'b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
    """
    # The hash above is for an empty (zero-length) file.
    #
    # Use an hexadecimal hash since it is case-insensitive,
    # so we avoid collisions on platforms like Windows.
    hex_digest = codecs.encode(data_digest, 'hex').decode()
    return os.path.join(output_dir, DATA_DIR_NAME, hex_digest[:2], hex_digest[2:])

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
    'Digest',
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

def to_cache_response(res_h):
    """Return a filtered version of `res_h`."""

    # Build a new response head with selected headers.
    headers = []
    for hdrn in _cache_http_response_headers:
        hdrn_lc = hdrn.lower()  # concatenate repeated headers
        hdrv = ', '.join(v for (h, v) in res_h.headers if h.lower() == hdrn_lc)
        if hdrv:
            headers.append((hdrn, hdrv))
    return _warchead.StatusAndHeaders(res_h.statusline, headers, res_h.protocol)

def _digest_from_path(hash, path):
    """Return the `hash` digest of the file at `path`.

    >>> import hashlib
    >>> import tempfile
    >>> with tempfile.NamedTemporaryFile() as tf:  # empty
    ...     digest = _digest_from_path(hashlib.sha256, tf.name)
    ...     print(base64.b64encode(digest))
    ...
    b'47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
    """
    buf = bytearray(4096)
    h = hash()
    with open(path, 'rb') as f:
        l = f.readinto(buf)
        while l:
            h.update(buf[:l])
            l = f.readinto(buf)
    return h.digest()

def _ipfs_cid_from_path(path):
    # This only computes and returns the CID, without seeding.
    # The daemon need not be running.
    # We may want to instead use native Python packages for this.
    ipfs_add = subprocess.run(['ipfs', 'add', '-qn', path],
                              stdout=subprocess.PIPE, check=True)
    return ipfs_add.stdout.decode().strip()

def descriptor_from_injection(inj):
    """Returns the descriptor for a given injection (as a mapping)."""
    # v0 descriptors only support HTTP exchanges,
    # with compulsory response head metadata,
    # and a single IPFS CID pointing to the body.
    meta_http_res_h = inj.meta_http_res_h.to_ascii_bytes().decode()
    desc = {
        '!ouinet_version': 0,
        'url': inj.uri,
        'id': inj.id,
        # The ``.000000`` is a work around a Boost limitation in date parsing
        # where microsecond precision in extended ISO dates is compulsory.
        # That limitation affects insertion in the Ouinet client.
        'ts': time.strftime('%Y-%m-%dT%H:%M:%S.000000Z', time.gmtime(inj.ts)),
        'head': meta_http_res_h,
        'body_link': inj.data_ipfs_cid,

        # These are not part of the descriptor v0 spec,
        # they are added to ease tools locate body data files.
        'body_size': inj.data_size,
        'body_digest': inj.data_digest,
    }
    return desc

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
    sig = priv_key.sign(sigbuf).signature
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

def http_key_id_for_injection(httpsig_pub_key):
    # Extra check to avoid accidentally revealing a private key,
    # since both private and public keys have an ``encode`` method.
    if not hasattr(httpsig_pub_key, 'verify'):
        raise TypeError("expected public key")
    b64enc = nacl.encoding.Base64Encoder
    return 'ed25519=' + httpsig_pub_key.encode(b64enc).decode()

_hdr_pfx = 'X-Ouinet-'
_hdr_version = _hdr_pfx + 'Version'
_hdr_uri = _hdr_pfx + 'URI'
_hdr_injection = _hdr_pfx + 'Injection'
_hdr_bsigs = _hdr_pfx + 'BSigs'
_hdr_data_size = _hdr_pfx + 'Data-Size'
_hdr_sig0 = _hdr_pfx + 'Sig0'
_http_bsigsfmt = (
    'keyId="%s"'
    ',algorithm="hs2019"'
    ',size=%d'
)

def http_inject(inj, httpsig_priv_key, httpsig_key_id=None, _ts=None):
    r"""Get an HTTP head for an injection using an Ed25519 private key.

    The result is returned as bytes.

    >>> import io
    >>> from base64 import b64encode as b64enc, b64decode as b64dec
    >>> from hashlib import sha256
    >>> from nacl.signing import SigningKey
    >>> from warcio.statusandheaders import StatusAndHeadersParser as parser
    >>>
    >>> bs = 65536
    >>> body = (b'0123' + b'x' * (bs - 8) + b'4567'
    ...         + b'89AB' + b'x' * (bs - 8) + b'CDEF'
    ...         + b'abcd')
    >>> b64_digest = b64enc(sha256(body).digest()).decode()
    >>> b64_digest
    'E4RswXyAONCaILm5T/ZezbHI87EKvKIdxURKxiVHwKE='
    >>>
    >>> head_s = b'''\
    ... HTTP/1.1 200 OK
    ... Date: Mon, 15 Jan 2018 20:31:50 GMT
    ... Server: Apache1
    ... Content-Type: text/html
    ... Content-Disposition: inline; filename="foo.html"
    ... Content-Length: 131076
    ... Server: Apache2
    ...
    ... '''.replace(b'\n', b'\r\n')
    >>> head = parser(['HTTP/1.0', 'HTTP/1.1']).parse(io.BytesIO(head_s))
    >>>
    >>> sk = SigningKey(b64dec(b'MfWAV5YllPAPeMuLXwN2mUkV9YaSSJVUcj/2YOaFmwQ='))
    >>> ts = 1516048310
    >>> class inj_incomplete:
    ...     uri = 'https://example.com/foo'
    ...     id = 'd6076384-2295-462b-a047-fe2c9274e58d'
    ...     ts = ts
    ...     block_size = bs
    ...     meta_http_res_h = head
    >>>
    >>> ts_incomplete = ts
    >>> signed_ref_incomplete = b'''\
    ... HTTP/1.1 200 OK
    ... Date: Mon, 15 Jan 2018 20:31:50 GMT
    ... Server: Apache1
    ... Content-Type: text/html
    ... Content-Disposition: inline; filename="foo.html"
    ... Content-Length: 131076
    ... Server: Apache2
    ... X-Ouinet-Version: 6
    ... X-Ouinet-URI: https://example.com/foo
    ... X-Ouinet-Injection: id=d6076384-2295-462b-a047-fe2c9274e58d,ts=1516048310
    ... X-Ouinet-BSigs: keyId="ed25519=DlBwx8WbSsZP7eni20bf5VKUH3t1XAF/+hlDoLbZzuw=",\
    ... algorithm="hs2019",size=65536
    ... X-Ouinet-Sig0: keyId="ed25519=DlBwx8WbSsZP7eni20bf5VKUH3t1XAF/+hlDoLbZzuw=",\
    ... algorithm="hs2019",created=1516048310,\
    ... headers="(response-status) (created) \
    ... date server content-type content-disposition \
    ... x-ouinet-version x-ouinet-uri x-ouinet-injection x-ouinet-bsigs",\
    ... signature="OhUfbxd63iV8UnoSoGBLY6cGVbsR+FB20gJk67rvxHx9CjvQzvIHjsKtmayrF6gmh2VIlZH07rT5Bpc+1lMsBg=="
    ...
    ... '''.replace(b'\n', b'\r\n')
    >>> signed_incomplete = http_inject(inj_incomplete, sk, _ts=ts_incomplete)
    >>> signed_incomplete == signed_ref_incomplete
    True
    >>> ts_complete = ts + 1
    >>> class inj_complete(inj_incomplete):
    ...     data_size = len(body)
    ...     data_digest = 'SHA-256=' + b64_digest
    >>>
    >>> signed_ref_complete = b'''\
    ... HTTP/1.1 200 OK
    ... Date: Mon, 15 Jan 2018 20:31:50 GMT
    ... Server: Apache1
    ... Content-Type: text/html
    ... Content-Disposition: inline; filename="foo.html"
    ... Content-Length: 131076
    ... Server: Apache2
    ... X-Ouinet-Version: 6
    ... X-Ouinet-URI: https://example.com/foo
    ... X-Ouinet-Injection: id=d6076384-2295-462b-a047-fe2c9274e58d,ts=1516048310
    ... X-Ouinet-BSigs: keyId="ed25519=DlBwx8WbSsZP7eni20bf5VKUH3t1XAF/+hlDoLbZzuw=",\
    ... algorithm="hs2019",size=65536
    ... X-Ouinet-Data-Size: 131076
    ... Digest: SHA-256=E4RswXyAONCaILm5T/ZezbHI87EKvKIdxURKxiVHwKE=
    ... X-Ouinet-Sig0: keyId="ed25519=DlBwx8WbSsZP7eni20bf5VKUH3t1XAF/+hlDoLbZzuw=",\
    ... algorithm="hs2019",created=1516048311,\
    ... headers="(response-status) (created) \
    ... date server content-type content-disposition \
    ... x-ouinet-version x-ouinet-uri x-ouinet-injection x-ouinet-bsigs \
    ... x-ouinet-data-size \
    ... digest",\
    ... signature="TL2i9D1a9b5X3p2qVOjanENO7FpltN9qUmTG0hTg9SMIrC7O5SRjzqsh/qg2TGUrf5hchaxhrWGRKUAJ3iPoDg=="
    ...
    ... '''.replace(b'\n', b'\r\n')
    >>> signed_complete = http_inject(inj_complete, sk, _ts=ts_complete)
    >>> signed_complete == signed_ref_complete
    True
    """
    res = inj.meta_http_res_h
    to_sign = _warchead.StatusAndHeaders(res.statusline, res.headers.copy(), res.protocol)
    to_sign.add_header(_hdr_version, str(6))
    to_sign.add_header(_hdr_uri, inj.uri)
    to_sign.add_header(_hdr_injection, 'id=%s,ts=%d' % (inj.id, inj.ts))
    if not httpsig_key_id:
        httpsig_key_id = http_key_id_for_injection(httpsig_priv_key.verify_key)
    if getattr(inj, 'block_size', 0) > 0:
        to_sign.add_header(_hdr_bsigs, _http_bsigsfmt % (httpsig_key_id, inj.block_size))
    if hasattr(inj, 'data_size'):
        to_sign.add_header(_hdr_data_size, str(inj.data_size))
    if hasattr(inj, 'data_digest'):
        to_sign.add_header('Digest', inj.data_digest)
    signature = http_signature(to_sign, httpsig_priv_key, httpsig_key_id, _ts=_ts)
    to_sign.add_header(_hdr_sig0, signature)
    return to_sign.to_ascii_bytes()

def block_signatures(inj, data_path, httpsig_priv_key):
    r"""Return block signatures for the given injection.

    Signatures are returned as bytes.  Each line in the result contains the
    hexadecimal offset of the block, a space character, the Base64-encoded
    signature for the block, a space character, the Base64-encoded data hash
    for the block, a space character, the Base64-encoded chain hash for the
    block, and a new line character.

    If the injection does not enable block signatures, return `None`.

    >>> from tempfile import NamedTemporaryFile as mktemp
    >>> from base64 import b64decode as b64dec
    >>> from nacl.signing import SigningKey
    >>>
    >>> bs = 65536
    >>> body = (b'0123' + b'x' * (bs - 8) + b'4567'
    ...         + b'89AB' + b'x' * (bs - 8) + b'CDEF'
    ...         + b'abcd')
    >>>
    >>> class inj:
    ...     id = 'd6076384-2295-462b-a047-fe2c9274e58d'
    ...     block_size = bs
    >>>
    >>> sk = SigningKey(b64dec(b'MfWAV5YllPAPeMuLXwN2mUkV9YaSSJVUcj/2YOaFmwQ='))
    >>> with mktemp() as data:
    ...     _ = data.write(body)
    ...     _ = data.seek(0)
    ...     bsigs = block_signatures(inj, data.name, sk)
    ...
    >>> bsigs_ref = b'''\
    ... 0\
    ...  r2OtBbBVBXT2b8Ch/eFfQt1eDoG8eMs/JQxnjzNPquF80WcUNwQQktsu0mF0+bwc3akKdYdBDeORNLhRjrxVBA==\
    ...  aERfr5o+kpvR4ZH7xC0mBJ4QjqPUELDzjmzt14WmntxH2p3EQmATZODXMPoFiXaZL6KNI50Ve4WJf/x3ma4ieA==\
    ...  4c0RNY1zc7KD7WqcgnEnGv2BJPLDLZ8ie8/kxtwBLoN2LJNnzUMFzXZoYy1NnddokpIxEm3dL+gJ7dr0xViVOg==
    ... 10000\
    ...  LfRN72Vv5QMNd6sn6HOWbfcoN6DA9kdjTXEfJvmgViZQZT5hlZXQpCOULyBreeZv3sd7j5FJzgu3CCUoBXOCCA==\
    ...  lfLy+XIYvDfWbg0+hDnfPZ2G548iBKNalciKnSzEDPLiqmxRng2oOAcpKwY5NicofgpuYrMGII2JwOS7XFPJNA==\
    ...  ELwO/upgGHUv+GGm8uFMqQPtpLpNHUtSsLPuGo7lflgLZGA8GVfrFF1yuNOx1U998iF2rAApn8Yua80Fnn+TKg==
    ... 20000\
    ...  oZ3hLELDPOK4y2b0Yd6ezoXaF37PqBXt/WX7YJAzfS4au/QewCQxMlds8qtNWjOrP9Gzyde3jjFn647srWI7DA==\
    ...  2AIvIGCtbv0perc9zFNVybIUBUsNF3ahNqZp0mp9OxT3OqDQ6/8Z7jMzaPAWS2QZqW2knj5IF1Pn6Wtxa9zLbw==\
    ...  zBvQ0lnfde2B6dRt2B0HvW/kaiL1TXNlbezQmhNqh0zCxMBHb0SWPsWeKNDbsHFdyKzZlauqzVSfAsHer0fq+w==
    ... '''
    >>> bsigs == bsigs_ref
    True
    >>>
    >>> with mktemp() as data:
    ...     bsigs = block_signatures(inj, data.name, sk)
    ...
    >>> bsigs_ref = b'''\
    ... 0\
    ...  sI1HJC2+BeXy39qqaivr9IrUB8B8dlUm8J3WrYlrH0HmdnfA5DlwIrd00sph3OSrJGw/ATzNbUI3xdTS2kccBQ==\
    ...  z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==\
    ...  gm3waEV99d0ZW0N6t+dzn/ddJnIYPwK7jhCJ+rz5e9ncgBEM9C28fP9Bx47LaNi6eKvmtReN6jmE34xVVBv5SQ==
    ... '''
    >>> bsigs == bsigs_ref
    True
    """
    block_size = getattr(inj, 'block_size', 0)
    if block_size <= 0:
        return None

    bsigs = io.BytesIO()
    b64enc = base64.b64encode
    sig_str_fmt = b'%s\x00%%d\x00%%s' % inj.id.encode()
    with open(data_path, 'rb') as dataf:
        block_offset = 0
        bsig = None
        block_chain_digest = None
        buf = bytearray(block_size)
        l = dataf.readinto(buf)
        first_read = True  # for empty data
        while first_read or l:
            first_read = False
            block_chain_hash = hashlib.sha512()
            block_chain_hash.update(bsig or b'')
            block_chain_hash.update(block_chain_digest or b'')
            block_data_digest = hashlib.sha512(buf[:l]).digest()
            block_chain_hash.update(block_data_digest)
            block_chain_digest = block_chain_hash.digest()
            bsig = httpsig_priv_key.sign(sig_str_fmt % (block_offset, block_chain_digest)).signature
            bsigs.write(b'%x %s %s %s\n' % (block_offset, b64enc(bsig),
                                            b64enc(block_data_digest), b64enc(block_chain_digest)))
            block_offset += l
            l = dataf.readinto(buf)

    return bsigs.getvalue()

def get_canonical_uri(uri):
    return uri  # TODO

class Injection:
    pass  # just a dummy container

_inject_block_size_default = 65536  # bytes

def inject_uri(uri, data_path,
               bep44_priv_key=None, httpsig_priv_key=None, httpsig_key_id=None,
               meta_http_res_h=None, **kwargs):
    """Create injection data for the injection of the `uri`.

    A tuple is returned with
    a dictionary mapping different injection data tags to
    their respective serialized data (as bytes),
    and a digest of the data itself (as bytes).
    """

    # Prepare the injection.
    inj = Injection()
    inj.uri = get_canonical_uri(uri)
    inj.id = str(uuid.uuid4())
    inj.ts = time.time()
    inj.data_size = os.path.getsize(data_path)
    data_digest = _digest_from_path(hashlib.sha256, data_path)
    inj.data_digest = 'SHA-256=' + base64.b64encode(data_digest).decode()
    inj.data_ipfs_cid = _ipfs_cid_from_path(data_path)
    inj.block_size = _inject_block_size_default
    if meta_http_res_h:
        inj.meta_http_res_h = to_cache_response(meta_http_res_h)
    for (k, v) in kwargs.items():  # other stuff like metadata
        setattr(inj, k, v)

    inj_data = {}

    # Generate the descriptor.
    logger.debug("creating descriptor for URI: %s", inj.uri)
    desc = descriptor_from_injection(inj)

    # Serialize the descriptor for index insertion.
    desc_data = json.dumps(desc, separators=(',', ':')).encode('utf-8')  # RFC 8259#8.1
    ipfs_add = subprocess.run(['ipfs', 'add', '-qn'],
                              input=desc_data,
                              stdout=subprocess.PIPE, check=True)
    desc_link = b'/ipfs/' + ipfs_add.stdout.strip()
    desc_inline = b'/zlib/' + zlib.compress(desc_data)
    inj_data[DESC_TAG] = desc_data

    # Prepare insertion of the descriptor into indexes.
    index_key = index_key_from_http_url(inj.uri)
    if bep44_priv_key:
        logger.debug("creating BEP44 insertion data for URI: %s", inj.uri)
        inj_data[INS_TAG_PFX + 'bep44'] = bep44_insert(
            index_key, desc_link, desc_inline, bep44_priv_key)

    # Create a signed HTTP response head.
    if httpsig_priv_key:
        logger.debug("creating HTTP signature for URI: %s", inj.uri)
        inj_data[HTTP_SIG_TAG] = http_inject(inj, httpsig_priv_key, httpsig_key_id)
        logger.debug("creating block signatures for URI: %s", inj.uri)
        inj_data[BLOCK_SIGS_TAG] = block_signatures(inj, data_path, httpsig_priv_key)

    return (inj_data, data_digest)

def inject_dir(input_dir, output_dir,
               bep44_priv_key=None, httpsig_priv_key=None, httpsig_key_id=None):
    """Sign content from `input_dir`, put insertion data in `output_dir`.

    `bep44_priv_key` is the Ed25519 private key to be used to
    sign insertions into the BEP44 index.

    `httpsig_priv_key` is the Ed25519 private key to be used to
    create HTTP signatures.
    `httpsig_key_id` is an identifier for that key in signatures.

    Limitations:

    - Only a single injection per URI is supported.
    - Only injection of HTTP GET exchanges is supported.

    For each injection to be performed for a given URI,
    somewhere under `input_dir` there must exist:

    - ``NAME.uri`` with the URI itself; the ``NAME`` is not relevant
    - ``NAME.http-res-h`` with the head of the HTTP GET response
    - ``NAME.data`` with the body of the HTTP GET response
      (after transfer decoding if a non-identity transfer encoding was used)

    The HTTP GET response head will be processed, thus the head in
    the resulting descriptor may differ from that in the ``.http-res-h`` file.

    See `save_uri_injection()` for more information on
    the storage of injections in `output_dir`.
    """
    http_parse = _warchead.StatusAndHeadersParser(['HTTP/1.0', 'HTTP/1.1']).parse

    # Look for URI files not yet having a descriptor file in the output directory.
    for (dirpath, dirnames, filenames) in os.walk(input_dir):
        for fn in filenames:
            if not fn.endswith(URI_FILE_EXT):
                continue  # not a URI file
            fp = os.path.join(dirpath, fn)
            uri_prefix = os.path.splitext(fp)[0]

            urip = uri_prefix + URI_FILE_EXT
            datap = uri_prefix + DATA_FILE_EXT
            http_res_hp = uri_prefix + HTTP_RES_H_FILE_EXT

            if not os.path.exists(datap):
                logger.warning("skipping URI with missing data file: %s", urip)
                continue  # data file must exist even if empty

            if not os.path.exists(http_res_hp):
                logger.warning("skipping URI with missing HTTP response head: %s", urip)
                continue  # only handle HTTP insertion for the moment

            with open(urip, 'rb') as urif, open(http_res_hp, 'rb') as http_res_hf:
                uri = urif.read().decode()  # only ASCII, RFC 3986#1.2.1
                http_headers = http_parse(http_res_hf)

            # We use the identity-encoded body to
            # make it self-standing and more amenable to seeding in other systems.
            norm = lambda enc: None if (not enc or enc == 'identity') else enc
            txenc = norm((http_headers.get_header('Transfer-Encoding') or '').lower())
            ctenc = norm((http_headers.get_header('Content-Encoding') or '').lower())
            http_headers.remove_header('Transfer-Encoding')
            http_headers.remove_header('Content-Encoding')

            # Trivial case, no decoding needed.
            if not txenc and not ctenc:
                save_uri_injection(uri, datap, output_dir,
                                   bep44_priv_key=bep44_priv_key,
                                   httpsig_priv_key=httpsig_priv_key,
                                   httpsig_key_id=httpsig_key_id,
                                   meta_http_res_h=http_headers)
                continue

            # Extract body data to a temporary file in the output directory,
            # so that it can be safely hard-linked into the data directory.
            os.makedirs(output_dir, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=output_dir, delete=True) as dataf:
                with open(datap, 'rb') as bodyf:
                    if txenc == 'chunked':
                        bodyf = _warcbuf.ChunkedDataReader(bodyf, decomp_type=ctenc)
                    elif ctenc in _warcbuf.BufferedReader.get_supported_decompressors():
                        bodyf = _warcbuf.BufferedReader(bodyf, decomp_type=ctenc)
                    shutil.copyfileobj(bodyf, dataf)
                    dataf.flush()

                datap = os.path.join(output_dir, dataf.name)
                # Use length of identity-encoded data.
                http_headers.replace_header('Content-Length', str(os.path.getsize(datap)))
                save_uri_injection(uri, datap, output_dir,
                                   bep44_priv_key=bep44_priv_key,
                                   httpsig_priv_key=httpsig_priv_key,
                                   httpsig_key_id=httpsig_key_id,
                                   meta_http_res_h=http_headers)

def inject_warc(warc_file, output_dir,
                bep44_priv_key=None, httpsig_priv_key=None, httpsig_key_id=None):
    # For marking GET requests pointed to by responses.
    seen_get_req = set()
    # For marking responses pointed to by GET requests.
    seen_get_resp = {}  # WARC record ID -> (URI, HTTP head, body) or None
    # These assume at most one ``WARC-Concurrent-To`` per request or response
    # (plus warcio only supports accessing one such header).

    for record in warcio.archiveiterator.WARCIterator(warc_file):
        if not record.http_headers:
            continue  # only handle HTTP insertion for the moment

        # According to
        # <https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/#warc-target-uri>,
        # response entries must have a ``WARC-Target-URI`` header with the exchange URI.
        # Since the only thing we need from the request is the URI,
        # we could only process response records,
        # however we still need to see the request to ensure it was a GET.

        if record.rec_type == 'response':
            # We need to read body data fully now,
            # since advancing to the next record exhausts it.
            # We also use the identity-encoded body to
            # make it self-standing and more amenable to seeding in other systems.
            uri = record.rec_headers.get_header('WARC-Target-URI')
            body = record.content_stream().read()
            record.http_headers.remove_header('Transfer-Encoding')
            record.http_headers.remove_header('Content-Encoding')
            record.http_headers.replace_header('Content-Length', str(len(body)))
            http_res_h = record.http_headers

            resp_id = record.rec_headers.get_header('WARC-Record-ID')
            req_id = record.rec_headers.get_header('WARC-Concurrent-To')
            if req_id in seen_get_req:
                seen_get_req.remove(req_id)
            elif resp_id not in seen_get_resp:
                seen_get_resp[resp_id] = (uri, http_res_h, body)  # delay until GET confirmation
                continue
            # GET previously confirmed, proceed.
            seen_get_resp.pop(resp_id, None)

        elif record.rec_type == 'request' and record.http_headers.protocol == 'GET':
            req_id = record.rec_headers.get_header('WARC-Record-ID')
            resp_id = record.rec_headers.get_header('WARC-Concurrent-To')
            if not resp_id:
                seen_get_req.add(req_id)  # mark as GET, later response may point to it
                continue
            if resp_id not in seen_get_resp:
                seen_get_resp[resp_id] = None  # confirm GET, pending response
                continue
            # GET confirmed, pop out response info and process it.
            (uri, http_res_h, body) = seen_get_resp.pop(resp_id)

        else:  # ignore other kinds of records
            continue

        # Extract body data to a temporary file in the output directory,
        # so that it can be safely hard-linked into the data directory.
        os.makedirs(output_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output_dir, delete=True) as dataf:
            bodyf = io.BytesIO(body)
            shutil.copyfileobj(bodyf, dataf)
            dataf.flush()

            datap = os.path.join(output_dir, dataf.name)
            save_uri_injection(uri, datap, output_dir,
                               bep44_priv_key=bep44_priv_key,
                               httpsig_priv_key=httpsig_priv_key,
                               httpsig_key_id=httpsig_key_id,
                               meta_http_res_h=http_res_h)

    logger.debug("dropped %d non-GET responses", len(seen_get_resp))

def _http_time_from_posix(ts):
    return time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(ts))

def _http_head_from_content_file(fpath, root_dir):
    headers = []
    (mtype, menc) = mimetypes.guess_type(fpath)
    if mtype:
        headers.append(('Content-Type', mtype))
    else:  # do not add header, see RFC7231#3.1.1.5
        logger.warning("failed to guess MIME type for content file: %s",
                       os.path.relpath(fpath, root_dir))
    if menc:
        headers.append(('Content-Encoding', menc))
    mtime = os.stat(fpath).st_mtime
    headers.append(('Last-Modified', _http_time_from_posix(mtime)))
    return _warchead.StatusAndHeaders('200 OK', headers, 'HTTP/1.1')

def inject_static_root(root_dir, repo_dir, base_uri,
                       httpsig_priv_key, httpsig_key_id):
    """TODO: document
    """
    root_dir = os.path.realpath(root_dir)
    repo_dir = os.path.realpath(repo_dir)
    if root_dir == repo_dir:
        raise ValueError("static cache root and repository cannot match")

    base_uri = re.sub(r'(/*)$', '', base_uri)
    quote = urllib.parse.quote

    for (dirpath, dirnames, filenames) in os.walk(root_dir):
        if dirpath == repo_dir:   # i.e. repo under root dir
            continue
        # E.g. with `http://foo.bar/' and `/path/to/root`,
        # `/path/to/root/blah/blah` -> `http://foo.bar/blah/blah/`.
        dir_uri_prefix = '%s%s/' % (base_uri, quote(dirpath[len(root_dir):].replace(os.path.sep, '/')))
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            uri = dir_uri_prefix + quote(fn)
            head = _http_head_from_content_file(fp, root_dir)
            save_static_injection(uri, fp, root_dir, repo_dir,
                                  httpsig_priv_key=httpsig_priv_key,
                                  httpsig_key_id=httpsig_key_id,
                                  meta_http_res_h=head)

def save_uri_injection(uri, data_path, output_dir, **kwargs):
    """Inject the `uri` and save insertion data to `output_dir`.

    This is only done if insertion data is not already present for the `uri`
    in `output_dir`.

    Control data is stored under `OUINET_DIR_NAME` in `ouinet_dir`,
    and content data is hard-linked under `DATA_DIR_NAME` in `ouinet_dir`.
    See `OUINET_DIR_INFO` and `DATA_DIR_INFO` for
    the format of output files in these directories.
    """
    _maybe_add_readme(os.path.join(output_dir, OUINET_DIR_NAME), OUINET_DIR_INFO)
    _maybe_add_readme(os.path.join(output_dir, DATA_DIR_NAME), DATA_DIR_INFO)

    uri_hash = hashlib.sha1(uri.encode()).hexdigest()
    inj_prefix = inj_prefix_from_uri_hash(uri_hash, output_dir)
    if glob.glob(inj_prefix + '.*'):
        logger.info("skipping URI with existing injection: %s", uri)
        return  # a descriptor for the URI already exists

    # After all the previous checks, proceed to the real injection.
    (inj_data, data_digest) = inject_uri(uri, data_path, **kwargs)

    # Write descriptor and insertion data to the output directory.
    # TODO: handle exceptions
    inj_dir = os.path.dirname(inj_prefix)
    os.makedirs(inj_prefix, exist_ok=True)
    for (itag, idata) in inj_data.items():
        if idata is None:
            continue
        with open('%s.%s' % (inj_prefix, itag), 'wb') as injf:
            logger.debug("writing injection data (%s): uri_hash=%s", itag, uri_hash)
            injf.write(idata)

    # Hard-link the data file (if not already there).
    # TODO: look for better options
    # TODO: handle exceptions
    out_data_path = data_path_from_data_digest(data_digest, output_dir)
    if not os.path.exists(out_data_path):
        out_data_dir = os.path.dirname(out_data_path)
        os.makedirs(out_data_dir, exist_ok=True)
        logger.debug("linking data file: uri_hash=%s", uri_hash)
        os.link(data_path, out_data_path)

def save_static_injection(uri, data_path, root_dir, repo_dir, **kwargs):
    print("XXXX INJECT", uri, data_path, kwargs)  # TODO

def _private_key_from_arg(priv_key):
    """Return the Ed25519 private key in command-line argument `priv_key`.

    Return `None` if no key is specified.
    """
    if os.path.sep in priv_key:  # path to file with key
        logger.debug("loading private key from file: %s", priv_key)
        with open(priv_key) as kf:
            priv_key = kf.read().strip()
    if priv_key:  # decode key
        priv_key = nacl.signing.SigningKey(
            nacl.signing.SignedMessage.fromhex(priv_key))
        return priv_key

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
        '--httpsig-private-key', metavar="KEY", default='',
        help=("hex-encoded private key for HTTP signatures; "
              "if KEY contains '{0}' (e.g. '.{0}httpsig.key'), "
              "handle as a file containing the encoded key".format(
                  os.path.sep
              )))
    parser.add_argument(
        '--content-base-uri', metavar="URI", default='',
        help=("a base URI to synthesize HTTP response headers "
              "for content files in the INPUT_DIR static cache root; "
              "OUTPUT_DIR will become a static cache repository for it"
              ))
    parser.add_argument(
        # Normalize to avoid confusing ``os.path.{base,dir}name()``.
        'input', metavar="INPUT_DIR|INPUT_WARC", type=os.path.normpath,
        help=("the directory where static cache content or HTTP exchanges are read from, "
              "or a WARC file containing such exchanges"))
    parser.add_argument(
        # Normalize to avoid confusing ``os.path.{base,dir}name()``.
        'output_directory', metavar="OUTPUT_DIR", type=os.path.normpath,
        help="the directory where content data, descriptors and insertion data will be saved to")
    args = parser.parse_args()

    # Retrieve private keys from disk or arguments.
    bep44_sk = _private_key_from_arg(args.bep44_private_key)
    httpsig_sk = _private_key_from_arg(args.httpsig_private_key)
    httpsig_kid = None
    sk2pkhex = lambda sk: sk.verify_key.encode(nacl.encoding.HexEncoder).decode()
    if bep44_sk:
        logger.info("BEP44 index public key: %s", sk2pkhex(bep44_sk))
    if httpsig_sk:
        logger.info("HTTP signatures public key: %s", sk2pkhex(httpsig_sk))
        httpsig_kid = http_key_id_for_injection(httpsig_sk.verify_key)

    if not os.path.isdir(args.input):
        with open(args.input, 'rb') as warcf:
            inject_warc(warcf, args.output_directory,
                        bep44_priv_key=bep44_sk,
                        httpsig_priv_key=httpsig_sk, httpsig_key_id=httpsig_kid)
    elif not args.content_base_uri:
        inject_dir(input_dir=args.input, output_dir=args.output_directory,
                   bep44_priv_key=bep44_sk,
                   httpsig_priv_key=httpsig_sk, httpsig_key_id=httpsig_kid)
    else:
        inject_static_root(root_dir=args.input, repo_dir=args.output_directory,
                           base_uri=args.content_base_uri,
                           httpsig_priv_key=httpsig_sk, httpsig_key_id=httpsig_kid)

if __name__ == '__main__':
    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=logging.INFO)
    sys.exit(main())
