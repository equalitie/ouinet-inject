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
import os
import subprocess
import uuid
import shutil
import sys
import tempfile
import time
import zlib

import bencoder
import nacl.encoding
import nacl.signing
import warcio.archiveiterator
import warcio.bufferedreaders as _warcbuf
import warcio.statusandheaders as _warchead


OUINET_DIR_NAME = '.ouinet'
URI_FILE_EXT = '.uri'
DATA_FILE_EXT = '.data'
HTTP_RPH_FILE_EXT = '.http-rph'

DESC_TAG = 'desc'
INS_TAG_PFX = 'ins-'

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
    ['.', 'data', 'e3', 'b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
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

def process_http_response(rp):
    """Return a filtered version of `rp` as a response string."""

    # Build a new response head string with selected headers.
    out_rp_str = '%s %s\r\n' % (rp.protocol, rp.statusline)
    for hdrn in _cache_http_response_headers:
        hdrn_lc = hdrn.lower()  # concatenate repeated headers
        hdrv = ', '.join(v for (h, v) in rp.headers if h.lower() == hdrn_lc)
        if hdrv:
            out_rp_str += '%s: %s\r\n' % (hdrn, hdrv)
    out_rp_str += '\r\n'
    return out_rp_str

def _digest_from_path(hash, path):
    """Return the `hash` digest of the file at `path`.

    >>> import hashlib
    >>> import tempfile
    >>> with tempfile.NamedTemporaryFile() as tf:  # empty
    >>>     digest = _digest_from_path(hashlib.sha256, tf.name)
    >>>     print(base64.b64encode(digest))
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
    meta_http_rph = process_http_response(inj.meta_http_rph)
    desc = {
        '!ouinet_version': 0,
        'url': inj.uri,
        'id': inj.id,
        # The ``.000000`` is a work around a Boost limitation in date parsing
        # where microsecond precision in extended ISO dates is compulsory.
        # That limitation affects insertion in the Ouinet client.
        'ts': time.strftime('%Y-%m-%dT%H:%M:%S.000000Z', inj.ts),
        'head': meta_http_rph,
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

class Injection:
    pass  # just a dummy container

def inject_uri(uri, data_path, bep44_priv_key=None, **kwargs):
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
    inj.ts = time.gmtime()
    inj.data_size = os.path.getsize(data_path)
    data_digest = _digest_from_path(hashlib.sha256, data_path)
    inj.data_digest = 'SHA-256=' + base64.b64encode(data_digest).decode()
    inj.data_ipfs_cid = _ipfs_cid_from_path(data_path)
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

    return (inj_data, data_digest)

def inject_dir(input_dir, output_dir, bep44_priv_key=None):
    """Sign content from `input_dir`, put insertion data in `output_dir`.

    `bep44_priv_key` is the Ed25519 private key to be used to
    sign insertions into the BEP44 index.

    Limitations:

    - Only a single injection per URI is supported.
    - Only injection of HTTP GET exchanges is supported.

    For each injection to be performed for a given URI,
    somewhere under `input_dir` there must exist:

    - ``NAME.uri`` with the URI itself; the ``NAME`` is not relevant
    - ``NAME.http-rph`` with the head of the HTTP GET response
    - ``NAME.data`` with the body of the HTTP GET response
      (after transfer decoding if a non-identity transfer encoding was used)

    The HTTP GET response head will be processed, thus the head in
    the resulting descriptor may differ from that in the ``.http-rph`` file.

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
            http_rphp = uri_prefix + HTTP_RPH_FILE_EXT

            if not os.path.exists(datap):
                logger.warning("skipping URI with missing data file: %s", urip)
                continue  # data file must exist even if empty

            if not os.path.exists(http_rphp):
                logger.warning("skipping URI with missing HTTP response head: %s", urip)
                continue  # only handle HTTP insertion for the moment

            with open(urip, 'rb') as urif, open(http_rphp, 'rb') as http_rphf:
                uri = urif.read().decode()  # only ASCII, RFC 3986#1.2.1
                http_headers = http_parse(http_rphf)

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
                                   meta_http_rph=http_headers)
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
                                   meta_http_rph=http_headers)

def inject_warc(warc_file, output_dir, bep44_priv_key=None):
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
            http_rph = record.http_headers

            resp_id = record.rec_headers.get_header('WARC-Record-ID')
            req_id = record.rec_headers.get_header('WARC-Concurrent-To')
            if req_id in seen_get_req:
                seen_get_req.remove(req_id)
            elif resp_id not in seen_get_resp:
                seen_get_resp[resp_id] = (uri, http_rph, body)  # delay until GET confirmation
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
            (uri, http_rph, body) = seen_get_resp.pop(resp_id)

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
                               meta_http_rph=http_rph)

    logger.debug("dropped %d non-GET responses", len(seen_get_resp))

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
        'input', metavar="INPUT_DIR|INPUT_WARC", type=os.path.normpath,
        help=("the directory where HTTP exchanges are read from, "
              "or a WARC file containing such exchanges"))
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

    if os.path.isdir(args.input):
        inject_dir(input_dir=args.input, output_dir=args.output_directory,
                   bep44_priv_key=bep44_priv_key)
    else:
        with open(args.input, 'rb') as warcf:
            inject_warc(warcf, args.output_directory,
                        bep44_priv_key=bep44_priv_key)

if __name__ == '__main__':
    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=logging.INFO)
    sys.exit(main())
