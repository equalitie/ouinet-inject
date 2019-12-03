"""Implement HTTP signatures as defined in draft-cavage-http-signatures_.

.. _draft-cavage-http-signatures: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12
"""

import base64
import collections
import time


_sigexclude = {
    'content-length',
    'transfer-encoding',
    'trailer',
}
_sigfmt = (
    'keyId="%s"'
    ',algorithm="hs2019"'
    ',created=%d'
    ',headers="%s"'
    ',signature="%s"'
)

def signature(res_h, priv_key, key_id, _ts=None):
    ts = _ts if _ts else time.time()  # for testing

    # Accumulate stripped values for repeated headers,
    # while getting the list of headers in input order.
    pseudo_headers = [('(response-status)', [res_h.get_statuscode()]),
                      ('(created)', ['%d' % ts])]  # keeps order
    header_values = collections.defaultdict(list, pseudo_headers)
    headers = [hn for (hn, _) in pseudo_headers]
    for (hn, hv) in res_h.headers:
        (hn, hv) = (hn.lower(), hv.strip())
        if hn in _sigexclude:
            continue  # exclude framing headers
        if hn not in header_values:
            headers.append(hn)
        header_values[hn].append(hv)

    sig_string = '\n'.join('%s: %s' % (hn, ', '.join(header_values[hn]))
                           for hn in headers).encode()  # only ASCII, RFC 7230#3.2.4
    encoded_sig = base64.b64encode(priv_key.sign(sig_string).signature).decode()

    return _sigfmt % (key_id, ts, ' '.join(headers), encoded_sig)
