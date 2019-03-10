from collections import namedtuple
from warcio.archiveiterator import WARCIterator

Request = namedtuple('Request', ['headers']) # no body - GET only assumed
Response = namedtuple('Response', ['headers', 'body'])
Value = namedtuple('Value', ['uri', 'request', 'response'], defaults=[None, None])

# URI -> Value
# Last Write Wins for key
state = {}

with open('./my.warc.gz', 'rb') as stream:
    for record in WARCIterator(stream):
        uri = record.rec_headers.get_header('WARC-Target-URI')
        oldval = state.get(uri, Value(uri))

        if record.rec_type == 'request':
            state[record.rec_headers.get_header('WARC-Target-URI')] = oldval._replace(request=Request(record.http_headers))
        elif record.rec_type == 'response':
            state[record.rec_headers.get_header('WARC-Target-URI')] = oldval._replace(response=Response(record.http_headers, record.content_stream().read()))
        else:
            continue

print(state['http://detectportal.firefox.com/success.txt'])
