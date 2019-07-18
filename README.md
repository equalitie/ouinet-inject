# Ouinet offline injector

This script allows someone owning the necessary private keys to perform
offline injection of content for later insertion into
[Ouinet](https://github.com/equalitie/ouinet), e.g. using
[ouinet-upload](https://github.com/equalitie/ouinet-upload).

## Keys

For the moment only two injection mechanisms are supported:

  - BitTorrent BEP44 keys for signing insertions into Ouinet's BEP44
    distributed cache index.
  - Ed25519 keys for creating signatures of HTTP response heads according to
    <https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-11>.

If you are running a Ouinet injector, you may use the ``ed25519-private-key``
and ``ed25519-public-key`` files present in its repository directory.

## Input

The only content supported at the moment are HTTP GET exchanges consisting of
a request and a response made of an HTTP response head and body.  These can be
provided either via a WARC file (e.g. coming from web crawling) or using an ad
hoc file-based format.

Please see <https://en.wikipedia.org/wiki/Web_ARChive> for more information on
the WARC file format and tools to produce it.

See the doc string of `ouinet.inject.inject_dir()` for a description of the ad
hoc input format.

## Output

The script produces a set of injection and content data files which are added
to a given output directory.  That directory can be circulated and used as
input to ``ouinet-upload`` on a different machine running a Ouinet client
configured to trust the public keys matching the private keys used for
injection.

Please look for ``readme.txt`` files in the output directory for a description
of its format.

Only a single injection per URI is supported.  Subsequent injections of the
same URI will be skipped.

Running the script on an output directory with existing content will add the
new injections to it without overwriting or deleting existing files.

## Setup

Installation of the package is not yet supported, but you can install its
Python dependencies with:

    $ pip install -r requirements.txt

You will also need to have the ``ipfs`` binary on your search path and an
initialized IPFS repo (i.e. run ``ipfs init``).  Please note that the binary
will only be used for some hash computations and that neither a running IPFS
daemon nor connection to the Internet are needed, and no changes to your IPFS
repo will happen.

## Usage

To inject the content in ``INPUT.warc.gz`` and put injection data in
``OUTPUT_DIR``, run:

    $ python3 -m ouinet.inject \
      --bep44-private-key=/path/to/bep44.key \
      --httpsig-private-key=/path/to/httpsig.key \
      INPUT.warc.gz OUTPUT_DIR

Where ``/path/to/{bep44,httpsig}.key`` should contain the hex-encoded
*private* BitTorrent BEP44 or HTTP signatures keys, respectively.  Please keep
those keys secret and safe!  The matching *public* keys will be printed as
part of the program's diagnostics.

To insert the content stored in `OUTPUT_DIR` from another machine using
``ouinet-upload``, run:

    $ python3 -m ouinet.upload DIRECTORY seed

(See ``ouinet-upload``'s documentation for more information.)
