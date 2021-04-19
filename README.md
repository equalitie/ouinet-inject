# Ouinet offline injector

This script allows someone owning the necessary private keys to perform
offline injection (signing) of content for later insertion into
[Ouinet](https://github.com/equalitie/ouinet).

## Keys

Two injection mechanisms are supported:

  - BitTorrent BEP44 keys for creating Ouinet URI descriptors that support
    sharing resources over IPFS (obsolete).

  - Ed25519 keys for creating a [Ouinet static cache][] repository with
    signatures of HTTP response heads and bodies' data blocks, ready for
    streaming to other users.

[Ouinet static cache]: https://github.com/equalitie/ouinet/blob/master/doc/ouinet-network-whitepaper.md#out-of-band-cache-entry-exchange

If you are running a Ouinet injector, you may use the ``ed25519-private-key``
file present in its repository directory.

## Input

Three kinds of input are supported:

  - HTTP GET responses stored as head and body in an ad hoc file-based format
    (obsolete).

    See the doc string of `ouinet.inject.inject_dir()` for a description of
    this format.

  - A WARC file coming from web crawling.

    See <https://en.wikipedia.org/wiki/Web_ARChive> for more information on
    the WARC file format and tools to produce it.

  - An arbitrary hierarchy of content files and directories plus a base URL,
    so that ``ROOT/path/to/file.txt`` with ``https://example.com/base/``
    becomes ``https://example.com/base/path/to/file.txt``.

## Output

The script produces a set of insertion and (depending on the kind of input)
content data files which are added to a given output directory.  That
directory can then be circulated and used on a different machine running a
Ouinet client (configured to trust the public keys matching the private keys
used for injection) and used there as if the content was retrieved over the
Ouinet network (e.g. for local access or seeding to others).

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
