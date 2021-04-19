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

Only a single injection per URI is supported, and each URI is made part of its
own resource group.  Please note that this can result in a considerable number
of resource groups to be announced by the receiving client.  More sensible
grouping mechanisms will be added in the future.

Please look for ``readme.txt`` files under the output directory for a
description of its format.

## Setup

Installation of the package is not yet supported, but you can install its
Python dependencies with:

    $ pip install -r requirements.txt

Of course, you can also do this in a virtual environment.

For injection using BEP44 keys (obsolete), you will also need to have the
``ipfs`` binary on your search path and an initialized IPFS repo (i.e. run
``ipfs init``).  Please note that the binary will only be used for some hash
computations and that neither a running IPFS daemon nor a connection to the
Internet are needed, and no changes to your IPFS repo will happen.

## Usage

To inject the content in ``INPUT.warc.gz`` and put injection data in
``OUTPUT_DIR``, run:

    $ python3 -m ouinet.inject \
      --httpsig-private-key=/path/to/httpsig.key \
      INPUT.warc.gz OUTPUT_DIR

Where ``/path/to/httpsig.key`` should contain the hex-encoded *private*
signature key.  Please keep that key secret and safe!  The matching *public*
key will be printed as part of the program's diagnostics.

To inject a hierarchy of files and directories, you also need to specify a
base URL to synthesize full HTTP responses to be injected:

    $ python3 -m ouinet.inject \
      --httpsig-private-key=/path/to/httpsig.key \
      --content-base-uri=https://example.com/pub/files/ \
      INPUT_DIR OUTPUT_DIR

So that ``INPUT_DIR/images/index.html`` becomes accessible via the URL
``https://example.com/pub/files/images/index.html``.  Please note that in this
case it is safe to use the input directory as the output directory, as
insertion data will just sit along the data files and point to them to avoid
duplication.  Then you only need to distribute the ``INPUT_DIR`` (instead of
both the ``INPUT_DIR`` and ``OUTPUT_DIR``).

Please note that running the script on an output directory with existing
insertion data or content will add the new injections to it without
overwriting or deleting existing files.  This is equivalent to indicating
``--overwrite=never``.  You can also use ``--overwrite=always`` (overwrites
all existing insertion data, never content files), or ``--overwrite=older``
(overwrites insertion data older than content in the input directory).
