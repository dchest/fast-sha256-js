SHA256-js
=========

SHA-256 implementation in JavaScript.
Public domain. No warranty.

Usage
-----

Functions accept and return `Uint8Array`s.

### sha256(message)

Returns SHA-256 hash of the message.


### sha256.hmac(key, message)

Returns HMAC-SHA-256 of the message for the key.


### sha256.pbkdf2(password, salt, rounds, dkLen)

Returns a key of length dkLen derived using PBKDF2-HMAC-SHA256
from the given password, salt, and the number of rounds.


Testing and building
--------------------

Install development dependencies:

    $ npm install

Run tests:

    $ npm test

Run tests on different source file:

    $ SHA256_SRC=sha256.min.js npm test

Run benchmark:

    $ npm run bench

(or in a browser, open `tests/bench.html`).

Build minified version:

    $ npm run build
