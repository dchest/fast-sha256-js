fast-sha256-js
==============

SHA-256 implementation in JavaScript with typed arrays that works in modern
browsers and Node.js. Implements the hash function, HMAC, and PBKDF2.

Public domain. No warranty.

[![Build Status](https://travis-ci.org/dchest/fast-sha256-js.svg?branch=master)
](https://travis-ci.org/dchest/fast-sha256-js)


Installation
------------

You can install fast-sha256-js via a package manager:

[Bower](http://bower.io):

    $ bower install fast-sha256

[NPM](https://www.npmjs.org/):

    $ npm install fast-sha256

or [download source code](https://github.com/dchest/fast-sha256-js/releases).


Usage
-----

Functions accept and return `Uint8Array`s.
To convert strings, use external library (for example,
[nacl.util](https://github.com/dchest/tweetnacl-js/)).

### sha256(message)

Returns a SHA-256 hash of the message.


### sha256.hmac(key, message)

Returns an HMAC-SHA-256 of the message for the key.


### sha256.pbkdf2(password, salt, rounds, dkLen)

Returns a key of length dkLen derived using PBKDF2-HMAC-SHA256
from the given password, salt, and the number of rounds.


Usage with TypeScript
---------------------

```
import sha256, { Hash, HMAC } from "fast-sha256";

sha256(data) // default export is hash

var h = new HMAC(key); // also Hash and HMAC classes
var mac = h.update(data).digest();

// alternatively:

import * as sha256 from "fast-sha256";

sha256.pbkdf2(password, salt, iterations, dkLen); // returns derived key 
```


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



Notes
-----

While this implementation is pretty fast compared to previous generation
implementations, if you need a faster one, check out
[asmCrypto](https://github.com/vibornoff/asmcrypto.js).
