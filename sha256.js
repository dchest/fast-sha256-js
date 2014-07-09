sha256 = function(m) {
  /** @const */ var K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
      h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19,
      w = new Uint32Array(64),
      mlen = m.length,
      left = mlen % 64,
      bitsHi = (mlen / 0x20000000) | 0,
      bitsLo = mlen << 3,
      padLen = (left < 56) ? 64 : 128,
      pad = new Uint8Array(padLen),
      i;


  function blocks(p, off, len) {
    var a, b, c, d, e, f, g, h, u, i, j, t1, t2;
    while (len >= 64) {
      a = h0;
      b = h1;
      c = h2;
      d = h3;
      e = h4;
      f = h5;
      g = h6;
      h = h7;

      for (i = 0; i < 16; i++) {
        j = off + i*4;
        w[i] = (((p[j  ] & 0xff) << 24) | ((p[j+1] & 0xff)<<16) |
                ((p[j+2] & 0xff) <<  8) | ( p[j+3] & 0xff));
      }

      for (i = 16; i < 64; i++) {
        u = w[i-2];
        t1 = (((u>>>17) | (u<<(32-17)>>>0)) ^ ((u>>>19) | (u<<(32-19)>>>0)) ^ (u>>>10));

        u = w[i-15];
        t2 = (((u>>>7) | (u<<(32-7)>>>0)) ^ ((u>>>18) | (u<<(32-18)>>>0)) ^ (u>>>3));

        u = (t1 + w[i-7] >>> 0) + (t2 + w[i-16] >>> 0) >>> 0;
        w[i] = u;
      }

      for (i = 0; i < 64; i++) {
        t1 = ((((((e>>>6) | (e<<(32-6))) ^ ((e>>>11) | (e<<(32-11))) ^
                 ((e>>>25) | (e<<(32-25)))) + ((e & f) ^ (~e & g))) | 0) +
                   ((h + ((K[i] + w[i]) | 0)) | 0)) | 0;

        t2 = ((((a>>>2) | (a<<(32-2))) ^ ((a>>>13) | (a<<(32-13))) ^
              ((a>>>22) | (a<<(32-22)))) + ((a & b) ^ (a & c) ^ (b & c))) | 0;

        h = g;
        g = f;
        f = e;
        e = (d + t1) | 0;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) | 0;
      }

      h0 = (h0 + a) | 0;
      h1 = (h1 + b) | 0;
      h2 = (h2 + c) | 0;
      h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0;
      h5 = (h5 + f) | 0;
      h6 = (h6 + g) | 0;
      h7 = (h7 + h) | 0;

      off += 64;
      len -= 64;
    }
  }

  /* process blocks */
  blocks(m, 0, m.length);

  /* finalize */
  for (i = 0; i < left; i++) pad[i] = m[mlen-left+i];
  pad[left] = 0x80;
  for (i = left + 1; i < padLen - 8; i++) pad[i] = 0;
  pad[padLen-8] = (bitsHi >>> 24) & 0xff;
  pad[padLen-7] = (bitsHi >>> 16) & 0xff;
  pad[padLen-6] = (bitsHi >>>  8) & 0xff;
  pad[padLen-5] = (bitsHi >>>  0) & 0xff;
  pad[padLen-4] = (bitsLo >>> 24) & 0xff;
  pad[padLen-3] = (bitsLo >>> 16) & 0xff;
  pad[padLen-2] = (bitsLo >>>  8) & 0xff;
  pad[padLen-1] = (bitsLo >>>  0) & 0xff;

  blocks(pad, 0, padLen);

  /* output hash */
  w[0] = h0;
  w[1] = h1;
  w[2] = h2;
  w[3] = h3;
  w[4] = h4;
  w[5] = h5;
  w[6] = h6;
  w[7] = h7;

  var hash = new Uint8Array(32);
  for (i = 0; i < 8; i++) {
    hash[i*4+0] = w[i]>>>24 & 0xff;
    hash[i*4+1] = w[i]>>>16 & 0xff;
    hash[i*4+2] = w[i]>>>8 & 0xff;
    hash[i*4+3] = w[i] & 0xff;
  }

  /* cleanup */
  h1 = h2 = h3 = h4 = h5 = h6 = h7 = 0;
  left = bitsHi = bitsLo = padLeft = 0;
  for (i = 0; i < pad.length; i++) pad[i] = 0;
  for (i = 0; i < w.length; i++) w[i] = 0;

  return hash;
};

if (typeof module !== 'undefined' && module.exports) module.exports = sha256;
