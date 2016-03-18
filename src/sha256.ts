// SHA-256 (+ HMAC and PBKDF2) for JavaScript.
//
// Written in 2014-2016 by Dmitry Chestnykh.
// Public domain, no warranty.
//
// Functions (accept and return Uint8Arrays):
//
//   sha256(message) -> hash
//   sha256.hmac(key, message) -> mac
//   sha256.pbkdf2(password, salt, rounds, dkLen) -> dk
//
//  Classes:
//  
//   new sha256.Hash()
//   new sha256.HMAC(key)
//

const K = new Uint32Array([
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

function hashBlocks(w: Int32Array, v: Int32Array, p: Uint8Array, pos: number, len: number) : number {
  let a: number, b: number, c: number, d: number, e: number,
      f: number, g: number, h: number, u: number, i: number,
      j: number, t1: number, t2: number;
  while (len >= 64) {
    a = v[0];
    b = v[1];
    c = v[2];
    d = v[3];
    e = v[4];
    f = v[5];
    g = v[6];
    h = v[7];

    for (i = 0; i < 16; i++) {
      j = pos + i*4;
      w[i] = (((p[j  ] & 0xff) << 24) | ((p[j+1] & 0xff)<<16) |
              ((p[j+2] & 0xff) <<  8) | ( p[j+3] & 0xff));
    }

    for (i = 16; i < 64; i++) {
      u = w[i-2];
      t1 = (u>>>17 | u<<(32-17)) ^ (u>>>19 | u<<(32-19)) ^ (u>>>10);

      u = w[i-15];
      t2 = (u>>>7 | u<<(32-7)) ^ (u>>>18 | u<<(32-18)) ^ (u>>>3);

      w[i] = (t1 + w[i-7] | 0) + (t2 + w[i-16] | 0);
    }

    for (i = 0; i < 64; i++) {
      t1 = (((((e>>>6 | e<<(32-6)) ^ (e>>>11 | e<<(32-11)) ^
                (e>>>25 | e<<(32-25))) + ((e & f) ^ (~e & g))) | 0) +
                  ((h + ((K[i] + w[i]) | 0)) | 0)) | 0;

      t2 = (((a>>>2 | a<<(32-2)) ^ (a>>>13 | a<<(32-13)) ^
            (a>>>22 | a<<(32-22))) + ((a & b) ^ (a & c) ^ (b & c))) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }

    v[0] += a;
    v[1] += b;
    v[2] += c;
    v[3] += d;
    v[4] += e;
    v[5] += f;
    v[6] += g;
    v[7] += h;

    pos += 64;
    len -= 64;
  }
  return pos;
}

export class Hash {
    public static digestLength: number = 32;
    public static blockSize: number = 64;
    
    public digestLength = Hash.digestLength;
    public blockSize = Hash.blockSize;
    
    // Note: Int32Array is used instead of Uint32Array for performance reasons.
    v: Int32Array = new Int32Array(8); // hash state
    w: Int32Array = new Int32Array(64); // temporary state
    buf: Uint8Array = new Uint8Array(128); // buffer for data to hash
    buflen: number  = 0; // number of bytes in buffer
    len: number = 0; // number of total bytes hashed
    finished: boolean = false; // indicates whether the hash was finalized 

    constructor() {
        this.reset();
    }
  
    // Re-initializes hash state making it possible
    // to re-use this instance to hash other data.
    public reset() {
        this.v[0] = 0x6a09e667;
        this.v[1] = 0xbb67ae85;
        this.v[2] = 0x3c6ef372;
        this.v[3] = 0xa54ff53a;
        this.v[4] = 0x510e527f;
        this.v[5] = 0x9b05688c;
        this.v[6] = 0x1f83d9ab;
        this.v[7] = 0x5be0cd19;
        this.buflen = 0;
        this.len = 0;
        this.finished = false;
    }
    
    // Cleans internal buffers and re-initializes hash state.
    public clean() {
        for (let i = 0; i < this.buf.length; i++) this.buf[i] = 0;
        for (let i = 0; i < this.w.length; i++) this.w[i] = 0;
        this.reset();
    }
    
    // Updates hash state with the given data.
    //
    // Optionally, length of the data can be specified to hash
    // fewer bytes than data.length.
    //
    // Throws error when trying to update already finalized hash:
    // instance must be reset to use it again.
    public update(data: Uint8Array, dataLength: number = data.length): Hash {
        if (this.finished) {
            throw new Error("SHA256: can't update because hash was finished.")
        }
        let dataPos = 0;
        this.len += dataLength;
        if (this.buflen > 0) {
            while (this.buflen < 64 && dataLength > 0) {
            this.buf[this.buflen++] = data[dataPos++];
                dataLength--;
            }
            if (this.buflen === 64) {
            hashBlocks(this.w, this.v, this.buf, 0, 64);
            this.buflen = 0;
            }
        }
        if (dataLength >= 64) {
            dataPos = hashBlocks(this.w, this.v, data, dataPos, dataLength);
            dataLength %= 64;
        }
        while (dataLength > 0) {
            this.buf[this.buflen++] = data[dataPos++];
            dataLength--;
        }
        return this;
    }
    
    // Finalizes hash state and puts hash into out.
    //
    // If hash was already finalized, puts the same value.
    public finish(out: Uint8Array): Hash {
        if (!this.finished) {
            const mlen = this.len;
            const left = this.buflen;
            const bhi = (mlen / 0x20000000) | 0;
            const blo = mlen << 3;
            const padlen = (mlen % 64 < 56) ? 64 : 128;

            this.buf[left] = 0x80;
            for (let i = left + 1; i < padlen - 8; i++) {
                this.buf[i] = 0;
            }
            this.buf[padlen-8] = (bhi >>> 24) & 0xff;
            this.buf[padlen-7] = (bhi >>> 16) & 0xff;
            this.buf[padlen-6] = (bhi >>>  8) & 0xff;
            this.buf[padlen-5] = (bhi >>>  0) & 0xff;
            this.buf[padlen-4] = (blo >>> 24) & 0xff;
            this.buf[padlen-3] = (blo >>> 16) & 0xff;
            this.buf[padlen-2] = (blo >>>  8) & 0xff;
            this.buf[padlen-1] = (blo >>>  0) & 0xff;

            hashBlocks(this.w, this.v, this.buf, 0, padlen);
    
            this.finished = true;
        }

        for (let i = 0; i < 8; i++) {
            out[i*4+0] = (this.v[i] >>> 24) & 0xff;
            out[i*4+1] = (this.v[i] >>> 16) & 0xff;
            out[i*4+2] = (this.v[i] >>>  8) & 0xff;
            out[i*4+3] = (this.v[i] >>>  0) & 0xff;
        }
        
        return this;
    }
    
    // Returns the final hash digest.
    public digest(): Uint8Array {
        const out = new Uint8Array(this.digestLength);
        this.finish(out);
        return out;
    }
}

export class HMAC {
    inner: Hash = new Hash();
    outer: Hash = new Hash();
    
    blockSize: number = this.inner.blockSize;
    digestLength: number = this.inner.digestLength;
    
    // Copies of hash states after keying.
    // Need for quick reset without hashing they key again.
    istate: Uint32Array; 
    ostate: Uint32Array; 

    constructor(key: Uint8Array) {
        const pad = new Uint8Array(this.blockSize);
        if (key.length > this.blockSize) {
            (new Hash()).update(key).finish(pad).clean();
        } else {
            for (let i = 0; i < key.length; i++) {
                pad[i] = key[i];
            }
        }
        for (let i = 0; i < pad.length; i++) {
            pad[i] ^= 0x36;
        }
        this.inner.update(pad);
        
        for (let i = 0; i < pad.length; i++) {
            pad[i] ^= 0x36 ^ 0x5c;
        }
        this.outer.update(pad);

        this.istate = new Uint32Array(this.digestLength / 4);
        this.ostate = new Uint32Array(this.digestLength / 4);

        for (let i = 0; i < this.istate.length; i++) {
            this.istate[i] = this.inner.v[i];
            this.ostate[i] = this.outer.v[i];
        }
        for (let i = 0; i < pad.length; i++) {
            pad[i] = 0;
        }
    }

    reset() {
        for (var i = 0; i < this.istate.length; i++) {
            this.inner.v[i] = this.istate[i];
            this.outer.v[i] = this.ostate[i];
        }
        this.inner.len = this.outer.len = this.inner.blockSize;
        this.inner.buflen = this.outer.buflen = 0;
        this.inner.finished = this.outer.finished = false;
    }

    clean() {
        for (var i = 0; i < this.istate.length; i++) {
            this.ostate[i] = this.istate[i] = 0;
        }
        this.inner.clean();
        this.outer.clean();
    }

    update(data: Uint8Array): HMAC {
        this.inner.update(data);
        return this;
    }

    finish(out: Uint8Array): HMAC {
        if (this.outer.finished) {
            this.outer.finish(out);
        } else {
            this.inner.finish(out);
            this.outer.update(out, this.digestLength).finish(out);
        }
        return this;
    }

    digest(): Uint8Array {
        const out = new Uint8Array(this.digestLength);
        this.finish(out);
        return out;
    }
}
 
export function hash(data: Uint8Array): Uint8Array {
    const h = (new Hash()).update(data);
    const digest = h.digest();
    h.clean();
    return digest;
}

export default hash;

export function hmac(key: Uint8Array, data: Uint8Array) {
    const h = (new HMAC(key)).update(data);
    const digest = h.digest();
    h.clean();
    return digest;
}

export function pbkdf2(password: Uint8Array, salt: Uint8Array, rounds: number, dkLen: number) {
    const ctr = new Uint8Array(4);
    const t = new Uint8Array(32);
    const u = new Uint8Array(32);
    const dk = new Uint8Array(dkLen);
    const prf = new HMAC(password);

    for (let i = 0; i * 32 < dkLen; i++) {
        let k = i + 1;
        ctr[0] = (k >>> 24) & 0xff;
        ctr[1] = (k >>> 16) & 0xff;
        ctr[2] = (k >>> 8)  & 0xff;
        ctr[3] = (k >>> 0)  & 0xff;
        prf.reset();
        prf.update(salt);
        prf.update(ctr);
        prf.finish(u);
        for (let j = 0; j < 32; j++) {
            t[j] = u[j];
        }
        for (let j = 2; j <= rounds; j++) {
            prf.reset();
            prf.update(u).finish(u);
            for (let k = 0; k < 32; k++) {
                t[k] ^= u[k];
            }
        }
        for (let j = 0; j < 32 && i*32 + j < dkLen; j++) {
            dk[i*32 + j] = t[j];
        }
    }
    for (let i = 0; i < 32; i++) {
        t[i] = u[i] = 0;
    }
    for (let i = 0; i < 4; i++) {
        ctr[i] = 0;
    }
    prf.clean();
    return dk;
}