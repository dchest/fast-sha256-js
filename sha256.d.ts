export declare class Hash {
    static digestLength: number;
    static blockSize: number;
    digestLength: number;
    blockSize: number;
    private state;
    private temp;
    private buffer;
    private bufferLength;
    private bytesHashed;
    finished: boolean;
    constructor();
    reset(): this;
    clean(): void;
    update(data: Uint8Array, dataLength?: number): Hash;
    finish(out: Uint8Array): Hash;
    digest(): Uint8Array;
    _saveState(out: Uint8Array): void;
    _restoreState(from: Uint8Array, bytesHashed: number): void;
}
export declare class HMAC {
    private inner;
    private outer;
    blockSize: number;
    digestLength: number;
    private istate;
    private ostate;
    constructor(key: Uint8Array);
    reset(): this;
    clean(): void;
    update(data: Uint8Array): HMAC;
    finish(out: Uint8Array): HMAC;
    digest(): Uint8Array;
}
export declare function hash(data: Uint8Array): Uint8Array;
export default hash;
export declare function hmac(key: Uint8Array, data: Uint8Array): Uint8Array;
export declare function pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number, dkLen: number): Uint8Array;
