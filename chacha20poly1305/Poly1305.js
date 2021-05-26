import { ChaCha20 } from "./ChaCha20.js";

function poly1305_mac(msg, key) {
    let mac = [];
    let r = 0n;
    let s = 0n;
    for (let i = 0; i < 16; i++) {
        r += BigInt(key[i]) << BigInt(i * 8);
        s += BigInt(key[i + 16]) << BigInt(i * 8);
    }
    r = r & BigInt("0x0ffffffc0ffffffc0ffffffc0fffffff");
    let a = 0n;
    let p = (1n << 130n) - 5n;
    for (let i = 1; i <= Math.ceil(msg.length / 16); i++) {
        let n = 1n;
        let len = 16;
        if (i == Math.ceil(msg.length / 16)) {
            len = msg.length - (i - 1) * 16;
        }
        for (let j = (16 * (i - 1) + len - 1); j >= 16 * (i - 1); j--) {
            n <<= 8n;
            n += BigInt(msg[j]);
        }
        a += n;
        a = (r * a) % p;
    }
    a += s;
    for (let i = 0; i < 16; i++) {
        let tmp = a & 255n;
        mac.push(parseInt(tmp.toString(10)));
        a >>= 8n;
    }
    return mac;
}

function poly1305_key_gen(key, nonce) {
    let counter = 0;
    let block = ChaCha20.block(key, counter, nonce);
    return block.slice(0, 32);
}

const Poly1305 = {
    mac: poly1305_mac,
    keyGen: poly1305_key_gen,
};

export { Poly1305 };
