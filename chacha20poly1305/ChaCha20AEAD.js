import { ChaCha20 } from "./ChaCha20.js";
import { Poly1305 } from "./Poly1305.js";

function chacha20_aead_encrypt(key, nonce, plaintext, aad) {
    let otk = Poly1305.keyGen(key, nonce);
    let ciphertext = ChaCha20.encrypt(key, 1, nonce, plaintext);
    let mac_data = pad16(aad);
    mac_data = mac_data.concat(pad16(ciphertext));
    mac_data = mac_data.concat(num_to_8_le_bytes(aad.length));
    mac_data = mac_data.concat(num_to_8_le_bytes(ciphertext.length));
    let tag = Poly1305.mac(mac_data, otk);
    return ciphertext.concat(tag);
}

function chacha20_aead_decrypt(key, nonce, aad, enc) {
    let otk = Poly1305.keyGen(key, nonce);
    let ciphertext = enc.slice(0, enc.length - 16);
    let tag = enc.slice(enc.length - 16);
    let mac_data = pad16(aad);
    mac_data = mac_data.concat(pad16(ciphertext));
    mac_data = mac_data.concat(num_to_8_le_bytes(aad.length));
    mac_data = mac_data.concat(num_to_8_le_bytes(ciphertext.length));
    let mac = Poly1305.mac(mac_data, otk);
    for (let i = 0; i < mac.length; i++) {
        if (mac[i] != tag[i]) {
            throw error("unmatch tag");
        }
    }
    let plaintext = ChaCha20.encrypt(key, 1, nonce, ciphertext);
    return plaintext;
}

function pad16(x) {
    let a = x.concat();
    while ((a.length % 16) != 0) {
        a.push(0);
    }
    return a;
}

function num_to_8_le_bytes(num) {
    let bs = [0, 0, 0, 0, 0, 0, 0, 0];
    let tmp = num;
    for (let i = 0; i < bs.length; i++) {
        bs[i] = tmp & 0xff;
        tmp >>= 8;
    }
    return bs;
}

const ChaCha20AEAD = {
  encrypt: chacha20_aead_encrypt,
  decrypt: chacha20_aead_decrypt,
};
export { ChaCha20AEAD };
