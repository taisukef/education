function Qround(state, x, y, z, w) {
    let a = state[x]; let b = state[y]; let c = state[z]; let d = state[w];
    a = (a + b) & 0xffffffff; d = d ^ a; d = (d << 16) | (d >>> 16);
    c = (c + d) & 0xffffffff; b = b ^ c; b = (b << 12) | (b >>> 20);
    a = (a + b) & 0xffffffff; d = d ^ a; d = (d << 8) | (d >>> 24);
    c = (c + d) & 0xffffffff; b = b ^ c; b = (b << 7) | (b >>> 25);
    state[x] = a; state[y] = b; state[z] = c; state[w] = d;
}

function inner_block(state) {
    Qround(state, 0, 4, 8, 12);
    Qround(state, 1, 5, 9, 13);
    Qround(state, 2, 6, 10, 14);
    Qround(state, 3, 7, 11, 15);
    Qround(state, 0, 5, 10, 15);
    Qround(state, 1, 6, 11, 12);
    Qround(state, 2, 7, 8, 13);
    Qround(state, 3, 4, 9, 14);
}

function ChaCha20_block(key, counter, nonce) {
    // 初期化
    // 定数
    let state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    // キー
    for (let i = 0; i < 8; i++) {
        state.push(key[i * 4] | (key[i * 4 + 1] << 8) |
            (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24));
    }
    // ブロックカウント
    state.push(counter);
    // ナンス
    for (let i = 0; i < 3; i++) {
        state.push(nonce[i * 4] | (nonce[i * 4 + 1] << 8) |
            (nonce[i * 4 + 2] << 16) | (nonce[i * 4 + 3] << 24));
    }
    // 最後の加算用に状態コピー
    let ininitial_state = state.concat();
    // 20ラウンド
    for (let i = 0; i < 10; i++) {
        inner_block(state);
    }
    // 加算
    for (let i = 0; i < state.length; i++) {
        state[i] = (state[i] + ininitial_state[i]) & 0xffffffff;
    }
    // シリアル化
    let block = [];
    for (let i = 0; i < state.length; i++) {
        block.push(state[i] & 0x000000ff);
        block.push((state[i] & 0x0000ff00) >>> 8);
        block.push((state[i] & 0x00ff0000) >>> 16);
        block.push((state[i] & 0xff000000) >>> 24);
    }
    return block;
}

function ChaCha20_encrypt(key, counter, nonce, plaintext) {
    let encrypted_message = [];
    for (let j = 0; j < Math.floor(plaintext.length / 64); j++) {
        let key_stream = ChaCha20_block(key, counter + j, nonce);
        for (let k = 0; k < 64; k++) {
            encrypted_message.push(plaintext[j * 64 + k] ^ key_stream[k]);
        }
    }
    if (plaintext.length % 64 != 0) {
        let j = Math.floor(plaintext.length / 64);
        let key_stream = ChaCha20_block(key, counter + j, nonce);
        for (let k = 0; k < plaintext.length % 64; k++) {
            encrypted_message.push(plaintext[j * 64 + k] ^ key_stream[k]);
        }
    }
    return encrypted_message;
}

const ChaCha20 = {
    block: ChaCha20_block,
    encrypt: ChaCha20_encrypt,
};
export { ChaCha20 };
