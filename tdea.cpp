#include <iostream>
#include <string>
#include <vector>
#include "sboxes.h"
using namespace std;


const int E[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1 };

const int P[32] = {
    16, 7,20,21,29,12,28,17,
     1,15,23,26, 5,18,31,10,
     2, 8,24,14,32,27, 3, 9,
    19,13,30, 6,22,11, 4,25};

const int PC1[56] = {
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,21,13,5,28,20,12,4
};

const int PC2[48] = {
    14,17,11,24,1,5,3,28,15,6,21,10,
    23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
};

const int KEY_SHIFT[17] = {
    0,1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};


vector<uint8_t> pad(const vector<uint8_t>& input) {
    vector<uint8_t> data = input;
    uint8_t pad = 8 - (input.size() % 8);
    data.insert(data.end(), pad, pad);
    return data;
}

vector<uint8_t> unpad(const vector<uint8_t>& input) {
    uint8_t pad = input.back();
    return vector<uint8_t>(input.begin(), input.end() - pad);
}


uint64_t permute(uint64_t input, const int* table, int inSize, int outSize) {
    uint64_t output = 0;
    for (int i = 0; i < outSize; ++i) {
        output <<= 1;
        int srcBit = inSize - table[i];
        output |= (input >> srcBit) & 1;
    }
    return output;
}
uint32_t feistel(uint32_t right, uint64_t subkey) {
    uint64_t expanded = permute(right, E, 32, 48);
    expanded ^= subkey;
    uint32_t output = 0;
    for (int i = 0; i < 8; ++i) {
        int chunk = (expanded >> (42 - 6 * i)) & 0x3F;
        int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        int col = (chunk >> 1) & 0x0F;
        output = (output << 4) | S_BOX[i][row][col];
    }
    return static_cast<uint32_t>(permute(output, P, 32, 32));
}
uint64_t des_block(uint64_t block, const vector<uint64_t>& keys) {
    uint32_t L = block >> 32;
    uint32_t R = block & 0xFFFFFFFF;
    for (int i = 0; i < 16; ++i) {
        uint32_t temp = R;
        R = L ^ feistel(R, keys[i]);
        L = temp;
    }
    return (uint64_t(R) << 32) | L;
}

vector<uint64_t> generate_keys(uint64_t key, bool decrypt = false) {
    uint64_t permuted = permute(key, PC1, 64, 56);
    uint32_t C = (permuted >> 28) & 0x0FFFFFFF;
    uint32_t D = permuted & 0x0FFFFFFF;
    vector<uint64_t> keys;

    for (int i = 1; i <= 16; ++i) {
        C = ((C << KEY_SHIFT[i]) | (C >> (28 - KEY_SHIFT[i]))) & 0x0FFFFFFF;
        D = ((D << KEY_SHIFT[i]) | (D >> (28 - KEY_SHIFT[i]))) & 0x0FFFFFFF;
        uint64_t CD = ((uint64_t)C << 28) | D;
        keys.push_back(permute(CD, PC2, 56, 48));
    }

    if (decrypt) reverse(keys.begin(), keys.end());
    return keys;
}


uint64_t tdea_block_encrypt(uint64_t block, uint64_t k1, uint64_t k2, uint64_t k3) {
    auto keys1 = generate_keys(k1, false);  
    auto keys2 = generate_keys(k2, true);   
    auto keys3 = generate_keys(k3, false);  
    //E(K1) -> D(K2) -> E(K3)
    block = des_block(block, keys1);
    block = des_block(block, keys2);
    block = des_block(block, keys3);
    return block;
}


uint64_t tdea_block_decrypt(uint64_t block, uint64_t k1, uint64_t k2, uint64_t k3) {
    auto keys3 = generate_keys(k3, true);  
    auto keys2 = generate_keys(k2, false);  
    auto keys1 = generate_keys(k1, true);   
    // D(K3) -> E(K2) -> D(K1)
    block = des_block(block, keys3);
    block = des_block(block, keys2);
    block = des_block(block, keys1);
    return block;
}


vector<uint64_t> tdea_encrypt(const vector<uint64_t>& input, uint64_t iv, uint64_t k1, uint64_t k2, uint64_t k3) {
    vector<uint64_t> cipher;
    uint64_t prev = iv;

    for (size_t i = 0; i < input.size(); i++) {
        uint64_t xored = input[i] ^ prev;
        uint64_t encrypted = tdea_block_encrypt(xored, k1, k2, k3);
        cipher.push_back(encrypted);
        prev = encrypted;
    }
    return cipher;
}

vector<uint64_t> tdea_decrypt(const vector<uint64_t>& input, uint64_t iv, uint64_t k1, uint64_t k2, uint64_t k3) {
    vector<uint64_t> plain;
    uint64_t prev = iv;

    for (size_t i = 0; i < input.size(); i++) {
        uint64_t decrypted = tdea_block_decrypt(input[i], k1, k2, k3);
        plain.push_back(decrypted ^ prev);
        prev = input[i];
    }
    return plain;
}


vector<uint64_t> text_to_blocks(const string& text) {
    vector<uint8_t> bytes(text.begin(), text.end());

    uint8_t pad_len = 8 - (bytes.size() % 8);
    bytes.insert(bytes.end(), pad_len, pad_len);

    vector<uint64_t> blocks;
    for (size_t i = 0; i < bytes.size(); i += 8) {
        uint64_t block = 0;
        for (int j = 0; j < 8; ++j) {
            block = (block << 8) | bytes[i + j];
        }
        blocks.push_back(block);
    }
    return blocks;
}

string blocks_to_text(const vector<uint64_t>& blocks) {
    vector<uint8_t> bytes;

    for (uint64_t block : blocks) {
        for (int j = 7; j >= 0; --j) {
            bytes.push_back((block >> (j * 8)) & 0xFF);
        }
    }

    if (!bytes.empty()) {
        uint8_t pad_len = bytes.back();
        if (pad_len > 0 && pad_len <= 8) {
            bytes.erase(bytes.end() - pad_len, bytes.end());
        }
    }

    return string(bytes.begin(), bytes.end());
}

int main() {
    uint64_t k1 = 0x133457799BBCDFF1;
    uint64_t k2 = 0x0E329232EA6D0D73;
    uint64_t k3 = 0x133457799BBCDFF1;
    uint64_t IV = 0xAC27EF451C1A4513;
    vector<uint64_t> input;
    vector<uint64_t> cipher;
    string plain;

    //cout << "Input your text: ";
    cout << "Input  message: ";
    string inputStr;
    getline(cin, inputStr);
    input = text_to_blocks(inputStr);


    cipher = tdea_encrypt(input, IV, k1, k2, k3);
    plain = blocks_to_text(tdea_decrypt(cipher, IV, k1, k2, k3));
    cout << "Encrypted text: ";
    for (auto c : cipher) printf("%016llX", c);
    cout << "\nDecrypted text: "<<plain;
    return 0;
}

