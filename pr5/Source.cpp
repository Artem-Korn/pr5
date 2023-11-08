#include "Header.h"
#define BYTE 8

// Registers init values
const vector<unsigned long> SHA_1::H({
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0
});

// Const values
const vector<unsigned long> SHA_1::K({
    0x5a827999,
    0x6ed9eba1,
    0x8f1bbcdc,
    0xca62c1d6
});

unsigned long SHA_1::convertToWord32(unsigned char a, unsigned char b, unsigned char c, unsigned char d)
{
    return (a << 24 | b << 16 | c << 8 | d);
}

unsigned char SHA_1::convertToWord8(unsigned long long int input, int part)
{
    return (input >> (part * 8));
}

string SHA_1::getHash(string input)
{
    vector<unsigned char> block = stringToBlock(input);

    // Break th block into an array of 'chunks' of 512 bits and each chunk into subarray of 16 32-bit 'words'
    vector<vector<unsigned long>> chanks(block.size() / 64);

    size_t chunk_index = 0;
    vector<unsigned long> prev_reg(SHA_1::H), reg(SHA_1::H);

    for (size_t i = 0; i < chanks.size(); i++)
    {
        chanks[i].reserve(80);

        for (size_t j = 0; j < 64; j += 4)
        {
            chanks[i].push_back(convertToWord32(
                block[chunk_index + j], 
                block[chunk_index + j + 1], 
                block[chunk_index + j + 2], 
                block[chunk_index + j + 3] 
            ));
        }

        // Extend each subarray to 80 words using bitwise operations
        for (size_t j = 16; j <= 79; j++)
        {
            unsigned long res = chanks[i][j - 3] ^ chanks[i][j - 8] ^ chanks[i][j - 14] ^ chanks[i][j - 16];
            chanks[i].push_back(res << 1 | res >> 31);
        }

        unsigned long k, f;

        // Looping through each chunk: bitwise operations and variable reassigment
        for (size_t j = 0; j < 80; j++)
        {
            if (j < 20) 
            {
                f = (reg[1] & reg[2]) | ((~reg[1]) & reg[3]);
                k = SHA_1::K[0];
            }
            else if (j < 40)
            {
                f = reg[1] ^ reg[2] ^ reg[3];
                k = SHA_1::K[1];
            }
            else if (j < 60)
            {
                f = (reg[1] & reg[2]) | (reg[1] & reg[3]) | (reg[2] & reg[3]);
                k = SHA_1::K[2];
            }
            else 
            {
                f = reg[1] ^ reg[2] ^ reg[3];
                k = SHA_1::K[3];
            }
            k = reg[4] + f + (reg[0] << 5 | reg[0] >> 27) + chanks[i][j] + k;

            reg[4] = reg[3];
            reg[3] = reg[2];
            reg[2] = (reg[1] << 30 | reg[1] >> 2);
            reg[1] = reg[0];
            reg[0] = k;
        }

        for (size_t i = 0; i < reg.size(); i++) 
        {
            prev_reg[i] = reg[i] + prev_reg[i];
        }

        chunk_index += 64;
        reg = prev_reg;
    }    

    return bitsetToHexString(prev_reg);
}

// Convert input string to binary block
vector<unsigned char> SHA_1::stringToBlock(string input)
{
    vector<unsigned char> block;
    size_t input_len = input.length();

    block.reserve(input_len + BYTE);

    // Convert ASCII codes to binary
    for (size_t i = 0; i < input_len; i++)
    {
        block.push_back(input[i]);
    }
    block.push_back(128);

    // Pad the binary message with zeros until its mod 64 != 56
    size_t block_len = input_len + 1;

    while (block_len % 64 != 56) {
        block.push_back(0);
        block_len++;
    }

    // Add length of input in binary and pad zeros
    unsigned long long int test(input_len * BYTE);

    for (int i = BYTE - 1; i >= 0; i--)
    {
        block.push_back(convertToWord8(test, i));
    }

    return block;
}

string SHA_1::bitsetToHexString(vector<unsigned long> bitset)
{
    stringstream stream;

    stream << setfill('0')  << hex;
    for (size_t i = 0; i < bitset.size(); i++)
    {
        stream << setw(8) << uppercase << bitset[i];
    }

    return stream.str();
}

void printLine()
{
    cout << "----------------------------------------------------------------\n";
}

void getTestResult(string name, string input)
{
    using chrono::high_resolution_clock;
    using chrono::duration_cast;
    using chrono::duration;
    using chrono::milliseconds;

    string expected, actual;

    printLine();
    cout << name << endl;

    auto t1 = high_resolution_clock::now();
    CryptoPP::SHA1 sha1;
    CryptoPP::StringSource(input, true,
        new CryptoPP::HashFilter(sha1,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(expected))));
    auto t2 = high_resolution_clock::now();

    duration<double, milli> ms_double = t2 - t1;
    cout << "Crypto function time: " << ms_double.count() << "ms" << endl;

    t1 = high_resolution_clock::now();
    actual = SHA_1::getHash(input);
    t2 = high_resolution_clock::now();

    ms_double = t2 - t1;
    cout << "Own function time:    " << ms_double.count() << "ms" << endl;

    if (actual.compare(expected) == 0)
    {
        cout << "Test completed!" << endl;
        cout << "actual:   " << actual << endl;
    }
    else
    {
        cout << "Test failed:" << endl;
        cout << "actual:   " << actual << endl;
        cout << "expected: " << expected << endl;
    }
    printLine();
}