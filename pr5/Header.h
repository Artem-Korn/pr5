#pragma once
#include <iostream>
#include <bitset>
#include <vector>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <string>
using namespace std;

class SHA_1 {
	static const vector<bitset<32>> H;
	static const vector<bitset<32>> K;

	static bitset<32>convertToWord32(bitset<8>, bitset<8>, bitset<8>, bitset<8>);
	static bitset<8>convertToWord8(bitset<64>, int);
	static vector<bitset<8>> stringToBlock(string);
	static string bitsetToHexString(vector<bitset<32>>);
public:
	static string getHash(string);
};

void getTestResult(string name, string input);
void printLine();