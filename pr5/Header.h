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
	static const vector<unsigned long> H;
	static const vector<unsigned long> K;

	static unsigned long convertToWord32(unsigned char, unsigned char, unsigned char, unsigned char);
	static unsigned char convertToWord8(unsigned long long int, int);
	static vector<unsigned char> stringToBlock(string);
	static string bitsetToHexString(vector<unsigned long>);
public:
	static string getHash(string);
};

void getTestResult(string name, string input);
void printLine();