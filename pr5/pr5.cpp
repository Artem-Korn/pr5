#include "Header.h"

int main()
{
	string input = "abcd1234;.";
	string addition = "abcd1234;.abcd1234;.abcd1234;.abcd1234;.abcd1234;.abcd1234;.abcd";

	for (int i = 0; i < 10; i++)
	{
		input += addition;
		getTestResult("Test " + to_string(i), input);
	}

	cout << "Input text value: " << endl;
	cin >> input;
	getTestResult("Input Test", input);
}