#include <iostream>


void reverse(char* str);

void main()
{
	char myStr[255] = "";
	std::cin >> myStr;
	reverse(myStr);
}

void reverse(char* str)
{
	char* revstr = str;
	for (int i = strlen(revstr); i >= 0; i--)
	{
		std::cout << str[i];
	}
	std::cout << std::endl;
}