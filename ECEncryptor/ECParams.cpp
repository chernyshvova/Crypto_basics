#include "stdafx.h"
#include "ECParams.h"

const unsigned char* crypt::ConvertconstCharToUnConstChar(const char* s)
{
    int len = strlen(s);
    unsigned char* s1 = new unsigned char[len];
    for (int i = 0; i < len; i++)
        s1[i] = s[i];
    return s1;
}