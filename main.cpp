// #include "./include/crypt.h"
#include <stdio.h>
#include <iostream>
#include <cmath>
#include <cstring>

#define PLAINTEXT "psokulac1"

int main(void)
{
    using namespace std;
    std::string plain_text = "psOkuloC1:1:";
    cout << plain_text.substr(0, plain_text.find_first_of(":")) << endl;
    cout << plain_text.substr(plain_text.find_first_of(":")+1, 1) << endl;
    

    

    return 0;
}
