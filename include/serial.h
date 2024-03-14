#ifndef __SERIAL__
#define __SERIAL__

#include "binfhecontext-ser.h"
#include <iostream>
#include <fstream>
using namespace lbcrypto;
using namespace std;

//const std::string DATAFOLDER = "FHE_context";


//DATAFOLDER 注意这里，应该为完整的地址，那么就要改这里面的函数。
void FHE_context_serial(std::string DATAFOLDER,BinFHEContext cc1);

BinFHEContext FHE_context_deserial(std::string DATAFOLDER);

//void FHE_cipher_serial(std::string DATAFOLDER,LWECiphertext ct1);
void FHE_cipher_serial(std::string DATAFOLDER,std::string filename,LWECiphertext ct1);
//LWECiphertext FHE_cipher_deserial(std::string DATAFOLDER);
LWECiphertext FHE_cipher_deserial(std::string DATAFOLDER,std::string filename);



#endif