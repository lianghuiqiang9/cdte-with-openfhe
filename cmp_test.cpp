#include <iostream>
#include <fstream>
#include "client.h"
#include "server.h"
//#include "node.h"
#include "utils.h"
//#include "serial.h"
#include "function.h"

using namespace std;
using namespace lbcrypto;
std::map<int, LWECiphertext> R1;
std::map<int, LWECiphertext> X1;


//g++ -o cmp_test cmp_test.cpp src/utils.cpp src/node.cpp src/function.cpp -O3 -I./include -I /usr/local/include/openfhe -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/binfhe -I /usr/local/include/openfhe/cereal -L /usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -fopenmp

//./cmp_test

int main(){
    std::cout<<"生成全同态加密方案..."<<std::endl;
    auto fhe = BinFHEContext();
    fhe.GenerateBinFHEContext(STD128, AP);

    // Sample Program: Step 2: Key Generation
    std::cout<<"生成私钥..."<<std::endl;
    // Generate the secret key
    auto sk = fhe.KeyGen();//sk={-1,0,1}^503
//    std::ofstream outputFile("sk.txt");outputFile << sk->GetElement();outputFile.close();
//    std::cout<<"sk->GetLength():"<<sk->GetLength()<<std::endl;

    std::cout << "生成Bootstrapping密钥..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    fhe.BTKeyGen(sk);

    std::cout << "密钥生成完成" << std::endl;

    LWECiphertext LWE_0=fhe.Encrypt(sk, 0);//注意不要进行改动。
    LWECiphertext LWE_1=fhe.Encrypt(sk, 1);

    int data_bits=11;
    int t=1480;
    vector<int> t_bitvector=IntegerToBinaryVector(t,data_bits);
    vector<LWECiphertext> t_LWE_cipher_bitvector(data_bits);
    
    cout<<"t= "<<t_bitvector<<endl;


    for(int i=0;i<data_bits;i++){
        t_LWE_cipher_bitvector[i]=fhe.Encrypt(sk,t_bitvector[i]);
    }

    int m;
    for(int i=1478;i<1483;i++)
    {
        m=i;
        vector<int> m_bitvector=IntegerToBinaryVector(m,data_bits);
    
        //cout<<"m = "<<m_bitvector<<endl;

        LWECiphertext ctResult=greater_or_equal(fhe,m_bitvector,t_LWE_cipher_bitvector,LWE_0,LWE_1);

        WEPlaintext result;//int64_t
        fhe.Decrypt(sk, ctResult, &result);
        std::cout  << "m = "<<m << " t = "<<t << " m>=t 为"<<m<<">="<<t <<"的比较结果为"<<result << endl;
    }

    return 0;
}
