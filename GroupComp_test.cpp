#include<iostream>
#include "binfhecontext.h"
#include "utils.h"
#include "function.h"
using namespace std;
using namespace lbcrypto;
//因为我们估计的叶子节点不多，所以我们打算只设计一串明文和一个密文的比较结果。

std::map<int, LWECiphertext> R1;//头文件只是声明，这里才开始定义全局变量
std::map<int, LWECiphertext> X1;

//g++ -o GroupComp_test GroupComp_test.cpp src/node.cpp src/function.cpp src/utils.cpp -O3 -I./include -I /usr/local/include/openfhe -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/binfhe -I /usr/local/include/openfhe/cereal -L /usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -fopenmp 


int main(){
    cout<<"服务器初始化全同态加密。"<<endl;
    auto fhe = BinFHEContext();
    fhe.GenerateBinFHEContext(STD128, AP);
    std::cout<<"生成私钥..."<<std::endl;
    auto sk = fhe.KeyGen();
    std::cout << "生成Bootstrapping密钥..." << std::endl;
    fhe.BTKeyGen(sk);
    std::cout << "全同态方案生成完成" << std::endl;
    LWECiphertext LWE_0=fhe.Encrypt(sk,0);//生成0的加密
    
    int num_bits = 11; // bit length of the values that will be compared
    int upper_bound = 1 << num_bits; // maximum value
    int n = 5;    // number of plaintexts that will be compared to the ciphertext

    int v=1050;//[1383, 966, 105, 115, 1105, 1279, 1098, 236, 1833, 1229]运行时间很长？？但是没有出错。现在将这个函数整合到main函数中。。
    //对属性v进行加密
    std::vector<int> v_bitvector=IntegerToBinaryVector(v,num_bits);
    std::vector<LWECiphertext> v_LWE_bitvector(num_bits);
    for(int i=0;i<num_bits;i++){
        v_LWE_bitvector[i]=fhe.Encrypt(sk,v_bitvector[i]);
    }
    //随机生成n个属性m
    vector<int> m(n);
    for(int i = 0; i < n; i++){
        m[i] = rand() % upper_bound;
        //2038+i;
    }

    cout<<"m "<<m<<endl;
    //将加密门限值和5个属性值组进行比较。
    int num_and_gates = rec_split_grouped_comp(fhe, v_LWE_bitvector, m,LWE_0);


       for (int i = 0; i < m.size(); i++){
            const LWECiphertext& res = fhe.EvalNOT(R1[m[i]]);//注意，这里只要取反就可以了
            LWEPlaintext dec_comp;
            fhe.Decrypt(sk,res,&dec_comp);

            cout << "dec_comp = " << dec_comp << endl;

            cout << " m[i] >= v = "<<(v <= m[i])<< endl;

        }


    return 0;
}