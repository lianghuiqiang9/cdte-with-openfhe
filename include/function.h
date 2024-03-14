#ifndef __FUNCTION_COMP__
#define __FUNCTION_COMP__

#include "binfhecontext.h"
#include "utils.h"
#include "node.h"

using namespace std;
using namespace lbcrypto;
//头文件只是声明全局变量。
extern std::map<int, LWECiphertext> R1;
extern std::map<int, LWECiphertext> X1;

//返回的ENC(m<t)
LWECiphertext less_than(const BinFHEContext &fhe, const vector<int>& m, const vector<LWECiphertext>& t, const LWECiphertext& LWE_0, const LWECiphertext& LWE_1);

//返回的ENC(m>=t)
LWECiphertext greater_or_equal(const BinFHEContext &fhe, const vector<int>& m, const vector<LWECiphertext>& t,const LWECiphertext& LWE_0, const LWECiphertext& LWE_1);


void traverse_rec(vector<LWECiphertext>& out, Node& node, const BinFHEContext& fhe);
void traverse(vector<LWECiphertext>& out, Node& node, const BinFHEContext& fhe,LWECiphertext& LWE_0,LWECiphertext& LWE_1);

vector<vector<LWECiphertext>> pdte(Node &root, std::vector<std::vector<int>> &client_data,int data_bits,int data_m, const BinFHEContext& fhe,  LWECiphertext& LWE_0,LWECiphertext& LWE_1);

const LWECiphertext& xnor(const LWECiphertext& a, const LWECiphertext& not_a, int b);
int grouped_comp(const BinFHEContext& fhe, const vector<LWECiphertext>& v_LWE_bitvector, const vector<int>& m,LWECiphertext& LWE_0);
int rec_split_grouped_comp(const BinFHEContext& fhe, const vector<LWECiphertext>& v_LWE_bitvector, const vector<int>& m,LWECiphertext& LWE_0, bool compX = true);

vector<vector<LWECiphertext>> General_pdte(Node &root, std::vector<std::vector<int>> &client_data,int data_bits,int data_m, const BinFHEContext& fhe,  LWECiphertext& LWE_0,LWECiphertext& LWE_1);
#endif