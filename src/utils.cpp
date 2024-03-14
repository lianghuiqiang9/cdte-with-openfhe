#include "utils.h"

using namespace std;

void swap(vector<int>& v, int i, int j)
{
    int tmp = v[i];
    v[i] = v[j];
    v[j] = tmp;
}

//template std::ostream& operator<< (std::ostream &out, std::vector<T> & u)

//由低位到高位合成
int BinaryVectorTointeger(const std::vector<int>& bits)
{
    int pow2 = 1;
    int res = 0;
    for (int i = 0; i < bits.size(); i++){
        res += bits[i] * pow2;
        pow2 <<=1;
    }
    return res;
}

//由低到高位
std::vector<int> IntegerToBinaryVector(int num, int num_bits) {
    std::vector<int> binaryVector(num_bits);
        for(int i = 0; i < num_bits; i++){
        binaryVector[i] = num & 1;
        num >>= 1;
    }
    return binaryVector;
}

int bitLength(int num) {
    int length = 0;
    while (num > 0) {
        num >>= 1; // 将数字右移一位
        length++;
    }
    return length;
}
