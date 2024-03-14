#ifndef __UTILS__
#define __UTILS__

#include <vector>
#include <iostream> 
#include <random>

void swap(std::vector<int>& v, int i, int j);

//由低位到高位合成
int BinaryVectorTointeger(const std::vector<int>& bits);

//由低到高位
std::vector<int> IntegerToBinaryVector(int num, int num_bits); 

//返回num的比特长度
int bitLength(int num);

template <typename T>
std::ostream& operator<< (std::ostream &out, std::vector<T> & u) {
    if (0 == u.size())
        return out << "[ ]";
        
    std::cout << "[";
    for (long i = 0; i < u.size()-1; i++)
        out << u[i] << ", ";
    out << u[u.size()-1] << "]";
    return out;
}




#endif