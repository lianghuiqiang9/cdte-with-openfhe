#include "node.h"
#include "utils.h"
#include <iostream>


//g++ -o node_test node_test.cpp src/utils.cpp src/node.cpp -I ./include -I /usr/local/include/openfhe -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/binfhe -I /usr/local/include/openfhe/cereal -L /usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -fopenmp && ./node_test


using namespace std;

int main(){
    string address="data/heart_11bits/model.json";

    auto root=Node(address);
    print_node(root);
    print_tree(root);
    int t_bitLength=11;
    int class_leaf_bit=bitLength(max_class_leaf_value(root));

    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, AP);
    std::cout<<"生成私钥..."<<std::endl;
    auto sk = cc.KeyGen();
    std::cout << "生成Bootstrapping密钥..." << std::endl;
    cc.BTKeyGen(sk);
    std::cout << "全同态方案生成完成" << std::endl;

    cout<<"对决策树的节点进行加密, 并且明文门限赋值0"<<endl;
    enc_tree(root,cc,sk,t_bitLength,class_leaf_bit);

    print_tree(root);

    cout<<"对决策树的节点进行解密，并且赋值到对应门限"<<endl;
    dec_tree(root,cc,sk,t_bitLength,class_leaf_bit);

    print_tree(root);

    cout<<"测试gen_with_depth函数"<<endl;
    root.gen_with_depth(2);

    print_tree(root);

    cout<<"测试max_index函数"<<endl;
    int max_index=max_feature_index(root);

    cout<<"max_index= "<<max_index<<endl;

    return 0;

}

