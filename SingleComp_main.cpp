#include <iostream>
#include <fstream>
#include "client.h"
#include "server.h"
#include "node.h"
#include "utils.h"
#include "function.h"

//g++ -o SingleComp_main SingleComp_main.cpp src/utils.cpp src/node.cpp src/function.cpp -O3 -I./include -I /usr/local/include/openfhe -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/binfhe -I /usr/local/include/openfhe/cereal -L /usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -fopenmp 

//./SingleComp_main

std::map<int, LWECiphertext> R1;//SingleComp_main中没有用到全局变量，仅仅为了编译通过
std::map<int, LWECiphertext> X1;

using namespace std;

int main(){
    cout<<"******************************* step 1: server begin *******************************"<<endl;

    auto start1=clock();
    auto start=clock();
    float run_time;

    cout<<"服务器读取隐私决策树信息"<<endl;
    string address_tree="data/heart_11bits/model.json";//"data/heart_11bits/model.json";
    int data_bits_s=11;//11

    std::ifstream ifs(address_tree);
    nlohmann::json j = nlohmann::json::parse(ifs);
    auto root = Node(j);
    auto root_original = Node(j);//仅做备份比较

    int t_bits=data_bits_s;//即是数据的最大比特长度，也是门限值的最大比特长度。

    cout<<"服务器打印决策树。"<<endl;
    print_tree(root);
    cout<<"服务器根据决策树设置决策结果的比特长度。"<<endl;
    int class_leaf_bit=bitLength(max_class_leaf_value(root));//这里要看情况的，是否是自己告诉，还是运算出来。但是肯定是服务器要自己做了，因为这里设置为最大也好像没有关系的。
    cout<<"决策结点的比特长度："<<class_leaf_bit<<endl;

    cout<<"服务器初始化全同态加密。"<<endl;
    auto fhe = BinFHEContext();
    fhe.GenerateBinFHEContext(STD128, AP);
    std::cout<<"生成私钥..."<<std::endl;
    auto sk = fhe.KeyGen();//sk作为全同态的私钥，不可发送给别人，但Bootstrapping key和keyswitch key需要发送给客户端，用于执行布尔电路运算。

    std::cout << "生成Bootstrapping密钥..." << std::endl;
    fhe.BTKeyGen(sk);
    std::cout << "全同态方案生成完成，时间为" << float(clock()-start)/CLOCKS_PER_SEC <<" s"<< std::endl;

    std::cout << "计算LWE_0，LWE_1。" << std::endl;
    LWECiphertext LWE_0=fhe.Encrypt(sk, 0);//注意不要进行改动。
    LWECiphertext LWE_1=fhe.Encrypt(sk, 1);

    start=clock();
    cout<<"服务器对决策树进行加密并打印加密决策树部分数据。"<<endl;
    enc_tree(root,fhe,sk,t_bits,class_leaf_bit);
    //print_tree(root);
    //cout<<"服务器对决策树进行解密验证。"<<endl;
    //dec_tree(root,fhe,sk,t_bits,class_leaf_bit);
    //cout<<"服务器对决策树进行解密验证结果。"<<endl;
    //print_tree(root);
    cout<<"服务器对决策树进行加密并打印加密决策树部分数据时间为 "<<float(clock()-start)/CLOCKS_PER_SEC <<" s"<< std::endl;
    
    std::cout << "服务器完成步骤1的时间为 " << float(clock()-start1)/CLOCKS_PER_SEC <<" s"<< std::endl;

    cout<<"服务器将全同态默认参数fhe，密态决策树root发送给客户端。"<<endl;
    //fhe,LWE_0,LWE_1,root
    cout<<"******************************* step 1: server end *******************************"<<endl;

    cout<<"******************************* step 2: client begin *******************************"<<endl;
    cout<<"客户端接收到全同态默认参数fhe，密态决策树root。并进行逆序列化"<<endl;
    start=clock();

    print_tree(root);

    cout<<"客户端读取隐私数据"<<endl;
    string address="data/electricity_10bits/x_test.csv";//"data/heart_11bits/model.json";
    int data_bits=data_bits_s;//11
    
    int data_m=5;//读取的行数
    //int data_m;cout<<"请输入读取数据行数"<<endl;cin>>data_m;
    std::vector<std::vector<int>> client_data=read_csv_to_vector(address,data_bits,data_m);
    int data_n=client_data[0].size();//每一行属性的个数

    cout<<"客户端打印文件，测试是否正确读取"<<endl;
    print_data(client_data);

    cout<<"客户端进行隐私决策树评估.."<<endl;
    vector<vector<LWECiphertext>> expect_result;
    
    expect_result=pdte(root,client_data,data_bits,data_m,fhe,LWE_0,LWE_1);//这个pdte这个函数十分重要。

    run_time = float(clock()-start)/CLOCKS_PER_SEC;
    std::cout << "客户端评估"<< data_m <<"行数据以完成步骤2的时间为 " << run_time <<" s"<< std::endl;

    cout << "客户端向服务器发送比较结果的密文"<<endl;
    //expect_result 二维LWECiphertext
    cout<<"*******************************ste 2: client end*******************************"<<endl;

    cout<<"*******************************step 3: server begin *******************************"<<endl;

    cout << "服务器接收到比较结果的密文"<<endl;

    start=clock();

    cout << "服务器解密并进行验证"<<endl;
    vector<int> pdte_result(data_m);
    for(int i=0;i<expect_result.size();i++){

        //服务器对expect_result进行解密
        vector<int> expect_result_bits(expect_result[i].size());
        for(int k=0;k<expect_result_bits.size();k++){
            LWEPlaintext result;
            fhe.Decrypt(sk,expect_result[i][k],&result);
            expect_result_bits[k]=result;
        }
        int expect_result_i=BinaryVectorTointeger(expect_result_bits);
        pdte_result[i]=expect_result_i;

        //服务器进行正确性检验
        std::vector<unsigned int> pf(client_data[i].size());
        for(int k=0;k<pf.size();k++){
            pf[k]=client_data[i][k];
        }

        int actural_result=root_original.eval(pf);
        cout<<"第 "<<i+1<<" 行数据的预期结果明文 "<<pdte_result[i]<<" 实际结果明文 "<<actural_result<<" 比较结果 "<<(expect_result_i==actural_result)<<endl;
    }

    run_time = float(clock()-start)/CLOCKS_PER_SEC;
    std::cout << "服务器完成步骤3的时间为 " << run_time << " s"<<std::endl;
    
    run_time = float(clock()-start1)/CLOCKS_PER_SEC;
    std::cout << "总的评估过程的运行时间为 " << run_time <<" s"<< std::endl;

    cout<<"*******************************step 3: server end*******************************"<<endl;

    return 0;
}

/*
*******************************hello server*******************************
服务器读取隐私决策树信息
服务器打印决策树。
                 (class: 0)
         (f: 7, t: 1746)
                 (class: 1)
 (f: 8, t: 1944)
                 (class: 1)
         (f: 10, t: 1954)
                         (class: 1)
                 (f: 4, t: 1633)
                         (class: 0)
服务器根据决策树设置决策结果的比特长度。
决策结点的比特长度：1
run_time = 0.000299
服务器初始化全同态加密。
生成私钥...
生成Bootstrapping密钥...
全同态方案生成完成
计算LWE_0,LWE_1
run_time = 29.1853
服务器对决策树进行加密并打印加密决策树部分数据。
run_time = 29.1894
服务器将全同态默认参数fhe，密态决策树root发送给客户端。
*******************************server end*******************************
*******************************hello client*******************************
客户端接收到全同态默认参数fhe，密态决策树root。并进行逆序列化
                 (class: 0)
         (f: 7, t: 0)
                 (class: 0)
 (f: 8, t: 0)
                 (class: 0)
         (f: 10, t: 0)
                         (class: 0)
                 (f: 4, t: 0)
                         (class: 0)
客户端读取隐私数据
请输入读取数据行数
3
run_time = 29.1897
客户端打印文件，测试是否正确读取
701 2047 2047 1361 605 1842 1861 1445 1842 819 2047 0 0 
1078 0 683 1263 980 1842 1675 1341 1842 0 0 0 0 
754 2047 683 1263 692 1842 1675 1705 1842 0 0 0 0 
客户端进行隐私决策树评估
进入第 1 行数据
属性在[4] 上的同态比较 1 个整数在 11 比特上。run_time = 6.84585
属性在[7] 上的同态比较 1 个整数在 11 比特上。run_time = 7.6424
属性在[8] 上的同态比较 1 个整数在 11 比特上。run_time = 10.5009
属性在[10] 上的同态比较 1 个整数在 11 比特上。run_time = 3.81527
第 1行数据同态遍历的时间为: 6.80834
进入第 2 行数据
属性在[4] 上的同态比较 1 个整数在 11 比特上。run_time = 6.85517
属性在[7] 上的同态比较 1 个整数在 11 比特上。run_time = 6.848
属性在[8] 上的同态比较 1 个整数在 11 比特上。run_time = 7.56377
属性在[10] 上的同态比较 1 个整数在 11 比特上。run_time = 11.3953
第 2行数据同态遍历的时间为: 6.83987
进入第 3 行数据
属性在[4] 上的同态比较 1 个整数在 11 比特上。run_time = 7.7514
属性在[7] 上的同态比较 1 个整数在 11 比特上。run_time = 7.5976
属性在[8] 上的同态比较 1 个整数在 11 比特上。run_time = 7.71351
属性在[10] 上的同态比较 1 个整数在 11 比特上。run_time = 12.7708
第 3行数据同态遍历的时间为: 6.85273
run_time = 146.992
客户端向服务器发送比较结果的密文
*******************************client end*******************************
*******************************hello server*******************************
服务器接收到比较结果的密文
服务器解密并进行验证
服务器解密expect_result并且验证
第 1行数据的预期结果明文 1 实际结果明文 1比较结果 1
第 2行数据的预期结果明文 0 实际结果明文 0比较结果 1
第 3行数据的预期结果明文 0 实际结果明文 0比较结果 1
**************************** run_time = 146.992
*******************************server end*******************************
*/


/*
                                                                                 (class: 0)
                                                                         (f: 7, t: 0)
                                                                                 (class: 0)
                                         (f: 2, t: 0)
                                                         (class: 0)
                                                 (f: 6, t: 0)
                                                         (class: 0)
客户端读取隐私数据
请输入读取数据行数
1
客户端打印文件，测试是否正确读取
480 341 239 47 368 3 382 569 
客户端进行隐私决策树评估..
第 1 行数据正在评估中..
属性在[0] 上的同态比较 118 个整数在 10 比特上。运行时间为 979.62 s
属性在[1] 上的同态比较 79 个整数在 10 比特上。运行时间为 509.039 s
属性在[2] 上的同态比较 79 个整数在 10 比特上。运行时间为 394.183 s
属性在[3] 上的同态比较 97 个整数在 10 比特上。运行时间为 624.766 s
属性在[4] 上的同态比较 101 个整数在 10 比特上。运行时间为 727.481 s
属性在[5] 上的同态比较 5 个整数在 10 比特上。运行时间为 43.7575 s
属性在[6] 上的同态比较 34 个整数在 10 比特上。运行时间为 167.836 s
属性在[7] 上的同态比较 40 个整数在 10 比特上。运行时间为 289.005 s
第 1 行数据同态遍历的时间为: 840.911 s
第 1 行数据总的评估时间为: 4576.6 s
客户端评估1行数据以完成步骤2的时间为 4576.62 s
客户端向服务器发送比较结果的密文
*******************************ste 2: client end*******************************
*******************************step 3: server begin *******************************
服务器接收到比较结果的密文
服务器解密并进行验证
第 1 行数据的预期结果明文 0 实际结果明文 0 比较结果 1
服务器完成步骤3的时间为 0.000127 s
总的评估过程的运行时间为 4606.27 s
*******************************step 3: server end*******************************
*/