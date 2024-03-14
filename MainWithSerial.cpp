#include <iostream>
#include <fstream>
#include "client.h"
#include "server.h"
#include "node.h"
#include "utils.h"
#include "function.h"
#include "serial.h"

//g++ -o MainWithSerial MainWithSerial.cpp src/serial.cpp src/utils.cpp src/node.cpp src/function.cpp -O3 -I./include -I /usr/local/include/openfhe -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/binfhe -I /usr/local/include/openfhe/cereal -L /usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -fopenmp 

//./MainWithSerial

using namespace std;

std::map<int, LWECiphertext> R1;//头文件只是声明，这里才开始定义全局变量
std::map<int, LWECiphertext> X1;

int main(){
    cout<<"******************************* step 1: server begin *******************************"<<endl;

    auto start1=clock();
    float run_time;

    cout<<"服务器读取隐私决策树信息"<<endl;
    string address_tree="data/heart_11bits/model.json";
    std::ifstream ifs(address_tree);
    nlohmann::json j = nlohmann::json::parse(ifs);
    auto root = Node(j);
    auto root_original = Node(j);//仅做备份比较
    int data_bits_s=11;
    int t_bits=data_bits_s;//即是数据的最大比特长度，也是门限值的最大比特长度。

    cout<<"服务器打印决策树。"<<endl;
    print_tree(root);
    cout<<"服务器根据决策树设置决策结果的比特长度。"<<endl;
    int class_leaf_bit=bitLength(max_class_leaf_value(root));//这里要看情况的，是否是自己告诉，还是运算出来。但是肯定是服务器要自己做了，因为这里设置为最大也好像没有关系的。
    cout<<"决策结点的比特长度："<<class_leaf_bit<<endl;

    cout<<"服务器初始化全同态加密。"<<endl;
    auto fhe = BinFHEContext();
    fhe.GenerateBinFHEContext(STD128);
    std::cout<<"生成私钥..."<<std::endl;
    auto sk = fhe.KeyGen();//sk作为全同态的私钥，不可发送给别人，但Bootstrapping key和keyswitch key需要发送给客户端，用于执行布尔电路运算。

    std::cout << "生成Bootstrapping密钥..." << std::endl;
    fhe.BTKeyGen(sk);
    std::cout << "全同态方案生成完成" << std::endl;

    std::cout << "计算LWE_0，LWE_1。" << std::endl;
    LWECiphertext LWE_0=fhe.Encrypt(sk, 0);//注意不要进行改动。
    LWECiphertext LWE_1=fhe.Encrypt(sk, 1);

    cout<<"服务器对决策树进行加密并打印加密决策树部分数据。"<<endl;
    enc_tree(root,fhe,sk,t_bits,class_leaf_bit);
    //print_tree(root);
    //cout<<"服务器对决策树进行解密验证。"<<endl;
    //dec_tree(root,fhe,sk,t_bits,class_leaf_bit);
    //cout<<"服务器对决策树进行解密验证结果。"<<endl;
    //print_tree(root);
    run_time = float(clock()-start1)/CLOCKS_PER_SEC;
    std::cout << "服务器完成步骤1的时间为 " << run_time <<" s"<< std::endl;

    cout<<"服务器将全同态默认参数fhe，密态决策树root发送给客户端。"<<endl;
    //fhe,LWE_0,LWE_1,root**********************************************
    //fhe
    const std::string DATAFOLDER = "FHEContext";
    FHE_context_serial(DATAFOLDER,fhe);
    //LWE_0.LWE_1
    FHE_cipher_serial(DATAFOLDER,"LWE_0",LWE_0);
    FHE_cipher_serial(DATAFOLDER,"LWE_1",LWE_1);

    //root
    const string CIPHERTREE="CipherTree";
    cout<<"从tree到json"<<endl;
    json j_cipher;
    build_json_from_tree_with_cipher(root,j_cipher);
    std::ofstream file_j_cipher(CIPHERTREE+"/model_out_cipher.json");
    file_j_cipher << j_cipher << std::endl;
    //tar操作，将这些文件打包起来。然后发送*********************************
    cout<<"******************************* step 1: server end *******************************"<<endl;

    cout<<"******************************* step 2: client begin *******************************"<<endl;
    cout<<"客户端接收到全同态默认参数fhe，密态决策树root。并进行逆序列化"<<endl;
    //tar操作，将文件解打包出来。******************************************
    BinFHEContext cc=FHE_context_deserial(DATAFOLDER);
    fhe=cc;

    LWECiphertext LWE_0_0=FHE_cipher_deserial(DATAFOLDER,"LWE_0");
    LWECiphertext LWE_1_0=FHE_cipher_deserial(DATAFOLDER,"LWE_1");
    LWE_0=LWE_0_0;LWE_1=LWE_1_0;

    cout<<"从json文件到tree"<<endl;
    Node node_j_cipher;
    std::ifstream file_j_cipher_i(CIPHERTREE+"/model_out_cipher.json");   
    nlohmann::json ref_j_cipher = nlohmann::json::parse(file_j_cipher_i);
    build_tree_from_json_with_cipher(ref_j_cipher, node_j_cipher);
    root=node_j_cipher;
    //**********************************************************************
    
    auto start2=clock();

    print_tree(root);

    cout<<"客户端读取隐私数据"<<endl;
    string address="data/heart_11bits/x_test.csv";
    int data_m=2;//读取的行数//
    //int data_m;cout<<"请输入读取数据行数\n\n\n"<<endl;cin>>data_m;//输入data_m=1报错？？？后面再改
    int data_bits=11;//属性的比特长度
    std::vector<std::vector<int>> client_data=read_csv_to_vector(address,data_bits,data_m);
    int data_n=client_data[0].size();//每一行属性的个数

    cout<<"客户端打印文件，测试是否正确读取"<<endl;
    print_data(client_data);

    cout<<"客户端进行隐私决策树评估.."<<endl;
    vector<vector<LWECiphertext>> expect_result;
    if(data_m==1){
        expect_result=pdte(root,client_data,data_bits,data_m,fhe,LWE_0,LWE_1);
    }else{
        expect_result=General_pdte(root,client_data,data_bits,data_m,fhe,LWE_0,LWE_1);//这个pdte这个函数十分重要。
    }
    run_time = float(clock()-start2)/CLOCKS_PER_SEC;
    std::cout << "客户端评估"<< data_m <<"行数据以完成步骤2的时间为 " << run_time <<" s"<< std::endl;

    cout << "客户端向服务器发送比较结果的密文"<<endl;
    //***********************************************************
    result_serial(expect_result,"CipherResult/Result.json");
    //***********************************************************
    cout<<"*******************************ste 2: client end*******************************"<<endl;

    cout<<"*******************************step 3: server begin *******************************"<<endl;

    cout << "服务器接收到比较结果的密文"<<endl;
    //***********************************************************
    std::vector<std::vector<LWECiphertext>> expect_result2;
    expect_result2=result_deserial("CipherResult/Result.json");
    expect_result=expect_result2;
    //***********************************************************

    auto start3=clock();

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

    run_time = float(clock()-start3)/CLOCKS_PER_SEC;
    std::cout << "服务器完成步骤3的时间为 " << run_time << " s"<<std::endl;
    
    run_time = float(clock()-start1)/CLOCKS_PER_SEC;
    std::cout << "总的评估过程的运行时间为 " << run_time <<" s"<< std::endl;

    cout<<"*******************************step 3: server end*******************************"<<endl;

    return 0;
}
