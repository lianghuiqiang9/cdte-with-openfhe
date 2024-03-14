
#include "function.h"

using namespace std;
using namespace lbcrypto;

//返回的ENC(m<t)
LWECiphertext less_than(const BinFHEContext &fhe, const vector<int>& m, const vector<LWECiphertext>& t, const LWECiphertext& LWE_0, const LWECiphertext& LWE_1)
{
    int num_bits = t.size();
    vector<int> not_m(num_bits);
    //m[i]\in {0,1} 所以1-m[i] \in {0,1}这个步骤为not gate
    for(int i = 0; i < num_bits; i++)
        not_m[i] = 1 - m[i];

    LWECiphertext res, tmp, x;
    x=LWE_1;

    //对最高位处理xnor 
    if (1 == not_m[num_bits-1]){
        res = t[num_bits-1];
    }else{
        res=LWE_0;
    }

    //对次高位处理
    for(int i = num_bits-2; i >= 0; i--){
        // compute tmp = x_{i+1} := v[i+1]*c[i+1] + not(v[i+1]) * not(c[i+1]) \in {0,1}
        if (m[i+1]){
            tmp = t[i+1];
        }else{
            tmp=fhe.EvalNOT(t[i+1]);
        }        
        // update x = x_{num_bits} * x_{num_bits-1} * ... * x_i
        x=fhe.EvalBinGate(AND,x,tmp);
        if (not_m[i]){
            // tmp = x * c[i]
            tmp=fhe.EvalBinGate(AND,x,t[i]);
            //res = (res + tmp);1 0=1, 0 0=0, 0 1=1 无 1 1=
            res=fhe.EvalBinGate(OR,res,tmp);
        }
    }
    return res;
}

//输入的是m的二进制向量，t的二进制密文。返回的ENC(m>=t)
LWECiphertext greater_or_equal(const BinFHEContext &fhe, const vector<int>& m, const vector<LWECiphertext>& t,const LWECiphertext& LWE_0, const LWECiphertext& LWE_1)
{
    //auto start=clock();
    //float run_time;

    LWECiphertext res = less_than(fhe, m, t,LWE_0,LWE_1);
    res=fhe.EvalNOT(res);

    //run_time = float(clock()-start)/CLOCKS_PER_SEC;
    //cout << "greater_or_equal run_time = " << run_time << endl;

    return res;
}

//补充算法其他







// Assume that the control bit of each internal node is already set
void traverse_rec(vector<LWECiphertext>& out, Node& node, const BinFHEContext& fhe){
    //cout<<"进入到traverse_rec"<<endl;
    LWECiphertext& parent = node.value;//函数内的操作，必须是门电路，否则会有溢出的风险。导致结果不正确。//b.应该为1的//cout<<"parent的解密结果为="<<fhe.decrypt(node.value)<<endl;
    
    if (node.is_leaf()) {
        //out = leaf_bits * parent + out;
        for(int i=0;i<node.LWECipher_class_leaf.size();i++){
            //0*0=0,0*1=0,1*0=0,1*1=1 AND
            LWECiphertext temp=fhe.EvalBinGate(AND,node.LWECipher_class_leaf[i],parent);
            out[i]=fhe.EvalBinGate(OR,out[i],temp);
        }
    }else{
        //cout<<"node.control_bit"<<node.control_bit->GetA()<<endl;
        node.right->value= fhe.EvalBinGate(AND,parent,node.control_bit);
        node.left->value=fhe.EvalNOT(node.right->value);

        node.left->value=fhe.EvalBinGate(AND,parent,node.left->value);
        traverse_rec(out, *(node.left), fhe);
        traverse_rec(out, *(node.right), fhe);
    }
}

void traverse(vector<LWECiphertext>& out, Node& node, const BinFHEContext& fhe,LWECiphertext& LWE_0,LWECiphertext& LWE_1){
        for(auto &e:out){
            e=LWE_0;
        }
        node.value=LWE_1;
        //cout<<"进入到traverse"<<endl;
        //进入到traveral前 out必须为0，parent 必须为1的加密
        traverse_rec(out, node, fhe);
}

//逐次将control_bit_vector的值复制到control中
void copy_control_bit_from_control_bit_vector(Node& node,int i){
    if (!node.is_leaf()) {
        node.control_bit=node.control_bit_vector[i];
        copy_control_bit_from_control_bit_vector(*(node.left),i);//你这里递归都能忘记访问叶子结点。
        copy_control_bit_from_control_bit_vector(*(node.right),i);
    }
}

vector<vector<LWECiphertext>> pdte(Node &root, std::vector<std::vector<int>> &client_data,int data_bits,int data_m, const BinFHEContext& fhe,  LWECiphertext& LWE_0,LWECiphertext& LWE_1){
    
    int class_leaf_bit=max_class_leaf_value_cipher_bit(root);//这里要看情况的，是否是自己告诉，还是运算出来。但是肯定是服务器要自己做了，因为这里设置为最大也好像没有关系的。//cout<<"* class_leaf_bit "<<class_leaf_bit<<endl;
    
    vector< vector<Node*> > nodes_by_feat = nodes_by_feature(root);//将结点进行排序，行为对应属性向量的位置(到最大index)，列为对应这个位置的结点
    int num_features = nodes_by_feat.size();
    std::vector< std::vector< vector< LWECiphertext > > > thrs_by_feat = thresholds_bitcipher_by_feature(nodes_by_feat);//按照刚才所做的，抽取其对应的密文门限值的密文向量。

    //现在进行同态遍历
    vector<vector<LWECiphertext>> expect_result(data_m);

    for(int i=0;i<data_m;i++){

        cout << "第 "<<i+1<<" 行数据正在评估中.."<<endl;
        auto start_i=clock();

        for(int j=0;j<num_features;j++){
            vector< vector< LWECiphertext > > t=thrs_by_feat[j];//抽取对应index的门限，因为可能不止一个，所以是二维向量。
            int n=t.size();
            if(0==n)
                continue;

            vector<int> m=IntegerToBinaryVector(client_data[i][j],data_bits);//抽取对应index的data，变为二进制向量。
        
            auto start=clock();
            float run_time;

            //找到了对应的index的Node
            vector<Node*>& nodes=nodes_by_feat[j];

            //对每一个决策结点，分别进行比较。然后将比较结果存储到该结点中。
            for(int k=0;k<n;k++){
                LWECiphertext enc_cmp=greater_or_equal(fhe,m,t[k],LWE_0,LWE_1);
                nodes[k]->control_bit=enc_cmp;
                run_time = float(clock()-start)/CLOCKS_PER_SEC;
            }

            cout << "属性在["<<j<<"] 上的同态比较 " << n    
            << " 个整数在 " << data_bits << " 比特上。运行时间为 " << run_time <<" s"<< endl;
        }
        //cout<<"i "<<i<<" class_leaf_bit "<<class_leaf_bit<<endl;
        vector<LWECiphertext> out(class_leaf_bit);//1是class_leaf的最大bit长度
        auto start = clock();
        traverse(out,root,fhe,LWE_0,LWE_1);
        expect_result[i]=out;
        float run_time = float(clock()-start)/CLOCKS_PER_SEC;
        cout << "第 "<<i+1<<" 行数据同态遍历的时间为: " << run_time <<" s"<< endl;

        float run_time_i = float(clock()-start_i)/CLOCKS_PER_SEC;
        cout << "第 "<<i+1<<" 行数据总的评估时间为: " << run_time_i <<" s"<< endl;
    }

    return expect_result;
}

const LWECiphertext& xnor(const LWECiphertext& a, const LWECiphertext& not_a, int b){
    if (b)
        return a;
    return not_a;
}

int grouped_comp(const BinFHEContext& fhe, const vector<LWECiphertext>& v_LWE_bitvector, const vector<int>& m,LWECiphertext& LWE_0)
{
    int vbits=v_LWE_bitvector.size();
    LWECiphertext zero=LWE_0;
    LWECiphertext tmp;
    //计算v的not_v
    vector<LWECiphertext> not_v_LWE_bitvector(vbits);
    for(int i=0;i<vbits;i++){
        not_v_LWE_bitvector[i]=fhe.EvalNOT(v_LWE_bitvector[i]);
    }

    R1 = {
            {0, v_LWE_bitvector[vbits-1] },
            {1, zero }
        };
    X1 = {
            {0, not_v_LWE_bitvector[vbits-1] },
            {1, v_LWE_bitvector[vbits-1] }    
        };

        int num_and_gates = 0;
    int k = vbits-2;
    while (k >= 0){
        std::map<int, LWECiphertext> R;
        std::map<int, LWECiphertext> X;
        for(int i = 0; i < m.size(); i++){
            int vk = m[i] >> k; // nbits-k most significant bits of m[i]
            int vk1 = m[i] >> (k+1); // nbits-k+1 most significant bits of m[i]
            int kth_bit = vk % 2; // k-th bit of m[i]
            if (0 == X.count(vk)){
                X[vk]=fhe.EvalBinGate(AND,xnor(v_LWE_bitvector[k], not_v_LWE_bitvector[k], kth_bit),X1[vk1]);

                // now compute R[vk] = R1[vk1] + X1[vk1] * (1-kth_bit) * bits_m[k] 
                if (kth_bit){
                    R[vk] = R1[vk1];
                    num_and_gates += 1;
                }else{
                    tmp=fhe.EvalBinGate(AND,X1[vk1],v_LWE_bitvector[k]);
                    R[vk]=fhe.EvalBinGate(OR,tmp,R1[vk1]);
                    //R[vk] = tmp + R1[vk1];//OR
                    num_and_gates += 2;
                }
            }
        }
        X1 = X;
        R1 = R;
        k -= 1;
    }
    return num_and_gates;
}
//输入ENC(v_i),i=1...\mu, 和m_1,m_2,...,m_n.
//输出R1=ENC(m_j>=v_i),j=1,...,n
int rec_split_grouped_comp(const BinFHEContext& fhe, const vector<LWECiphertext>& v_LWE_bitvector, const vector<int>& m,LWECiphertext& LWE_0, bool compX)
{
    int vbits=v_LWE_bitvector.size();//v的比特长度，这里是11
    //m=50
    if(vbits<=log(m.size())/log(2)){
        return grouped_comp(fhe,v_LWE_bitvector,m,LWE_0);
    }
    int k = floor(vbits / 2);
    int two_to_k = 1 << k;
    vector<LWECiphertext> lsb_v(k);
    vector<LWECiphertext> msb_v(vbits - k);

    for(int i = 0; i < k; i++)
        lsb_v[i] = v_LWE_bitvector[i];
    for(int i = 0; i < vbits-k; i++)
        msb_v[i] = v_LWE_bitvector[k + i];

    vector<int> lsb_m(m.size());
    vector<int> msb_m(m.size());
    for(int i = 0; i < m.size(); i++)
        lsb_m[i] = m[i] % two_to_k;
    for(int i = 0; i < m.size(); i++)
        msb_m[i] = m[i] >> k;
    int msb_num_ands = rec_split_grouped_comp(fhe, msb_v, msb_m, LWE_0);
    auto msbR = R1;
    auto msbX = X1;
    int lsb_num_ands = rec_split_grouped_comp(fhe, lsb_v, lsb_m, LWE_0);
    auto lsbR = R1;
    auto lsbX = X1;

    std::map<int, LWECiphertext> R;
    std::map<int, LWECiphertext> X;
    LWECiphertext tmp;

    int num_ands_X = 0;

    for(int i = 0; i < m.size(); i++){
        int mi = m[i];
        int msb_mi = msb_m[i];
        int lsb_mi = lsb_m[i];

        if (0 == X.count(mi)){
            // R[vi] = msbR[ msb_vi ] + msbX[ msb_vi ] and lsbR[ lsb_vi ]
            tmp=fhe.EvalBinGate(AND,msbX[ msb_mi ], lsbR[ lsb_mi ]);
            R[mi] = fhe.EvalBinGate(OR,msbR[ msb_mi ],tmp);
            num_ands_X += 1;
            if(compX){
                //X[vi] = msbX[ msb_vi ] and lsbX[ lsb_vi ]
                X[mi]=fhe.EvalBinGate(AND,msbX[ msb_mi ], lsbX[ lsb_mi ]);
                num_ands_X += 1;
            }
        }
    }
    int total_gates = msb_num_ands + lsb_num_ands + num_ands_X;
    R1 = R;//这里更新了全局的R1
    X1 = X;
    return total_gates;

}

//std::map<int, LWECiphertext> R1;
//std::map<int, LWECiphertext> X1;
//int split_grouped_comp(std::map<int, LWECiphertext> &R1,std::map<int, LWECiphertext> &X1, const BinFHEContext& fhe, const vector<LWECiphertext>& v_LWE_bitvector, const vector<int>& m,LWECiphertext& LWE_0, bool compX){
//
//
//}

vector<vector<LWECiphertext>> General_pdte(Node &root, std::vector<std::vector<int>> &client_data,int data_bits,int data_m, const BinFHEContext& fhe,  LWECiphertext& LWE_0,LWECiphertext& LWE_1){
    
    int class_leaf_bit=max_class_leaf_value_cipher_bit(root);//这里要看情况的，是否是自己告诉，还是运算出来。但是肯定是服务器要自己做了，因为这里设置为最大也好像没有关系的。//cout<<"* class_leaf_bit "<<class_leaf_bit<<endl;
    
    vector< vector<Node*> > nodes_by_feat = nodes_by_feature(root);//将结点进行排序，行为对应属性向量的位置(到最大index)，列为对应这个位置的结点
    int num_features = nodes_by_feat.size();
    std::vector< std::vector< vector< LWECiphertext > > > thrs_by_feat = thresholds_bitcipher_by_feature(nodes_by_feat);//按照刚才所做的，抽取其对应的密文门限值的密文向量。

    //现在进行同态遍历
    vector<vector<LWECiphertext>> expect_result(data_m);

    auto start_i=clock();

        for(int j=0;j<num_features;j++){
            vector< vector< LWECiphertext > > t=thrs_by_feat[j];//抽取对应index的门限，因为可能不止一个，所以是二维向量。
            int n=t.size();
            if(0==n)
                continue;
            cout << "第 "<<j<<" 位数据正在评估中.."<<endl;
            vector<int> m(data_m);
            for(int _i=0;_i<data_m;_i++){
                m[_i]=client_data[_i][j];
            }

            auto start=clock();
            float run_time;

            //找到了对应的index的Node
            vector<Node*>& nodes=nodes_by_feat[j];

            //对每一个决策结点，分别进行比较。然后将比较结果存储到该结点中。
            for(int k=0;k<n;k++){
                //LWECiphertext enc_cmp=greater_or_equal(fhe,m,t[k],LWE_0,LWE_1);
                int num_and_gates = rec_split_grouped_comp(fhe, t[k], m,LWE_0);
                //R1和X1需不需要清空呢？？不需要
                vector<LWECiphertext> enc_cmp(data_m);
                for(int l=0;l<data_m;l++){
                    enc_cmp[l]= fhe.EvalNOT(R1[m[l]]);
                }
                nodes[k]->control_bit_vector=enc_cmp;
                //cout<<nodes[k]->control_bit_vector<<endl;
                run_time = float(clock()-start)/CLOCKS_PER_SEC;
            }

            cout << "属性在["<<j<<"] 上的同态比较 " << data_m    
            << " 个整数在 " << data_bits << " 比特上。运行时间为 " << run_time <<" s"<< endl;
        }

    float run_time_i = float(clock()-start_i)/CLOCKS_PER_SEC;
    cout << "数据总的评估时间为: " << run_time_i <<" s"<< endl;

    for(int i=0;i<data_m;i++){
        vector<LWECiphertext> out(class_leaf_bit);//1是class_leaf的最大bit长度
        auto start = clock();
        copy_control_bit_from_control_bit_vector(root,i);//如果优化掉，也会增加运行内存。
        traverse(out,root,fhe,LWE_0,LWE_1);
        expect_result[i]=out;
        float run_time = float(clock()-start)/CLOCKS_PER_SEC;
        cout << "第 "<<i+1<<" 行数据同态遍历的时间为: " << run_time <<" s"<< endl;
    }

    return expect_result;

}