#include "node.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;


void print_node(Node& a, string tabs){
    if (a.is_leaf()){
       cout << tabs << "(class: " << a.class_leaf << ")" << endl; 
    }else{
        cout << tabs
            << "(f: " << a.feature_index 
            << ", t: " << a.threshold
            << ")" << endl; 
    }
}

void print(std::shared_ptr<Node> a, string tabs) {
    if (a->is_leaf()){
       print_node(*a, tabs);
    }else{
        print(a->right, tabs + "        ");
        print_node(*a, tabs);
        print(a->left, tabs + "        ");
    }
}

void print_tree(Node& a) {
    std::shared_ptr<Node> tmp_a = std::make_shared<Node>(a);
    print(tmp_a, " ");
}

void build_tree_from_json(json::reference ref, Node& node) {
    if (!ref["leaf"].is_null()) {
        node.class_leaf = ref["leaf"].get<Leaf>();
        node.left = nullptr;
        node.right = nullptr;
    } else {
        node.threshold = ref["internal"]["threshold"].get<unsigned>();
        node.feature_index = ref["internal"]["feature"].get<unsigned>();
        node.op = ref["internal"]["op"].get<std::string>();
        node.class_leaf = -1;

        node.left = std::make_shared<Node>();
        node.right = std::make_shared<Node>();
        build_tree_from_json(ref["internal"]["left"], *node.left);
        build_tree_from_json(ref["internal"]["right"], *node.right);
    }
}

Node::Node(json::reference j) {
    build_tree_from_json(j, *this);
}

Node::Node(std::string filename) {
    std::ifstream file(filename);
    nlohmann::json ref = nlohmann::json::parse(file);
    build_tree_from_json(ref, *this);
}

bool Node::is_leaf() const {
    return this->left == nullptr && this->right == nullptr;
}

void Node::gen_with_depth(int d) {
    if (d == 0) {
        this->class_leaf = 0;
        this->left = nullptr;
        this->right = nullptr;
        return;
    }
    this->class_leaf = -1;
    (*this->left).gen_with_depth(d-1);
    (*this->right).gen_with_depth(d-1);
}

unsigned Node::get_depth() {
    if (this->is_leaf()) {
        return 0;
    } else {
        auto l = this->left->get_depth();
        auto r = this->right->get_depth();
        if (l > r) {
            return l + 1;
        } else {
            return r + 1;
        }
    }
}

void eval_rec(unsigned &out, const Node& node, const std::vector<unsigned int> &features, unsigned parent) {
    if (node.is_leaf()) {
        out += node.class_leaf * parent;
    }else{
        if (node.op == "leq") {
            if (features[node.feature_index] < node.threshold) {
                eval_rec(out, *node.left, features, parent);
                eval_rec(out, *node.right, features, parent*(1-parent));
            } else {
                eval_rec(out, *node.left, features, parent*(1-parent));
                eval_rec(out, *node.right, features, parent);
            }
        } else {
            // unimplemented
            assert(false);
        }
    }
}

unsigned Node::eval(const std::vector<unsigned int> &features) {
    unsigned out = 0;
    unsigned parent = 1;
    eval_rec(out, *this, features, parent);
    return out;
}




void filter_by_feature_index(Node& a, int feature_index, vector<Node*>& vec){
    if (!a.is_leaf()){
        if (a.feature_index == feature_index){
            vec.push_back(&a);
        }
        filter_by_feature_index(*(a.left), feature_index, vec);
        filter_by_feature_index(*(a.right), feature_index, vec);
    }
}

std::vector<Node*> filter_by_feature_index(Node& a, int feature_index){
    vector<Node*> vec;
    filter_by_feature_index(a, feature_index, vec);
    return vec;
}


int max_feature_index(Node& a){
    if (a.is_leaf())
        return -1;
    int f_l = max_feature_index(*(a.left));
    int f_r = max_feature_index(*(a.right));
    
    int max_f = (f_l > f_r ? f_l : f_r);
    if (a.feature_index > max_f)
        max_f = a.feature_index;
    return max_f;
}
int max_class_leaf_value(Node& a){
    if (a.is_leaf())
        return a.class_leaf;
    int leftMax = max_class_leaf_value(*(a.left));
    int rightMax = max_class_leaf_value(*(a.right));

    // 返回左右子树中的较大值
    return std::max(leftMax, rightMax);
}
/*
int max_class_leaf_value_cipher_bit(Node& a){
    if (a.is_leaf()){
        return a.LWECipher_class_leaf.size();
        cout<<"a.LWECipher_class_leaf.size() "<<a.LWECipher_class_leaf.size()<<endl;
    }
    int leftMax = max_class_leaf_value_cipher_bit(*(a.left));//尤其是递归函数，换掉头函数后，不要忘记将里面的函数换掉，犯了两次这样的错误了。
    int rightMax = max_class_leaf_value_cipher_bit(*(a.right));

    // 返回左右子树中的较大值
    return std::max(leftMax, rightMax);
}
*/

int max_class_leaf_value_cipher_bit(Node& a){
    if (a.is_leaf()){
        return a.LWECipher_class_leaf.size();
    }
    return max_class_leaf_value_cipher_bit(*(a.left));//尤其是递归函数，换掉头函数后，不要忘记将里面的函数换掉，犯了两次这样的错误了。
}


std::vector< std::vector< Node* > > nodes_by_feature(Node& node){
    int max_feat_index = max_feature_index(node);
    vector< vector<Node*> > nodes_by_feature(max_feat_index + 1);
    for(int i = 0; i <= max_feat_index; i++){
        nodes_by_feature[i] = filter_by_feature_index(node, i);
    }

    return nodes_by_feature;
}

std::vector< std::vector< int > > thresholds_by_feature(std::vector<std::vector<Node*> > nodes_by_feat){
    int n = nodes_by_feat.size();
    vector< vector< int > > thrs_by_feature(n);

    for(int i = 0; i < n; i++){
        int _n = nodes_by_feat[i].size();
        thrs_by_feature[i] = vector<int>(_n);
        for(int j = 0; j < _n; j++){
            thrs_by_feature[i][j] = nodes_by_feat[i][j]->threshold;
            cout << thrs_by_feature[i][j] << ", ";
        }
        cout << endl;
    }
    return thrs_by_feature;
}
//抽取其密文门限值。并且排列起来
std::vector< std::vector< std::vector<LWECiphertext> > > thresholds_bitcipher_by_feature(std::vector<std::vector<Node*> > nodes_by_feat){
    int n = nodes_by_feat.size();
    vector< vector< vector<LWECiphertext> > > thrs_by_feature(n);

    for(int i = 0; i < n; i++){
        int _n = nodes_by_feat[i].size();
        thrs_by_feature[i] = vector<vector<LWECiphertext>>(_n);
        for(int j = 0; j < _n; j++){
            thrs_by_feature[i][j] = nodes_by_feat[i][j]->LWECipher_threshold;
            //cout << thrs_by_feature[i][j] << ", ";//这里不知道会不会出错
        }
    }
    return thrs_by_feature;
}


void enc_tree(Node& a, BinFHEContext fhe, LWEPrivateKey sk, int t_bitLength, int class_bitLength){
    if (!a.is_leaf()){
        //将门限值二进制展开，逐比特进行加密。
        std::vector<int> t_bitvector=IntegerToBinaryVector(a.threshold,t_bitLength);
        std::vector<LWECiphertext> t_LWE_bitvector(t_bitLength);
        for(int i=0;i<t_bitLength;i++){
            t_LWE_bitvector[i]=fhe.Encrypt(sk,t_bitvector[i]);
        }
        a.LWECipher_threshold=t_LWE_bitvector;
        a.threshold=0;

        enc_tree(*(a.left), fhe, sk, t_bitLength,class_bitLength);
        enc_tree(*(a.right), fhe, sk, t_bitLength,class_bitLength);
    }else{
        //进入到叶子结点。将叶子节点加密
        //将class_leaf二进制展开，逐比特进行加密。
        std::vector<int> class_bitvector=IntegerToBinaryVector(a.class_leaf,class_bitLength);
        std::vector<LWECiphertext> class_LWE_bitvector(class_bitLength);
        for(int i=0;i<class_bitLength;i++){
            class_LWE_bitvector[i]=fhe.Encrypt(sk,class_bitvector[i]);
        }
        a.LWECipher_class_leaf=class_LWE_bitvector;
        a.class_leaf=0;
    }
}

void dec_tree(Node& a, BinFHEContext fhe, LWEPrivateKey sk, int t_bitLength,int class_bitLength){
    if (!a.is_leaf()){
        //逐比特进行解密，并且合成二进制数。
        std::vector<int> t_bitvector(t_bitLength);
        for(int i=0;i<t_bitLength;i++){
            LWEPlaintext result;//int64_t
            fhe.Decrypt(sk, a.LWECipher_threshold[i], &result);
            t_bitvector[i]=result;
        }
        a.threshold=BinaryVectorTointeger(t_bitvector);
        
        dec_tree(*(a.left), fhe, sk, t_bitLength, class_bitLength);
        dec_tree(*(a.right), fhe, sk, t_bitLength, class_bitLength);
    }else{
        //进入到叶子结点
        std::vector<int> class_bitvector(class_bitLength);
        for(int i=0;i<class_bitLength;i++){
            LWEPlaintext result;//int64_t
            fhe.Decrypt(sk, a.LWECipher_class_leaf[i], &result);
            class_bitvector[i]=result;
        }
        a.class_leaf=BinaryVectorTointeger(class_bitvector);

    }
}

void build_json_from_tree(Node& node, json::reference ref){
    if(node.is_leaf()){
        //如果a是叶子结点
        ref["leaf"]=node.class_leaf;
    }else{
        //如果不是的话，看看情况如何。
        ref["internal"]["threshold"]=node.threshold;
        ref["internal"]["feature"]=node.feature_index;
        ref["internal"]["op"]=node.op;
        build_json_from_tree(*node.left, ref["internal"]["left"]);
        build_json_from_tree(*node.right, ref["internal"]["right"]);
    }
}


void ConvertToCipher(std::vector<LWECiphertext> &LWECipher_threshold,std::vector<std::vector<int>> &cta,std::vector<int> &ctb){
    usint dim=cta[0].size();
    lbcrypto::NativeInteger mod;
    lbcrypto::NativeInteger p;
    mod.SetValue(std::to_string(1024));
    p.SetValue(std::to_string(4));
    for(int i=0;i<cta.size();i++){
        lbcrypto::NativeVector ca_i(dim,mod);
        for (usint j = 0; j < dim; j++){
            ca_i[j] = lbcrypto::NativeInteger(std::to_string(cta[i][j]));
        }

        lbcrypto::NativeInteger cb_i;
        cb_i.SetValue(std::to_string(ctb[i]));

        lbcrypto::LWECiphertext ct_i = std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(std::move(ca_i), cb_i));
        ct_i->SetptModulus(p);

        LWECipher_threshold[i]=ct_i;
    }
}


void ConvertToVector(std::vector<LWECiphertext> &LWECipher_threshold,std::vector<std::vector<int>> &cta,std::vector<int> &ctb){
    int dim=LWECipher_threshold[0]->GetLength();
        for(int i=0;i<cta.size();i++){
            std::vector<int> cta_i(dim);
            for(int j=0;j<dim;j++){
                cta_i[j]=LWECipher_threshold[i]->GetA()[j].ConvertToInt();
            }
            cta[i]=cta_i;
            ctb[i]=LWECipher_threshold[i]->GetB().ConvertToInt();            
        }
}


void build_json_from_tree_with_cipher(Node& node, json::reference ref){
    if(node.is_leaf()){
        //如果a是叶子结点
        //后续这里会变成密文形式的
        
        ref["leaf"]["class_leaf"]=node.class_leaf;
        int class_cipher_length=node.LWECipher_class_leaf.size();
        std::vector<std::vector<int>> cta(class_cipher_length);    
        std::vector<int> ctb(class_cipher_length);
        ConvertToVector(node.LWECipher_class_leaf,cta,ctb);
        ref["leaf"]["LWECipher_class_leaf"]["class_cipher_length"]=class_cipher_length;
        ref["leaf"]["LWECipher_class_leaf"]["dim"]=node.LWECipher_class_leaf[0]->GetLength();
        ref["leaf"]["LWECipher_class_leaf"]["cta"]=cta;
        ref["leaf"]["LWECipher_class_leaf"]["ctb"]=ctb;
        

    }else{
        //如果不是的话，看看情况如何。
        ref["internal"]["threshold"]=node.threshold;
        ref["internal"]["feature"]=node.feature_index;
        ref["internal"]["op"]=node.op;
        //关键在于，如何将LWE密文变为序列化，
        //首先变为vector，然后就好办了。
        //ok,真的要这么办了，感觉好麻烦的，
        int t_cipher_length=node.LWECipher_threshold.size();
        std::vector<std::vector<int>> cta(t_cipher_length);    
        std::vector<int> ctb(t_cipher_length);
        ConvertToVector(node.LWECipher_threshold,cta,ctb);
        ref["internal"]["LWECipher_threshold"]["t_cipher_length"]=t_cipher_length;
        ref["internal"]["LWECipher_threshold"]["dim"]=node.LWECipher_threshold[0]->GetLength();
        ref["internal"]["LWECipher_threshold"]["cta"]=cta;
        ref["internal"]["LWECipher_threshold"]["ctb"]=ctb;
        
        build_json_from_tree_with_cipher(*node.left, ref["internal"]["left"]);
        build_json_from_tree_with_cipher(*node.right, ref["internal"]["right"]);
    }
}



void build_tree_from_json_with_cipher(json::reference ref, Node& node) {
    if (!ref["leaf"]["class_leaf"].is_null()) {
        node.class_leaf = ref["leaf"]["class_leaf"].get<Leaf>();

        int class_cipher_length=ref["leaf"]["LWECipher_class_leaf"]["class_cipher_length"];
        int dim=ref["leaf"]["LWECipher_class_leaf"]["dim"];
        std::vector<std::vector<int>> cta(class_cipher_length);
        std::vector<int> ctb(class_cipher_length);
        for(int i=0;i<cta.size();i++){
            std::vector<int> cta_i(dim);
            for(int j=0;j<dim;j++){
                cta_i[j]=ref["leaf"]["LWECipher_class_leaf"]["cta"].at(i).at(j);
            }
            cta[i]=cta_i;
            ctb[i]=ref["leaf"]["LWECipher_class_leaf"]["ctb"].at(i);
        }
        //将vector变为cipher
        std::vector<LWECiphertext> LWECipher_class_leaf(class_cipher_length);
        node.LWECipher_class_leaf=LWECipher_class_leaf;
        ConvertToCipher(node.LWECipher_class_leaf,cta,ctb);

        node.left = nullptr;
        node.right = nullptr;
    } else {
        node.threshold = ref["internal"]["threshold"].get<unsigned>();
        node.feature_index = ref["internal"]["feature"].get<unsigned>();
        node.op = ref["internal"]["op"].get<std::string>();
        node.class_leaf = -1;
        //将json变为vector
        int t_cipher_length=ref["internal"]["LWECipher_threshold"]["t_cipher_length"];
        int dim=ref["internal"]["LWECipher_threshold"]["dim"];
        std::vector<std::vector<int>> cta(t_cipher_length);
        std::vector<int> ctb(t_cipher_length);
        for(int i=0;i<cta.size();i++){
            std::vector<int> cta_i(dim);
            for(int j=0;j<dim;j++){
                cta_i[j]=ref["internal"]["LWECipher_threshold"]["cta"].at(i).at(j);
            }
            cta[i]=cta_i;
            ctb[i]=ref["internal"]["LWECipher_threshold"]["ctb"].at(i);
        }
        //将vector变为cipher
        std::vector<LWECiphertext> LWECipher_threshold(t_cipher_length);
        node.LWECipher_threshold=LWECipher_threshold;
        ConvertToCipher(node.LWECipher_threshold,cta,ctb);

        node.left = std::make_shared<Node>();
        node.right = std::make_shared<Node>();
        //不要忘记用该函数名进行递归。
        build_tree_from_json_with_cipher(ref["internal"]["left"], *node.left);
        build_tree_from_json_with_cipher(ref["internal"]["right"], *node.right);
    }
}


void result_serial(std::vector<std::vector<LWECiphertext>> &expect_result,std::string filename){
    int m=expect_result.size();
    int n=expect_result[0].size();
    std::vector<std::vector<std::vector<int>>> cta3(m);
    std::vector<std::vector<int>> ctb3(m);
    for(int i=0;i<m;i++){
        std::vector<std::vector<int>> cta(n);    
        std::vector<int> ctb(n);
        ConvertToVector(expect_result[i],cta,ctb);
        cta3[i]=cta;
        ctb3[i]=ctb;
    }
    
    //此时cta3,ctb3为向量。将其变为json文件
    json j3;
    j3["m"]=m;
    j3["n"]=n;
    j3["dim"]=expect_result[0][0]->GetLength();

    j3["cta3"]=cta3;
    j3["ctb3"]=ctb3;

    std::ofstream file3(filename);
    file3 << j3 << std::endl;
    std::cout<<filename<<"文件生成完成"<<std::endl;
}

std::vector<std::vector<LWECiphertext>> result_deserial(std::string filename){
    std::ifstream file3_3(filename);   
    nlohmann::json ref3 = nlohmann::json::parse(file3_3);

        int ref_m=ref3["m"];
        int ref_n=ref3["n"];
        int ref_dim=ref3["dim"];
        std::vector<std::vector<std::vector<int>>> ref_cta3(ref_m);
        std::vector<std::vector<int>> ref_ctb3(ref_m);
        for(int i=0;i<ref_m;i++){
            std::vector<std::vector<int>> cta(ref_n);
            std::vector<int> ctb(ref_n);
            for(int j=0;j<cta.size();j++){
                std::vector<int> cta_i(ref_dim);
                for(int k=0;k<ref_dim;k++){
                    cta_i[k]=ref3["cta3"].at(i).at(j).at(k);
                }
                cta[j]=cta_i;
                ctb[j]=ref3["ctb3"].at(i).at(j);
            }

            ref_cta3[i]=cta;
            ref_ctb3[i]=ctb;
        }
    std::cout<<filename<<"向量生成完成"<<std::endl;
        //ref_cta3,ref_ctb3为vector向量。
        //将vector变为cipher
        std::vector<std::vector<LWECiphertext>> expect_result(ref_m);
        for(int i=0;i<ref_m;i++){

            std::vector<LWECiphertext> LWECipher_threshold(ref_n);        
            ConvertToCipher(LWECipher_threshold,ref_cta3[i],ref_ctb3[i]);
            expect_result[i]=LWECipher_threshold;
        }
    return expect_result;
}


std::vector<std::vector<int>> read_csv_to_vector(std::string address,int data_bits,int data_m){
    std::vector<std::vector<int>> data;
    std::ifstream file(address);

    if (!file.is_open()) {
        std::cerr << "无法打开文件" << std::endl;
        return data;
    }
    std::string line;

    // 逐行读取CSV文件
    for(int i=0;i<data_m;i++){
        std::getline(file, line);
        std::vector<int> row;
        std::stringstream lineStream(line);
        std::string cell;

        // 按逗号分隔值并将它们转换为整数并存储到向量中
        while (std::getline(lineStream, cell, ',')) {
            int cellValue;
            std::istringstream(cell) >> cellValue;
            row.push_back(cellValue);
        }

        data.push_back(row);
    }
    return data;
}


void print_data(std::vector<std::vector<int>> data){
        for (const auto& row : data) {
        for (const auto& cell : row) {
            std::cout << cell << " ";
        }
        std::cout << std::endl;
    }
}