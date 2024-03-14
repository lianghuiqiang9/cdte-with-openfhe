#ifndef __NODE__
#define __NODE__

#include "json.hpp"
#include "utils.h"
//#include "serial.h"
#include "binfhecontext.h"

using json = nlohmann::json;
using namespace lbcrypto;
using namespace std;
typedef unsigned Leaf;

class Node {
public:
    std::shared_ptr<Node> left;
    std::shared_ptr<Node> right;
    int feature_index;

    int threshold;
    std::vector<LWECiphertext> LWECipher_threshold;//threshold的二进制展开加密向量

    int class_leaf; // class assigned to the feature. Only leaves have this field set
    std::vector<LWECiphertext> LWECipher_class_leaf;//class_leaf的二进制展开加密向量

    std::string op;

    LWECiphertext control_bit; // result of comparison of encrypted feature with the threshold value
    std::vector<LWECiphertext> control_bit_vector;//注意区别，这里只是向量，用于General_pdte,维度由数据的行数决定。
    LWECiphertext value;

    Node() = default;
    explicit Node(json::reference j);
    explicit Node(std::string filename);
    void gen_with_depth(int d);
    unsigned get_depth();
    bool is_leaf() const;
    unsigned eval(const std::vector<unsigned> &features);
};

void print_node(Node& a, std::string tabs = "");

void print_tree(Node& a);

std::vector<Node*> filter_by_feature_index(Node& a, int feature_index);

int max_feature_index(Node& a);

int max_class_leaf_value(Node& a);
int max_class_leaf_value_cipher_bit(Node& a);
std::vector< std::vector< Node* > > nodes_by_feature(Node& node);

std::vector< std::vector< int > > thresholds_by_feature(std::vector<std::vector<Node*> > nodes_by_feat);

std::vector< std::vector< std::vector<LWECiphertext> > > thresholds_bitcipher_by_feature(std::vector<std::vector<Node*> > nodes_by_feat);

void enc_tree(Node& a, BinFHEContext fhe, LWEPrivateKey sk, int t_bitLength,int class_bitLength);
void dec_tree(Node& a, BinFHEContext fhe, LWEPrivateKey sk, int t_bitLength,int class_bitLength);

void build_tree_from_json(json::reference ref, Node& node);
void build_json_from_tree(Node& node, json::reference ref);

void ConvertToCipher(std::vector<LWECiphertext> &LWECipher_threshold,std::vector<std::vector<int>> &cta,std::vector<int> &ctb);
void ConvertToVector(std::vector<LWECiphertext> &LWECipher_threshold,std::vector<std::vector<int>> &cta,std::vector<int> &ctb);

void result_serial(std::vector<std::vector<LWECiphertext>> &expect_result,std::string filename);
std::vector<std::vector<LWECiphertext>> result_deserial(std::string filename);

void build_json_from_tree_with_cipher(Node& node, json::reference ref);
void build_tree_from_json_with_cipher(json::reference ref, Node& node);

std::vector<std::vector<int>> read_csv_to_vector(std::string address,int data_bits,int data_m);
void print_data(std::vector<std::vector<int>> data);

#endif