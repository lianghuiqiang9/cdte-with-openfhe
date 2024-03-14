#include "binfhecontext-ser.h"
#include "serial.h"
using namespace lbcrypto;

// path where files will be written to
const std::string DATAFOLDER = "FHEContext";//首先要新建一个FHE_context文件夹

//g++ -o serial_test serial_test.cpp src/serial.cpp -O3 -I./include -I /usr/local/include/openfhe -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/binfhe -I /usr/local/include/openfhe/cereal -L /usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -fopenmp 

//./serial_test


int main() {
    // Generating the crypto context

    auto cc1 = BinFHEContext();

    cc1.GenerateBinFHEContext(STD128);//STD128, AP//默认GINX
    //STD128 GINX ksKey 1.98G refreshKey 626MB
    //消耗时间大概3分钟（很慢）
    std::cout << "Generating keys." << std::endl;

    // Generating the secret key
    auto sk1 = cc1.KeyGen();

    // Generate the bootstrapping keys
    cc1.BTKeyGen(sk1);

    std::cout << "Done generating all keys." << std::endl;

    // Encryption for a ciphertext that will be serialized
    auto ct1 = cc1.Encrypt(sk1, 1);

    // CODE FOR SERIALIZATION

    auto start=clock();
    float run_time;
    // Serializing context
    FHE_context_serial(DATAFOLDER,cc1);

        run_time = float(clock()-start)/CLOCKS_PER_SEC;
    std::cout << "run_time = " << run_time <<" s"<< std::endl;

    // Serializing private keys

    if (!Serial::SerializeToFile(DATAFOLDER + "/sk1.txt", sk1, SerType::JSON)) {
        std::cerr << "Error serializing sk1" << std::endl;
        return 1;
    }
    std::cout << "The secret key sk1 key been serialized." << std::endl;

    
    // Serializing a ciphertext
    FHE_cipher_serial(DATAFOLDER,"ct1",ct1);

    // CODE FOR DESERIALIZATION
    auto start2=clock();
    // Deserializing the cryptocontext

    BinFHEContext cc=FHE_context_deserial(DATAFOLDER);

    run_time = float(clock()-start2)/CLOCKS_PER_SEC;
    std::cout << "run_time = " << run_time <<" s"<< std::endl;
    // Deserializing the secret key

    LWEPrivateKey sk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/sk1.txt", sk, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the secret key" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been deserialized." << std::endl;

    // Deserializing a previously serialized ciphertext

    LWECiphertext ct=FHE_cipher_deserial(DATAFOLDER,"ct1");
    
    // OPERATIONS WITH DESERIALIZED KEYS AND CIPHERTEXTS

    auto ct2 = cc.Encrypt(sk, 1);

    std::cout << "Running the computation" << std::endl;

    auto ctResult = cc.EvalBinGate(AND, ct, ct2);

    std::cout << "The computation has completed" << std::endl;

    LWEPlaintext result;

    cc.Decrypt(sk, ctResult, &result);

    std::cout << "result of 1 AND 1 = " << result << std::endl;

    return 0;
}
/*
Generating keys.
Done generating all keys.
The cryptocontext has been serialized.
The refreshing key has been serialized.
The key switching key has been serialized.
FHE_context_serial run_time = 83.4678
The secret key sk1 key been serialized.
A ciphertext has been serialized.
FHE_cipher_serial run_time = 0.008462
The cryptocontext has been deserialized.
The refresh key has been deserialized.
The switching key has been deserialized.
FHE_context_deserial run_time = 88.4085
The secret key has been deserialized.
The ciphertext has been deserialized.
FHE_cipher_deserial run_time = 0.000621
Running the computation
The computation has completed
result of 1 AND 1 = 1
*/