#include "serial.h"

//const std::string DATAFOLDER = "FHE_context";

//serial全同态加密数据，参数，bsk，ksk
void FHE_context_serial(std::string DATAFOLDER,BinFHEContext cc1){

    auto start=clock();
    float run_time;

    if (!Serial::SerializeToFile(DATAFOLDER + "/cryptoContext.txt", cc1, SerType::JSON)) {
        std::cerr << "Error serializing the cryptocontext" << std::endl;
        
    }
    std::cout << "The cryptocontext has been serialized." << std::endl;

    // Serializing refreshing and key switching keys (needed for bootstrapping)

    if (!Serial::SerializeToFile(DATAFOLDER + "/refreshKey.txt", cc1.GetRefreshKey(), SerType::JSON)) {
        std::cerr << "Error serializing the refreshing key" << std::endl;
        
    }
    std::cout << "The refreshing key has been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/ksKey.txt", cc1.GetSwitchKey(), SerType::JSON)) {
        std::cerr << "Error serializing the switching key" << std::endl;
        
    }
    std::cout << "The key switching key has been serialized." << std::endl;

    run_time = float(clock()-start)/CLOCKS_PER_SEC;
    cout << "FHE_context_serial run_time = " << run_time << endl;


}

BinFHEContext FHE_context_deserial(std::string DATAFOLDER){
    auto start=clock();
    float run_time;

    BinFHEContext cc;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/cryptoContext.txt", cc, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the cryptocontext" << std::endl;
        
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    // deserializing the refreshing and switching keys (for bootstrapping)

    RingGSWACCKey refreshKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/refreshKey.txt", refreshKey, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the refresh key" << std::endl;
        
    }
    std::cout << "The refresh key has been deserialized." << std::endl;

    LWESwitchingKey ksKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/ksKey.txt", ksKey, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the switching key" << std::endl;
        
    }
    std::cout << "The switching key has been deserialized." << std::endl;

    // Loading the keys in the cryptocontext
    cc.BTKeyLoad({refreshKey, ksKey});

    run_time = float(clock()-start)/CLOCKS_PER_SEC;
    cout << "FHE_context_deserial run_time = " << run_time << endl;

    
    return cc;
}

void FHE_cipher_serial(std::string DATAFOLDER,std::string filename,LWECiphertext ct1){
    auto start=clock();
    float run_time;

    if (!Serial::SerializeToFile(DATAFOLDER +"/" + filename + ".txt", ct1, SerType::JSON)) {
        std::cerr << "Error serializing ct1" << std::endl;        
    }
    std::cout << "A ciphertext has been serialized." << std::endl;

    run_time = float(clock()-start)/CLOCKS_PER_SEC;
    cout << "FHE_cipher_serial run_time = " << run_time << endl;

}

LWECiphertext FHE_cipher_deserial(std::string DATAFOLDER,std::string filename){
    auto start=clock();
    float run_time;
    
    LWECiphertext ct;
    if (Serial::DeserializeFromFile(DATAFOLDER +"/" + filename + ".txt", ct, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the ciphertext" << std::endl;        
    }
    std::cout << "The ciphertext has been deserialized." << std::endl;

    run_time = float(clock()-start)/CLOCKS_PER_SEC;
    cout << "FHE_cipher_deserial run_time = " << run_time << endl;

    return ct;

}



