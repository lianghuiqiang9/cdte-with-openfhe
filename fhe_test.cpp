#include <binfhecontext.h>
#include <iostream>
#include <fstream>

///usr/bin/g++ -fdiagnostics-color=always -g /home/ubuntu220402/Workspace/SortingHat_CPP/FHE_test.cpp -I /usr/local/include/openfhe -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/binfhe -I /usr/local/include/openfhe/cereal -L /usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -fopenmp -o /home/ubuntu220402/Workspace/SortingHat_CPP/FHE_test

//终端运行命令
//g++ -o fhe_test fhe_test.cpp -O3 -I /usr/local/include/openfhe -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/binfhe -I /usr/local/include/openfhe/cereal -L /usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -fopenmp 

//./fhe_test

using namespace lbcrypto;

int main() {

    std::cout<<"生成全同态加密方案..."<<std::endl;
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, AP);//如果不加AP，那么默认的就是GINX

    // Sample Program: Step 2: Key Generation
    std::cout<<"生成私钥..."<<std::endl;
    auto sk = cc.KeyGen();//sk={-1,0,1}^503
//    std::ofstream outputFile("sk.txt");outputFile << sk->GetElement();outputFile.close();
//    std::cout<<"sk->GetLength():"<<sk->GetLength()<<std::endl;

    std::cout << "生成Bootstrapping密钥..." << std::endl;
    cc.BTKeyGen(sk);
    std::cout << "密钥生成完成" << std::endl;
    std::cout << "加密中..." << std::endl;
    auto ct1 = cc.Encrypt(sk, 1);std::cout<<"*";
    
    std::cout << "输出加密的部分信息a,as+\\detla m+e..." << std::endl;
    //ct1是一个LWE密文，a={1-1024}^503,b=as+m+e={1-1024}, 
    std::cout<<"a:= "<<ct1->GetA()<<std::endl;
//    std::ofstream outputFilect1_A("ct1_A.txt");outputFilect1_A << ct1->GetA();outputFilect1_A.close();    
    std::cout<<"b=as+\\detla m+e:= "<<ct1->GetB().ToString()<<std::endl;
//    std::ofstream outputFilect1_B("ct1_B.txt");outputFilect1_B << ct1->GetB().ToString();outputFilect1_B.close();
//    std::cout <<"ct1->GetModulus():"<< ct1->GetModulus()<<std::endl;
//    std::cout <<"ct1->GetLength():"<< ct1->GetLength()<<std::endl;

    auto ctA0 = cc.Encrypt(sk, 0);
    auto ctA1 = cc.Encrypt(sk, 1);
    auto ctB0 = cc.Encrypt(sk, 0);
    auto ctB1 = cc.Encrypt(sk, 1);
    lbcrypto::LWECiphertext A[4];
    A[0]=ctA0;A[1]=ctA0,A[2]=ctA1,A[3]=ctA1;
    lbcrypto::LWECiphertext B[4];
    B[0]=ctB0;B[1]=ctB1,B[2]=ctB0,B[3]=ctB1;
    //enum BINGATE { OR, AND, NOR, NAND, XOR_FAST, XNOR_FAST, MAJORITY, AND3, OR3, AND4, OR4, CMUX, XOR, XNOR };        
    //A 0 0 1 1
    //B 0 1 0 1
    std::cout  << "0 0 1 1 A"<<std::endl;
    std::cout  << "0 1 0 1 B"<<std::endl;

    for(int i=0;i<4;i++){
      auto ctResult = cc.EvalBinGate(AND, A[i], B[i]);
      LWEPlaintext result;//int64_t
      cc.Decrypt(sk, ctResult, &result);
      std::cout  << result << " ";
    }
    std::cout<< "AND "  << std::endl;

    for(int i=0;i<4;i++){
      auto ctResult = cc.EvalBinGate(OR, A[i], B[i]);
      LWEPlaintext result;//int64_t
      cc.Decrypt(sk, ctResult, &result);
      std::cout  << result << " ";
    }
    std::cout << "OR " << std::endl;

    for(int i=0;i<4;i++){
      auto ctResult = cc.EvalBinGate(XOR, A[i], B[i]);
      LWEPlaintext result;//int64_t
      cc.Decrypt(sk, ctResult, &result);
      std::cout  << result << " ";
    }
    std::cout << "XOR " << std::endl;

    for(int i=0;i<4;i++){
      auto ctResult = cc.EvalBinGate(NAND, A[i], B[i]);
      LWEPlaintext result;//int64_t
      cc.Decrypt(sk, ctResult, &result);
      std::cout  << result << " ";
    }
    std::cout << "NAND " << std::endl;

    for(int i=0;i<4;i++){
      auto ctResult = cc.EvalBinGate(NOR, A[i], B[i]);
      LWEPlaintext result;//int64_t
      cc.Decrypt(sk, ctResult, &result);
      std::cout  << result << " ";
    }
    std::cout << "NOR "  << std::endl;

    for(int i=0;i<4;i++){
      auto ctResult = cc.EvalBinGate(XNOR, A[i], B[i]);
      LWEPlaintext result;//int64_t
      cc.Decrypt(sk, ctResult, &result);
      std::cout  << result << " ";
    }
    std::cout << "XNOR " << std::endl;

    for(int i=0;i<4;i++){
      auto ctResult = cc.EvalNOT(A[i]);
      LWEPlaintext result;//int64_t
      cc.Decrypt(sk, ctResult, &result);
      std::cout  << result << " ";
    }
    std::cout << "NOT " << std::endl;


    return 0;
}

/*
生成全同态加密方案...
生成私钥...
生成Bootstrapping密钥...
密钥生成完成
加密中...
*ENC run_time = 4.9e-05
输出加密的部分信息a,as+\detla m+e...
a:= [253 52 326 825 480 210 561 496 852 28 692 125 881 736 1019 852 721 677 263 965 227 969 629 301 448 303 282 86 838 21 133 645 787 165 343 487 828 967 570 601 682 620 566 841 807 500 436 485 488 1018 841 540 223 471 352 611 504 702 59 839 968 553 760 474 439 737 30 972 562 678 380 838 146 918 905 86 844 447 974 23 808 962 561 340 110 339 71 205 102 725 498 249 84 546 543 921 580 294 274 813 161 631 159 66 729 463 670 398 852 526 484 493 172 1 257 11 875 267 697 702 197 745 796 171 168 789 226 96 919 992 752 278 356 992 524 738 844 916 861 891 578 717 317 54 394 468 995 582 827 449 1022 810 422 632 924 901 721 802 35 121 933 203 653 121 904 367 778 234 511 935 820 402 445 154 991 1016 246 656 955 397 896 633 742 782 629 304 888 518 548 157 192 53 452 787 28 494 908 624 523 106 47 986 403 113 701 768 145 625 634 775 1016 1008 160 213 837 990 736 24 261 43 375 300 541 12 653 615 445 177 88 495 801 10 336 386 165 21 51 973 587 381 823 481 126 802 257 572 835 209 160 1021 649 303 710 960 422 113 778 455 720 439 466 120 283 341 867 325 562 321 93 685 79 131 505 869 883 6 262 621 487 268 79 6 37 87 989 16 904 366 187 257 284 884 743 976 472 65 777 820 60 632 372 522 539 866 373 251 553 758 862 848 150 774 93 782 81 464 222 992 289 863 880 745 942 620 208 523 724 552 164 443 50 16 41 413 111 124 669 678 112 78 661 309 386 899 346 970 911 545 758 736 415 57 284 494 245 493 994 162 837 411 840 911 513 609 1018 889 61 145 970 247 263 377 572 631 703 327 241 63 790 307 450 923 776 299 135 585 461 511 881 370 506 107 757 113 895 342 828 685 335 225 743 268 886 937 694 615 359 634 871 765 310 668 226 174 295 721 575 957 394 437 178 800 792 849 964 12 286 812 980 939 761 815 733 700 876 201 291 330 101 130 347 706 44 535 772 651 341 709 141 629 93 432 39 603 735 695 334 235 593 189 233 807 297 669 375 819 254 903 997 6 784 824 500 496 478 129 94 984 952 1002 194 829 917 549 845 740 985 698 556 397 476 911 173 385 852 356 761 96 89 130 95 518 283] modulus: 1024
b=as+\detla m+e:= 690
0 0 1 1 A
0 1 0 1 B
*AND run_time = 0.3997
0 *AND run_time = 0.37773
0 *AND run_time = 0.377585
0 *AND run_time = 0.390602
1 AND = 
*OR run_time = 0.441115
0 *OR run_time = 0.411755
1 *OR run_time = 0.378964
1 *OR run_time = 0.381385
1 OR = 
0 1 1 0 XOR = 
1 1 1 0 NAND = 
1 0 0 0 NOR = 
1 0 0 1 XNOR = 
1 1 0 0 NOT =
*/