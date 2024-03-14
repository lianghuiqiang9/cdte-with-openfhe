
# 模型流程
这是一个两方密态模型，服务器和客户端。
1. 服务器将决策树加密发送给客户端，
2. 客户端在密态决策树用明文数据进行评估，返回一个密文结果发送给服务器。
3. 服务器得到密文结果用私钥解密得到评估结果。

# 需要安装的库
首先要按照OpenFHE的官方指导https://github.com/openfheorg/openfhe-development 安装。成功安
装并生成了用户示例。
（在安装过程中 
#cmake ..  -BUILD_STATIC=OFF
#export LD_LIBRARY_PATH=/usr/local/lib
）走动态库，并且编译时，要链接到库的地址。

# 密钥序列化，
序列化和逆序列化时间在80s，87s左右。并且我们进行了压缩处理。使用了tar命令。但是压缩和解压缩时间为20s左右吧（未计算）。

# 编译运行，
主要由GroupComp_main.cpp SingleComp_main.cpp MainWithSerial.cpp三个文件，main()函数前有编译命令。
