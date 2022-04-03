# Intel SGX Remote Attestation (Real) 


## 程序总体设计
  程序基于Intel SGX SDK 中样例代码的Remote attestation编写。客户端和服务端分别启动一个独立的enclave，两者完全通过不可信程序建立的socket TCP连接进行通讯。
  在实际开发过程中，我将client端和server端的代码调用关系修改成了真正的网络通信，工作比较繁琐。主要是请求包和响应包的内存分配问题比较繁琐，而且由于时间比较紧张，也没有对双方的响应包进行比较严格的检查。
  为了实现远程设置秘钥的功能，采用接受一个32字节的设置包来专门设置server端加密秘钥。思路是将设置包的前16字节看做一个token，为了开发方便使用5到20这16个无符号整数，后16字节为enclave随机生成的key，将整个包使用协商出来的秘钥进行加密。服务端接收到后，对数据进行解密，验证前面的token是否正确，如正确，则将后面16字节设置为加密服务的密钥。
 出于演示目的和时间关系，加密和解密服务只运行一次，并且没有用协商出来的信道秘钥进行加密。

## 主要函数说明
### 1.网络通讯函数
  网络通讯采用最简单的socket进行通讯，主要代码都放在service_provider.cpp中，传输数据采用声明两个全局的buffer进行通讯，可扩展性比较差。
### 2.服务端加解密函数
  主要代码在isv_app.cpp中，分别为myaesencrypt()、myaesdecrypt()、 myaessetkey()三个函数，主要实现功能为调用enclave中的加解密函数，设置秘钥函数，并将结果发送到client端。

## 总结
  如intel 在github上的代码不能直接clone编译，会存在一些无法编译的问题；Remoteattestation代码也不能直接编译，在试过多种方法以后，发现在github上另外一个工程提供的libsample_libcrypto.so才是正确静态编译的动态库。实际调试过程中，还发现最后一步的解密怎么也不能正确的执行。这也有待于解决。实际调试发现是SGX_ERROR_MAC_MISMATCH错误，还无法解决。

## 代码编译运行方法
  运行该代码需要安装intel sgx sdk（推荐使用Ubuntu16.04系统），在Intel官方的01download.org有提供，如果不采用模拟器的方式编译，还需要安装驱动，具体参考这一篇博客文章https://blog.csdn.net/qiu_pengfei/article/details/78795697 。安装完成后需要采用source 命令引用sdk中生成的environment文件。
编译方法为进入server或者client目录，执行make SGX_MODE=SIM，即可编译完成，并且可以用gdb进行调试非enclave代码。如果选择prerelease对代码进行编译，需要先对生成的enclave.so进行签名，签名证书需要想intel申请，比较还比较苛刻。
运行方法为在本地先运行server端的app，然后运行client端的app，自动通过本地的12333端口进行通讯，需要远程通讯可以修改代码中指定的127.0.0.1地址。
