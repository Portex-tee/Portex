//
// Created by jojjiw on 2022/4/9.
//

#ifndef LM_LOG_H
#define LM_LOG_H
#include "merklecpp.h"
#include <iostream>
#include <cstdio>

#include <openssl/sha.h>

typedef merkle::TreeT<32, merkle::sha256_openssl> ChronTreeT;

void sha256(const std::string &srcStr, std::string &encodedHexStr)
{
    unsigned char mdStr[33] = { 0 };
    SHA256((const unsigned char *)srcStr.c_str(), srcStr.length(), mdStr);// 调用sha256哈希

    char buf[65] = { 0 };
    char tmp[3] = { 0 };
    for (int i = 0; i < 32; i++)// 哈希后的十六进制串 32字节
    {
        sprintf(tmp, "%02x", mdStr[i]);
        strcat(buf, tmp);
    }
    buf[64] = '\0'; // 后面都是0，从32字节截断
    encodedHexStr = std::string(buf);
}

class Proofs {
public:
    ChronTreeT::Hash node;
    ChronTreeT::Hash root;
    std::shared_ptr<ChronTreeT::Path> path;

    bool verify_proofs() {
        if (!path->verify(root)) {
            return false;
        }
        return true;
    }
};


class LogTree {
public:
    ChronTreeT chronTree;

    int append(ChronTreeT::Hash hash, Proofs &prf);

    int merkle_test(){
        std::string srcStr = "message", encodedHexStr;

        sha256(srcStr, encodedHexStr);

        ChronTreeT::Hash hash(encodedHexStr);
        std::vector<ChronTreeT::Hash> hashes;
        hashes.push_back(hash);
        for (auto h : hashes)
            chronTree.insert(h);
        auto root = chronTree.root();
        auto path = chronTree.path(hashes.size() - 1);
        assert(path->verify(root));
        std::cout << "verify succeed" << std::endl;
        return 0;
    }
};


int LogTree::append(ChronTreeT::Hash hash, Proofs &prf) {
    int ret = 0;
    prf.node = hash;
    chronTree.insert(hash);
    prf.root = chronTree.root();
    prf.path = chronTree.path(0);
    return ret;
}



#endif //LM_LOG_H
