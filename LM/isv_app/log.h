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


typedef struct _log_header_t{
    uint32_t size[3];
}log_header_t;

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

    int serialise(uint8_t *bytes, log_header_t *header);

    int deserialise(uint8_t *bytes, log_header_t *header);
};

int Proofs::serialise(uint8_t *bytes, log_header_t *header) {
    int size = 0;
    std::vector<uint8_t> vec;

    // node
    node.serialise(vec);
    std::copy(vec.begin(), vec.end(), bytes + size);
    header->size[0] = node.serialised_size();
    size += header->size[0];

    // root
    root.serialise(vec);
    std::copy(vec.begin(), vec.end(), bytes + size);
    header->size[1] = root.serialised_size();
    size += header->size[1];

    // path
    path->serialise(vec);
    std::copy(vec.begin(), vec.end(), bytes + size);
    header->size[2] = path->serialised_size();
    size += header->size[2];

    return size;
}

int Proofs::deserialise(uint8_t *bytes, log_header_t *header) {

    int size = 0, len;
    std::vector<uint8_t> vec;

    // node
    len = header->size[0];
    vec.assign(bytes + size, bytes + size + len);
    node.deserialise(vec);
    size += header->size[0];

    // root
    len = header->size[1];
    vec.assign(bytes + size, bytes + size + len);
    root.deserialise(vec);
    size += header->size[1];

    // path
    len = header->size[2];
    vec.assign(bytes + size, bytes + size + len);
    path->deserialise(vec);
    size += header->size[2];

    return size;
}


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
