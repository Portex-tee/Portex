//
// Created by jojjiw on 2022/4/9.
//

#ifndef LM_LOG_H
#define LM_LOG_H

#include "merklecpp.h"
#include <iostream>
#include <cstdio>
#include <map>
#include <vector>
#include <chrono>
#include <sys/time.h>
#include "json.hpp"

#include <openssl/sha.h>

using json = nlohmann::json;

typedef merkle::TreeT<32, merkle::sha256_openssl> ChronTreeT;

typedef struct _log_header_t {
    uint32_t size[3];
} log_header_t;

void sha256(const std::string &srcStr, std::string &encodedHexStr);

std::string get_timestamp(timeval &tv);

class Proofs {
public:
    ChronTreeT::Hash node;
    ChronTreeT::Hash root;
    std::shared_ptr<ChronTreeT::Path> path;

    bool verify_proofs();

    int serialise(uint8_t *bytes);

    int deserialise(uint8_t *bytes);
};

class LogTree {
public:
    ChronTreeT chronTree;
    std::map<int, std::vector<std::string>> lexTree;

    int append(int id, const std::string &node, ChronTreeT::Hash hash, Proofs &prf);

    void trace(int ID, std::vector<json> &lst);

//    int merkle_test() {
//        std::string srcStr = "message", encodedHexStr;
//
//        sha256(srcStr, encodedHexStr);
//
//        ChronTreeT::Hash hash(encodedHexStr);
//        std::vector<ChronTreeT::Hash> hashes;
//        hashes.push_back(hash);
//        for (auto h : hashes)
//            chronTree.insert(h);
//        auto root = chronTree.root();
//        auto path = chronTree.path(hashes.size() - 1);
//        assert(path->verify(root));
//        std::cout << "verify succeed" << std::endl;
//        return 0;
//    }
};

#endif //LM_LOG_H
