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
#include "aibe.h"

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

class LogNode {
public:
    json node;
    size_t index;
    ChronTreeT::Hash hash;

    LogNode() = default;
};

class LogTree {
public:
    ChronTreeT chronTree;
    std::map<int, LogNode> lexTree;

    int append(json &node, Proofs &prf);

    int trace(int idsn, LogNode &logNode, Proofs &prf);
};

#endif //LM_LOG_H
