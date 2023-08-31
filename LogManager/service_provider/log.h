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
#include <iomanip>
#include <sys/time.h>
#include "json.hpp"

#include <openssl/sha.h>

using json = nlohmann::json;

typedef merkle::TreeT<32, merkle::sha256_openssl> ChronTreeT;

typedef struct _log_header_t {
    uint32_t size[3];
} log_header_t;

void sha256(const std::string &srcStr, std::string &encodedHexStr);

std::string get_timestamp();


std::string get_future_timestamp(int seconds);


std::chrono::system_clock::time_point parse_timestamp(const std::string& timestamp);

bool compare_timestamps(const std::string& timestamp1, const std::string& timestamp2);

std::string vectorToHex(const std::vector<uint8_t>& data);

std::vector<uint8_t> hexToVector(const std::string& hexString);


std::string wrapText(const std::string &input, size_t lineLength = 16);

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

    int append(int idsn, json &node, Proofs &prf);

    int trace(int idsn, LogNode &logNode, Proofs &prf);
};

#endif //LM_LOG_H
