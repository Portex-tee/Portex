#include "log.h"

void sha256(const std::string &srcStr, std::string &encodedHexStr) {
    unsigned char mdStr[33] = {0};
    SHA256((const unsigned char *) srcStr.c_str(), srcStr.length(), mdStr);// 调用sha256哈希

    char buf[65] = {0};
    char tmp[3] = {0};
    for (int i = 0; i < 32; i++)// 哈希后的十六进制串 32字节
    {
        sprintf(tmp, "%02x", mdStr[i]);
        strcat(buf, tmp);
    }
    buf[64] = '\0'; // 后面都是0，从32字节截断
    encodedHexStr = std::string(buf);
}

std::string get_future_timestamp(int seconds) {
    auto now = std::chrono::system_clock::now();
    now += std::chrono::seconds(seconds);

    std::time_t now_tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&now_tt);

    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() % 1000;

    std::ostringstream stream;
    stream << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << millis;

    return stream.str();
}

std::string get_timestamp() {
    return get_future_timestamp(0);
}

std::chrono::system_clock::time_point parse_timestamp(const std::string &timestamp) {
    std::istringstream stream(timestamp);
    std::tm tm{};
    char extra;

    stream >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S") >> extra;

    int millis;
    stream >> millis;

    std::time_t tt = std::mktime(&tm);
    auto duration = std::chrono::system_clock::from_time_t(tt);

    return duration + std::chrono::milliseconds(millis);
}

bool compare_timestamps(const std::string &timestamp1, const std::string &timestamp2) {
    return parse_timestamp(timestamp1) < parse_timestamp(timestamp2);
}

int Proofs::serialise(uint8_t *bytes) {
    log_header_t header;
    int size = 0;
    std::vector<uint8_t> vec;

    header.size[0] = node.serialised_size();
    header.size[1] = root.serialised_size();
//    header.size[2] = path->serialised_size();

    size += sizeof(log_header_t);

    // node
    vec.clear();
    node.serialise(vec);
    std::copy(vec.begin(), vec.end(), bytes + size);
    size += header.size[0];

    // root
    vec.clear();
    root.serialise(vec);
    std::copy(vec.begin(), vec.end(), bytes + size);
    size += header.size[1];

    // path
    vec.clear();
    path->serialise(vec);
    header.size[2] = vec.size();
    std::copy(vec.begin(), vec.end(), bytes + size);
    size += header.size[2];

    memcpy(bytes, &header, sizeof(log_header_t));

    return size;
}

int Proofs::deserialise(uint8_t *bytes) {

    int size = 0, len;
    std::vector<uint8_t> vec;
    log_header_t header;

    len = sizeof(log_header_t);
    memcpy(&header, bytes, len);
    size += len;

    // node
    len = header.size[0];
    vec.clear();
    vec.assign(bytes + size, bytes + size + len);
    node.deserialise(vec);
    size += len;

    // root
    len = header.size[1];
    vec.clear();
    vec.assign(bytes + size, bytes + size + len);
    root.deserialise(vec);
    size += len;

    // path
    len = header.size[2];
    vec.clear();
    vec.assign(bytes + size, bytes + size + len);
    path = std::make_shared<ChronTreeT::Path>(vec);
    size += len;

    return size;
}

bool Proofs::verify_proofs() {
    return path->verify(root);
}

int LogTree::append(int idsn, json &j_node, Proofs &prf) {
    LogNode node;
    node.node = j_node;

    std::string j_str = j_node.dump() ,encodedHexStr;
    std::cout << "jnode" << j_str << std::endl;
    sha256(j_str, encodedHexStr);
    ChronTreeT::Hash hash(encodedHexStr);
    node.hash = hash;

    int ret = 0;

    prf.node = hash;
    chronTree.insert(hash);
    prf.root = chronTree.root();
    prf.path = chronTree.path(chronTree.max_index());

    node.index = chronTree.max_index();

    lexTree[idsn] = node;
    return ret;
}

int LogTree::trace(int idsn, LogNode &logNode, Proofs &prf) {
    if (lexTree.find(idsn) == lexTree.end()) {
        return 0;
    }

    logNode = lexTree[idsn];

    prf.node = logNode.hash;
    prf.root = chronTree.root();
    prf.path = chronTree.path(logNode.index);
    return 1;
}
