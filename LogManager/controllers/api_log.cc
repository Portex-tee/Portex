#include "api_log.h"
#include "log.h"

using namespace api;

extern LogTree logTree;

// Add definition of your processing function here
void api::log::get_proof(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                         std::string string) const {

    Json::Value ret;
    ret["code"] = 0;
    ret["msg"] = "ok";

    Json::Value data;
    data["hash"] = string;
    ret["data"] = data;

    auto resp = HttpResponse::newHttpJsonResponse(ret);
    callback(resp);
}

void api::log::list(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) const {

//    return details of logTree
    Json::Value ret;
    ret["code"] = 0;
    ret["msg"] = "ok";
    ret["size"] = int(logTree.lexTree.size());

    Json::Value data;

//    data is a list of logTree.lexTree
    for (auto it = logTree.lexTree.begin(); it != logTree.lexTree.end(); it++) {
        Json::Value item;
        item["id"] = it->first;
        item["size"] = int(it->second.size());
        Json::Value proof;
        for (auto it2 = it->second.begin(); it2 != it->second.end(); it2++) {
//            parse it2 (json string) to json object
            Json::Reader reader;
            Json::Value item2;
            reader.parse(*it2, item2);
            proof.append(item2);
        }
        item["proof"] = proof;
        data.append(item);
    }


    ret["data"] = data;

    auto resp = HttpResponse::newHttpJsonResponse(ret);
    callback(resp);
}

void api::log::table(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    Json::Value ret;
    ret["code"] = 0;
    ret["msg"] = "ok";
    ret["size"] = int(logTree.lexTree.size());

    Json::Value data;

    for (auto & it : logTree.lexTree) {
        for (auto & it2 : it.second) {
            Json::Reader reader;
            Json::Value item2;
            reader.parse(it2, item2);
            data.append(item2);
        }
    }

    ret["data"] = data;

    drogon::HttpViewData httpViewData;
    int intsize = ret.size() + 2;
    httpViewData.insert("list", intsize);
    std::cout << "in controller " << httpViewData.get<int>("list") << std::endl;
    auto resp = HttpResponse::newHttpViewResponse("LogView.csp", httpViewData);
    callback(resp);
}
