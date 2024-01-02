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
