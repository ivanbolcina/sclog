#include <pistache/endpoint.h>
#include <pistache/http_headers.h>
#include <pistache/router.h>
#include <pistache/http.h>
#include <log4cplus/loggingmacros.h>
#include <log4cplus/configurator.h>
#include <log4cplus/helpers/loglog.h>
#include <log4cplus/helpers/fileinfo.h>
#include <log4cplus/initializer.h>
#include "Poco/Data/Session.h"
#include "Poco/Data/SessionPool.h"
#include "Poco/Data/MySQL/Connector.h"
#include "Poco/DateTime.h"
#include "Poco/Data/LOB.h"
#include "Poco/Data/DataException.h"
#include <nlohmann/json.hpp>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <cbor.h>
#include <toml.hpp>
#include "utils.h"
#include "entry.hpp"
#include "signer.hpp"

using namespace std;
using namespace log4cplus;
using namespace log4cplus::helpers;
using namespace Pistache;
using namespace Pistache::Http::Mime;
using namespace Pistache::Rest;
using Poco::DateTime;
using Poco::DateTimeFormatter;
using Poco::DateTimeParser;
using Poco::LocalDateTime;
using Poco::Data::Session;
using Poco::Data::SessionPool;
using Poco::Data::Statement;
using json = nlohmann::json;
using namespace Poco::Data::Keywords;

class BasicService
{
public:
    explicit BasicService(Address addr) : httpEndpoint(std::make_shared<Http::Endpoint>(addr)), g_mutex(), conf_version(1), conf_key_name(""), port((int)addr.port())
    {
        logger = log4cplus::Logger::getInstance(LOG4CPLUS_TEXT("main"));
    }

    void init()
    {
        auto config = toml::parse_file("configuration.toml");
        auto db_type = config["db"]["type"].value_or("MySQL");
        auto db_url = config["db"]["url"].value_or("");
        if (string(db_url).empty())
            throw logic_error("configuration:db:url");
        conf_version = 1;
        conf_key_name = config["sign"]["keyname"].value_or("AKEY");
        size_t threads = std::thread::hardware_concurrency();
        auto opts = Http::Endpoint::options()
                        .flags(Tcp::Options::ReuseAddr | Tcp::Options::ReusePort)
                        .threads(static_cast<int>(threads));
        httpEndpoint->init(opts);
        setupRoutes();
        httpEndpoint->setHandler(router.handler());
        pool = std::make_shared<Poco::Data::SessionPool>(db_type, db_url);
        ostringstream oss;
        oss << "Audit service running at port " << port;
        LOG4CPLUS_INFO(logger, oss.str().c_str());
    }

    void start()
    {
        httpEndpoint->serve();
    }

private:
    std::mutex g_mutex;
    int port;
    int conf_version;
    string conf_key_name;

    void setupRoutes()
    {
        using namespace Rest;

        Routes::Post(router, "/send", Routes::bind(&BasicService::on_send, this));
    }

    string read_string(json input, string name)
    {
        try
        {
            auto tsinsinp = input.at(name);
            if (tsinsinp.is_string())
            {
                return tsinsinp.get<string>();
            }
        }
        catch (exception ex)
        {
            return "";
        }
        return "";
    }

    void on_send(const Rest::Request &request, Http::ResponseWriter response)
    {
        std::lock_guard<std::mutex> guard(g_mutex);
        // insert some rows
        try
        {
            // get ts now
            auto tsaudit = DateTime();
            // get session
            auto session = pool->get();
            // read body
            std::string inputraw = request.body();
            std::istringstream inputstreamraw(inputraw);
            json input;
            inputstreamraw >> input;
            // parse ts_ins
            int tz;
            string tsinsstr = read_string(input, "timestamp");
            auto tsins = DateTimeParser::parse(Poco::DateTimeFormat::ISO8601_FORMAT, tsinsstr, tz);
            tsins.makeUTC(tz);
            // construct audit record
            AuditRecord rec;
            rec.key_name = conf_key_name;
            rec.version = conf_version;
            rec.ts_audit = tsaudit;
            rec.ts_ins = tsins;
            rec.component = read_string(input, "component");
            rec.log_level = read_string(input, "log_level");
            rec.track_id = read_string(input, "track_id");
            rec.user_id = read_string(input, "user_id");
            rec.message = read_string(input, "message");
            rec.custom = read_string(input, "custom");
            // read previous record
            AuditRecord prev;
            auto select = Statement(session);
            select << "select id,rec_signature from SC_LOG order by 1 desc limit 1",
                into(prev.id),
                into(prev.signature_lob),
                range(0, 1); //  iterate over result set one row at a time
            // store previous record data into current record
            while (!select.done())
            {
                if (select.execute())
                {
                    rec.previous_id = prev.id;
                    rec.previous_signature_lob = prev.signature_lob;
                }
            }
            // sign record
            signer.insert_signature(rec);
            // put signature into lob
            std::vector<unsigned char> tmp;
            for (int i = 0; i < rec.signature->size(); i++)
                tmp.push_back(rec.signature->at(i));
            Poco::Data::BLOB data((tmp));
            rec.signature_lob = data;
            // insert data
            auto insert = Statement(session);
            insert << R"sql(
                        INSERT INTO SC_LOG 
                        (
                            version,ts_ins,ts_audit,component,
                            rec_signature,prev_signature,prev_id,
                            log_level,track_id,user_id,
                            message,custom,key_name
                        )
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        )sql",
                use(rec.version),
                use(rec.ts_ins),
                use(rec.ts_audit),
                use(rec.component),
                use(rec.signature_lob),
                use(rec.previous_signature_lob),
                use(rec.previous_id),
                use(rec.log_level),
                use(rec.track_id),
                use(rec.user_id),
                use(rec.message),
                use(rec.custom),
                use(rec.key_name);
            insert.execute();
            LOG4CPLUS_INFO(logger, "audit entry inserted");
            response.send(Http::Code::Ok, "OK!");
        }
        catch (Poco::Data::DataException &ex)
        {
            std::cerr << ex.displayText() << std::endl;
            ostringstream oss;
            oss << "error on log:";
            oss << ex.displayText();
            auto strerr = oss.str();
            LOG4CPLUS_ERROR(logger, strerr.c_str());
            response.send(Http::Code::Internal_Server_Error, "Error!");
        }
    }

    std::shared_ptr<Http::Endpoint> httpEndpoint;
    Rest::Router router;
    log4cplus::Logger logger;
    int time;
    std::shared_ptr<SessionPool> pool;
    RecordSigner signer;
};

int main(int argc, char **argv)
{
    log4cplus::Initializer initializer;
    PropertyConfigurator::doConfigure(LOG4CPLUS_TEXT("log.properties"));
    Poco::Data::MySQL::Connector::registerConnector();
    int th = std::thread::hardware_concurrency();
    auto config = toml::parse_file("configuration.toml");
    auto portnum = atoi(config["server"]["port"].value_or("2001"));
    Port port(portnum);
    Address addr(Ipv4::any(), port);
    BasicService service(addr);
    service.init();
    service.start();
}
