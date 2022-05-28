
#include <algorithm>
#include <functional>
#include <cctype>
#include <stdexcept>
#include "botan/hash.h"
#include "botan/hex.h"
#include <botan/p11.h>
#include "botan/p11_object.h"
#include "botan/p11_module.h"
#include "botan/p11_types.h"
#include "botan/p11_x509.h"
#include "botan/auto_rng.h"
#include "botan/p11_randomgenerator.h"
#include "botan/p11_rsa.h"
#include <botan/auto_rng.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <log4cplus/loggingmacros.h>
#include <log4cplus/configurator.h>
#include <log4cplus/helpers/loglog.h>
#include <log4cplus/helpers/stringhelper.h>
#include <log4cplus/helpers/fileinfo.h>
#include <log4cplus/loggingmacros.h>
#include <log4cplus/initializer.h>
#include "Poco/DateTimeParser.h"
#include "Poco/DateTimeFormat.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/DateTimeParser.h"
#include <cbor.h>
#include <memory>
#include <vector>
#include <toml.hpp>
#include "../include/utils.h"
#include "../include/signer.hpp"

using namespace std;
using namespace log4cplus;
using namespace log4cplus::helpers;

class Encoder
{

    static void add_long(CborEncoder *encoder, long data);
    static void add_long_nullable(CborEncoder *encoder, Poco::Nullable<long> data);
    static void add_string(CborEncoder *encoder, string data);
    static void add_datetime(CborEncoder *encoder, DateTime ldt);
    static void add_localdatetime(CborEncoder *encoder, LocalDateTime ldt);
    static void add_blob(CborEncoder *encoder, Poco::Nullable<BLOB> &data);

public:
    static shared_ptr<std::vector<uint8_t>> encode(AuditRecord &record);
};

void Encoder::add_long_nullable(CborEncoder *encoder, Poco::Nullable<long> data)
{
    CborError err;
    if (data.isNull())
        err = cbor_encode_null(encoder);
    else
        err = cbor_encode_int(encoder, data.value());
    if (err == CborNoError)
        return;
    if (err == CborErrorOutOfMemory)
        throw length_error("buffer");
    throw runtime_error("unknown");
}

void Encoder::add_long(CborEncoder *encoder, long data)
{
    auto err = cbor_encode_int(encoder, data);
    if (err == CborNoError)
        return;
    if (err == CborErrorOutOfMemory)
        throw length_error("buffer");
    throw runtime_error("unknown");
}

void Encoder::add_string(CborEncoder *encoder, string data)
{
    auto err = cbor_encode_byte_string(encoder, reinterpret_cast<const unsigned char *>(data.c_str()), data.size());
    if (err == CborNoError)
        return;
    if (err == CborErrorOutOfMemory)
        throw length_error("buffer");
    throw runtime_error("unknown");
}

void Encoder::add_datetime(CborEncoder *encoder, DateTime ldt)
{
    auto curr = DateTimeFormatter::format(ldt, Poco::DateTimeFormat::ISO8601_FORMAT, Poco::DateTimeFormatter::UTC);
    add_string(encoder, curr);
}

void Encoder::add_localdatetime(CborEncoder *encoder, LocalDateTime ldt)
{
    auto curr = DateTimeFormatter::format(ldt.utc(), Poco::DateTimeFormat::ISO8601_FORMAT, ldt.tzd());
    add_string(encoder, curr);
}

void Encoder::add_blob(CborEncoder *encoder, Poco::Nullable<BLOB> &data)
{
    CborError err;
    if (data.isNull())
        err = cbor_encode_null(encoder);
    else
        err = cbor_encode_byte_string(encoder, data.value().content().data(), data.value().size());
    if (err == CborNoError)
        return;
    if (err == CborErrorOutOfMemory)
        throw length_error("buffer");
    throw runtime_error("unknown");
}

shared_ptr<std::vector<uint8_t>> Encoder::encode(AuditRecord &record)
{
    CborEncoder encoder;
    shared_ptr<std::vector<uint8_t>> outdata(new std::vector<uint8_t>());
    uint8_t *buff = nullptr;
    int size = 1024;
    while (true)
    {
        size <<= 2;
        if (buff != nullptr)
            free(buff);
        buff = (uint8_t *)malloc(size);
        cbor_encoder_init(&encoder, buff, size, 0);
        try
        {
            add_long(&encoder, record.version);
            add_localdatetime(&encoder, record.ts_audit);
            add_string(&encoder, record.component);
            add_localdatetime(&encoder, record.ts_ins);
            add_long_nullable(&encoder, record.previous_id);
            add_blob(&encoder, record.previous_signature_lob);

            add_string(&encoder, record.log_level);
            add_string(&encoder, record.track_id);
            add_string(&encoder, record.user_id);
            add_string(&encoder, record.message);
            add_string(&encoder, record.custom);
            add_string(&encoder, record.key_name);
            break;
        }
        catch (const std::length_error &e)
        {
            if (size > 10000000)
                throw e;
            continue;
        }
    }
    auto lenfin = cbor_encoder_get_buffer_size(&encoder, buff);
    for (auto i = 0; i < lenfin; i++)
        outdata->push_back(buff[i]);
    free(buff);
    return outdata;
}

class RecordSignerImpl
{
    log4cplus::Logger logger;
    shared_ptr<Botan::PKCS11::Session> session;
    shared_ptr<Botan::PKCS11::Module> module;
    shared_ptr<Botan::PKCS11::Slot> slot;
    Botan::AutoSeeded_RNG rng;
    Botan::PKCS11::ObjectHandle signing_key_handle;
    string algorithm;

public:
    RecordSignerImpl();
    virtual ~RecordSignerImpl() = default;
    void insert_signature(AuditRecord &record);
    
};

RecordSignerImpl::RecordSignerImpl() : rng(), session(nullptr), signing_key_handle(0)
{
    auto config = toml::parse_file( "configuration.toml" );
    auto modulename =config["sign"]["module"].value_or("/usr/lib/softhsm/libsofthsm2.so");
    auto slotname =config["sign"]["slot"].value_or("sclog");
    auto keyname=config["sign"]["keyname"].value_or("AKEY");
    auto cnfpin=string(config["sign"]["pin"].value_or("0000"));
    algorithm = config["sign"]["algorithm"].value_or("EMSA4(SHA-256)");
    logger = log4cplus::Logger::getInstance(LOG4CPLUS_TEXT("RecordSigner"));
    module = make_shared<Botan::PKCS11::Module>(modulename);
    // Sometimes useful if a newly connected token is not detected by the PKCS#11 module
    module->reload();
    Botan::PKCS11::Info info = module->get_info();
    LOG4CPLUS_INFO(logger, "pkcs#11 lib version " << info.libraryVersion.major);
    std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots(*module, true);
    Botan::PKCS11::SlotId sid;
    bool fnd = false;
    for (int i = 0; i < slots.size(); i++)
    {
        slot = make_shared<Botan::PKCS11::Slot>(*module, slots.at(i));
        // print firmware version of the slot
        Botan::PKCS11::SlotInfo slot_info = slot->get_slot_info();
        // print firmware version of the token
        Botan::PKCS11::TokenInfo token_info = slot->get_token_info();
        std::string label2 = reinterpret_cast<char *>(token_info.label);
        auto label = first(label2);
        LOG4CPLUS_INFO(logger, label.c_str());
        if (trim_copy(label).compare(slotname) == 0)
        {
            fnd = true;
            sid = slots.at(i);
            LOG4CPLUS_INFO(logger, "found slot at index " << i);
        }
    }
    if (fnd)
    {
        slot = make_shared<Botan::PKCS11::Slot>(*module, sid);
        session = make_shared<Botan::PKCS11::Session>(*slot, true);
        Botan::PKCS11::secure_string pin;
        std::copy(cnfpin.begin(),cnfpin.end(),back_inserter(pin));
        session->login(Botan::PKCS11::UserType::User, pin);
        LOG4CPLUS_INFO(logger, "executer login");
        Botan::PKCS11::AttributeContainer search_template;
        search_template.add_string(Botan::PKCS11::AttributeType::Label, keyname);
        search_template.add_class(Botan::PKCS11::ObjectClass::PrivateKey);
        auto found_objs =
            Botan::PKCS11::Object::search<Botan::PKCS11::PKCS11_RSA_PrivateKey>(*(session.get()), search_template.attributes());
        for (auto item : found_objs)
        {
            signing_key_handle = item.handle();
        }
    }
}

void RecordSignerImpl::insert_signature(AuditRecord &record)
{
    record.version = 1;
    auto tobesigned = Encoder::encode(record);
    auto datax = Encoder::encode(record);
    Botan::secure_vector<uint8_t> plaintext;
    std::copy(datax->begin(), datax->end(), std::back_inserter(plaintext));
    for (int i = 0; i < datax->size(); i++)
    {
        plaintext.push_back(datax->at(i));
    }
    Botan::PKCS11::PKCS11_RSA_PrivateKey key(*(session.get()), signing_key_handle);
    Botan::PK_Signer signer(key, rng, algorithm, Botan::IEEE_1363);
    auto signeddata = signer.sign_message(plaintext, rng);
    record.signature = make_shared<std::vector<uint8_t>>();
    // std::copy(signeddata.begin(),signeddata.end(),std::back_inserter(record.signature));
    for (int i = 0; i < signeddata.size(); i++)
    {
        record.signature->push_back(signeddata.at(i));
    }
    LOG4CPLUS_INFO(logger, "executed signature");
}

RecordSigner::RecordSigner()
{
    impl = new RecordSignerImpl();
}

RecordSigner::~RecordSigner()
{
    delete (RecordSignerImpl *)impl;
}

void RecordSigner::insert_signature(AuditRecord &record)
{
    ((RecordSignerImpl *)impl)->insert_signature(record);
}