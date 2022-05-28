#ifndef ENTRY_H
#define ENTRY_H

#include "Poco/DateTime.h"
#include "Poco/LocalDateTime.h"
#include "Poco/DateTimeParser.h"
#include "Poco/DateTimeFormat.h"
#include "Poco/Nullable.h"
#include "Poco/Data/LOB.h"

using Poco::DateTime;
using Poco::DateTimeParser;
using Poco::DateTimeFormatter;
using Poco::LocalDateTime;
using Poco::Nullable;
using Poco::Data::LOB;
using Poco::Data::BLOB;
using namespace std;

struct AuditRecord
{
    AuditRecord()=default;
    long id;
    int version;
    string component;
    DateTime ts_audit;
    DateTime ts_ins;
    shared_ptr<std::vector<uint8_t>> signature;
    shared_ptr<std::vector<uint8_t>> previous_signature;
    Poco::Nullable<BLOB> signature_lob;
    Poco::Nullable<BLOB> previous_signature_lob;
    Poco::Nullable<long> previous_id;
    string log_level;
    string track_id;
    string user_id;
    string message;
    string custom;
    string key_name;
};


#endif