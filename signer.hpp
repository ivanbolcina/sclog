#ifndef SIGNER_H
#define SIGNER_H

#include "entry.hpp"

using namespace std;


class RecordSigner
{
    void *impl {nullptr};
public:
    RecordSigner();
    virtual ~RecordSigner();
    void insert_signature(AuditRecord &record);
};

#endif