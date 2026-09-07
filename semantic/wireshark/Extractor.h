// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "extraction/Normalizer.h"
#include <epan/epan_dissect.h>
namespace sspa
{
class Extractor
{
public:
    static DecodedPacket copy(epan_dissect_t*, packet_info*);
    static QString tapFilter();
    static QStringList missingFields();
};
}
