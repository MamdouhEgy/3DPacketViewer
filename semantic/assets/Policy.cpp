// SPDX-License-Identifier: GPL-2.0-or-later
#include "Policy.h"
#include <QJsonArray>
#include <cmath>
namespace sspa
{
std::optional<Policy> Policy::parse(const QJsonObject& root, QString& error)
{
    Policy p;
    const QSet<QString> allowed { "schema_version", "assets", "enforce_control_sources",
        "transaction_timeout_ms", "sv_counter_modulus", "expected_sample_rate", "expected_interval_ms",
        "interval_tolerance_ms" };
    for (auto it = root.begin(); it != root.end(); ++it)
        if (!allowed.contains(it.key())) {
            error = "Unknown configuration key: " + it.key();
            return {};
        }
    if (root.value("schema_version") != "1.0") {
        error = "Expected policy schema_version 1.0";
        return {};
    }
    auto number = [&](QString key, double low, double high, double fallback) -> std::optional<double> {
        if (!root.contains(key))
            return fallback;
        const auto v = root[key];
        if (!v.isDouble() || !std::isfinite(v.toDouble()) || v.toDouble() < low || v.toDouble() > high) {
            error = "Invalid policy number: " + key;
            return {};
        }
        return v.toDouble();
    };
    auto timeout = number("transaction_timeout_ms", 1, 3600000, 5000);
    auto modulus = number("sv_counter_modulus", 0, 65536, 0);
    auto rate = number("expected_sample_rate", 0, 10000000, 0);
    auto interval = number("expected_interval_ms", 0, 3600000, 0);
    auto tolerance = number("interval_tolerance_ms", 0, 3600000, 0);
    if (!timeout || !modulus || !rate || !interval || !tolerance)
        return {};
    if (std::floor(*modulus) != *modulus || *modulus == 1 || std::floor(*rate) != *rate) {
        error = "Counter modulus and sample rate must be whole numbers; modulus is zero or at least two";
        return {};
    }
    p.transactionTimeoutMs = *timeout;
    p.svCounterModulus = qint64(*modulus);
    p.expectedSampleRate = qint64(*rate);
    p.expectedIntervalMs = *interval;
    p.intervalToleranceMs = *tolerance;
    if (root.contains("enforce_control_sources") && !root["enforce_control_sources"].isBool()) {
        error = "enforce_control_sources must be boolean";
        return {};
    }
    p.enforceControlSources = root["enforce_control_sources"].toBool();
    if (root.contains("assets") && !root["assets"].isObject()) {
        error = "assets must be an object";
        return {};
    }
    const auto assets = root["assets"].toObject();
    if (assets.size() > 10000) {
        error = "Asset limit exceeded";
        return {};
    }
    const QSet<QString> roles { "UNKNOWN", "CONTROL_CENTER", "RTU", "PROTECTION_IED", "MERGING_UNIT", "HMI",
        "ENGINEERING", "GATEWAY" };
    const QSet<QString> keys { "role", "name", "control_source", "peers", "protocols", "publishers",
        "datasets", "common_addresses", "ioas", "vlans", "functions" };
    for (auto it = assets.begin(); it != assets.end(); ++it) {
        if (!it.value().isObject() || it.key().size() > 200) {
            error = "Invalid asset";
            return {};
        }
        const auto o = it.value().toObject();
        Asset a;
        for (auto k = o.begin(); k != o.end(); ++k)
            if (!keys.contains(k.key())) {
                error = "Unknown asset property: " + k.key();
                return {};
            }
        if ((o.contains("role") && !o["role"].isString())
            || (o.contains("name") && (!o["name"].isString() || o["name"].toString().size() > 200))) {
            error = "Asset name and role must be bounded strings";
            return {};
        }
        a.role = o.value("role").toString("UNKNOWN");
        a.name = o.value("name").toString().left(200);
        if (!roles.contains(a.role)) {
            error = "Unknown asset role";
            return {};
        }
        if (o.contains("control_source") && !o["control_source"].isBool()) {
            error = "control_source must be boolean";
            return {};
        }
        a.controlSource = o["control_source"].toBool();
        for (const auto& key : { "peers", "protocols", "publishers", "datasets", "common_addresses", "ioas",
                 "vlans", "functions" }) {
            if (!o.contains(key))
                continue;
            if (!o[key].isArray() || o[key].toArray().size() > 10000) {
                error = "Invalid asset list";
                return {};
            }
            for (auto v : o[key].toArray()) {
                if (QString(key) == "peers" || QString(key) == "protocols" || QString(key) == "publishers"
                    || QString(key) == "datasets") {
                    if (!v.isString() || v.toString().size() > 256) {
                        error = "Invalid identity policy";
                        return {};
                    }
                    auto* set = QString(key) == "peers" ? &a.peers
                        : QString(key) == "protocols"   ? &a.protocols
                        : QString(key) == "publishers"  ? &a.publishers
                                                        : &a.datasets;
                    set->insert(v.toString());
                } else {
                    const double max = QString(key) == "vlans" ? 4095
                        : QString(key) == "functions"          ? 255
                        : QString(key) == "common_addresses"   ? 65535
                                                               : 16777215;
                    if (!v.isDouble() || v.toDouble() < 0 || v.toDouble() > max
                        || std::floor(v.toDouble()) != v.toDouble()) {
                        error = "Invalid numeric policy";
                        return {};
                    }
                    auto* set = QString(key) == "vlans"      ? &a.vlans
                        : QString(key) == "functions"        ? &a.functions
                        : QString(key) == "common_addresses" ? &a.commonAddresses
                                                             : &a.ioas;
                    set->insert(qint64(v.toDouble()));
                }
            }
        }
        p.assets.insert(it.key(), a);
    }
    return p;
}
QString Policy::role(const QString& endpoint) const
{
    return assets.contains(endpoint) ? assets[endpoint].role : "UNKNOWN";
}
QVector<Finding> Policy::evaluate(const Event& e) const
{
    QVector<Finding> findings;
    auto add = [&](QString rule, QString expected, QString observed) {
        Finding f;
        f.rule = rule;
        f.protocol = e.protocol;
        f.category = "CONFIGURED_POLICY";
        f.severity = "WARNING";
        f.frames = { e.frame };
        f.expected = expected;
        f.observed = observed;
        f.basis = "Configured asset/topology policy, schema 1.0";
        f.explanation = expected + ". Observed: " + observed
            + ". This is a configured policy mismatch, not proof of malicious intent.";
        for (const auto& value : e.values)
            f.evidence += value.evidence;
        findings.push_back(f);
    };
    if (e.flag("control") && enforceControlSources
        && (!assets.contains(e.source) || !assets[e.source].controlSource))
        add(e.protocol + "_UNEXPECTED_COMMAND_SOURCE", "Control source must be explicitly authorized",
            e.sourceRole);
    if (assets.contains(e.source)) {
        const auto& a = assets[e.source];
        if (!a.peers.empty() && !a.peers.contains(e.destination))
            add("UNEXPECTED_PEER", "Configured peer", "Unlisted destination");
        if (!a.protocols.empty() && !a.protocols.contains(e.protocol))
            add("UNEXPECTED_PROTOCOL", "Configured protocol", e.protocol);
        if (!a.vlans.empty() && (!e.has("vlan") || !a.vlans.contains(e.integer("vlan"))))
            add("VLAN_POLICY", "Configured VLAN", e.text("vlan"));
        if (!a.functions.empty() && e.has("function") && !a.functions.contains(e.integer("function")))
            add("FUNCTION_POLICY", "Configured function", e.text("function"));
        if (!a.publishers.empty() && !a.publishers.contains(e.publisher))
            add("PUBLISHER_POLICY", "Configured publisher", "Unlisted publisher identity");
        if (!a.datasets.empty() && e.has("dataset") && !a.datasets.contains(e.text("dataset")))
            add("DATASET_POLICY", "Configured dataset", "Unlisted dataset identity");
    }
    const auto target = e.flag("control") ? e.destination : e.source;
    if (assets.contains(target)) {
        const auto& a = assets[target];
        if (!a.commonAddresses.empty() && e.has("common_address")
            && !a.commonAddresses.contains(e.integer("common_address")))
            add("COMMON_ADDRESS_POLICY", "Configured Common Address", e.text("common_address"));
        if (!a.ioas.empty() && e.has("ioa") && !a.ioas.contains(e.integer("ioa")))
            add("IOA_POLICY", "Configured IOA", e.text("ioa"));
    }
    return findings;
}
}
