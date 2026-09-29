#include "detect.h"

int timeToSeconds(const std::string& time);  // defined below; used by trackFailedLogin

void trackFailedLogin(
    const LogEntry& entry,
    std::unordered_map<std::string, int>& failedLoginCounts,
    std::unordered_map<std::string, int>& failedUserCounts,
    std::unordered_map<std::string, std::vector<int>>& failedLoginTimestamps) {
    if (entry.message.find("Login failed") != std::string::npos) {
        if (!entry.ip.empty()) {
            failedLoginCounts[entry.ip]++;
            failedLoginTimestamps[entry.ip].push_back(timeToSeconds(entry.time));
        }
        if (!entry.user.empty()) {
            failedUserCounts[entry.user]++;
        }

    }

}
void printSecurityAlerts(const std::unordered_map<std::string, int>& failedLoginCounts,
                          const std::unordered_map<std::string, int>& failedUserCounts,
                        int& suspiciousIpCount,
                        int& suspiciousUserCount
                    ) {
     suspiciousIpCount = 0;
     suspiciousUserCount = 0;

    std::cout << "\n --- Security Alerts --- \n";

    for (const auto& pair : failedLoginCounts) {
        if (pair.second >=3) {
            suspiciousIpCount++;

            std::string riskLevel = getRiskLevel(pair.second);

            std::cout << "[" << riskLevel << "] IP "
                      << pair.first
                      << " had " 
                      << pair.second
                      << " failed login attempts.\n";
        }
    }

    for (const auto& pair : failedUserCounts) {

        if (pair.second >= 3) {
            suspiciousUserCount++;

            std::string riskLevel = getRiskLevel(pair.second);

            std::cout << "[" << riskLevel << "] User "
                      << pair.first
                      << " had " 
                      << pair.second
                      << " failed login attempts.\n";
        }
    }
}

bool hasHighErrorRate(int totalLogs, int errorCount, const DetectionSettings& s) {
    if (totalLogs == 0) return false;
    double errorRate = static_cast<double>(errorCount) / totalLogs;
    return errorCount >= s.highErrorMinErrors && errorRate >= s.highErrorMinRate;
}

int timeToSeconds(const std::string& time) {
    int hours = std::stoi(time.substr(0, 2));
    int minutes = std::stoi(time.substr(3, 2));
    int seconds = std::stoi(time.substr(6, 2));

    return hours * 3600 + minutes * 60 + seconds;
}

bool hasRapidFailedLogins(const std::vector<int>& times){

    if (times.size() < 3) {
        return false;
    }
    for (size_t i = 0; i +2 < times.size(); i++){
        if (times[i+2] - times[i] <= 60) {
            return true;
        }
    }
    return false;
}

// Migrate the repeated-failure detector onto alerts. Same risk levels as
// printSecurityAlerts -- one logic, two renderers.
void pushRepeatedFailureAlerts(
    const std::vector<LogEntry>& entries,
    const std::unordered_map<std::string, int>& failedLoginCounts,
    const std::unordered_map<std::string, int>& failedUserCounts,
    const DetectionSettings& s) {
    std::unordered_map<std::string, long long> ipLastSeen, userLastSeen;
    for (const auto& e : entries) {
        long long ep = logEntryEpoch(e);
        if (!e.ip.empty() && ep > ipLastSeen[e.ip]) ipLastSeen[e.ip] = ep;
        if (!e.user.empty() && ep > userLastSeen[e.user]) userLastSeen[e.user] = ep;
    }
    for (const auto& pair : failedLoginCounts) {
        if (pair.second >= s.repeatedFailureMinAttempts) {
            std::ostringstream msg;
            msg << "IP " << pair.first << " had " << pair.second
                << " failed login attempts.";
            long long ep = ipLastSeen.count(pair.first) ? ipLastSeen[pair.first] : 0;
            pushAlert(getRiskLevel(pair.second), "repeated_failures",
                      msg.str(), pair.first, "", ep);
        }
    }
    for (const auto& pair : failedUserCounts) {
        if (pair.second >= s.repeatedFailureMinAttempts) {
            std::ostringstream msg;
            msg << "User " << pair.first << " had " << pair.second
                << " failed login attempts.";
            long long ep = userLastSeen.count(pair.first) ? userLastSeen[pair.first] : 0;
            pushAlert(getRiskLevel(pair.second), "repeated_failures",
                      msg.str(), "", pair.first, ep);
        }
    }
}

// Epoch-based rapid brute force. Pushes real Alerts with timestamps,
// so incidents can compute durations later.
void pushRapidBruteForceEpochAlerts(const std::vector<LogEntry>& entries,
                                    const DetectionSettings& s) {
    std::unordered_map<std::string, std::vector<long long>> timesByIp;
    for (const auto& e : entries) {
        if (e.message.find("Login failed") == std::string::npos) continue;
        if (e.ip.empty()) continue;
        timesByIp[e.ip].push_back(logEntryEpoch(e));
    }
    for (const auto& pair : timesByIp) {
        long long start = firstWindowStart(pair.second, s.bruteForceWindowSeconds,
                                           s.bruteForceMinAttempts);
        if (start >= 0) {
            pushAlert("HIGH", "rapid_brute_force",
                      formatRapidBruteForceMessage(pair.first, s),
                      pair.first, "", start);
        }
    }
}

// PASSWORD SPRAY: one IP, >= N distinct usernames within the window.
void detectPasswordSpray(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    std::unordered_map<std::string, std::vector<std::pair<long long, std::string>>> byIp;
    for (const auto& e : entries) {
        if (e.message.find("Login failed") == std::string::npos) continue;
        if (e.ip.empty() || e.user.empty()) continue;
        byIp[e.ip].push_back({logEntryEpoch(e), e.user});
    }
    for (auto& pair : byIp) {
        auto& ev = pair.second;
        std::sort(ev.begin(), ev.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        for (size_t i = 0; i < ev.size(); ++i) {
            std::unordered_set<std::string> users;
            for (size_t j = i; j < ev.size() && ev[j].first - ev[i].first <= s.sprayWindowSeconds; ++j) {
                users.insert(ev[j].second);
            }
            if (users.size() >= static_cast<size_t>(s.sprayMinUsers)) {
                std::ostringstream msg;
                msg << "Password spray from IP " << pair.first << ": "
                    << users.size() << " distinct usernames within "
                    << s.sprayWindowSeconds << " seconds.";
                pushAlert("HIGH", "password_spray", msg.str(), pair.first, "", ev[i].first);
                break;
            }
        }
    }
}

// DISTRIBUTED ATTACK: >= N distinct IPs on one username within the window.
void detectDistributedAttack(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    std::unordered_map<std::string, std::vector<std::pair<long long, std::string>>> byUser;
    for (const auto& e : entries) {
        if (e.message.find("Login failed") == std::string::npos) continue;
        if (e.ip.empty() || e.user.empty()) continue;
        byUser[e.user].push_back({logEntryEpoch(e), e.ip});
    }
    for (auto& pair : byUser) {
        auto& ev = pair.second;
        std::sort(ev.begin(), ev.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        for (size_t i = 0; i < ev.size(); ++i) {
            std::unordered_set<std::string> ips;
            for (size_t j = i; j < ev.size() && ev[j].first - ev[i].first <= s.distributedWindowSeconds; ++j) {
                ips.insert(ev[j].second);
            }
            if (ips.size() >= static_cast<size_t>(s.distributedMinIps)) {
                std::ostringstream msg;
                msg << "Distributed attack on user '" << pair.first << "': "
                    << ips.size() << " distinct source IPs within "
                    << s.distributedWindowSeconds << " seconds.";
                pushAlert("HIGH", "distributed_attack", msg.str(), "", pair.first, ev[i].first);
                break;
            }
        }
    }
}

// LOGIN FAILURE BURST: N+ failed logins within the window, any source.
void detectLoginBurst(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    std::vector<long long> failTimes;
    for (const auto& e : entries) {
        if (e.message.find("Login failed") != std::string::npos)
            failTimes.push_back(logEntryEpoch(e));
    }
    long long start = firstWindowStart(failTimes, s.loginBurstWindowSeconds,
                                       s.loginBurstMinAttempts);
    if (start >= 0) {
        std::ostringstream msg;
        msg << "Login failure burst: " << s.loginBurstMinAttempts
            << "+ failed logins within " << s.loginBurstWindowSeconds << " seconds.";
        pushAlert("CRITICAL", "login_burst", msg.str(), "", "", start);
    }
}

// N+ ERROR events within the window (any source).
void detectErrorBursts(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    std::vector<long long> errorTimes;
    for (const auto& e : entries)
        if (e.severity == "ERROR") errorTimes.push_back(logEntryEpoch(e));
    long long start = firstWindowStart(errorTimes, s.errorBurstWindowSeconds,
                                       s.errorBurstMinCount);
    if (start >= 0) {
        std::ostringstream msg;
        msg << "Error burst: " << s.errorBurstMinCount << "+ ERROR events within "
            << s.errorBurstWindowSeconds << " seconds.";
        pushAlert("MEDIUM", "error_burst", msg.str(), "", "", start);
    }
}

// REPEATED IDENTICAL ERRORS: same message text N+ times.
void detectRepeatedErrors(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    std::unordered_map<std::string, int> counts;
    std::unordered_map<std::string, long long> lastSeen;
    for (const auto& e : entries) {
        if (e.severity != "ERROR") continue;
        counts[e.message]++;
        long long ep = logEntryEpoch(e);
        if (ep > lastSeen[e.message]) lastSeen[e.message] = ep;
    }
    for (const auto& pair : counts) {
        if (pair.second >= s.repeatedErrorMinCount) {
            std::ostringstream msg;
            msg << "Repeated error (" << pair.second << "x): \""
                << pair.first.substr(0, 80) << "\"";
            pushAlert("MEDIUM", "repeated_error", msg.str(), "", "", lastSeen[pair.first]);
        }
    }
}

// SAME SERVICE repeatedly failing (service=... pulled from the message).
void detectServiceFailures(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    std::unordered_map<std::string, int> counts;
    std::unordered_map<std::string, long long> lastSeen;
    for (const auto& e : entries) {
        if (e.severity != "ERROR") continue;
        std::string svc = extractValue(e.message, "service");
        if (svc.empty()) continue;
        counts[svc]++;
        long long ep = logEntryEpoch(e);
        if (ep > lastSeen[svc]) lastSeen[svc] = ep;
    }
    for (const auto& pair : counts) {
        if (pair.second >= s.serviceFailureMinCount) {
            std::ostringstream msg;
            msg << "Service '" << pair.first << "' failed " << pair.second << " times.";
            pushAlert("MEDIUM", "service_failure", msg.str(), "", "", lastSeen[pair.first]);
        }
    }
}

// WARN -> ERROR ESCALATION: WARN then ERROR, same ip or service, within the window.
void detectWarnEscalation(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    for (size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].severity != "WARN") continue;
        std::string svc = extractValue(entries[i].message, "service");
        long long t0 = logEntryEpoch(entries[i]);
        for (size_t j = i + 1; j < entries.size(); ++j) {
            if (entries[j].severity != "ERROR") continue;
            long long dt = logEntryEpoch(entries[j]) - t0;
            if (dt < 0 || dt > s.warnEscalationWindowSeconds) continue;
            bool sameIp = !entries[i].ip.empty() && entries[i].ip == entries[j].ip;
            bool sameSvc = !svc.empty() && svc == extractValue(entries[j].message, "service");
            if (sameIp || sameSvc) {
                std::ostringstream msg;
                msg << "WARN escalated to ERROR within " << s.warnEscalationWindowSeconds
                    << " seconds"
                    << (sameSvc ? " for service='" + svc + "'" : "")
                    << (sameIp ? " from IP " + entries[i].ip : "") << ".";
                pushAlert("MEDIUM", "warn_escalation", msg.str(),
                          sameIp ? entries[i].ip : "", "", logEntryEpoch(entries[j]));
                break;
            }
        }
    }
}

// UNUSUALLY DENSE ACTIVITY: any window far above the mean rate.
void detectDenseActivity(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    if (entries.size() < 60) return;
    std::vector<long long> times;
    for (const auto& e : entries) times.push_back(logEntryEpoch(e));
    std::sort(times.begin(), times.end());
    long long span = times.back() - times.front();
    if (span < 120) return;
    double meanPerBucket = static_cast<double>(times.size()) / (span / 60 + 1);
    long long threshold = std::max<long long>(50, static_cast<long long>(5 * meanPerBucket));

    long long worst = 0, worstEnd = 0;
    size_t left = 0;
    for (size_t right = 0; right < times.size(); ++right) {
        while (times[right] - times[left] > s.denseWindowSeconds) ++left;
        long long count = static_cast<long long>(right - left + 1);
        if (count > worst) { worst = count; worstEnd = times[right]; }
    }
    if (worst >= threshold) {
        std::ostringstream msg;
        msg << "Unusually dense activity: " << worst << " events within "
            << s.denseWindowSeconds << " seconds"
            << " (average " << static_cast<long long>(meanPerBucket) << "/min).";
        pushAlert("LOW", "dense_activity", msg.str(), "", "", worstEnd);
    }
}

// OFF-HOURS ACCESS: successful logins inside the configured off-hours window.
void detectOffHoursAccess(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    for (const auto& e : entries) {
        std::string m = toLower(e.message);
        if (m.find("login") == std::string::npos) continue;
        if (m.find("success") == std::string::npos && m.find("accepted") == std::string::npos)
            continue;
        int hour = (e.time[0] - '0') * 10 + (e.time[1] - '0');  // validated HH:MM:SS
        bool off = (s.offHoursStart <= s.offHoursEnd)
            ? (hour >= s.offHoursStart && hour < s.offHoursEnd)
            : (hour >= s.offHoursStart || hour < s.offHoursEnd);  // wraps midnight
        if (off) {
            std::ostringstream msg;
            msg << "Off-hours login: user '" << (e.user.empty() ? "?" : e.user)
                << "' at " << e.time << (e.ip.empty() ? "" : " from " + e.ip) << ".";
            pushAlert("MEDIUM", "off_hours_access", msg.str(), e.ip, e.user, logEntryEpoch(e));
        }
    }
}

// IMPOSSIBLE TRAVEL: same user from 2+ distinct IPs within a short window.
void detectImpossibleTravel(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    std::unordered_map<std::string, std::vector<std::pair<long long, std::string>>> byUser;
    for (const auto& e : entries) {
        if (e.user.empty() || e.ip.empty()) continue;
        byUser[e.user].push_back({logEntryEpoch(e), e.ip});
    }
    for (auto& pair : byUser) {
        auto& ev = pair.second;
        std::sort(ev.begin(), ev.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        for (size_t i = 0; i < ev.size(); ++i) {
            std::unordered_set<std::string> ips;
            for (size_t j = i;
                 j < ev.size() && ev[j].first - ev[i].first <= s.impossibleTravelWindowSeconds;
                 ++j) {
                ips.insert(ev[j].second);
            }
            if (ips.size() >= 2) {
                std::ostringstream msg;
                msg << "Impossible travel: user '" << pair.first << "' seen from "
                    << ips.size() << " distinct IPs within "
                    << s.impossibleTravelWindowSeconds << " seconds.";
                pushAlert("HIGH", "impossible_travel", msg.str(), "", pair.first, ev[i].first);
                break;
            }
        }
    }
}

// PRIVILEGE ESCALATION: sudo/su/escalation keywords together with denied/failed.
void detectPrivilegeEscalation(const std::vector<LogEntry>& entries,
                               const DetectionSettings& /*s*/) {
    for (const auto& e : entries) {
        std::string m = toLower(e.message);
        bool priv = m.find("sudo") != std::string::npos
                 || m.find("escalat") != std::string::npos
                 || m.find("runas") != std::string::npos
                 || m.find("su:") != std::string::npos
                 || m.rfind("su ", 0) == 0
                 || m.find(" su ") != std::string::npos;
        bool denied = m.find("failed") != std::string::npos
                   || m.find("denied") != std::string::npos
                   || m.find("unauthorized") != std::string::npos
                   || m.find("not permitted") != std::string::npos
                   || m.find("not allowed") != std::string::npos;
        if (priv && denied) {
            std::ostringstream msg;
            msg << "Possible privilege escalation attempt: \""
                << e.message.substr(0, 100) << "\"";
            pushAlert("HIGH", "privilege_escalation", msg.str(),
                      e.ip, e.user, logEntryEpoch(e));
        }
    }
}

// Parse a data volume mentioned in a message, normalized to megabytes.
double parseVolumeMB(const std::string& msg) {
    double total = 0.0;
    size_t i = 0;
    while (i < msg.size()) {
        bool digitStart = std::isdigit(static_cast<unsigned char>(msg[i])) != 0;
        bool dotStart = msg[i] == '.' && i + 1 < msg.size()
            && std::isdigit(static_cast<unsigned char>(msg[i + 1])) != 0;
        if (digitStart || dotStart) {
            size_t j = i;
            while (j < msg.size()
                   && (std::isdigit(static_cast<unsigned char>(msg[j])) != 0
                       || msg[j] == '.' || msg[j] == ',')) ++j;
            std::string num = msg.substr(i, j - i);
            num.erase(std::remove(num.begin(), num.end(), ','), num.end());
            size_t k = j;
            while (k < msg.size() && msg[k] == ' ') ++k;
            size_t u = k;
            while (u < msg.size() && std::isalpha(static_cast<unsigned char>(msg[u])) != 0) ++u;
            std::string unit = toLower(msg.substr(k, u - k));
            double mult = 0.0;
            if (unit == "b" || unit == "byte" || unit == "bytes") mult = 1.0 / (1024 * 1024);
            else if (unit == "kb" || unit == "kbyte" || unit == "kbytes" || unit == "kilobyte" || unit == "kilobytes") mult = 1.0 / 1024;
            else if (unit == "mb" || unit == "mbyte" || unit == "mbytes" || unit == "megabyte" || unit == "megabytes") mult = 1.0;
            else if (unit == "gb" || unit == "gbyte" || unit == "gbytes" || unit == "gigabyte" || unit == "gigabytes") mult = 1024.0;
            else if (unit == "tb" || unit == "terabyte" || unit == "terabytes") mult = 1024.0 * 1024;
            if (mult > 0.0) {
                try { total += std::stod(num) * mult; }
                catch (const std::exception&) { /* ignore unparsable */ }
            }
            i = (u > k) ? u : j;
        } else {
            ++i;
        }
    }
    return total;
}

// DATA EXFILTRATION: large transfer volumes per IP inside a short window.
void detectDataExfiltration(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    std::unordered_map<std::string, std::vector<std::pair<long long, double>>> byIp;
    for (const auto& e : entries) {
        if (e.ip.empty()) continue;
        std::string m = toLower(e.message);
        bool xfer = m.find("byte") != std::string::npos
                 || m.find("download") != std::string::npos
                 || m.find("upload") != std::string::npos
                 || m.find("transfer") != std::string::npos;
        if (!xfer) continue;
        double mb = parseVolumeMB(e.message);
        if (mb <= 0.0) continue;
        byIp[e.ip].push_back({logEntryEpoch(e), mb});
    }
    for (auto& pair : byIp) {
        auto& ev = pair.second;
        std::sort(ev.begin(), ev.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        for (size_t i = 0; i < ev.size(); ++i) {
            double sum = 0.0;
            for (size_t j = i;
                 j < ev.size() && ev[j].first - ev[i].first <= s.exfilWindowSeconds;
                 ++j) {
                sum += ev[j].second;
            }
            if (sum >= s.exfilMinMB) {
                std::ostringstream msg;
                msg << "Possible data exfiltration from " << pair.first << ": "
                    << static_cast<long long>(sum) << " MB transferred within "
                    << s.exfilWindowSeconds << " seconds.";
                pushAlert("HIGH", "data_exfiltration", msg.str(), pair.first, "", ev[i].first);
                break;
            }
        }
    }
}

// NEW IP FOR USER: a known user appears from an IP never seen for them.
// The user's very first appearance is not an alert.
void detectNewIpForUser(const std::vector<LogEntry>& entries,
                         const DetectionSettings& /*s*/) {
    std::unordered_map<std::string, std::unordered_set<std::string>> knownIps;
    std::unordered_set<std::string> seenUsers;
    std::vector<const LogEntry*> order;
    order.reserve(entries.size());
    for (const auto& e : entries) order.push_back(&e);
    std::sort(order.begin(), order.end(),
              [](const LogEntry* a, const LogEntry* b) {
                  return logEntryEpoch(*a) < logEntryEpoch(*b);
              });
    for (const LogEntry* pp : order) {
        const LogEntry& e = *pp;
        if (e.user.empty() || e.ip.empty()) continue;
        if (seenUsers.count(e.user) != 0 && knownIps[e.user].count(e.ip) == 0) {
            std::ostringstream msg;
            msg << "New IP for user '" << e.user << "': first seen from " << e.ip << ".";
            pushAlert("MEDIUM", "new_ip_for_user", msg.str(), e.ip, e.user, logEntryEpoch(e));
        }
        seenUsers.insert(e.user);
        knownIps[e.user].insert(e.ip);
    }
}

// The detection pipeline: every detector, one call, fresh vector.
void runAllDetectors(const std::vector<LogEntry>& entries, const DetectionSettings& settings) {
    alerts.clear();

    std::unordered_map<std::string, int> failedLoginCounts, failedUserCounts;
    std::unordered_map<std::string, std::vector<int>> failedLoginTimes;
    for (const auto& e : entries)
        trackFailedLogin(e, failedLoginCounts, failedUserCounts, failedLoginTimes);

    pushRepeatedFailureAlerts(entries, failedLoginCounts, failedUserCounts, settings);
    pushRapidBruteForceEpochAlerts(entries, settings);
    detectPasswordSpray(entries, settings);
    detectDistributedAttack(entries, settings);
    detectLoginBurst(entries, settings);
    detectErrorBursts(entries, settings);
    detectRepeatedErrors(entries, settings);
    detectServiceFailures(entries, settings);
    detectWarnEscalation(entries, settings);
    detectDenseActivity(entries, settings);
    detectOffHoursAccess(entries, settings);
    detectImpossibleTravel(entries, settings);
    detectPrivilegeEscalation(entries, settings);
    detectDataExfiltration(entries, settings);
    detectNewIpForUser(entries, settings);

    int errorCount = 0;
    for (const auto& e : entries) if (e.severity == "ERROR") errorCount++;
    if (hasHighErrorRate(static_cast<int>(entries.size()), errorCount, settings)) {
        std::ostringstream msg;
        msg << "High global error rate: " << errorCount << " of " << entries.size()
            << " logs are ERROR.";
        pushAlert("MEDIUM", "high_error_rate", msg.str());
    }
}

// ---------- threat / risk scoring ----------
int scoreForAlertType(const std::string& type) {
    if (type == "repeated_failures")  return 10;
    if (type == "rapid_brute_force")  return 30;
    if (type == "password_spray")     return 40;
    if (type == "distributed_attack") return 40;
    if (type == "login_burst")        return 35;
    if (type == "error_burst")        return 15;
    if (type == "repeated_error")     return 10;
    if (type == "service_failure")    return 15;
    if (type == "warn_escalation")    return 10;
    if (type == "dense_activity")     return 5;
    if (type == "high_error_rate")    return 20;
    if (type == "off_hours_access")   return 15;
    if (type == "impossible_travel")  return 35;
    if (type == "privilege_escalation") return 30;
    if (type == "data_exfiltration")  return 35;
    if (type == "new_ip_for_user")    return 10;
    return 5;
}

std::string riskTier(int score) {
    if (score >= 80) return "CRITICAL";
    if (score >= 50) return "HIGH";
    if (score >= 25) return "MEDIUM";
    return "LOW";
}
// Aggregate scores per IP and per user across ALL alerts.
void aggregateRiskScores(std::unordered_map<std::string, int>& ipScores,
                         std::unordered_map<std::string, int>& userScores) {
    for (const auto& a : alerts) {
        int pts = scoreForAlertType(a.type);
        if (!a.ip.empty())   ipScores[a.ip] += pts;
        if (!a.user.empty()) userScores[a.user] += pts;
    }
}

int riskScoreForIp(const std::string& ip) {
    std::unordered_map<std::string, int> ipScores, userScores;
    aggregateRiskScores(ipScores, userScores);
    auto it = ipScores.find(ip);
    return it == ipScores.end() ? 0 : it->second;
}

int riskScoreForUser(const std::string& user) {
    std::unordered_map<std::string, int> ipScores, userScores;
    aggregateRiskScores(ipScores, userScores);
    int score = 0;
    for (const auto& p : userScores)
        if (toLower(p.first) == toLower(user)) score = p.second;
    return score;
}
void printRiskScores() {
    std::unordered_map<std::string, int> ipScores, userScores;
    aggregateRiskScores(ipScores, userScores);
    std::cout << "\n --- Risk Scores --- \n";
    for (const auto& pair : ipScores)
        std::cout << "IP " << pair.first << ": " << pair.second
                  << " [" << riskTier(pair.second) << "]\n";
    for (const auto& pair : userScores)
        std::cout << "User " << pair.first << ": " << pair.second
                  << " [" << riskTier(pair.second) << "]\n";
}

void exportRiskSection(std::ofstream& report) {
    std::unordered_map<std::string, int> ipScores, userScores;
    aggregateRiskScores(ipScores, userScores);
    report << "Risk scores:\n";
    for (const auto& pair : ipScores)
        report << "  IP " << pair.first << ": " << pair.second
               << " [" << riskTier(pair.second) << "]\n";
    for (const auto& pair : userScores)
        report << "  User " << pair.first << ": " << pair.second
               << " [" << riskTier(pair.second) << "]\n";
    report << "\n";
}

// compiled: clean. scores accumulate across detectors instead of
// living and dying inside one threshold check.
// ============================================================
// INCIDENT CORRELATION ENGINE
// Related alerts (shared IP or user) become one Incident with
// a real duration, worst severity, and combined risk.
// ============================================================


int severityRank(const std::string& s) {
    if (s == "CRITICAL") return 4;
    if (s == "HIGH")     return 3;
    if (s == "MEDIUM")   return 2;
    return 1;
}

std::string formatDuration(long long seconds) {
    if (seconds < 0) seconds = 0;
    if (seconds < 60) return std::to_string(seconds) + " seconds";
    long long m = seconds / 60, s = seconds % 60;
    if (m < 60) return std::to_string(m) + "m " + std::to_string(s) + "s";
    return std::to_string(m / 60) + "h " + std::to_string(m % 60) + "m";
}
// Group alerts into incidents: a shared non-empty IP or user chains
// an alert onto the seed's incident.
std::vector<Incident> correlateIncidents(const std::vector<Alert>& allAlerts) {
    std::vector<Incident> incidents;
    std::vector<bool> used(allAlerts.size(), false);
    int nextId = 1;

    for (size_t i = 0; i < allAlerts.size(); ++i) {
        if (used[i]) continue;
        const Alert& seed = allAlerts[i];
        Incident inc;
        inc.id = nextId++;
        inc.severity = seed.severity;
        inc.eventCount = 0;
        inc.riskScore = 0;
        inc.startTime = 0;
        inc.endTime = 0;
        std::unordered_set<std::string> ipSet, userSet, typeSet;

        for (size_t j = i; j < allAlerts.size(); ++j) {
            if (used[j]) continue;
            const Alert& a = allAlerts[j];
            bool sameIp = !seed.ip.empty() && seed.ip == a.ip;
            bool sameUser = !seed.user.empty() && seed.user == a.user;
            if (j == i || sameIp || sameUser) {
                used[j] = true;
                if (severityRank(a.severity) > severityRank(inc.severity))
                    inc.severity = a.severity;
                if (!a.ip.empty())   ipSet.insert(a.ip);
                if (!a.user.empty()) userSet.insert(a.user);
                typeSet.insert(a.type);
                inc.riskScore += scoreForAlertType(a.type);
                inc.eventCount++;
                if (a.epoch > 0) {
                    if (inc.startTime == 0 || a.epoch < inc.startTime) inc.startTime = a.epoch;
                    if (a.epoch > inc.endTime) inc.endTime = a.epoch;
                }
            }
        }
        inc.ips.assign(ipSet.begin(), ipSet.end());
        inc.users.assign(userSet.begin(), userSet.end());
        inc.detectorTypes.assign(typeSet.begin(), typeSet.end());
        incidents.push_back(inc);
    }
    return incidents;
}
void printIncidents(const std::vector<Incident>& incidents) {
    std::cout << "\n --- Incidents (" << incidents.size() << ") --- \n";
    for (const auto& inc : incidents) {
        std::cout << "\nINCIDENT #" << inc.id << " -- " << inc.severity << "\n";
        if (inc.startTime > 0 && inc.endTime > inc.startTime)
            std::cout << "Duration: " << formatDuration(inc.endTime - inc.startTime) << "\n";
        if (!inc.ips.empty()) {
            std::cout << "IPs: ";
            for (const auto& ip : inc.ips) std::cout << ip << " ";
            std::cout << "\n";
        }
        if (!inc.users.empty())
            std::cout << "Users targeted: " << inc.users.size() << "\n";
        std::cout << "Events: " << inc.eventCount
                  << " | Risk score: " << inc.riskScore
                  << " [" << riskTier(inc.riskScore) << "]\n";
        std::cout << "Detectors triggered:\n";
        for (const auto& t : inc.detectorTypes) std::cout << "  - " << t << "\n";
    }
}

void exportIncidentsSection(std::ofstream& report,
                            const std::vector<Incident>& incidents) {
    report << "Incidents (" << incidents.size() << "):\n";
    for (const auto& inc : incidents) {
        report << "\nINCIDENT #" << inc.id << " -- " << inc.severity << "\n";
        if (inc.startTime > 0 && inc.endTime > inc.startTime)
            report << "Duration: " << formatDuration(inc.endTime - inc.startTime) << "\n";
        report << "Events: " << inc.eventCount
               << " | Risk score: " << inc.riskScore
               << " [" << riskTier(inc.riskScore) << "]\n";
        report << "Detectors: ";
        for (const auto& t : inc.detectorTypes) report << t << " ";
        report << "\n";
    }
    report << "\n";
}

// compiled: clean. durations work because Alert carries epoch now --
// the old startTime/endTime TODO is finally dead.
// ============================================================
