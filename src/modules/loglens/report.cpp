#include "report.h"

void printSummary(
    int totalLogs,
    int infoCount,
    int warningCount,
    int errorCount,
    int suspiciousIpCount,
    int suspiciousUserCount,
    int invalidLineCount,
    bool highErrorRate,
    int rapidBruteForceCount
) {
    std::cout << "\n --- Log Summary --- \n";
    std::cout << "Total logs: " << totalLogs << '\n';
    std::cout << "INFO: " << infoCount << '\n';
    std::cout << "WARN: " << warningCount << '\n';
    std::cout << "ERROR: " << errorCount << '\n';
    std::cout << "Suspicious IPs: " << suspiciousIpCount << '\n';
    std::cout << "Suspicious Users: " << suspiciousUserCount << '\n';
    std::cout << "Total Alerts: " << suspiciousIpCount + suspiciousUserCount +(highErrorRate ? 1 : 0) + rapidBruteForceCount << '\n';
    std::cout << "Invalid lines skipped: " << invalidLineCount << '\n';
}
void exportReport(
    int totalLogs,
    int infoCount,
    int warningCount,
    int errorCount,
    int suspiciousIpCount,
    int suspiciousUserCount,
    int invalidCount,
    bool highErrorRate,
    int rapidBruteForceCount,
    const std::unordered_map<std::string, std::vector<int>>& failedLoginTimes,
    const std::unordered_map<std::string, int>& failedLoginCounts,
    const std::unordered_map<std::string, int>& failedUserCounts
) {

    std::filesystem::create_directory("reports");

    auto now = std::chrono::system_clock::now();
    std::time_t nowTime = std::chrono::system_clock::to_time_t(now);

    std::tm localTime;
    ll_localtime(&localTime, &nowTime);

    std::ostringstream filenameStream;
    filenameStream << "reports/report_"
                   << std::put_time(&localTime, "%Y-%m-%d_%H-%M-%S")
                   << ".txt";
    std::ofstream report(filenameStream.str());


    if (!report.is_open()) {
        std::cerr << "Could not create report file.\n";
        return;
    }

    report << "LogLens Analysis Report\n";
    report << "=======================\n";
    report << "Total logs: " << totalLogs << "\n";
    report << "INFO: " << infoCount << "\n";
    report << "WARN: " << warningCount << "\n";
    report << "ERROR: " << errorCount << "\n";
    report << "Suspicious IPs: " << suspiciousIpCount << "\n";
    report << "Suspicious Users: " << suspiciousUserCount << "\n";
    report << "Total Alerts: " << suspiciousIpCount + suspiciousUserCount + (highErrorRate ? 1 : 0) + rapidBruteForceCount << "\n\n";
    report << "Invalid lines skipped: " << invalidCount << "\n\n";

    report << "Alerts:\n";

    for (const auto& pair : failedLoginCounts) {
        if (pair.second >= 3) {
            std::string riskLevel = getRiskLevel(pair.second);

            report << "[" << riskLevel << "] IP "
                << pair.first
                << " had " 
                << pair.second
                << " failed login attempts.\n";
        }
    }

    for (const auto& pair :failedUserCounts) {
        if (pair.second >= 3) {
            std::string riskLevel = getRiskLevel(pair.second);

            report << "[" << riskLevel << "] User "
                << pair.first
                << " had " 
                << pair.second
                << " failed login attempts.\n";
        }
    }
    if (highErrorRate) {
        double errorPercent = (static_cast<double>(errorCount) / totalLogs) * 100;
        report << "[MEDIUM] High error rate detected: "
               << errorCount
               << " of "
               << totalLogs
               << " logs are ERROR ("
               << std::fixed << std::setprecision(1) << errorPercent
               << "%)\n";
    }



    report.close();

    std::cout << "\nReport saved to " << filenameStream.str() << "\n";
}
void exportAlertsSection(std::ofstream& report) {
    report << "Alerts (" << alerts.size() << "):\n";
    for (const auto& a : alerts) {
        report << "[" << a.severity << "] " << a.message << "\n";
    }
    report << "\n";
}

// compiled: clean. printSecurityAlerts() stays for now (compat);
// the new pipeline reads `alerts`. Final main() uses the vector.
// ============================================================

SummaryCounts computeCounts(const std::vector<LogEntry>& entries, int invalidCount,
                            const DetectionSettings& settings) {
    SummaryCounts c;
    c.invalid = invalidCount;
    std::unordered_map<std::string, int> failedLoginCounts, failedUserCounts;
    std::unordered_map<std::string, std::vector<int>> failedLoginTimes;
    for (const auto& e : entries) {
        c.total++;
        if (e.severity == "INFO") c.info++;
        else if (e.severity == "WARN") c.warn++;
        else if (e.severity == "ERROR") c.error++;
        trackFailedLogin(e, failedLoginCounts, failedUserCounts, failedLoginTimes);
    }
    for (const auto& p : failedLoginCounts) if (p.second >= 3) c.suspiciousIps++;
    for (const auto& p : failedUserCounts) if (p.second >= 3) c.suspiciousUsers++;
    c.highErrorRate = hasHighErrorRate(c.total, c.error, settings);
    c.rapidBruteForce = countAlertsOfType("rapid_brute_force");
    return c;
}

void exportFullReport(const SessionState& st) {
    std::filesystem::create_directory("reports");
    std::string path = "reports/report_full_" + reportTimestamp() + ".txt";
    std::ofstream report(path);
    if (!report.is_open()) {
        std::cerr << "Could not create report file.\n";
        return;
    }
    SummaryCounts c = computeCounts(st.entries, st.invalidCount, st.settings);
    report << "LogLens Full Analysis Report\n";
    report << "============================\n";
    report << "Source: " << st.sourcePath << "\n";
    report << "Total logs: " << c.total << " (invalid skipped: " << c.invalid << ")\n";
    writeInvalidBreakdown(report, st.invalidReasons);
    report << "INFO: " << c.info << " | WARN: " << c.warn << " | ERROR: " << c.error << "\n\n";
    exportAlertsSection(report);
    exportRapidBruteForceSection(report);
    exportIncidentsSection(report, st.incidents);
    exportRiskSection(report);
    report.close();
    std::cout << "\nFull report saved to " << path << "\n";
}

bool exportAlertsJson(const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        std::cerr << "cannot write " << path << "\n";
        return false;
    }
    out << "[\n";
    for (size_t i = 0; i < alerts.size(); ++i) {
        const Alert& a = alerts[i];
        out << "  {\n"
            << "    \"severity\": \"" << jsonEscape(a.severity) << "\",\n"
            << "    \"type\": \"" << jsonEscape(a.type) << "\",\n"
            << "    \"message\": \"" << jsonEscape(a.message) << "\",\n"
            << "    \"ip\": \"" << jsonEscape(a.ip) << "\",\n"
            << "    \"user\": \"" << jsonEscape(a.user) << "\",\n"
            << "    \"epoch\": " << a.epoch << ",\n"
            << "    \"timestamp\": \""
            << (a.epoch > 0 ? jsonEscape(epochToString(a.epoch)) : "") << "\"\n"
            << "  }" << (i + 1 < alerts.size() ? "," : "") << "\n";
    }
    out << "]\n";
    return true;
}

bool exportAlertsCsv(const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        std::cerr << "cannot write " << path << "\n";
        return false;
    }
    out << "severity,type,message,ip,user,epoch,timestamp\n";
    for (const auto& a : alerts) {
        out << csvEscape(a.severity) << ","
            << csvEscape(a.type) << ","
            << csvEscape(a.message) << ","
            << csvEscape(a.ip) << ","
            << csvEscape(a.user) << ","
            << a.epoch << ","
            << (a.epoch > 0 ? epochToString(a.epoch) : "") << "\n";
    }
    return true;
}

bool exportEntriesCsv(const std::string& path, const std::vector<LogEntry>& entries) {
    std::ofstream out(path);
    if (!out.is_open()) {
        std::cerr << "cannot write " << path << "\n";
        return false;
    }
    out << "date,time,severity,message,user,ip,source_file\n";
    for (const auto& e : entries) {
        out << csvEscape(e.date) << ","
            << csvEscape(e.time) << ","
            << csvEscape(e.severity) << ","
            << csvEscape(e.message) << ","
            << csvEscape(e.user) << ","
            << csvEscape(e.ip) << ","
            << csvEscape(e.sourceFile) << "\n";
    }
    return true;
}

// Legacy text report (last night's format), rebuilt from session state so the
// old export path keeps working alongside the new full report.
void exportLegacyReport(SessionState& st) {
    SummaryCounts c = computeCounts(st.entries, st.invalidCount, st.settings);
    std::unordered_map<std::string, std::vector<int>> failedLoginTimes;
    std::unordered_map<std::string, int> failedLoginCounts, failedUserCounts;
    for (const auto& e : st.entries)
        trackFailedLogin(e, failedLoginCounts, failedUserCounts, failedLoginTimes);
    exportReport(c.total, c.info, c.warn, c.error,
                 c.suspiciousIps, c.suspiciousUsers, st.invalidCount,
                 c.highErrorRate, countAlertsOfType("rapid_brute_force"),
                 failedLoginTimes, failedLoginCounts, failedUserCounts);
}

void filterLogs(const std::vector<LogEntry>& entries) {
    std::string filterChoice;

    while (true) {
        std::cout << "\nWould you like to filter logs? (y/n):";
        std::getline(std::cin, filterChoice);

        filterChoice = toLower(filterChoice);

        if (filterChoice == "y"){
            break;
        } else if (filterChoice == "n") {
            return;
        } else {
            std::cout << "Invalid choice. Please enter 'y' or 'n'.\n";
        } 
    }

    std::string filterType;
    std::string filterValue;

    while (true) {
        std::cout << "Filter by severity, user, ip, or keyword: ";
        std::getline(std::cin, filterType);

        filterType = toLower(filterType);

        if (filterType == "severity" ||
            filterType == "user" ||
            filterType == "ip" ||
            filterType == "keyword") {
            break;
        } 

        std::cout << "Invalid filter type. Try again.\n";
    }

    std::cout << "Enter value to filter by: ";
    std::getline(std::cin, filterValue);

    std::cout << "\n--- Filter Results ---\n";

    bool found = false;

    for (const auto& entry : entries) {
        bool match = false;

        std::string type = toLower(filterType);
        std::string value = toLower(filterValue);

        if (type == "severity" && toLower(entry.severity) == value) {
            match = true;
        }
        else if (type == "user" && toLower(entry.user) == value) {
            match = true;
        }
        else if (type == "ip" && entry.ip == filterValue) {
            match = true;
        }
        else if (type == "keyword" && toLower(entry.message).find(value) != std::string::npos) {
            match = true;
        }

        if (match) {
            found = true;

            std::cout << entry.date
                      << " | " << entry.time
                      << " | " << entry.severity
                      << " | " << entry.message
                      << '\n';
        }
    }
    if (!found) {
        std::cout << "No matching logs found.\n";
    }
}
// ADVANCED QUERYING
// severity=ERROR user=admin contains="db timeout" after=18:40:00
// Combinations work. Quotes group multi-word values.
// ============================================================


Query parseQuery(const std::string& input) {
    Query q;
    std::vector<std::string> tokens;
    std::string cur;
    bool inQuotes = false;
    for (char c : input) {
        if (c == '"') { inQuotes = !inQuotes; continue; }
        if (c == ' ' && !inQuotes) {
            if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
        } else cur += c;
    }
    if (!cur.empty()) tokens.push_back(cur);

    for (const auto& token : tokens) {
        auto pos = token.find('=');
        if (pos == std::string::npos) continue;
        std::string key = toLower(token.substr(0, pos));
        std::string val = token.substr(pos + 1);
        if (key == "severity")      q.severity = val;
        else if (key == "user")     q.user = val;
        else if (key == "ip")       q.ip = val;
        else if (key == "contains") q.contains = val;
        else if (key == "after")    q.after = val;
        else if (key == "before")   q.before = val;
    }
    return q;
}
// Time bounds: "HH:MM:SS" applies to each entry's own date;
// "YYYY-MM-DD HH:MM:SS" is absolute.

// Time bounds: "HH:MM:SS" applies to each entry's own date;
// "YYYY-MM-DD HH:MM:SS" is absolute. Bad input -> epoch 0 (no match shift).
static long long boundToEpoch(const std::string& bound, const std::string& refDate) {
    try {
        if (bound.size() > 8)
            return toEpochSeconds(parseDateTime(bound.substr(0, 10), bound.substr(11)));
        return toEpochSeconds(parseDateTime(refDate, bound));
    } catch (const std::exception&) {
        return 0;
    }
}

bool matchesQuery(const LogEntry& e, const Query& q) {
    if (!q.severity.empty() && toLower(e.severity) != toLower(q.severity)) return false;
    if (!q.user.empty() && toLower(e.user) != toLower(q.user)) return false;
    if (!q.ip.empty() && e.ip != q.ip) return false;
    if (!q.contains.empty() &&
        toLower(e.message).find(toLower(q.contains)) == std::string::npos) return false;
    long long ep = logEntryEpoch(e);
    if (!q.after.empty() && ep < boundToEpoch(q.after, e.date)) return false;
    if (!q.before.empty() && ep > boundToEpoch(q.before, e.date)) return false;
    return true;
}

std::vector<LogEntry> runQuery(const std::vector<LogEntry>& entries, const Query& q) {
    std::vector<LogEntry> out;
    for (const auto& e : entries)
        if (matchesQuery(e, q)) out.push_back(e);
    return out;
}
void sortEntries(std::vector<LogEntry>& entries, const std::string& key) {
    std::string k = toLower(key);
    if (k == "timestamp") {
        std::sort(entries.begin(), entries.end(),
                  [](const LogEntry& a, const LogEntry& b) {
                      return logEntryEpoch(a) < logEntryEpoch(b);
                  });
    } else if (k == "severity") {
        std::sort(entries.begin(), entries.end(),
                  [](const LogEntry& a, const LogEntry& b) { return a.severity < b.severity; });
    } else if (k == "ip") {
        std::sort(entries.begin(), entries.end(),
                  [](const LogEntry& a, const LogEntry& b) { return a.ip < b.ip; });
    } else if (k == "user") {
        std::sort(entries.begin(), entries.end(),
                  [](const LogEntry& a, const LogEntry& b) { return a.user < b.user; });
    } else if (k == "risk") {
        std::unordered_map<std::string, int> ipScores, userScores;
        aggregateRiskScores(ipScores, userScores);
        std::sort(entries.begin(), entries.end(),
                  [&](const LogEntry& a, const LogEntry& b) {
                      int sa = ipScores.count(a.ip) ? ipScores[a.ip] : 0;
                      int sb = ipScores.count(b.ip) ? ipScores[b.ip] : 0;
                      return sa > sb;
                  });
    } else {
        std::cout << "unknown sort key.\n";
    }
}
// CLI option 5: prompt, parse, run, print.
void runQueryCli(const std::vector<LogEntry>& entries) {
    std::cout << "query (e.g. severity=ERROR user=admin contains=\"db timeout\"): ";
    std::string input;
    std::getline(std::cin, input);
    if (input.empty()) return;
    Query q = parseQuery(input);
    std::vector<LogEntry> hits = runQuery(entries, q);
    for (const auto& e : hits)
        std::cout << e.date << " | " << e.time << " | " << e.severity
                  << " | " << e.message << "\n";
    std::cout << hits.size() << " hit(s).\n";
}

// compiled: clean. `severity=ERROR user=admin` combined queries work;
// quoted multi-word contains values parse correctly.
// ============================================================
// ENTITY PROFILING
// IP and user dossiers: activity, failures, risk, incidents.
// ============================================================

void printIpProfile(const std::string& ip, const std::vector<LogEntry>& entries,
                    const std::vector<Incident>& incidents) {
    int total = 0, failed = 0;
    std::unordered_set<std::string> users;
    std::string firstSeen, lastSeen;
    for (const auto& e : entries) {
        if (e.ip != ip) continue;
        total++;
        if (e.message.find("Login failed") != std::string::npos) failed++;
        if (!e.user.empty()) users.insert(e.user);
        std::string ts = e.date + " " + e.time;
        if (firstSeen.empty() || ts < firstSeen) firstSeen = ts;
        if (lastSeen.empty() || ts > lastSeen) lastSeen = ts;
    }
    int score = riskScoreForIp(ip);
    int incidentCount = 0;
    for (const auto& inc : incidents)
        for (const auto& i : inc.ips)
            if (i == ip) { incidentCount++; break; }

    std::cout << "\nIP Profile: " << ip << "\n-------------------------\n";
    std::cout << "Total events: " << total << "\n";
    std::cout << "Failed logins: " << failed << "\n";
    std::cout << "Users targeted: " << users.size() << "\n";
    std::cout << "First seen: " << (firstSeen.empty() ? "n/a" : firstSeen) << "\n";
    std::cout << "Last seen: " << (lastSeen.empty() ? "n/a" : lastSeen) << "\n";
    std::cout << "Risk score: " << score << "\n";
    std::cout << "Risk: " << riskTier(score) << "\n";
    std::cout << "Incidents: " << incidentCount << "\n";
}
void printUserProfile(const std::string& user, const std::vector<LogEntry>& entries) {
    int total = 0, failed = 0, success = 0;
    std::unordered_set<std::string> ips;
    for (const auto& e : entries) {
        if (toLower(e.user) != toLower(user)) continue;
        total++;
        if (e.message.find("Login failed") != std::string::npos) failed++;
        if (e.message.find("Login successful") != std::string::npos) success++;
        if (!e.ip.empty()) ips.insert(e.ip);
    }
    int score = riskScoreForUser(user);
    int alertCount = 0;
    for (const auto& a : alerts)
        if (toLower(a.user) == toLower(user)) alertCount++;

    std::cout << "\nUser Profile: " << user << "\n-------------------------\n";
    std::cout << "Total events: " << total << "\n";
    std::cout << "Failed logins: " << failed << "\n";
    std::cout << "Successful logins: " << success << "\n";
    std::cout << "Source IPs: " << ips.size() << "\n";
    std::cout << "Alerts involving user: " << alertCount << "\n";
    std::cout << "Risk score: " << score << "\n";
    std::cout << "Risk: " << riskTier(score) << "\n";
}

// compiled: clean. the CLI forward declarations from the menu phase
// resolve here. options 8/9 fully wired.
// ============================================================
