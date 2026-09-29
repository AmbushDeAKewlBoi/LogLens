#include "cli.h"

void printSummaryFromEntries(const std::vector<LogEntry>& entries, int invalidCount,
                             const std::map<std::string, int>& invalidReasons,
                             const DetectionSettings& settings) {
    SummaryCounts c = computeCounts(entries, invalidCount, settings);
    printSummary(c.total, c.info, c.warn, c.error, c.suspiciousIps,
                 c.suspiciousUsers, c.invalid, c.highErrorRate, c.rapidBruteForce);
    writeInvalidBreakdown(std::cout, invalidReasons);
}

void refreshAnalysis(SessionState& st) {
    runAllDetectors(st.entries, st.settings);
    st.incidents = correlateIncidents(alerts);
}

bool loadIntoState(SessionState& st, const std::string& path) {
    std::vector<std::string> files = discoverLogFiles(path);
    if (files.empty()) {
        std::cout << "no .log files found at: " << path << "\n";
        return false;
    }
    st.sourcePath = path;
    st.invalidReasons.clear();
    st.entries = loadLogs(files, st.invalidCount, st.invalidReasons);
    refreshAnalysis(st);
    std::cout << "loaded " << st.entries.size() << " entries from "
              << files.size() << " file(s).\n";
    return true;
}

// --- menu helpers ---
void alertsMenu() {
    std::cout << "severity filter (LOW/MEDIUM/HIGH/CRITICAL, empty=all): ";
    std::string sev;
    std::getline(std::cin, sev);
    std::cout << "type filter (empty=all): ";
    std::string typ;
    std::getline(std::cin, typ);
    sev = toUpper(sev);
    typ = toLower(typ);
    int n = 0;
    for (const auto& a : alerts) {
        if (!sev.empty() && a.severity != sev) continue;
        if (!typ.empty() && toLower(a.type).find(typ) == std::string::npos) continue;
        std::cout << "[" << a.severity << "] (" << a.type << ") " << a.message << "\n";
        ++n;
    }
    std::cout << n << " alert(s) shown.\n";
}

void filterQueryMenu(SessionState& st) {
    std::cout << "1. Filter logs\n2. Query logs\n3. Both\n4. Sort logs\n0. Back\nchoice: ";
    std::string c;
    std::getline(std::cin, c);
    if (c == "1" || c == "3") filterLogs(st.entries);
    if (c == "2" || c == "3") runQueryCli(st.entries);
    if (c == "4") {
        std::cout << "sort by (timestamp/severity/ip/user/risk): ";
        std::string key; std::getline(std::cin, key);
        std::vector<LogEntry> sorted = st.entries;
        sortEntries(sorted, key);
        for (size_t i = 0; i < sorted.size() && i < 20; ++i)
            std::cout << sorted[i].date << " | " << sorted[i].time << " | "
                      << sorted[i].severity << " | " << sorted[i].message << "\n";
        if (sorted.size() > 20)
            std::cout << "... (" << sorted.size() - 20 << " more)\n";
    }
    if (c != "0" && c != "1" && c != "2" && c != "3" && c != "4") std::cout << "unknown choice.\n";
}

void exportMenu(SessionState& st) {
    while (true) {
        std::cout << "\n--- Export ---\n"
                  << "1. Full text report\n"
                  << "2. Alerts JSON\n"
                  << "3. Alerts CSV\n"
                  << "4. Entries CSV\n"
                  << "5. Legacy text report\n"
                  << "0. Back\nchoice: ";
        std::string c;
        if (!std::getline(std::cin, c)) break;
        if (c == "0") break;
        std::filesystem::create_directory("reports");
        std::string ts = reportTimestamp();
        if (c == "1") {
            exportFullReport(st);
        } else if (c == "2") {
            std::string p = "reports/alerts_" + ts + ".json";
            if (exportAlertsJson(p)) std::cout << "wrote " << p << "\n";
        } else if (c == "3") {
            std::string p = "reports/alerts_" + ts + ".csv";
            if (exportAlertsCsv(p)) std::cout << "wrote " << p << "\n";
        } else if (c == "4") {
            std::string p = "reports/entries_" + ts + ".csv";
            if (exportEntriesCsv(p, st.entries)) std::cout << "wrote " << p << "\n";
        } else if (c == "5") {
            exportLegacyReport(st);
        } else {
            std::cout << "unknown choice.\n";
        }
    }
}

void profileMenu(SessionState& st) {
    std::cout << "1. IP profile\n2. User profile\n0. Back\nchoice: ";
    std::string c;
    std::getline(std::cin, c);
    if (c == "1") {
        std::cout << "ip: ";
        std::string ip;
        std::getline(std::cin, ip);
        printIpProfile(ip, st.entries, st.incidents);
    } else if (c == "2") {
        std::cout << "user: ";
        std::string user;
        std::getline(std::cin, user);
        printUserProfile(user, st.entries);
    } else if (c != "0") {
        std::cout << "unknown choice.\n";
    }
}

bool changeSetting(DetectionSettings& s, int num) {
    std::string val;
    auto getInt = [&](const char* name, int& field, int lo, int hi) {
        std::cout << name << " [" << field << "]: ";
        std::getline(std::cin, val);
        if (val.empty()) { std::cout << "unchanged.\n"; return false; }
        try {
            int v = std::stoi(val);
            if (v < lo || v > hi) { std::cout << "out of range.\n"; return false; }
            field = v;
            return true;
        } catch (const std::exception&) { std::cout << "not a number.\n"; return false; }
    };
    auto getLL = [&](const char* name, long long& field, long long lo, long long hi) {
        std::cout << name << " [" << field << "]: ";
        std::getline(std::cin, val);
        if (val.empty()) { std::cout << "unchanged.\n"; return false; }
        try {
            long long v = std::stoll(val);
            if (v < lo || v > hi) { std::cout << "out of range.\n"; return false; }
            field = v;
            return true;
        } catch (const std::exception&) { std::cout << "not a number.\n"; return false; }
    };
    auto getDbl = [&](const char* name, double& field, double lo, double hi) {
        std::cout << name << " [" << field << "]: ";
        std::getline(std::cin, val);
        if (val.empty()) { std::cout << "unchanged.\n"; return false; }
        try {
            double v = std::stod(val);
            if (v < lo || v > hi) { std::cout << "out of range.\n"; return false; }
            field = v;
            return true;
        } catch (const std::exception&) { std::cout << "not a number.\n"; return false; }
    };
    switch (num) {
        case 1:  return getInt("brute_force_min_attempts", s.bruteForceMinAttempts, 2, 100000);
        case 2:  return getLL("brute_force_window_seconds", s.bruteForceWindowSeconds, 1, 86400);
        case 3:  return getInt("spray_min_users", s.sprayMinUsers, 2, 100000);
        case 4:  return getLL("spray_window_seconds", s.sprayWindowSeconds, 1, 86400);
        case 5:  return getInt("distributed_min_ips", s.distributedMinIps, 2, 100000);
        case 6:  return getLL("distributed_window_seconds", s.distributedWindowSeconds, 1, 86400);
        case 7:  return getInt("login_burst_min_attempts", s.loginBurstMinAttempts, 2, 1000000);
        case 8:  return getLL("login_burst_window_seconds", s.loginBurstWindowSeconds, 1, 86400);
        case 9:  return getInt("error_burst_min_count", s.errorBurstMinCount, 2, 100000);
        case 10: return getLL("error_burst_window_seconds", s.errorBurstWindowSeconds, 1, 86400);
        case 11: return getInt("repeated_failure_min_attempts", s.repeatedFailureMinAttempts, 2, 100000);
        case 12: return getInt("repeated_error_min_count", s.repeatedErrorMinCount, 2, 100000);
        case 13: return getInt("service_failure_min_count", s.serviceFailureMinCount, 2, 100000);
        case 14: return getLL("warn_escalation_window_seconds", s.warnEscalationWindowSeconds, 1, 86400);
        case 15: return getInt("high_error_min_errors", s.highErrorMinErrors, 1, 1000000);
        case 16: return getDbl("high_error_min_rate", s.highErrorMinRate, 0.0, 1.0);
        case 17: return getLL("dense_window_seconds", s.denseWindowSeconds, 1, 3600);
        case 18: return getInt("off_hours_start", s.offHoursStart, 0, 23);
        case 19: return getInt("off_hours_end", s.offHoursEnd, 0, 23);
        case 20: return getLL("impossible_travel_window_seconds", s.impossibleTravelWindowSeconds, 1, 86400);
        case 21: return getLL("exfil_window_seconds", s.exfilWindowSeconds, 1, 86400);
        case 22: return getDbl("exfil_min_mb", s.exfilMinMB, 0.0, 1e12);
        default: std::cout << "unknown setting number.\n"; return false;
    }
}

void settingsMenu(SessionState& st) {
    while (true) {
        std::cout << "\n--- Detection settings ---\n"
                  << "1. View settings\n"
                  << "2. Change a setting\n"
                  << "3. Load settings from file\n"
                  << "4. Save settings to file\n"
                  << "0. Back\nchoice: ";
        std::string c;
        if (!std::getline(std::cin, c)) break;
        if (c == "0") break;
        else if (c == "1") printSettings(st.settings);
        else if (c == "2") {
            printSettings(st.settings);
            std::cout << "setting number (0=cancel): ";
            std::string n;
            std::getline(std::cin, n);
            int num = 0;
            try { num = std::stoi(n); } catch (const std::exception&) { num = -1; }
            if (num > 0 && changeSetting(st.settings, num)) {
                refreshAnalysis(st);
                std::cout << "settings applied; analysis refreshed.\n";
            }
        } else if (c == "3") {
            std::cout << "config path: ";
            std::string p;
            std::getline(std::cin, p);
            if (!p.empty() && loadSettings(p, st.settings)) {
                refreshAnalysis(st);
                std::cout << "loaded; analysis refreshed.\n";
            }
        } else if (c == "4") {
            std::cout << "config path [loglens.cfg]: ";
            std::string p;
            std::getline(std::cin, p);
            if (p.empty()) p = "loglens.cfg";
            if (saveSettings(p, st.settings)) std::cout << "saved to " << p << "\n";
        } else {
            std::cout << "unknown choice.\n";
        }
    }
}

// ---------- live log monitoring ----------
// Tails the file: polls for appended bytes every 500ms, parses + validates
// each new line, runs the fast brute-force check immediately and a full
// detector refresh every 5s. Handles truncation/rotation. Stops on
// Ctrl+C (SIGINT) or q+Enter.
volatile std::sig_atomic_t g_liveStop = 0;
void liveSigintHandler(int) { g_liveStop = 1; }

bool stdinHasQuit() {
#if defined(_WIN32)
    // Non-blocking console check: any keypress of q/Q stops the monitor.
    if (_kbhit()) {
        int ch = _getch();
        if (ch == 'q' || ch == 'Q') return true;
    }
    return false;
#else
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    struct timeval tv{0, 0};
    if (select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv) <= 0) return false;
    std::string line;
    if (!std::getline(std::cin, line)) return true;  // EOF -> quit
    return toLower(line) == "q";
#endif
}

void liveCheckEntry(const LogEntry& e,
                    std::unordered_map<std::string, std::vector<long long>>& recentFails,
                    const DetectionSettings& settings) {
    if (e.message.find("Login failed") != std::string::npos && !e.ip.empty()) {
        recentFails[e.ip].push_back(logEntryEpoch(e));
        auto& v = recentFails[e.ip];
        if (v.size() > 50) v.erase(v.begin(), v.begin() + (v.size() - 50));  // cap memory
        if (occurredWithin(v, settings.bruteForceWindowSeconds,
                           settings.bruteForceMinAttempts)) {
            std::cout << "\n>>> [HIGH] RAPID BRUTE FORCE from " << e.ip << " <<<\n\n";
        }
    }
}

void liveMonitor(const std::string& path, const DetectionSettings& settings) {
    std::cout << "\nLogLens Live Monitor\nWatching: " << path
              << "\n(Ctrl+C or q+Enter to stop)\n\n";
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        std::cerr << "not a regular file: " << path << "\n";
        return;
    }

    g_liveStop = 0;
#if defined(_WIN32)
    auto oldSig = std::signal(SIGINT, liveSigintHandler);
#else
    struct sigaction sa{};
    struct sigaction oldsa{};
    sa.sa_handler = liveSigintHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, &oldsa);
#endif

    std::uintmax_t offset = fs::file_size(path, ec);
    if (ec) offset = 0;
    std::string carry;  // trailing partial line from the previous poll
    std::vector<LogEntry> entries;
    std::unordered_map<std::string, std::vector<long long>> recentFails;
    std::unordered_set<std::string> seenAlertKeys;
    auto lastFull = std::chrono::steady_clock::now();

    while (g_liveStop == 0) {
        if (stdinHasQuit()) break;

        std::uintmax_t size = fs::file_size(path, ec);
        if (!ec) {
            if (size < offset) {
                std::cout << "[live] file truncated or rotated -- restarting from beginning.\n";
                offset = 0;
                carry.clear();
                entries.clear();
                recentFails.clear();
                alerts.clear();
                seenAlertKeys.clear();
            } else if (size > offset) {
                std::ifstream in(path, std::ios::binary);
                if (in) {
                    in.seekg(static_cast<std::streamoff>(offset));
                    std::string chunk(static_cast<size_t>(size - offset), '\0');
                    in.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
                    chunk.resize(static_cast<size_t>(in.gcount()));
                    offset += chunk.size();
                    std::string data = carry + chunk;
                    carry.clear();
                    size_t pos = 0;
                    while (true) {
                        size_t nl = data.find('\n', pos);
                        if (nl == std::string::npos) { carry = data.substr(pos); break; }
                        std::string line = data.substr(pos, nl - pos);
                        if (!line.empty() && line.back() == '\r') line.pop_back();
                        pos = nl + 1;
                        if (line.empty()) continue;
                        LogEntry e = parseLogLine(line);
                        if (invalidReason(e) != InvalidReason::OK) continue;
                        e.sourceFile = path;
                        entries.push_back(e);
                        std::cout << "[" << e.time << "] " << e.severity
                                  << "  " << e.message << "\n";
                        liveCheckEntry(e, recentFails, settings);
                    }
                    if (entries.size() > 100000)  // cap memory on very long watches
                        entries.erase(entries.begin(), entries.begin() + 20000);
                }
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (!entries.empty() && now - lastFull >= std::chrono::seconds(5)) {
            lastFull = now;
            runAllDetectors(entries, settings);
            for (const auto& a : alerts) {
                if (seenAlertKeys.insert(alertKey(a)).second) {
                    std::cout << "[live "
                              << (a.epoch > 0 ? epochToString(a.epoch)
                                              : epochToString(std::time(nullptr)))
                              << "] [" << a.severity << "] " << a.message << "\n";
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

#if defined(_WIN32)
    std::signal(SIGINT, oldSig);
#else
    sigaction(SIGINT, &oldsa, nullptr);
#endif
    std::cout << "\nlive monitor stopped.\n";
}

// ---------- the interactive menu ----------
void runCli(SessionState& st) {
    while (true) {
        std::cout << "\n========= LogLens =========\n"
                  << "1. Summary\n"
                  << "2. Security alerts\n"
                  << "3. Filter / query logs\n"
                  << "4. Export\n"
                  << "5. Live tail mode\n"
                  << "6. IP & user profiles\n"
                  << "7. Detection settings\n"
                  << "8. Incidents\n"
                  << "9. Risk scores\n"
                  << "0. Exit\n"
                  << "choice: ";
        std::string choice;
        if (!std::getline(std::cin, choice)) { std::cout << "\nbye.\n"; break; }

        if (choice == "0") { std::cout << "bye.\n"; break; }
        else if (choice == "1")
            printSummaryFromEntries(st.entries, st.invalidCount, st.invalidReasons, st.settings);
        else if (choice == "2") alertsMenu();
        else if (choice == "3") filterQueryMenu(st);
        else if (choice == "4") exportMenu(st);
        else if (choice == "5") {
            std::string p = st.sourcePath;
            if (!std::filesystem::is_regular_file(p)) {
                std::cout << "file to watch: ";
                std::getline(std::cin, p);
            } else {
                std::cout << "watch [" << p << "] (Enter) or type another path: ";
                std::string alt;
                std::getline(std::cin, alt);
                if (!alt.empty()) p = alt;
            }
            if (!p.empty()) liveMonitor(p, st.settings);
        }
        else if (choice == "6") profileMenu(st);
        else if (choice == "7") settingsMenu(st);
        else if (choice == "8") printIncidents(st.incidents);
        else if (choice == "9") printRiskScores();
        else std::cout << "unknown choice.\n";
    }
}
