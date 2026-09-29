#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <thread>
#include <cstring>
#include <csignal>
#include <map>
#include <cctype>
#include <random>
#include <deque>
#if !defined(_WIN32)
#include <sys/select.h>
#include <unistd.h>
#else
#include <conio.h>
#endif

#if defined(_WIN32)
// localtime_s on Windows, plain localtime on POSIX
#define ll_localtime(out, t) localtime_s((out), (t))
#else
inline int ll_localtime(std::tm* out, const std::time_t* t) {
    const std::tm* r = std::localtime(t);
    if (!r) return 1;
    std::memcpy(out, r, sizeof(std::tm));
    return 0;
}
#endif

struct LogEntry {
    std::string date;
    std::string time;
    std::string severity;
    std::string message;
    std::string user;
    std::string ip;
    std::string sourceFile;
};

enum class InvalidReason { OK, BAD_DATE, BAD_TIME, BAD_SEVERITY, MISSING_MESSAGE };

struct Alert {
    std::string severity;
    std::string type;
    std::string message;
    std::string ip;
    std::string user;
    long long epoch;
};

struct DateTime {
    int year, month, day, hour, minute, second;
};

struct DetectionSettings {
    int bruteForceMinAttempts = 3;
    long long bruteForceWindowSeconds = 60;
    int sprayMinUsers = 5;
    long long sprayWindowSeconds = 300;
    int distributedMinIps = 4;
    long long distributedWindowSeconds = 300;
    int loginBurstMinAttempts = 20;
    long long loginBurstWindowSeconds = 60;
    int errorBurstMinCount = 3;
    long long errorBurstWindowSeconds = 120;
    int repeatedFailureMinAttempts = 3;
    int repeatedErrorMinCount = 3;
    int serviceFailureMinCount = 3;
    long long warnEscalationWindowSeconds = 300;
    int highErrorMinErrors = 3;
    double highErrorMinRate = 0.30;
    long long denseWindowSeconds = 60;
    int offHoursStart = 22;
    int offHoursEnd = 6;
    long long impossibleTravelWindowSeconds = 600;
    long long exfilWindowSeconds = 600;
    double exfilMinMB = 100.0;
    long long largeFileLines = 200000;
    long long streamRetainMinutes = 120;
};

struct Incident {
    int id;
    long long startTime;
    long long endTime;
    std::string severity;
    std::vector<std::string> ips;
    std::vector<std::string> users;
    std::vector<std::string> detectorTypes;
    int eventCount;
    int riskScore;
};

struct Query {
    std::string severity;
    std::string user;
    std::string ip;
    std::string contains;
    std::string after;
    std::string before;
};

struct SummaryCounts {
    int total = 0, info = 0, warn = 0, error = 0, invalid = 0;
    int suspiciousIps = 0, suspiciousUsers = 0, rapidBruteForce = 0;
    bool highErrorRate = false;
};

struct SessionState {
    std::string sourcePath;
    std::vector<LogEntry> entries;
    int invalidCount = 0;
    std::map<std::string, int> invalidReasons;
    std::vector<Incident> incidents;
    DetectionSettings settings;
};

std::string extractValue(const std::string& text, const std::string& key) {
    std::string target = key + "=";
    size_t start = text.find(target);
    if (start == std::string::npos) return "";
    start += target.length();
    size_t end = text.find(' ', start);
    if (end == std::string::npos) return text.substr(start);
    return text.substr(start, end - start);
}

std::string toLower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return text;
}

std::string toUpper(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return text;
}

std::string getRiskLevel(int failedAttempts) {
    if (failedAttempts >= 10) return "HIGH";
    else if (failedAttempts >= 5) return "MEDIUM";
    return "LOW";
}

bool isAllDigits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

bool isLeapYear(int y) { return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0); }

int daysInMonth(int y, int m) {
    static const int days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    if (m < 1 || m > 12) return 0;
    if (m == 2 && isLeapYear(y)) return 29;
    return days[m - 1];
}

bool validSeverity(const std::string& s) {
    std::string u = toUpper(s);
    return u == "INFO" || u == "WARN" || u == "WARNING" || u == "ERROR"
        || u == "DEBUG" || u == "CRITICAL";
}

InvalidReason invalidReason(const LogEntry& entry) {
    const std::string& d = entry.date;
    bool dateShape = d.length() == 10 && d[4] == '-' && d[7] == '-'
        && isAllDigits(d.substr(0, 4)) && isAllDigits(d.substr(5, 2))
        && isAllDigits(d.substr(8, 2));
    if (!dateShape) return InvalidReason::BAD_DATE;
    int y = std::stoi(d.substr(0, 4));
    int mo = std::stoi(d.substr(5, 2));
    int da = std::stoi(d.substr(8, 2));
    if (y < 1970 || y > 2100 || mo < 1 || mo > 12 || da < 1 || da > daysInMonth(y, mo))
        return InvalidReason::BAD_DATE;

    const std::string& t = entry.time;
    bool timeShape = t.length() == 8 && t[2] == ':' && t[5] == ':'
        && isAllDigits(t.substr(0, 2)) && isAllDigits(t.substr(3, 2))
        && isAllDigits(t.substr(6, 2));
    if (!timeShape) return InvalidReason::BAD_TIME;
    int hh = std::stoi(t.substr(0, 2));
    int mi = std::stoi(t.substr(3, 2));
    int ss = std::stoi(t.substr(6, 2));
    if (hh > 23 || mi > 59 || ss > 59) return InvalidReason::BAD_TIME;

    if (!validSeverity(entry.severity)) return InvalidReason::BAD_SEVERITY;
    if (entry.message.find_first_not_of(" \t\r\n") == std::string::npos)
        return InvalidReason::MISSING_MESSAGE;
    return InvalidReason::OK;
}

bool isValidLogLine(const LogEntry& entry) {
    return invalidReason(entry) == InvalidReason::OK;
}

std::string invalidReasonText(InvalidReason r) {
    switch (r) {
        case InvalidReason::BAD_DATE:       return "BAD_DATE";
        case InvalidReason::BAD_TIME:       return "BAD_TIME";
        case InvalidReason::BAD_SEVERITY:   return "BAD_SEVERITY";
        case InvalidReason::MISSING_MESSAGE: return "MISSING_MESSAGE";
        default:                            return "OK";
    }
}

void writeInvalidBreakdown(std::ostream& os, const std::map<std::string, int>& reasons) {
    for (const auto& p : reasons)
        os << "  invalid [" << p.first << "]: " << p.second << "\n";
}

static std::string trimStr(std::string v) {
    size_t a = v.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = v.find_last_not_of(" \t\r\n");
    return v.substr(a, b - a + 1);
}

bool setSettingByKey(DetectionSettings& s, const std::string& key, const std::string& val) {
    try {
        if (key == "brute_force_min_attempts") s.bruteForceMinAttempts = std::stoi(val);
        else if (key == "brute_force_window_seconds") s.bruteForceWindowSeconds = std::stoll(val);
        else if (key == "spray_min_users") s.sprayMinUsers = std::stoi(val);
        else if (key == "spray_window_seconds") s.sprayWindowSeconds = std::stoll(val);
        else if (key == "distributed_min_ips") s.distributedMinIps = std::stoi(val);
        else if (key == "distributed_window_seconds") s.distributedWindowSeconds = std::stoll(val);
        else if (key == "login_burst_min_attempts") s.loginBurstMinAttempts = std::stoi(val);
        else if (key == "login_burst_window_seconds") s.loginBurstWindowSeconds = std::stoll(val);
        else if (key == "error_burst_min_count") s.errorBurstMinCount = std::stoi(val);
        else if (key == "error_burst_window_seconds") s.errorBurstWindowSeconds = std::stoll(val);
        else if (key == "repeated_failure_min_attempts") s.repeatedFailureMinAttempts = std::stoi(val);
        else if (key == "repeated_error_min_count") s.repeatedErrorMinCount = std::stoi(val);
        else if (key == "service_failure_min_count") s.serviceFailureMinCount = std::stoi(val);
        else if (key == "warn_escalation_window_seconds") s.warnEscalationWindowSeconds = std::stoll(val);
        else if (key == "high_error_min_errors") s.highErrorMinErrors = std::stoi(val);
        else if (key == "high_error_min_rate") s.highErrorMinRate = std::stod(val);
        else if (key == "dense_window_seconds") s.denseWindowSeconds = std::stoll(val);
        else if (key == "off_hours_start") s.offHoursStart = std::stoi(val);
        else if (key == "off_hours_end") s.offHoursEnd = std::stoi(val);
        else if (key == "impossible_travel_window_seconds") s.impossibleTravelWindowSeconds = std::stoll(val);
        else if (key == "exfil_window_seconds") s.exfilWindowSeconds = std::stoll(val);
        else if (key == "exfil_min_mb") s.exfilMinMB = std::stod(val);
        else if (key == "large_file_lines") s.largeFileLines = std::stoll(val);
        else if (key == "stream_retain_minutes") s.streamRetainMinutes = std::stoll(val);
        else return false;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool readSettings(std::istream& in, const std::string& srcName, DetectionSettings& s) {
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        auto hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        line = trimStr(line);
        if (line.empty()) continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) {
            std::cerr << "config " << srcName << ":" << lineno << ": ignoring line (no '=')\n";
            continue;
        }
        std::string key = trimStr(line.substr(0, eq));
        std::string val = trimStr(line.substr(eq + 1));
        if (!setSettingByKey(s, key, val))
            std::cerr << "config " << srcName << ":" << lineno
                      << ": unknown key or bad value '" << key << "' (ignored)\n";
    }
    return true;
}

bool loadSettings(const std::string& path, DetectionSettings& s) {
    std::ifstream in(path);
    if (!in.is_open()) {
        std::cerr << "cannot open config file: " << path << "\n";
        return false;
    }
    return readSettings(in, path, s);
}

void writeSettings(std::ostream& out, const DetectionSettings& s) {
    out << "brute_force_min_attempts=" << s.bruteForceMinAttempts << "\n";
    out << "brute_force_window_seconds=" << s.bruteForceWindowSeconds << "\n";
    out << "spray_min_users=" << s.sprayMinUsers << "\n";
    out << "spray_window_seconds=" << s.sprayWindowSeconds << "\n";
    out << "distributed_min_ips=" << s.distributedMinIps << "\n";
    out << "distributed_window_seconds=" << s.distributedWindowSeconds << "\n";
    out << "login_burst_min_attempts=" << s.loginBurstMinAttempts << "\n";
    out << "login_burst_window_seconds=" << s.loginBurstWindowSeconds << "\n";
    out << "error_burst_min_count=" << s.errorBurstMinCount << "\n";
    out << "error_burst_window_seconds=" << s.errorBurstWindowSeconds << "\n";
    out << "repeated_failure_min_attempts=" << s.repeatedFailureMinAttempts << "\n";
    out << "repeated_error_min_count=" << s.repeatedErrorMinCount << "\n";
    out << "service_failure_min_count=" << s.serviceFailureMinCount << "\n";
    out << "warn_escalation_window_seconds=" << s.warnEscalationWindowSeconds << "\n";
    out << "high_error_min_errors=" << s.highErrorMinErrors << "\n";
    out << "high_error_min_rate=" << s.highErrorMinRate << "\n";
    out << "dense_window_seconds=" << s.denseWindowSeconds << "\n";
    out << "off_hours_start=" << s.offHoursStart << "\n";
    out << "off_hours_end=" << s.offHoursEnd << "\n";
    out << "impossible_travel_window_seconds=" << s.impossibleTravelWindowSeconds << "\n";
    out << "exfil_window_seconds=" << s.exfilWindowSeconds << "\n";
    out << "exfil_min_mb=" << s.exfilMinMB << "\n";
    out << "large_file_lines=" << s.largeFileLines << "\n";
    out << "stream_retain_minutes=" << s.streamRetainMinutes << "\n";
}

bool saveSettings(const std::string& path, const DetectionSettings& s) {
    std::ofstream out(path);
    if (!out.is_open()) {
        std::cerr << "cannot write config file: " << path << "\n";
        return false;
    }
    out << "# LogLens detection settings (key=value, '#' starts a comment)\n";
    writeSettings(out, s);
    return true;
}

void printSettings(const DetectionSettings& s) {
    std::cout << "Detection settings:\n"
              << "   1. brute_force_min_attempts       = " << s.bruteForceMinAttempts << "\n"
              << "   2. brute_force_window_seconds     = " << s.bruteForceWindowSeconds << "\n"
              << "   3. spray_min_users                = " << s.sprayMinUsers << "\n"
              << "   4. spray_window_seconds           = " << s.sprayWindowSeconds << "\n"
              << "   5. distributed_min_ips            = " << s.distributedMinIps << "\n"
              << "   6. distributed_window_seconds     = " << s.distributedWindowSeconds << "\n"
              << "   7. login_burst_min_attempts       = " << s.loginBurstMinAttempts << "\n"
              << "   8. login_burst_window_seconds     = " << s.loginBurstWindowSeconds << "\n"
              << "   9. error_burst_min_count          = " << s.errorBurstMinCount << "\n"
              << "  10. error_burst_window_seconds     = " << s.errorBurstWindowSeconds << "\n"
              << "  11. repeated_failure_min_attempts  = " << s.repeatedFailureMinAttempts << "\n"
              << "  12. repeated_error_min_count       = " << s.repeatedErrorMinCount << "\n"
              << "  13. service_failure_min_count      = " << s.serviceFailureMinCount << "\n"
              << "  14. warn_escalation_window_seconds = " << s.warnEscalationWindowSeconds << "\n"
              << "  15. high_error_min_errors          = " << s.highErrorMinErrors << "\n"
              << "  16. high_error_min_rate            = " << s.highErrorMinRate << "\n"
              << "  17. dense_window_seconds           = " << s.denseWindowSeconds << "\n"
              << "  18. off_hours_start                = " << s.offHoursStart << "\n"
              << "  19. off_hours_end                  = " << s.offHoursEnd << "\n"
              << "  20. impossible_travel_window_secs  = " << s.impossibleTravelWindowSeconds << "\n"
              << "  21. exfil_window_seconds           = " << s.exfilWindowSeconds << "\n"
              << "  22. exfil_min_mb                   = " << s.exfilMinMB << "\n"
              << "  23. large_file_lines               = " << s.largeFileLines << "\n"
              << "  24. stream_retain_minutes          = " << s.streamRetainMinutes << "\n";
}

std::vector<Alert> alerts;

void pushAlert(const std::string& severity,
               const std::string& type,
               const std::string& message,
               const std::string& ip = "",
               const std::string& user = "",
               long long epoch = 0) {
    alerts.push_back(Alert{severity, type, message, ip, user, epoch});
}

void printAlerts() {
    std::cout << "\n --- Alerts (" << alerts.size() << ") --- \n";
    for (const auto& a : alerts)
        std::cout << "[" << a.severity << "] " << a.message << "\n";
}

int countAlertsOfType(const std::string& type) {
    int n = 0;
    for (const auto& a : alerts) if (a.type == type) n++;
    return n;
}

int countAlertsOfSeverity(const std::string& severity) {
    int n = 0;
    for (const auto& a : alerts) if (a.severity == severity) n++;
    return n;
}

std::string formatRapidBruteForceMessage(const std::string& ip, const DetectionSettings& s) {
    std::ostringstream msg;
    msg << "Rapid brute-force activity detected from IP " << ip << ": "
        << s.bruteForceMinAttempts << " or more failed logins within "
        << s.bruteForceWindowSeconds << " seconds.";
    return msg.str();
}

std::vector<Alert> rapidBruteForceAlerts() {
    std::vector<Alert> out;
    for (const auto& a : alerts)
        if (a.type == "rapid_brute_force") out.push_back(a);
    return out;
}

int countRapidBruteForce() { return countAlertsOfType("rapid_brute_force"); }

void exportRapidBruteForceSection(std::ofstream& report) {
    std::vector<Alert> rbf = rapidBruteForceAlerts();
    if (rbf.empty()) return;
    report << "Rapid brute-force (" << rbf.size() << "):\n";
    for (const auto& a : rbf)
        report << "[" << a.severity << "] " << a.message << "\n";
    report << "\n";
}

DateTime parseDateTime(const std::string& date, const std::string& time) {
    DateTime dt{};
    dt.year   = std::stoi(date.substr(0, 4));
    dt.month  = std::stoi(date.substr(5, 2));
    dt.day    = std::stoi(date.substr(8, 2));
    dt.hour   = std::stoi(time.substr(0, 2));
    dt.minute = std::stoi(time.substr(3, 2));
    dt.second = std::stoi(time.substr(6, 2));
    return dt;
}

long long daysFromCivil(int y, int m, int d) {
    y -= (m <= 2);
    const long long era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<long long>(doe) - 719468;
}

long long toEpochSeconds(const DateTime& dt) {
    return daysFromCivil(dt.year, dt.month, dt.day) * 86400LL
         + dt.hour * 3600LL + dt.minute * 60LL + dt.second;
}

long long logEntryEpoch(const LogEntry& e) {
    return toEpochSeconds(parseDateTime(e.date, e.time));
}

bool occurredWithin(std::vector<long long> eventTimes, long long windowSeconds,
                    int minEvents = 3) {
    if (eventTimes.size() < static_cast<size_t>(minEvents)) return false;
    std::sort(eventTimes.begin(), eventTimes.end());
    for (size_t i = 0; i + minEvents <= eventTimes.size(); ++i) {
        if (eventTimes[i + minEvents - 1] - eventTimes[i] <= windowSeconds) return true;
    }
    return false;
}

long long firstWindowStart(std::vector<long long> eventTimes, long long windowSeconds,
                           int minEvents = 3) {
    if (eventTimes.size() < static_cast<size_t>(minEvents)) return -1;
    std::sort(eventTimes.begin(), eventTimes.end());
    for (size_t i = 0; i + minEvents <= eventTimes.size(); ++i) {
        if (eventTimes[i + minEvents - 1] - eventTimes[i] <= windowSeconds)
            return eventTimes[i];
    }
    return -1;
}

std::string epochToString(long long epoch) {
    std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tmv{};
    ll_localtime(&tmv, &t);
    std::ostringstream o;
    o << std::put_time(&tmv, "%Y-%m-%d %H:%M:%S");
    return o.str();
}

std::string reportTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tmv{};
    ll_localtime(&tmv, &t);
    std::ostringstream o;
    o << std::put_time(&tmv, "%Y-%m-%d_%H-%M-%S");
    return o.str();
}

std::string jsonEscape(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    o << "\\u";
                    const char* hex = "0123456789abcdef";
                    unsigned v = static_cast<unsigned char>(c);
                    o << hex[(v >> 12) & 15] << hex[(v >> 8) & 15]
                      << hex[(v >> 4) & 15] << hex[v & 15];
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

std::string csvEscape(const std::string& s) {
    if (s.find_first_of("\",\n\r") == std::string::npos) return s;
    std::string o = "\"";
    for (char c : s) {
        if (c == '"') o += "\"\"";
        else o += c;
    }
    o += "\"";
    return o;
}

std::string alertKey(const Alert& a) {
    return a.type + "|" + a.severity + "|" + a.ip + "|" + a.user + "|" + a.message;
}

LogEntry parseLogLine(const std::string& line) {
    std::istringstream parser(line);
    LogEntry entry;
    parser >> entry.date;
    parser >> entry.time;
    parser >> entry.severity;
    std::getline(parser, entry.message);
    if (!entry.message.empty() && entry.message[0] == ' ') {
        entry.message.erase(0, 1);
    }

    std::string sev = toUpper(entry.severity);
    if (sev == "WARNING") sev = "WARN";
    entry.severity = sev;
    entry.user = extractValue(entry.message, "user");
    entry.ip = extractValue(entry.message, "ip");
    return entry;
}

std::vector<std::string> discoverLogFiles(const std::string& path) {
    std::vector<std::string> files;
    namespace fs = std::filesystem;
    std::error_code ec;
    if (fs::is_directory(path, ec)) {
        for (const auto& p : fs::recursive_directory_iterator(path, ec)) {
            if (p.is_regular_file() && p.path().extension() == ".log")
                files.push_back(p.path().string());
        }
    } else if (fs::is_regular_file(path, ec)) {
        files.push_back(path);
    } else {
        std::cerr << "Path not found: " << path << "\n";
    }
    std::sort(files.begin(), files.end());
    return files;
}

std::vector<LogEntry> loadLogs(const std::vector<std::string>& files, int& invalidCount,
                               std::map<std::string, int>& invalidReasons) {
    std::vector<LogEntry> entries;
    invalidCount = 0;
    invalidReasons.clear();
    for (const auto& f : files) {
        std::ifstream in(f);
        if (!in.is_open()) {
            std::cerr << "Could not open: " << f << "\n";
            continue;
        }
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            LogEntry e = parseLogLine(line);
            InvalidReason r = invalidReason(e);
            if (r != InvalidReason::OK) {
                invalidCount++;
                invalidReasons[invalidReasonText(r)]++;
                continue;
            }
            e.sourceFile = f;
            entries.push_back(e);
        }
    }

    std::sort(entries.begin(), entries.end(),
              [](const LogEntry& a, const LogEntry& b) {
                  return logEntryEpoch(a) < logEntryEpoch(b);
              });
    return entries;
}

int timeToSeconds(const std::string& time);

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

void detectOffHoursAccess(const std::vector<LogEntry>& entries, const DetectionSettings& s) {
    for (const auto& e : entries) {
        std::string m = toLower(e.message);
        if (m.find("login") == std::string::npos) continue;
        if (m.find("success") == std::string::npos && m.find("accepted") == std::string::npos)
            continue;
        int hour = (e.time[0] - '0') * 10 + (e.time[1] - '0');
        bool off = (s.offHoursStart <= s.offHoursEnd)
            ? (hour >= s.offHoursStart && hour < s.offHoursEnd)
            : (hour >= s.offHoursStart || hour < s.offHoursEnd);
        if (off) {
            std::ostringstream msg;
            msg << "Off-hours login: user '" << (e.user.empty() ? "?" : e.user)
                << "' at " << e.time << (e.ip.empty() ? "" : " from " + e.ip) << ".";
            pushAlert("MEDIUM", "off_hours_access", msg.str(), e.ip, e.user, logEntryEpoch(e));
        }
    }
}

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

void detectPrivilegeEscalation(const std::vector<LogEntry>& entries,
                               const DetectionSettings& ) {
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
                catch (const std::exception&) {  }
            }
            i = (u > k) ? u : j;
        } else {
            ++i;
        }
    }
    return total;
}

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

void detectNewIpForUser(const std::vector<LogEntry>& entries,
                         const DetectionSettings& ) {
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

struct RuleInfo {
    std::string id;
    std::string name;
    std::string description;
    std::string defaultSeverity;
    bool enabled = true;
    void (*run)(const std::vector<LogEntry>&, const DetectionSettings&) = nullptr;
};

void detectRepeatedFailures(const std::vector<LogEntry>& entries,
                            const DetectionSettings& s) {
    std::unordered_map<std::string, int> failedLoginCounts, failedUserCounts;
    std::unordered_map<std::string, std::vector<int>> failedLoginTimes;
    for (const auto& e : entries)
        trackFailedLogin(e, failedLoginCounts, failedUserCounts, failedLoginTimes);
    pushRepeatedFailureAlerts(entries, failedLoginCounts, failedUserCounts, s);
}

void detectHighErrorRate(const std::vector<LogEntry>& entries,
                         const DetectionSettings& s) {
    int errorCount = 0;
    for (const auto& e : entries) if (e.severity == "ERROR") errorCount++;
    if (hasHighErrorRate(static_cast<int>(entries.size()), errorCount, s)) {
        std::ostringstream msg;
        msg << "High global error rate: " << errorCount << " of " << entries.size()
            << " logs are ERROR.";
        pushAlert("MEDIUM", "high_error_rate", msg.str());
    }
}

std::vector<RuleInfo>& ruleRegistry() {
    static std::vector<RuleInfo> rules;
    static bool initialized = false;
    if (!initialized) {
        initialized = true;
        rules = {
            {"rapid_brute_force", "Rapid brute force",
             ">= brute_force_min_attempts failed logins from one IP inside the window",
             "HIGH", true, pushRapidBruteForceEpochAlerts},
            {"repeated_failures", "Repeated failures",
             "sustained failed-login counts per IP / per user", "MEDIUM", true,
             detectRepeatedFailures},
            {"password_spray", "Password spray",
             ">= spray_min_users distinct usernames from one IP inside the window",
             "HIGH", true, detectPasswordSpray},
            {"distributed_attack", "Distributed account attack",
             "one account attacked from >= distributed_min_ips IPs", "HIGH", true,
             detectDistributedAttack},
            {"login_burst", "Login burst",
             ">= login_burst_min_attempts logins inside the window", "MEDIUM", true,
             detectLoginBurst},
            {"error_burst", "Error burst",
             ">= error_burst_min_count ERRORs inside the window", "MEDIUM", true,
             detectErrorBursts},
            {"repeated_errors", "Repeated errors",
             "the same error message repeating >= repeated_error_min_count times",
             "MEDIUM", true, detectRepeatedErrors},
            {"service_failures", "Service failures",
             ">= service_failure_min_count failures for one service", "HIGH", true,
             detectServiceFailures},
            {"warn_escalation", "WARN-to-ERROR escalation",
             "WARNs for a component followed by ERRORs inside the window", "MEDIUM",
             true, detectWarnEscalation},
            {"dense_activity", "Dense activity",
             "unusually dense log volume inside the window", "LOW", true,
             detectDenseActivity},
            {"high_error_rate", "High error rate",
             "global ERROR share above high_error_min_rate", "MEDIUM", true,
             detectHighErrorRate},
            {"off_hours_access", "Off-hours access",
             "successful logins outside the configured off-hours window", "MEDIUM",
             true, detectOffHoursAccess},
            {"impossible_travel", "Impossible travel",
             "same user from 2+ distinct IPs inside the window", "HIGH", true,
             detectImpossibleTravel},
            {"privilege_escalation", "Privilege escalation",
             "sudo/su/escalation keywords combined with denied/failed", "HIGH", true,
             detectPrivilegeEscalation},
            {"data_exfiltration", "Data exfiltration",
             "large transferred volumes (>= exfil_min_mb) inside the window", "HIGH",
             true, detectDataExfiltration},
            {"new_ip_for_user", "New IP for user",
             "known user seen from an IP never used by them before", "MEDIUM", true,
             detectNewIpForUser},
        };
    }
    return rules;
}

RuleInfo* findRule(const std::string& id) {
    for (auto& r : ruleRegistry())
        if (r.id == id) return &r;
    return nullptr;
}

bool setRuleEnabled(const std::string& id, bool enabled) {
    RuleInfo* r = findRule(id);
    if (!r) return false;
    r->enabled = enabled;
    return true;
}

int countEnabledRules() {
    int n = 0;
    for (const auto& r : ruleRegistry()) if (r.enabled) ++n;
    return n;
}

void listRules() {
    for (const auto& r : ruleRegistry()) {
        std::cout << (r.enabled ? "[ON]  " : "[OFF] ") << r.id
                  << "  (" << r.defaultSeverity << ") " << r.name << "\n"
                  << "        " << r.description << "\n";
    }
    std::cout << countEnabledRules() << " of " << ruleRegistry().size()
              << " rules enabled.\n";
}

// runs every enabled registered rule against a fresh alert list
void runAllDetectors(const std::vector<LogEntry>& entries, const DetectionSettings& settings) {
    alerts.clear();
    for (const auto& r : ruleRegistry()) {
        if (r.enabled && r.run != nullptr) r.run(entries, settings);
    }
}

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

// groups alerts sharing an IP or user into one incident
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

void writeFullReport(std::ofstream& os, const SessionState& st) {
    SummaryCounts c = computeCounts(st.entries, st.invalidCount, st.settings);
    os << "LogLens Full Analysis Report\n";
    os << "============================\n";
    os << "Source: " << st.sourcePath << "\n";
    os << "Total logs: " << c.total << " (invalid skipped: " << c.invalid << ")\n";
    writeInvalidBreakdown(os, st.invalidReasons);
    os << "INFO: " << c.info << " | WARN: " << c.warn << " | ERROR: " << c.error << "\n\n";
    exportAlertsSection(os);
    exportRapidBruteForceSection(os);
    exportIncidentsSection(os, st.incidents);
    exportRiskSection(os);
}

void exportFullReport(const SessionState& st) {
    std::filesystem::create_directory("reports");
    std::string path = "reports/report_full_" + reportTimestamp() + ".txt";
    std::ofstream report(path);
    if (!report.is_open()) {
        std::cerr << "Could not create report file.\n";
        return;
    }
    writeFullReport(report, st);
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

// "HH:MM:SS" applies to the entry's own date; full timestamps are absolute; bad input -> 0
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

void printSummaryFromEntries(const std::vector<LogEntry>& entries, int invalidCount,
                             const std::map<std::string, int>& invalidReasons,
                             const DetectionSettings& settings) {
    SummaryCounts c = computeCounts(entries, invalidCount, settings);
    printSummary(c.total, c.info, c.warn, c.error, c.suspiciousIps,
                 c.suspiciousUsers, c.invalid, c.highErrorRate, c.rapidBruteForce);
    writeInvalidBreakdown(std::cout, invalidReasons);
}

bool g_forceStream = false;
long long countFileLines(const std::string& path);
bool loadStreamIntoState(SessionState& st, const std::vector<std::string>& files);

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
    long long totalLines = 0;
    for (const auto& f : files) totalLines += countFileLines(f);
    bool useStream = g_forceStream || totalLines > st.settings.largeFileLines;
    if (useStream) {
        std::cout << "large input (" << totalLines << " lines) -> streaming load path.\n";
        if (!loadStreamIntoState(st, files)) return false;
    } else {
        st.entries = loadLogs(files, st.invalidCount, st.invalidReasons);
    }
    refreshAnalysis(st);
    std::cout << "loaded " << st.entries.size() << " entries from "
              << files.size() << " file(s).\n";
    return true;
}

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
        case 23: return getLL("large_file_lines", s.largeFileLines, 1000, 1000000000);
        case 24: return getLL("stream_retain_minutes", s.streamRetainMinutes, 1, 10080);
        default: std::cout << "unknown setting number.\n"; return false;
    }
}

void sessionMenu(SessionState& st);
void rulesMenu(SessionState& st);

void settingsMenu(SessionState& st) {
    while (true) {
        std::cout << "\n--- Detection settings ---\n"
                  << "1. View settings\n"
                  << "2. Change a setting\n"
                  << "3. Load settings from file\n"
                  << "4. Save settings to file\n"
                  << "5. Detection rules (list/toggle)\n"
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
        } else if (c == "5") {
            rulesMenu(st);
        } else {
            std::cout << "unknown choice.\n";
        }
    }
}

volatile std::sig_atomic_t g_liveStop = 0;
void liveSigintHandler(int) { g_liveStop = 1; }

bool stdinHasQuit() {
#if defined(_WIN32)

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
    if (!std::getline(std::cin, line)) return true;
    return toLower(line) == "q";
#endif
}

void liveCheckEntry(const LogEntry& e,
                    std::unordered_map<std::string, std::vector<long long>>& recentFails,
                    const DetectionSettings& settings) {
    if (e.message.find("Login failed") != std::string::npos && !e.ip.empty()) {
        recentFails[e.ip].push_back(logEntryEpoch(e));
        auto& v = recentFails[e.ip];
        if (v.size() > 50) v.erase(v.begin(), v.begin() + (v.size() - 50));
        if (occurredWithin(v, settings.bruteForceWindowSeconds,
                           settings.bruteForceMinAttempts)) {
            std::cout << "\n>>> [HIGH] RAPID BRUTE FORCE from " << e.ip << " <<<\n\n";
        }
    }
}

// tails the file every 500ms; restarts cleanly on truncation or rotation
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
    std::string carry;
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
                    if (entries.size() > 100000)
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
                  << "10. Sessions (save/load/recent)\n"
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
        else if (choice == "10") sessionMenu(st);
        else std::cout << "unknown choice.\n";
    }
}

struct SimClock {
    int y, mo, d, h, mi, s;
    void addSeconds(int n) {
        s += n;
        while (s >= 60) { s -= 60; ++mi; }
        while (mi >= 60) { mi -= 60; ++h; }
        while (h >= 24) { h -= 24; ++d; }
        while (d > daysInMonth(y, mo)) {
            d -= daysInMonth(y, mo);
            ++mo;
            if (mo > 12) { mo = 1; ++y; }
        }
    }
    std::string stamp() const {
        std::ostringstream o;
        o << std::setw(4) << std::setfill('0') << y << '-'
          << std::setw(2) << std::setfill('0') << mo << '-'
          << std::setw(2) << std::setfill('0') << d << ' '
          << std::setw(2) << std::setfill('0') << h << ':'
          << std::setw(2) << std::setfill('0') << mi << ':'
          << std::setw(2) << std::setfill('0') << s;
        return o.str();
    }
};

struct SimOptions {
    std::string mode = "mixed";  // normal|bruteforce|spray|errorstorm|mixed
    long long lines = 1000;
    std::string outPath;
    double speed = 0.0;
    unsigned int seed = 42;
};

static std::string simPick(std::mt19937& rng, const std::vector<std::string>& v) {
    std::uniform_int_distribution<size_t> d(0, v.size() - 1);
    return v[d(rng)];
}

bool runSimulator(const SimOptions& o) {
    std::string mode = toLower(o.mode);
    if (mode != "normal" && mode != "bruteforce" && mode != "spray"
        && mode != "errorstorm" && mode != "mixed") {
        std::cerr << "unknown sim mode: " << o.mode
                  << " (normal|bruteforce|spray|errorstorm|mixed)\n";
        return false;
    }
    if (o.lines < 0) { std::cerr << "--sim-lines must be >= 0\n"; return false; }

    std::ostream* out = &std::cout;
    std::ofstream file;
    if (!o.outPath.empty()) {
        file.open(o.outPath);
        if (!file.is_open()) {
            std::cerr << "cannot write sim output: " << o.outPath << "\n";
            return false;
        }
        out = &file;
    }

    std::mt19937 rng(o.seed);
    auto ri = [&](int lo, int hi) {
        return std::uniform_int_distribution<int>(lo, hi)(rng);
    };
    const std::vector<std::string> users =
        {"admin", "root", "jdoe", "asmith", "operator", "guest", "svc_backup", "mchen"};
    const std::vector<std::string> ips =
        {"192.168.1.10", "192.168.1.11", "10.0.0.8", "172.16.0.5", "203.0.113.9"};
    const std::string attackerIp = "10.0.0.7";
    const char* errMsgs[] = {"Database connection lost", "Service worker failed",
                             "Disk full on /var/log", "Upstream timeout after 30s"};

    SimClock clock{2026, 9, 22, 9, 0, 0};

    for (long long i = 0; i < o.lines; ++i) {
        std::string sev, msg;
        if (mode == "bruteforce") {

            clock.addSeconds(ri(1, 3));
            std::string user = (ri(1, 10) == 1) ? simPick(rng, users) : "admin";
            sev = "WARN";
            msg = "Login failed for user=" + user + " ip=" + attackerIp + " (bad password)";
        } else if (mode == "spray") {

            clock.addSeconds(ri(2, 8));
            std::string user = users[static_cast<size_t>(i) % users.size()];
            sev = "WARN";
            msg = "Login failed for user=" + user + " ip=" + attackerIp;
        } else if (mode == "errorstorm") {
            clock.addSeconds(ri(0, 2));
            sev = "ERROR";
            msg = std::string(errMsgs[ri(0, 3)]) + " on srv-" + std::to_string(ri(1, 3));
        } else {

            clock.addSeconds(ri(1, 20));
            std::string user = simPick(rng, users);
            std::string ip = simPick(rng, ips);
            int roll = ri(1, 100);
            if (roll <= 80) {
                sev = "INFO";
                msg = "Login successful for user=" + user + " ip=" + ip;
            } else if (roll <= 90) {
                sev = "WARN";
                msg = "Disk usage at " + std::to_string(ri(70, 95)) + "% on srv-1";
            } else {
                sev = "ERROR";
                msg = "Connection timeout to db-primary";
            }
            if (mode == "mixed") {
                int m = ri(1, 100);
                if (m <= 12) {
                    clock.addSeconds(ri(1, 4));
                    sev = "WARN"; user = "admin"; ip = attackerIp;
                    msg = "Login failed for user=admin ip=" + ip + " (bad password)";
                } else if (m <= 16) {
                    sev = "ERROR";
                    msg = std::string(errMsgs[ri(0, 3)]) + " on srv-1";
                } else if (m == 17) {
                    sev = "WARN";
                    msg = "sudo: user=" + user + " ip=" + ip + " denied: not permitted";
                } else if (m == 18) {
                    sev = "INFO";
                    msg = "user=" + user + " ip=" + ip + " downloaded "
                        + std::to_string(ri(120, 800)) + " MB from share";
                }
            }
        }
        *out << clock.stamp() << ' ' << sev << ' ' << msg << '\n';
        if (o.speed > 0.0)
            std::this_thread::sleep_for(std::chrono::duration<double>(1.0 / o.speed));
    }
    if (file.is_open()) {
        file.close();
        std::cout << "simulator wrote " << o.lines << " lines (" << mode << ") -> "
                  << o.outPath << "\n";
    }
    return true;
}

std::string sessEscape(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '\\') o += "\\\\";
        else if (c == '|') o += "\\|";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else o += c;
    }
    return o;
}

std::string sessUnescape(const std::string& s) {
    std::string o;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char n = s[++i];
            if (n == 'n') o += '\n';
            else if (n == 'r') o += '\r';
            else o += n;
        } else {
            o += s[i];
        }
    }
    return o;
}

std::vector<std::string> splitEscaped(const std::string& line) {
    std::vector<std::string> parts;
    std::string cur;
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '\\' && i + 1 < line.size()) {
            cur += line[i];
            cur += line[i + 1];
            ++i;
        } else if (line[i] == '|') {
            parts.push_back(cur);
            cur.clear();
        } else {
            cur += line[i];
        }
    }
    parts.push_back(cur);
    for (auto& p : parts) p = sessUnescape(p);
    return parts;
}

struct ProjectSession {
    std::string logPath;
    DetectionSettings settings;
    std::vector<std::pair<std::string, bool>> ruleStates;
    std::vector<Alert> savedAlerts;
    std::string savedAt;
    std::string note;
};

std::string nowStamp() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    ll_localtime(&tmv, &t);
    std::ostringstream o;
    o << std::put_time(&tmv, "%Y-%m-%d %H:%M:%S");
    return o.str();
}

bool saveSession(const std::string& path, const ProjectSession& ps) {
    std::ofstream out(path);
    if (!out.is_open()) {
        std::cerr << "cannot write session file: " << path << "\n";
        return false;
    }
    out << "# LogLens session file v1 (key=value, '#' starts a comment)\n";
    out << "note=" << sessEscape(ps.note) << "\n";
    out << "log_path=" << sessEscape(ps.logPath) << "\n";
    out << "saved_at=" << ps.savedAt << "\n";
    out << "[settings]\n";
    writeSettings(out, ps.settings);
    out << "[rules]\n";
    for (const auto& rs : ps.ruleStates)
        out << rs.first << "=" << (rs.second ? "1" : "0") << "\n";
    out << "[alerts]\n";
    for (const auto& a : ps.savedAlerts) {
        out << sessEscape(a.severity) << '|' << sessEscape(a.type) << '|'
            << sessEscape(a.message) << '|' << sessEscape(a.ip) << '|'
            << sessEscape(a.user) << '|' << a.epoch << "\n";
    }
    out << "[end]\n";
    return true;
}

bool loadSession(const std::string& path, ProjectSession& ps) {
    std::ifstream in(path);
    if (!in.is_open()) {
        std::cerr << "cannot open session file: " << path << "\n";
        return false;
    }
    ps = ProjectSession();
    std::string line, section, settingsText;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string t = trimStr(line);
        if (t.empty() || t[0] == '#') continue;
        if (t.size() > 2 && t.front() == '[' && t.back() == ']') {
            section = t.substr(1, t.size() - 2);
            if (section == "end") break;
            continue;
        }
        if (section.empty()) {
            auto eq = t.find('=');
            if (eq == std::string::npos) continue;
            std::string key = trimStr(t.substr(0, eq));
            std::string val = t.substr(eq + 1);
            if (key == "note") ps.note = sessUnescape(trimStr(val));
            else if (key == "log_path") ps.logPath = sessUnescape(trimStr(val));
            else if (key == "saved_at") ps.savedAt = trimStr(val);
        } else if (section == "settings") {
            settingsText += t + "\n";
        } else if (section == "rules") {
            auto eq = t.find('=');
            if (eq == std::string::npos) continue;
            std::string id = trimStr(t.substr(0, eq));
            std::string val = trimStr(t.substr(eq + 1));
            if (!id.empty()) ps.ruleStates.push_back({id, val == "1"});
        } else if (section == "alerts") {
            std::vector<std::string> f = splitEscaped(t);
            if (f.size() != 6) continue;
            Alert a;
            a.severity = f[0]; a.type = f[1]; a.message = f[2];
            a.ip = f[3]; a.user = f[4];
            try { a.epoch = std::stoll(f[5]); } catch (const std::exception&) { a.epoch = 0; }
            ps.savedAlerts.push_back(a);
        }
    }
    if (!settingsText.empty()) {
        std::istringstream ss(settingsText);
        readSettings(ss, path + " [settings]", ps.settings);
    }
    return true;
}

void applySession(SessionState& st, const ProjectSession& ps) {
    st.settings = ps.settings;
    for (const auto& rs : ps.ruleStates) setRuleEnabled(rs.first, rs.second);
    alerts = ps.savedAlerts;
    st.sourcePath = ps.logPath;
    st.entries.clear();
    st.invalidCount = 0;
    st.invalidReasons.clear();
    st.incidents = correlateIncidents(alerts);
}

std::vector<std::string> readRecent(const std::string& recentFile = "loglens_recent.txt") {
    std::vector<std::string> out;
    std::ifstream in(recentFile);
    std::string line;
    while (std::getline(in, line)) {
        line = trimStr(line);
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

void pushRecent(const std::string& path,
                const std::string& recentFile = "loglens_recent.txt") {
    std::vector<std::string> v = readRecent(recentFile);
    v.erase(std::remove(v.begin(), v.end(), path), v.end());
    v.insert(v.begin(), path);
    if (v.size() > 10) v.resize(10);
    std::ofstream out(recentFile);
    if (!out.is_open()) {
        std::cerr << "cannot write " << recentFile << "\n";
        return;
    }
    for (const auto& p : v) out << p << "\n";
}

void sessionMenu(SessionState& st) {
    while (true) {
        std::cout << "\n--- Sessions ---\n"
                  << "1. Save session\n"
                  << "2. Load session\n"
                  << "3. Recent sessions\n"
                  << "0. Back\nchoice: ";
        std::string c;
        if (!std::getline(std::cin, c)) break;
        if (c == "0") break;
        else if (c == "1") {
            std::cout << "session file path [session.llsession]: ";
            std::string p;
            std::getline(std::cin, p);
            if (p.empty()) p = "session.llsession";
            std::cout << "note (optional): ";
            std::string note;
            std::getline(std::cin, note);
            ProjectSession ps;
            ps.logPath = st.sourcePath;
            ps.settings = st.settings;
            for (const auto& r : ruleRegistry()) ps.ruleStates.push_back({r.id, r.enabled});
            ps.savedAlerts = alerts;
            ps.savedAt = nowStamp();
            ps.note = note;
            if (saveSession(p, ps)) {
                pushRecent(p);
                std::cout << "saved " << ps.savedAlerts.size() << " alerts to " << p << "\n";
            }
        } else if (c == "2") {
            std::vector<std::string> recent = readRecent();
            for (size_t i = 0; i < recent.size(); ++i)
                std::cout << "  " << (i + 1) << ". " << recent[i] << "\n";
            std::cout << "number from recent, or a path (empty=cancel): ";
            std::string pick;
            std::getline(std::cin, pick);
            if (pick.empty()) continue;
            std::string p = pick;
            try {
                size_t n = static_cast<size_t>(std::stoul(pick));
                if (n >= 1 && n <= recent.size()) p = recent[n - 1];
            } catch (const std::exception&) {  }
            ProjectSession ps;
            if (loadSession(p, ps)) {
                applySession(st, ps);
                pushRecent(p);
                std::cout << "loaded session from " << p << ": " << ps.savedAlerts.size()
                          << " alerts (saved " << ps.savedAt << ")"
                          << (ps.note.empty() ? "" : " note: " + ps.note) << "\n";
            }
        } else if (c == "3") {
            std::vector<std::string> recent = readRecent();
            if (recent.empty()) std::cout << "(no recent sessions)\n";
            for (size_t i = 0; i < recent.size(); ++i)
                std::cout << "  " << (i + 1) << ". " << recent[i] << "\n";
        } else {
            std::cout << "unknown choice.\n";
        }
    }
}

struct StreamingStats {
    long long totalLines = 0;
    long long validEntries = 0;
    long long invalidCount = 0;
    long long info = 0, warn = 0, error = 0;
    std::map<std::string, int> invalidReasons;
};

long long countFileLines(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return 0;
    const size_t N = 65536;
    std::vector<char> buf(N);
    long long lines = 0;
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(N));
        std::streamsize n = in.gcount();
        for (std::streamsize i = 0; i < n; ++i)
            if (buf[i] == '\n') ++lines;
    }
    return lines;
}

// huge files: streams line by line, keeps only recent history in memory
bool loadStreamIntoState(SessionState& st, const std::vector<std::string>& files) {
    StreamingStats stats;
    std::deque<LogEntry> window;
    long long retainSecs = st.settings.streamRetainMinutes * 60;
    long long maxEpoch = 0;
    std::vector<char> iobuf(65536);

    for (const auto& f : files) {
        std::ifstream in(f);
        if (!in.is_open()) {
            std::cerr << "Could not open: " << f << "\n";
            continue;
        }
        in.rdbuf()->pubsetbuf(iobuf.data(), iobuf.size());
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            ++stats.totalLines;
            LogEntry e = parseLogLine(line);
            InvalidReason r = invalidReason(e);
            if (r != InvalidReason::OK) {
                ++stats.invalidCount;
                ++stats.invalidReasons[invalidReasonText(r)];
                continue;
            }
            ++stats.validEntries;
            if (e.severity == "INFO") ++stats.info;
            else if (e.severity == "WARN") ++stats.warn;
            else if (e.severity == "ERROR") ++stats.error;
            e.sourceFile = f;
            long long ep = logEntryEpoch(e);
            if (ep > maxEpoch) maxEpoch = ep;
            window.push_back(e);
            while (!window.empty()
                   && logEntryEpoch(window.front()) < maxEpoch - retainSecs)
                window.pop_front();
        }
    }
    st.entries.assign(window.begin(), window.end());
    std::sort(st.entries.begin(), st.entries.end(),
              [](const LogEntry& a, const LogEntry& b) {
                  return logEntryEpoch(a) < logEntryEpoch(b);
              });
    st.invalidCount = static_cast<int>(stats.invalidCount);
    st.invalidReasons = stats.invalidReasons;
    std::cout << "streamed " << stats.totalLines << " lines (" << stats.validEntries
              << " valid), retained last " << st.settings.streamRetainMinutes
              << " min: " << st.entries.size() << " entries in memory.\n";
    return true;
}

void rulesMenu(SessionState& st) {
    while (true) {
        std::cout << "\n--- Detection rules ---\n";
        listRules();
        std::cout << "rule id to toggle (empty=back): ";
        std::string id;
        if (!std::getline(std::cin, id) || id.empty()) break;
        RuleInfo* r = findRule(id);
        if (!r) {
            std::cout << "unknown rule id.\n";
            continue;
        }
        r->enabled = !r->enabled;
        std::cout << r->id << " -> " << (r->enabled ? "ON" : "OFF") << "\n";
        refreshAnalysis(st);
        std::cout << "analysis refreshed.\n";
    }
}

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " [options] [logfile|folder]\n"
              << "Analyze a log file (or folder of .log files), or run tools.\n"
              << "With no arguments, prompts for a file and opens the menu.\n"
              << "Options:\n"
              << "  --file PATH            log file or folder to analyze\n"
              << "  --watch PATH           live-tail PATH, then exit\n"
              << "  --export FMT --out PATH\n"
              << "                         export analysis; FMT = txt|json|csv\n"
              << "                         (json/csv = alerts, txt = full report)\n"
              << "  --format FMT           export format when --export has none\n"
              << "  --rule ID --enable|--disable\n"
              << "                         toggle a detection rule (see --list-rules)\n"
              << "  --list-rules           list detection rules and exit\n"
              << "  --threshold KEY=VALUE  override a detection setting\n"
              << "                         (uses config-file key names)\n"
              << "  --config PATH          load detection settings from PATH\n"
              << "                         (./loglens.cfg autoloads if present)\n"
              << "  --sim MODE             run the log simulator:\n"
              << "                         normal|bruteforce|spray|errorstorm|mixed\n"
              << "    --sim-lines N        lines to emit (default 1000)\n"
              << "    --sim-out PATH       write to file (default: stdout)\n"
              << "    --sim-speed LPS      lines/sec, 0 = instant (default)\n"
              << "    --sim-seed N         RNG seed (default 42)\n"
              << "  --save-session PATH    save analysis session after the run\n"
              << "  --load-session PATH    load a saved session (no re-analysis)\n"
              << "  --stream               force the streaming load path\n"
              << "  --gui                  how to build/run the GUI companion\n"
              << "  --export-json PATH     write alerts as JSON (legacy)\n"
              << "  --export-csv PATH      write alerts as CSV (legacy)\n"
              << "  --export-entries PATH  write log entries as CSV (legacy)\n"
              << "  --batch                run without the interactive menu\n"
              << "  -h, --help             this help\n";
}

void printGuiHelp() {
    std::cout << "LogLens GUI (sprint blocks 11-13) is a separate Dear ImGui\n"
              << "companion app, not bundled with this CLI build.\n\n"
              << "To build it you need Dear ImGui + GLFW + an OpenGL3 backend:\n"
              << "  1. Install them, e.g. via vcpkg:\n"
              << "       vcpkg install imgui glfw3 --triplet x64-windows\n"
              << "  2. Build the gui/ sources against the LogLens core\n"
              << "     (modules/loglens/*.h + *.cpp), linking imgui, glfw\n"
              << "     and OpenGL.\n"
              << "  3. Run the GUI app, e.g.:\n"
              << "       loglens_gui --file <logfile>\n\n"
              << "The GUI is a thin view layer (dashboard, live screen) over the\n"
              << "same Alert/detector core this CLI uses.\n";
}

int main(int argc, char* argv[]) {
    std::string filePath, configPath, watchPath;
    std::vector<std::pair<std::string, std::string>> exports;
    std::string pendingFmt;
    bool exportSeen = false;
    std::string simMode, simOut, saveSessionPath, loadSessionPath;
    long long simLines = 1000;
    double simSpeed = 0.0;
    unsigned simSeed = 42;
    std::string exportJson, exportCsv, exportEntries;
    bool batch = false, forceStream = false;
    bool wantListRules = false, wantGui = false;
    std::string pendingRule;
    std::vector<std::pair<std::string, bool>> ruleToggles;
    std::vector<std::pair<std::string, std::string>> thresholdOv;

    auto needArg = [&](const std::string& flag, int& i, std::string& out) -> bool {
        if (i + 1 >= argc) {
            std::cerr << flag << " needs an argument\n";
            return false;
        }
        out = argv[++i];
        return true;
    };

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") { printUsage(argv[0]); return 0; }
        else if (a == "--gui") wantGui = true;
        else if (a == "--list-rules") wantListRules = true;
        else if (a == "--file") { if (!needArg(a, i, filePath)) return 1; }
        else if (a == "--watch") { if (!needArg(a, i, watchPath)) return 1; }
        else if (a == "--export") {
            std::string nxt = (i + 1 < argc) ? argv[i + 1] : "";
            pendingFmt.clear();
            if (nxt == "txt" || nxt == "json" || nxt == "csv") { pendingFmt = nxt; ++i; }
            exportSeen = true;
        }
        else if (a == "--format") { if (!needArg(a, i, pendingFmt)) return 1; }
        else if (a == "--out") {
            std::string p;
            if (!needArg(a, i, p)) return 1;
            exports.push_back({pendingFmt.empty() ? "txt" : pendingFmt, p});
            pendingFmt.clear();
        }
        else if (a == "--rule") { if (!needArg(a, i, pendingRule)) return 1; }
        else if (a == "--enable" || a == "--disable") {
            if (pendingRule.empty()) {
                std::cerr << a << " needs a preceding --rule <id>\n";
                return 1;
            }
            ruleToggles.push_back({pendingRule, a == "--enable"});
            pendingRule.clear();
        }
        else if (a == "--threshold") {
            std::string kv;
            if (!needArg(a, i, kv)) return 1;
            auto eq = kv.find('=');
            if (eq == std::string::npos) {
                std::cerr << "--threshold needs KEY=VALUE\n";
                return 1;
            }
            thresholdOv.push_back({kv.substr(0, eq), kv.substr(eq + 1)});
        }
        else if (a == "--config") { if (!needArg(a, i, configPath)) return 1; }
        else if (a == "--sim") { if (!needArg(a, i, simMode)) return 1; }
        else if (a == "--sim-lines") {
            std::string v;
            if (!needArg(a, i, v)) return 1;
            try { simLines = std::stoll(v); }
            catch (const std::exception&) { std::cerr << "--sim-lines needs an integer\n"; return 1; }
        }
        else if (a == "--sim-out") { if (!needArg(a, i, simOut)) return 1; }
        else if (a == "--sim-speed") {
            std::string v;
            if (!needArg(a, i, v)) return 1;
            try { simSpeed = std::stod(v); }
            catch (const std::exception&) { std::cerr << "--sim-speed needs a number\n"; return 1; }
        }
        else if (a == "--sim-seed") {
            std::string v;
            if (!needArg(a, i, v)) return 1;
            try { simSeed = static_cast<unsigned>(std::stoul(v)); }
            catch (const std::exception&) { std::cerr << "--sim-seed needs an integer\n"; return 1; }
        }
        else if (a == "--save-session") { if (!needArg(a, i, saveSessionPath)) return 1; }
        else if (a == "--load-session") { if (!needArg(a, i, loadSessionPath)) return 1; }
        else if (a == "--stream") forceStream = true;
        else if (a == "--batch") batch = true;
        else if (a == "--export-json") { if (!needArg(a, i, exportJson)) return 1; }
        else if (a == "--export-csv") { if (!needArg(a, i, exportCsv)) return 1; }
        else if (a == "--export-entries") { if (!needArg(a, i, exportEntries)) return 1; }
        else if (!a.empty() && a[0] == '-') {
            std::cerr << "unknown option: " << a << "\n\n";
            printUsage(argv[0]);
            return 1;
        }
        else filePath = a;
    }

    if (wantGui) { printGuiHelp(); return 0; }

    DetectionSettings settings;
    std::string cfg = configPath.empty() ? "loglens.cfg" : configPath;
    if (std::filesystem::exists(cfg)) {
        if (loadSettings(cfg, settings))
            std::cout << "loaded detection settings from " << cfg << "\n";
    } else if (!configPath.empty()) {
        std::cerr << "config file not found: " << configPath << "\n";
    }

    for (const auto& kv : thresholdOv) {
        if (!setSettingByKey(settings, kv.first, kv.second)) {
            std::cerr << "bad --threshold '" << kv.first << "=" << kv.second
                      << "' (unknown key or bad value)\n";
            return 1;
        }
        std::cout << "threshold override: " << kv.first << "=" << kv.second << "\n";
    }

    ruleRegistry();
    if (!pendingRule.empty()) {
        std::cerr << "--rule " << pendingRule << " needs --enable or --disable\n";
        return 1;
    }
    for (const auto& rt : ruleToggles) {
        if (!setRuleEnabled(rt.first, rt.second)) {
            std::cerr << "unknown rule id: " << rt.first << " (see --list-rules)\n";
            return 1;
        }
        std::cout << "rule " << rt.first << " -> " << (rt.second ? "ON" : "OFF") << "\n";
    }
    if (wantListRules) { listRules(); return 0; }

    if (!simMode.empty()) {
        SimOptions so;
        so.mode = simMode;
        so.lines = simLines;
        so.outPath = simOut;
        so.speed = simSpeed;
        so.seed = simSeed;
        return runSimulator(so) ? 0 : 1;
    }

    g_forceStream = forceStream;
    SessionState st;
    st.settings = settings;
    bool fromSession = !loadSessionPath.empty();

    if (fromSession) {
        ProjectSession ps;
        if (!loadSession(loadSessionPath, ps)) return 1;
        applySession(st, ps);
        pushRecent(loadSessionPath);
        std::cout << "loaded session from " << loadSessionPath << ": "
                  << ps.savedAlerts.size() << " alerts (saved " << ps.savedAt << ")"
                  << (ps.note.empty() ? "" : " note: " + ps.note) << "\n";
        printAlerts();
        printIncidents(st.incidents);
        printRiskScores();
        exportFullReport(st);
    } else {
        if (!watchPath.empty()) { liveMonitor(watchPath, settings); return 0; }
        if (filePath.empty()) {
            if (batch) {
                std::cerr << "no input file (use --file, a positional path, or --load-session)\n";
                return 1;
            }
            std::cout << "Enter log file path (file or folder) [default: data/sample.log]: ";
            if (!std::getline(std::cin, filePath)) return 0;
            if (filePath.empty()) filePath = "data/sample.log";
        }
        if (!loadIntoState(st, filePath)) return 1;

        printSummaryFromEntries(st.entries, st.invalidCount, st.invalidReasons, st.settings);
        printAlerts();
        printIncidents(st.incidents);
        printRiskScores();
        exportFullReport(st);
    }

    if (exportSeen && exports.empty()) {
        std::cerr << "--export needs --out <path>\n";
        return 1;
    }
    for (const auto& ex : exports) {
        std::string fmt = toLower(ex.first);
        const std::string& exportOut = ex.second;
        if (fmt != "txt" && fmt != "json" && fmt != "csv") {
            std::cerr << "bad export format: " << ex.first << " (txt|json|csv)\n";
            return 1;
        }
        if (fmt == "json") {
            if (exportAlertsJson(exportOut)) std::cout << "alerts JSON -> " << exportOut << "\n";
        } else if (fmt == "csv") {
            if (exportAlertsCsv(exportOut)) std::cout << "alerts CSV -> " << exportOut << "\n";
        } else {
            std::ofstream o(exportOut);
            if (!o.is_open()) {
                std::cerr << "cannot write " << exportOut << "\n";
                return 1;
            }
            writeFullReport(o, st);
            o.close();
            std::cout << "full report -> " << exportOut << "\n";
        }
    }
    if (!exportJson.empty() && exportAlertsJson(exportJson))
        std::cout << "alerts JSON -> " << exportJson << "\n";
    if (!exportCsv.empty() && exportAlertsCsv(exportCsv))
        std::cout << "alerts CSV -> " << exportCsv << "\n";
    if (!exportEntries.empty() && exportEntriesCsv(exportEntries, st.entries))
        std::cout << "entries CSV -> " << exportEntries << "\n";

    if (!saveSessionPath.empty()) {
        ProjectSession ps;
        ps.logPath = st.sourcePath;
        ps.settings = st.settings;
        for (const auto& r : ruleRegistry()) ps.ruleStates.push_back({r.id, r.enabled});
        ps.savedAlerts = alerts;
        ps.savedAt = nowStamp();
        if (saveSession(saveSessionPath, ps)) {
            pushRecent(saveSessionPath);
            std::cout << "session saved -> " << saveSessionPath << "\n";
        }
    }

    if (!batch) runCli(st);
    return 0;
}
