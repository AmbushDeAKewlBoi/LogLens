#include "core.h"

// ---------- string utils ----------
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

// ---------- validation: real checks, not just shape ----------
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

// Why a line was rejected. Checked in order: date, time, severity, message.
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

// ---------- detection settings: load / save / print ----------
static std::string trimStr(std::string v) {
    size_t a = v.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = v.find_last_not_of(" \t\r\n");
    return v.substr(a, b - a + 1);
}

bool loadSettings(const std::string& path, DetectionSettings& s) {
    std::ifstream in(path);
    if (!in.is_open()) {
        std::cerr << "cannot open config file: " << path << "\n";
        return false;
    }
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
            std::cerr << "config " << path << ":" << lineno << ": ignoring line (no '=')\n";
            continue;
        }
        std::string key = trimStr(line.substr(0, eq));
        std::string val = trimStr(line.substr(eq + 1));
        bool known = true;
        try {
            if (key == "brute_force_min_attempts")       s.bruteForceMinAttempts = std::stoi(val);
            else if (key == "brute_force_window_seconds") s.bruteForceWindowSeconds = std::stoll(val);
            else if (key == "spray_min_users")            s.sprayMinUsers = std::stoi(val);
            else if (key == "spray_window_seconds")       s.sprayWindowSeconds = std::stoll(val);
            else if (key == "distributed_min_ips")        s.distributedMinIps = std::stoi(val);
            else if (key == "distributed_window_seconds") s.distributedWindowSeconds = std::stoll(val);
            else if (key == "login_burst_min_attempts")  s.loginBurstMinAttempts = std::stoi(val);
            else if (key == "login_burst_window_seconds") s.loginBurstWindowSeconds = std::stoll(val);
            else if (key == "error_burst_min_count")     s.errorBurstMinCount = std::stoi(val);
            else if (key == "error_burst_window_seconds") s.errorBurstWindowSeconds = std::stoll(val);
            else if (key == "repeated_failure_min_attempts") s.repeatedFailureMinAttempts = std::stoi(val);
            else if (key == "repeated_error_min_count")  s.repeatedErrorMinCount = std::stoi(val);
            else if (key == "service_failure_min_count") s.serviceFailureMinCount = std::stoi(val);
            else if (key == "warn_escalation_window_seconds") s.warnEscalationWindowSeconds = std::stoll(val);
            else if (key == "high_error_min_errors")     s.highErrorMinErrors = std::stoi(val);
            else if (key == "high_error_min_rate")       s.highErrorMinRate = std::stod(val);
            else if (key == "dense_window_seconds")      s.denseWindowSeconds = std::stoll(val);
            else if (key == "off_hours_start")           s.offHoursStart = std::stoi(val);
            else if (key == "off_hours_end")             s.offHoursEnd = std::stoi(val);
            else if (key == "impossible_travel_window_seconds") s.impossibleTravelWindowSeconds = std::stoll(val);
            else if (key == "exfil_window_seconds")      s.exfilWindowSeconds = std::stoll(val);
            else if (key == "exfil_min_mb")              s.exfilMinMB = std::stod(val);
            else known = false;
        } catch (const std::exception&) {
            std::cerr << "config " << path << ":" << lineno
                      << ": bad value for '" << key << "' (ignored)\n";
            continue;
        }
        if (!known)
            std::cerr << "config " << path << ":" << lineno
                      << ": unknown key '" << key << "' (ignored)\n";
    }
    return true;
}

bool saveSettings(const std::string& path, const DetectionSettings& s) {
    std::ofstream out(path);
    if (!out.is_open()) {
        std::cerr << "cannot write config file: " << path << "\n";
        return false;
    }
    out << "# LogLens detection settings (key=value, '#' starts a comment)\n";
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
              << "  22. exfil_min_mb                   = " << s.exfilMinMB << "\n";
}

// ---------- alert store: the single source of truth ----------
std::vector<Alert> alerts;

void pushAlert(const std::string& severity,
               const std::string& type,
               const std::string& message,
               const std::string& ip ,
               const std::string& user ,
               long long epoch ) {
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

// Rapid brute-force reporting reads the shared alerts vector (populated by
// pushRapidBruteForceEpochAlerts) instead of recomputing from login maps.
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

// ---------- datetime engine (civil calendar, midnight-safe) ----------
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
                    int minEvents ) {
    if (eventTimes.size() < static_cast<size_t>(minEvents)) return false;
    std::sort(eventTimes.begin(), eventTimes.end());
    for (size_t i = 0; i + minEvents <= eventTimes.size(); ++i) {
        if (eventTimes[i + minEvents - 1] - eventTimes[i] <= windowSeconds) return true;
    }
    return false;
}

long long firstWindowStart(std::vector<long long> eventTimes, long long windowSeconds,
                           int minEvents ) {
    if (eventTimes.size() < static_cast<size_t>(minEvents)) return -1;
    std::sort(eventTimes.begin(), eventTimes.end());
    for (size_t i = 0; i + minEvents <= eventTimes.size(); ++i) {
        if (eventTimes[i + minEvents - 1] - eventTimes[i] <= windowSeconds)
            return eventTimes[i];
    }
    return -1;
}

// ---------- export helpers ----------
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

// Stable identity for "have I printed this alert already" (live mode).
std::string alertKey(const Alert& a) {
    return a.type + "|" + a.severity + "|" + a.ip + "|" + a.user + "|" + a.message;
}
