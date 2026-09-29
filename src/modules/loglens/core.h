#ifndef LOGLENS_CORE_H
#define LOGLENS_CORE_H

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
#if !defined(_WIN32)
#include <sys/select.h>
#include <unistd.h>
#else
#include <conio.h>  // _kbhit() for non-blocking q-to-quit on Windows
#endif

// PORTABILITY: localtime_s exists on Windows (MSVC/MinGW); POSIX only has
// the non-thread-safe localtime(). This wrapper compiles on both without
// any external shim.
#if defined(_WIN32)
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
    std::string sourceFile;  // which log file this entry came from (multi-file analysis)
};

// Validation outcome for a parsed line.
enum class InvalidReason { OK, BAD_DATE, BAD_TIME, BAD_SEVERITY, MISSING_MESSAGE };

struct Alert {
    std::string severity;  // LOW, MEDIUM, HIGH, CRITICAL
    std::string type;      // "rapid_brute_force", "password_spray", ...
    std::string message;   // human-readable, shared by terminal + report
    std::string ip;
    std::string user;
    long long epoch;       // 0 if the detector has no timestamp
};

struct DateTime {
    int year, month, day, hour, minute, second;
};

// Every magic threshold in one place. Defaults match the original behavior.
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
    int offHoursStart = 22;   // off-hours window is [start, end), wraps midnight
    int offHoursEnd = 6;
    long long impossibleTravelWindowSeconds = 600;
    long long exfilWindowSeconds = 600;
    double exfilMinMB = 100.0;
};

struct Incident {
    int id;
    long long startTime;  // epoch; 0 if no alert carried a timestamp
    long long endTime;
    std::string severity;  // worst severity inside
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
    std::string after;   // HH:MM:SS or YYYY-MM-DD HH:MM:SS
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
    std::map<std::string, int> invalidReasons;  // BAD_DATE -> n, ...
    std::vector<Incident> incidents;
    DetectionSettings settings;
};

extern std::vector<Alert> alerts;

std::string extractValue(const std::string& text, const std::string& key);
std::string toLower(std::string text);
std::string toUpper(std::string text);
std::string getRiskLevel(int failedAttempts);
bool isAllDigits(const std::string& s);
bool isLeapYear(int y);
int daysInMonth(int y, int m);
bool validSeverity(const std::string& s);
InvalidReason invalidReason(const LogEntry& entry);
bool isValidLogLine(const LogEntry& entry);
std::string invalidReasonText(InvalidReason r);
void writeInvalidBreakdown(std::ostream& os, const std::map<std::string, int>& reasons);
bool loadSettings(const std::string& path, DetectionSettings& s);
bool saveSettings(const std::string& path, const DetectionSettings& s);
void printSettings(const DetectionSettings& s);
void pushAlert(const std::string& severity,
               const std::string& type,
               const std::string& message,
               const std::string& ip = "",
               const std::string& user = "",
               long long epoch = 0);
void printAlerts();
int countAlertsOfType(const std::string& type);
int countAlertsOfSeverity(const std::string& severity);
std::string formatRapidBruteForceMessage(const std::string& ip, const DetectionSettings& s);
std::vector<Alert> rapidBruteForceAlerts();
int countRapidBruteForce();
void exportRapidBruteForceSection(std::ofstream& report);
DateTime parseDateTime(const std::string& date, const std::string& time);
long long daysFromCivil(int y, int m, int d);
long long toEpochSeconds(const DateTime& dt);
long long logEntryEpoch(const LogEntry& e);
bool occurredWithin(std::vector<long long> eventTimes, long long windowSeconds,
                    int minEvents = 3);
long long firstWindowStart(std::vector<long long> eventTimes, long long windowSeconds,
                           int minEvents = 3);
std::string epochToString(long long epoch);
std::string reportTimestamp();
std::string jsonEscape(const std::string& s);
std::string csvEscape(const std::string& s);
std::string alertKey(const Alert& a);

#endif  // LOGLENS_CORE_H
