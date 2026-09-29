#ifndef LOGLENS_REPORT_H
#define LOGLENS_REPORT_H

#include "core.h"
#include "detect.h"

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
);
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
);
void exportAlertsSection(std::ofstream& report);
SummaryCounts computeCounts(const std::vector<LogEntry>& entries, int invalidCount,
                            const DetectionSettings& settings);
void exportFullReport(const SessionState& st);
bool exportAlertsJson(const std::string& path);
bool exportAlertsCsv(const std::string& path);
bool exportEntriesCsv(const std::string& path, const std::vector<LogEntry>& entries);
void exportLegacyReport(SessionState& st);
void filterLogs(const std::vector<LogEntry>& entries);
Query parseQuery(const std::string& input);
bool matchesQuery(const LogEntry& e, const Query& q);
std::vector<LogEntry> runQuery(const std::vector<LogEntry>& entries, const Query& q);
void sortEntries(std::vector<LogEntry>& entries, const std::string& key);
void runQueryCli(const std::vector<LogEntry>& entries);
void printIpProfile(const std::string& ip, const std::vector<LogEntry>& entries,
                    const std::vector<Incident>& incidents);
void printUserProfile(const std::string& user, const std::vector<LogEntry>& entries);

#endif  // LOGLENS_REPORT_H
