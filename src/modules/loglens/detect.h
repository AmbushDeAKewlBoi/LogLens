#ifndef LOGLENS_DETECT_H
#define LOGLENS_DETECT_H

#include "core.h"

int timeToSeconds(const std::string& time);  // defined below; used by trackFailedLogin

void trackFailedLogin(
    const LogEntry& entry,
    std::unordered_map<std::string, int>& failedLoginCounts,
    std::unordered_map<std::string, int>& failedUserCounts,
    std::unordered_map<std::string, std::vector<int>>& failedLoginTimestamps);
void printSecurityAlerts(const std::unordered_map<std::string, int>& failedLoginCounts,
                          const std::unordered_map<std::string, int>& failedUserCounts,
                        int& suspiciousIpCount,
                        int& suspiciousUserCount
                    );
bool hasHighErrorRate(int totalLogs, int errorCount, const DetectionSettings& s);
int timeToSeconds(const std::string& time);
bool hasRapidFailedLogins(const std::vector<int>& times);
void pushRepeatedFailureAlerts(
    const std::vector<LogEntry>& entries,
    const std::unordered_map<std::string, int>& failedLoginCounts,
    const std::unordered_map<std::string, int>& failedUserCounts,
    const DetectionSettings& s);
void pushRapidBruteForceEpochAlerts(const std::vector<LogEntry>& entries,
                                    const DetectionSettings& s);
void detectPasswordSpray(const std::vector<LogEntry>& entries, const DetectionSettings& s);
void detectDistributedAttack(const std::vector<LogEntry>& entries, const DetectionSettings& s);
void detectLoginBurst(const std::vector<LogEntry>& entries, const DetectionSettings& s);
void detectErrorBursts(const std::vector<LogEntry>& entries, const DetectionSettings& s);
void detectRepeatedErrors(const std::vector<LogEntry>& entries, const DetectionSettings& s);
void detectServiceFailures(const std::vector<LogEntry>& entries, const DetectionSettings& s);
void detectWarnEscalation(const std::vector<LogEntry>& entries, const DetectionSettings& s);
void detectDenseActivity(const std::vector<LogEntry>& entries, const DetectionSettings& s);
void detectOffHoursAccess(const std::vector<LogEntry>& entries, const DetectionSettings& s);
void detectImpossibleTravel(const std::vector<LogEntry>& entries, const DetectionSettings& s);
void detectPrivilegeEscalation(const std::vector<LogEntry>& entries,
                               const DetectionSettings& /*s*/);
double parseVolumeMB(const std::string& msg);
void detectDataExfiltration(const std::vector<LogEntry>& entries, const DetectionSettings& s);
void detectNewIpForUser(const std::vector<LogEntry>& entries,
                         const DetectionSettings& /*s*/);
void runAllDetectors(const std::vector<LogEntry>& entries, const DetectionSettings& settings);
int scoreForAlertType(const std::string& type);
std::string riskTier(int score);
void aggregateRiskScores(std::unordered_map<std::string, int>& ipScores,
                         std::unordered_map<std::string, int>& userScores);
int riskScoreForIp(const std::string& ip);
int riskScoreForUser(const std::string& user);
void printRiskScores();
void exportRiskSection(std::ofstream& report);
int severityRank(const std::string& s);
std::string formatDuration(long long seconds);
std::vector<Incident> correlateIncidents(const std::vector<Alert>& allAlerts);
void printIncidents(const std::vector<Incident>& incidents);
void exportIncidentsSection(std::ofstream& report,
                            const std::vector<Incident>& incidents);

#endif  // LOGLENS_DETECT_H
