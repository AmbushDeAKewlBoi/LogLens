#ifndef LOGLENS_CLI_H
#define LOGLENS_CLI_H

#include "core.h"
#include "parse.h"
#include "detect.h"
#include "report.h"

extern volatile std::sig_atomic_t g_liveStop;

void printSummaryFromEntries(const std::vector<LogEntry>& entries, int invalidCount,
                             const std::map<std::string, int>& invalidReasons,
                             const DetectionSettings& settings);
void refreshAnalysis(SessionState& st);
bool loadIntoState(SessionState& st, const std::string& path);
void alertsMenu();
void filterQueryMenu(SessionState& st);
void exportMenu(SessionState& st);
void profileMenu(SessionState& st);
bool changeSetting(DetectionSettings& s, int num);
void settingsMenu(SessionState& st);
void liveSigintHandler(int);
bool stdinHasQuit();
void liveCheckEntry(const LogEntry& e,
                    std::unordered_map<std::string, std::vector<long long>>& recentFails,
                    const DetectionSettings& settings);
void liveMonitor(const std::string& path, const DetectionSettings& settings);
void runCli(SessionState& st);

#endif  // LOGLENS_CLI_H
