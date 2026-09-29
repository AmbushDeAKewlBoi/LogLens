#ifndef LOGLENS_PARSE_H
#define LOGLENS_PARSE_H

#include "core.h"

LogEntry parseLogLine(const std::string& line);
std::vector<std::string> discoverLogFiles(const std::string& path);
std::vector<LogEntry> loadLogs(const std::vector<std::string>& files, int& invalidCount,
                               std::map<std::string, int>& invalidReasons);

#endif  // LOGLENS_PARSE_H
