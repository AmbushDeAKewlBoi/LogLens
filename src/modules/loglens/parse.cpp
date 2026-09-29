#include "parse.h"

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
    // normalize severity: case-insensitive, WARNING -> WARN
    std::string sev = toUpper(entry.severity);
    if (sev == "WARNING") sev = "WARN";
    entry.severity = sev;
    entry.user = extractValue(entry.message, "user");
    entry.ip = extractValue(entry.message, "ip");
    return entry;
}

// MULTI-FILE / FOLDER ANALYSIS
// LogEntry.sourceFile (added to the struct in phase 0) finally
// gets used: every entry remembers where it came from.
// ============================================================

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
    // one merged timeline, ordered by real epoch time
    std::sort(entries.begin(), entries.end(),
              [](const LogEntry& a, const LogEntry& b) {
                  return logEntryEpoch(a) < logEntryEpoch(b);
              });
    return entries;
}
