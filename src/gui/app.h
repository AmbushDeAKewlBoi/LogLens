#pragma once

#include "loglens/core.h"
#include "loglens/parse.h"
#include "loglens/detect.h"
#include "loglens/report.h"
#include "loglens/cli.h"
#include "imgui.h"

#include <functional>
#include <unordered_set>
#include <cstdint>

enum class Screen { Dashboard, Live, Alerts, Query, Settings };

struct RuleInfo {
    std::string id;
    std::string name;
    std::string description;
    bool enabled = true;
    void (*run)(const std::vector<LogEntry>&, const DetectionSettings&) = nullptr;
};

struct AlertFilter {
    char text[128] = "";
    int severity = 0;
};

struct DashboardState {
    AlertFilter filter;
};

struct LiveState {
    bool watching = false;
    bool paused = false;
    std::string path;
    std::uintmax_t offset = 0;
    std::vector<LogEntry> entries;
    std::vector<Alert> stream;
    std::unordered_set<std::string> seen;
    double lastPoll = 0.0;
    double lastRefresh = 0.0;
    int selected = -1;
    bool autoScroll = true;
    int invalidSkipped = 0;
};

struct FileBrowser {
    bool open = false;
    bool popupOpen = false;
    bool saveMode = false;
    std::string dir;
    std::string selectedFile;
    char saveName[256] = "";
    char extFilter[32] = ".log";
    int selectedIdx = -1;
    std::function<void(const std::string&)> onPick;
};

class LogLensApp {
public:
    LogLensApp();

    SessionState state;
    std::vector<Alert> currentAlerts;
    Screen screen = Screen::Dashboard;
    std::vector<RuleInfo> rules;
    DashboardState dash;
    AlertFilter alertsFilter;
    LiveState live;
    FileBrowser browser;
    std::vector<std::string> recentFiles;
    std::string statusMessage = "No log file loaded. Use File > Open log…";
    bool showAbout = false;
    bool exitRequested = false;
    char queryInput[256] = "";
    std::vector<LogEntry> queryResults;
    std::string querySummary;
    bool queryRan = false;
    int querySort = 0;

    DetectionSettings& settings() { return state.settings; }

    bool loadFile(const std::string& path);
    void refreshAnalysis();
    void runEnabledDetectorsInto(const std::vector<LogEntry>& entries,
                                 std::vector<Alert>& out);

    void withCurrentAlerts(const std::function<void()>& fn);
    static bool alertVisible(const Alert& a, const AlertFilter& f);
    void addRecent(const std::string& path);
    void loadRecent();
    void saveRecent();

    void startLive(const std::string& path);
    void stopLive();
    void resetLive();
    void pollLive(double now);

    void render();
    void renderMenuBar();
    void renderSidebar();
    void renderStatusBar();
    void renderDashboard();
    void renderLive();
    void renderAlerts();
    void renderQuery();
    void renderSettings();
    void renderFileBrowser();
    void renderAbout();

    static ImVec4 severityColor(const std::string& sev);
    static void severityBadge(const std::string& sev);
    static void statCard(const char* label, int value, const ImVec4& color);
    static void riskBadge(const std::string& tier);

private:
    void openBrowser(bool saveMode, const char* extFilter, const char* defaultName,
                     std::function<void(const std::string&)> onPick);
    std::string recentFilePath() const;
};
