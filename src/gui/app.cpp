// LogLens GUI — application foundation: rule registry, analysis plumbing,
// menu bar, sidebar, file browser, settings/query/alerts screens, widgets.
#include "app.h"

#include <cstdlib>
#include <sstream>

// Adapt two detectors whose signatures don't match the registry's shape.
static void runRepeatedFailures(const std::vector<LogEntry>& entries,
                                const DetectionSettings& s) {
    std::unordered_map<std::string, int> failedLoginCounts, failedUserCounts;
    std::unordered_map<std::string, std::vector<int>> failedLoginTimes;
    for (const auto& e : entries)
        trackFailedLogin(e, failedLoginCounts, failedUserCounts, failedLoginTimes);
    pushRepeatedFailureAlerts(entries, failedLoginCounts, failedUserCounts, s);
}

static void runHighErrorRate(const std::vector<LogEntry>& entries,
                             const DetectionSettings& s) {
    int errorCount = 0;
    for (const auto& e : entries)
        if (e.severity == "ERROR") errorCount++;
    if (hasHighErrorRate(static_cast<int>(entries.size()), errorCount, s)) {
        std::ostringstream msg;
        msg << "High global error rate: " << errorCount << " of " << entries.size()
            << " logs are ERROR.";
        pushAlert("MEDIUM", "high_error_rate", msg.str());
    }
}

// Build the rule registry in pipeline order.
LogLensApp::LogLensApp() {
    rules = {
        {"repeated_failures", "Repeated login failures",
         "3+ failed logins for one IP or user (LOW/MEDIUM/HIGH by count).", true,
         runRepeatedFailures},
        {"rapid_brute_force", "Rapid brute force",
         "N failed logins from one IP inside a short window (epoch-stamped).", true,
         pushRapidBruteForceEpochAlerts},
        {"password_spray", "Password spraying",
         "One IP trying many distinct usernames.", true, detectPasswordSpray},
        {"distributed_attack", "Distributed account attack",
         "Many IPs targeting one account.", true, detectDistributedAttack},
        {"login_burst", "Login burst",
         "Abnormal burst of login attempts overall.", true, detectLoginBurst},
        {"error_burst", "Error burst",
         "Cluster of ERROR lines inside a short window.", true, detectErrorBursts},
        {"repeated_error", "Repeated errors",
         "Same error message repeating.", true, detectRepeatedErrors},
        {"service_failure", "Service failures",
         "Repeated service start/stop/failure messages.", true, detectServiceFailures},
        {"warn_escalation", "WARN-to-ERROR escalation",
         "Warnings that turn into errors shortly after.", true, detectWarnEscalation},
        {"dense_activity", "Dense activity",
         "Unusually many log lines in a short window.", true, detectDenseActivity},
        {"high_error_rate", "High error rate",
         "Global ERROR share above threshold.", true, runHighErrorRate},
        {"off_hours_access", "Off-hours access",
         "Successful logins outside configured hours.", true, detectOffHoursAccess},
        {"impossible_travel", "Impossible travel",
         "Same user from 2+ IPs within a short window.", true, detectImpossibleTravel},
        {"privilege_escalation", "Privilege escalation",
         "sudo/su/admin keywords with failed/denied.", true, detectPrivilegeEscalation},
        {"data_exfiltration", "Data exfiltration",
         "Large byte/download volumes per IP in a window.", true, detectDataExfiltration},
        {"new_ip_for_user", "New IP for user",
         "Known user seen from a never-before-seen IP.", true, detectNewIpForUser},
    };
    loadRecent();
}

// Analysis plumbing (no ImGui calls — unit-testable).
bool LogLensApp::loadFile(const std::string& path) {
    SessionState fresh;
    fresh.settings = state.settings;  // keep the user's thresholds
    if (!loadIntoState(fresh, path)) {
        statusMessage = "Failed to load: " + path;
        return false;
    }
    state = std::move(fresh);
    refreshAnalysis();
    addRecent(path);
    std::ostringstream ss;
    ss << "Loaded " << state.entries.size() << " entries (" << state.invalidCount
       << " invalid) from " << path;
    statusMessage = ss.str();
    queryRan = false;
    return true;
}

void LogLensApp::refreshAnalysis() {
    runEnabledDetectorsInto(state.entries, currentAlerts);
    state.incidents = correlateIncidents(currentAlerts);
}

// Swap the library's global alert vector aside, run only enabled rules, then
// restore it. Keeps the live tail's detector runs from clobbering the main
// analysis (and vice versa).
void LogLensApp::runEnabledDetectorsInto(const std::vector<LogEntry>& entries,
                                         std::vector<Alert>& out) {
    std::vector<Alert> saved = alerts;
    alerts.clear();
    for (const auto& r : rules)
        if (r.enabled && r.run) r.run(entries, state.settings);
    out = alerts;
    alerts = std::move(saved);
}

void LogLensApp::withCurrentAlerts(const std::function<void()>& fn) {
    std::vector<Alert> saved = alerts;
    alerts = currentAlerts;
    fn();
    alerts = std::move(saved);
}

bool LogLensApp::alertVisible(const Alert& a, const AlertFilter& f) {
    static const char* names[] = {"", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    if (f.severity > 0 && a.severity != names[f.severity]) return false;
    if (f.text[0] != '\0') {
        std::string needle = toLower(f.text);
        std::string hay = toLower(a.message + " " + a.type + " " + a.ip + " " + a.user);
        if (hay.find(needle) == std::string::npos) return false;
    }
    return true;
}

std::string LogLensApp::recentFilePath() const {
#if defined(_WIN32)
    const char* home = std::getenv("USERPROFILE");
#else
    const char* home = std::getenv("HOME");
#endif
    std::string dir = home ? home : ".";
    return dir + "/.loglens_recent";
}

void LogLensApp::loadRecent() {
    recentFiles.clear();
    std::ifstream f(recentFilePath());
    std::string line;
    while (std::getline(f, line) && recentFiles.size() < 8) {
        if (!line.empty()) recentFiles.push_back(line);
    }
}

void LogLensApp::saveRecent() {
    std::ofstream f(recentFilePath(), std::ios::trunc);
    for (const auto& p : recentFiles) f << p << "\n";
}

void LogLensApp::addRecent(const std::string& path) {
    recentFiles.erase(std::remove(recentFiles.begin(), recentFiles.end(), path),
                      recentFiles.end());
    recentFiles.insert(recentFiles.begin(), path);
    if (recentFiles.size() > 8) recentFiles.resize(8);
    saveRecent();
}

// Reusable widgets.
ImVec4 LogLensApp::severityColor(const std::string& sev) {
    if (sev == "CRITICAL") return ImVec4(1.0f, 0.25f, 0.25f, 1.0f);
    if (sev == "HIGH")     return ImVec4(1.0f, 0.45f, 0.20f, 1.0f);
    if (sev == "MEDIUM")   return ImVec4(1.0f, 0.75f, 0.20f, 1.0f);
    if (sev == "LOW")      return ImVec4(0.55f, 0.80f, 0.55f, 1.0f);
    if (sev == "ERROR")    return ImVec4(1.0f, 0.35f, 0.35f, 1.0f);
    if (sev == "WARN")     return ImVec4(1.0f, 0.75f, 0.20f, 1.0f);
    if (sev == "INFO")     return ImVec4(0.45f, 0.70f, 1.00f, 1.0f);
    return ImVec4(0.65f, 0.65f, 0.65f, 1.0f);
}

void LogLensApp::severityBadge(const std::string& sev) {
    ImVec2 ts = ImGui::CalcTextSize(sev.c_str());
    const float padX = 6.0f, padY = 2.0f;
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    ImVec2 p1(p0.x + ts.x + padX * 2.0f, p0.y + ts.y + padY * 2.0f);
    ImVec4 bg = severityColor(sev);
    bg.w = 0.30f;
    ImGui::GetWindowDrawList()->AddRectFilled(p0, p1, ImGui::GetColorU32(bg), 4.0f);
    ImGui::GetWindowDrawList()->AddText(ImVec2(p0.x + padX, p0.y + padY),
                                       ImGui::GetColorU32(ImVec4(1, 1, 1, 1)),
                                       sev.c_str());
    ImGui::Dummy(ImVec2(p1.x - p0.x, p1.y - p0.y));
}

void LogLensApp::riskBadge(const std::string& tier) {
    ImVec4 c(0.65f, 0.65f, 0.65f, 1.0f);
    if (tier == "HIGH") c = ImVec4(1.0f, 0.35f, 0.35f, 1.0f);
    else if (tier == "MEDIUM") c = ImVec4(1.0f, 0.75f, 0.20f, 1.0f);
    else if (tier == "LOW") c = ImVec4(0.55f, 0.80f, 0.55f, 1.0f);
    ImGui::TextColored(c, "%s", tier.c_str());
}

void LogLensApp::statCard(const char* label, int value, const ImVec4& color) {
    ImGui::BeginChild(label, ImVec2(150, 62));
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    ImVec2 avail = ImGui::GetContentRegionAvail();
    ImGui::GetWindowDrawList()->AddRect(
        p0, ImVec2(p0.x + avail.x, p0.y + 62.0f),
        ImGui::GetColorU32(ImVec4(0.45f, 0.45f, 0.50f, 0.6f)), 6.0f);
    ImGui::Dummy(ImVec2(0, 6));
    ImGui::TextUnformatted(label);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%d", value);
    ImGui::TextColored(color, "%s", buf);
    ImGui::EndChild();
}

// Frame rendering.
void LogLensApp::render() {
    renderMenuBar();

    const float barH = ImGui::GetFrameHeight();
    ImGui::BeginChild("sidebar", ImVec2(150, -barH - 4));
    renderSidebar();
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("main", ImVec2(0, -barH - 4));
    switch (screen) {
        case Screen::Dashboard: renderDashboard(); break;
        case Screen::Live:      renderLive();      break;
        case Screen::Alerts:    renderAlerts();    break;
        case Screen::Query:     renderQuery();     break;
        case Screen::Settings:  renderSettings();  break;
    }
    ImGui::EndChild();

    renderStatusBar();
    renderFileBrowser();
    renderAbout();

    if (live.watching) pollLive(ImGui::GetTime());
}

void LogLensApp::renderMenuBar() {
    if (!ImGui::BeginMainMenuBar()) return;
    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open log...", "Ctrl+O"))
            openBrowser(false, ".log", "", [this](const std::string& p) { loadFile(p); });
        if (ImGui::BeginMenu("Open recent", !recentFiles.empty())) {
            for (const auto& p : recentFiles)
                if (ImGui::MenuItem(p.c_str())) loadFile(p);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Export")) {
            if (ImGui::MenuItem("Alerts as JSON..."))
                openBrowser(true, ".json", "alerts.json",
                            [this](const std::string& p) {
                                withCurrentAlerts(
                                    [&] { exportAlertsJson(p); });
                                statusMessage = "Alerts exported to " + p;
                            });
            if (ImGui::MenuItem("Alerts as CSV..."))
                openBrowser(true, ".csv", "alerts.csv",
                            [this](const std::string& p) {
                                withCurrentAlerts(
                                    [&] { exportAlertsCsv(p); });
                                statusMessage = "Alerts exported to " + p;
                            });
            if (ImGui::MenuItem("Entries as CSV..."))
                openBrowser(true, ".csv", "entries.csv",
                            [this](const std::string& p) {
                                exportEntriesCsv(p, state.entries);
                                statusMessage = "Entries exported to " + p;
                            });
            if (ImGui::MenuItem("Full report (TXT, into reports/)")) {
                withCurrentAlerts([this] { exportFullReport(state); });
                statusMessage = "Full text report written into reports/.";
            }
            ImGui::EndMenu();
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4")) exitRequested = true;
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
        if (ImGui::MenuItem("Dashboard")) screen = Screen::Dashboard;
        if (ImGui::MenuItem("Live Monitor")) screen = Screen::Live;
        if (ImGui::MenuItem("Alerts")) screen = Screen::Alerts;
        if (ImGui::MenuItem("Query")) screen = Screen::Query;
        if (ImGui::MenuItem("Settings")) screen = Screen::Settings;
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Help")) {
        if (ImGui::MenuItem("About LogLens")) showAbout = true;
        ImGui::EndMenu();
    }
    ImGui::EndMainMenuBar();
}

void LogLensApp::renderSidebar() {
    ImGui::TextUnformatted("LogLens");
    ImGui::Separator();
    struct Item { const char* label; Screen s; };
    static const Item items[] = {
        {"Dashboard", Screen::Dashboard},
        {"Live Monitor", Screen::Live},
        {"Alerts", Screen::Alerts},
        {"Query", Screen::Query},
        {"Settings", Screen::Settings},
    };
    for (const auto& it : items) {
        bool active = (screen == it.s);
        if (active) ImGui::TextColored(ImVec4(0.45f, 0.70f, 1.0f, 1.0f), ">");
        if (active) ImGui::SameLine();
        if (ImGui::Button(it.label, ImVec2(-1, 0))) screen = it.s;
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextWrapped("%s", state.sourcePath.empty() ? "no file loaded"
                                                      : state.sourcePath.c_str());
    if (ImGui::Button("Open log...", ImVec2(-1, 0)))
        openBrowser(false, ".log", "", [this](const std::string& p) { loadFile(p); });
}

void LogLensApp::renderStatusBar() {
    ImGui::Separator();
    ImGui::TextUnformatted(statusMessage.c_str());
}

// Hand-rolled ImGui file browser (no native-dialog dependency).
void LogLensApp::openBrowser(bool saveMode, const char* extFilter,
                             const char* defaultName,
                             std::function<void(const std::string&)> onPick) {
    browser.saveMode = saveMode;
    browser.onPick = std::move(onPick);
    browser.selectedFile.clear();
    browser.selectedIdx = -1;
    std::snprintf(browser.saveName, sizeof(browser.saveName), "%s",
                  defaultName ? defaultName : "");
    std::snprintf(browser.extFilter, sizeof(browser.extFilter), "%s",
                  extFilter ? extFilter : "");
    std::error_code ec;
    browser.dir = std::filesystem::current_path(ec).string();
    if (ec) browser.dir = ".";
    browser.open = true;  // render loop turns this into OpenPopup once
}

void LogLensApp::renderFileBrowser() {
    if (browser.open) {
        ImGui::OpenPopup("File browser");
        browser.open = false;
        browser.popupOpen = true;
    }
    if (!browser.popupOpen) return;

    bool keepOpen = true;
    ImGui::SetNextWindowSize(ImVec2(560, 420), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal("File browser", &keepOpen,
                               ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped("%s", browser.dir.c_str());
        ImGui::Separator();

        // Collect entries: directories first, then files (extension-filtered
        // in open mode; all files hidden in save mode).
        struct Row { std::string name; bool isDir; };
        std::vector<Row> rows;
        {
            std::error_code ec;
            std::filesystem::directory_iterator it(browser.dir, ec), end;
            for (; it != end; it.increment(ec)) {
                if (ec) break;
                std::error_code ec2;
                bool isDir = it->is_directory(ec2);
                std::string name = it->path().filename().string();
                if (name.empty()) continue;
                if (!isDir && !browser.saveMode && browser.extFilter[0] != '\0') {
                    std::string lower = toLower(name);
                    if (lower.size() < std::strlen(browser.extFilter) ||
                        lower.compare(lower.size() - std::strlen(browser.extFilter),
                                      std::string::npos, browser.extFilter) != 0)
                        continue;
                }
                if (!isDir && browser.saveMode) continue;
                rows.push_back({name, isDir});
            }
        }
        std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
            if (a.isDir != b.isDir) return a.isDir > b.isDir;
            return toLower(a.name) < toLower(b.name);
        });

        ImGui::BeginChild("browser_list", ImVec2(0, 260));
        int idx = 0;
        if (ImGui::Selectable("..", false)) {
            std::filesystem::path p(browser.dir);
            if (p.has_parent_path()) browser.dir = p.parent_path().string();
            browser.selectedFile.clear();
        }
        for (const auto& r : rows) {
            std::string label = (r.isDir ? "[dir] " : "") + r.name;
            bool selected = (browser.selectedFile == r.name);
            if (ImGui::Selectable(label.c_str(), selected)) {
                browser.selectedFile = r.name;
                browser.selectedIdx = idx;
                if (r.isDir) {
                    browser.dir =
                        (std::filesystem::path(browser.dir) / r.name).string();
                    browser.selectedFile.clear();
                }
            }
            ++idx;
        }
        ImGui::EndChild();
        ImGui::Separator();

        bool canOk = false;
        std::string chosen;
        if (browser.saveMode) {
            ImGui::InputText("File name", browser.saveName,
                             sizeof(browser.saveName));
            canOk = browser.saveName[0] != '\0';
            if (canOk)
                chosen = (std::filesystem::path(browser.dir) /
                          browser.saveName)
                             .string();
        } else {
            canOk = !browser.selectedFile.empty();
            if (canOk)
                chosen = (std::filesystem::path(browser.dir) /
                          browser.selectedFile)
                             .string();
        }

        if (ImGui::Button(browser.saveMode ? "Save" : "Open", ImVec2(120, 0))) {
            if (canOk && browser.onPick) browser.onPick(chosen);
            ImGui::CloseCurrentPopup();
            browser.popupOpen = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            ImGui::CloseCurrentPopup();
            browser.popupOpen = false;
        }
        ImGui::EndPopup();
    } else {
        browser.popupOpen = false;  // closed via X
    }
}

// Settings screen: thresholds, rule toggles, config load/save.
void LogLensApp::renderSettings() {
    ImGui::TextUnformatted("Detection settings");
    ImGui::Separator();

    DetectionSettings& s = state.settings;
    if (ImGui::BeginTable("settings", 2, ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Setting");
        ImGui::TableSetupColumn("Value");
        ImGui::TableHeadersRow();
        auto intRow = [](const char* label, int* v) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(label);
            ImGui::TableNextColumn();
            ImGui::PushID(label);
            ImGui::InputInt("##v", v, 1, 10);
            ImGui::PopID();
        };
        auto dblRow = [](const char* label, double* v) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(label);
            ImGui::TableNextColumn();
            ImGui::PushID(label);
            ImGui::InputDouble("##v", v, 0.0, 0.0, "%.2f");
            ImGui::PopID();
        };
        auto llRow = [](const char* label, long long* v) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(label);
            ImGui::TableNextColumn();
            ImGui::PushID(label);
            int tmp = static_cast<int>(*v);
            if (ImGui::InputInt("##v", &tmp, 1, 60) && tmp > 0)
                *v = tmp;
            ImGui::PopID();
        };
        intRow("Brute force: min attempts", &s.bruteForceMinAttempts);
        llRow("Brute force: window (s)", &s.bruteForceWindowSeconds);
        intRow("Password spray: min users", &s.sprayMinUsers);
        llRow("Password spray: window (s)", &s.sprayWindowSeconds);
        intRow("Distributed attack: min IPs", &s.distributedMinIps);
        intRow("Login burst: min attempts", &s.loginBurstMinAttempts);
        intRow("Error burst: min count", &s.errorBurstMinCount);
        llRow("Error burst: window (s)", &s.errorBurstWindowSeconds);
        intRow("Repeated failures: min attempts", &s.repeatedFailureMinAttempts);
        intRow("Repeated errors: min count", &s.repeatedErrorMinCount);
        intRow("Service failures: min count", &s.serviceFailureMinCount);
        intRow("Off-hours start (hour)", &s.offHoursStart);
        intRow("Off-hours end (hour)", &s.offHoursEnd);
        dblRow("Exfiltration: min MB", &s.exfilMinMB);
        dblRow("High error rate: min ratio", &s.highErrorMinRate);
        intRow("High error rate: min errors", &s.highErrorMinErrors);
        ImGui::EndTable();
    }

    if (ImGui::Button("Apply & re-analyze", ImVec2(200, 0))) {
        refreshAnalysis();
        statusMessage = "Settings applied; analysis refreshed.";
    }
    ImGui::SameLine();
    static char cfgPath[256] = "loglens.cfg";
    ImGui::InputText("config file", cfgPath, sizeof(cfgPath));
    ImGui::SameLine();
    if (ImGui::Button("Load")) {
        if (loadSettings(cfgPath, state.settings)) {
            refreshAnalysis();
            statusMessage = std::string("Settings loaded from ") + cfgPath;
        } else {
            statusMessage = std::string("Could not load ") + cfgPath;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Save")) {
        if (saveSettings(cfgPath, state.settings))
            statusMessage = std::string("Settings saved to ") + cfgPath;
        else
            statusMessage = std::string("Could not save ") + cfgPath;
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextUnformatted("Detection rules");
    for (auto& r : rules) {
        ImGui::Checkbox(r.name.c_str(), &r.enabled);
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "(%s)", r.id.c_str());
        ImGui::Indent();
        ImGui::TextWrapped("%s", r.description.c_str());
        ImGui::Unindent();
    }
    if (ImGui::Button("Apply rule changes & re-analyze", ImVec2(260, 0))) {
        refreshAnalysis();
        statusMessage = "Rule set applied; analysis refreshed.";
    }
}

// Query screen: expression input using parseQuery/runQuery.
void LogLensApp::renderQuery() {
    ImGui::TextUnformatted("Query logs");
    ImGui::TextWrapped(
        "Expression like: severity=ERROR user=admin ip=10.0.0.1 contains=\"disk "
        "full\" after=10:00:00 before=12:00:00");
    bool run = ImGui::InputText("query", queryInput, sizeof(queryInput),
                                ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Run")) run = true;
    ImGui::SameLine();
    const char* sorts[] = {"time", "severity", "ip", "user"};
    ImGui::Combo("sort by", &querySort, sorts, 4);

    if (run && queryInput[0] != '\0') {
        Query q = parseQuery(queryInput);
        queryResults = runQuery(state.entries, q);
        static const char* keys[] = {"time", "severity", "ip", "user"};
        sortEntries(queryResults, keys[querySort]);
        std::ostringstream ss;
        ss << queryResults.size() << " matching entries";
        querySummary = ss.str();
        queryRan = true;
    }

    if (queryRan) {
        ImGui::Separator();
        ImGui::TextUnformatted(querySummary.c_str());
        if (ImGui::BeginTable("query_results", 5,
                              ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV |
                                  ImGuiTableFlags_ScrollY,
                              ImVec2(0, 400))) {
            ImGui::TableSetupColumn("Time");
            ImGui::TableSetupColumn("Severity");
            ImGui::TableSetupColumn("IP");
            ImGui::TableSetupColumn("User");
            ImGui::TableSetupColumn("Message");
            ImGui::TableHeadersRow();
            size_t shown = 0;
            for (const auto& e : queryResults) {
                if (shown++ >= 2000) break;  // keep huge results responsive
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%s %s", e.date.c_str(), e.time.c_str());
                ImGui::TableNextColumn();
                severityBadge(e.severity);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(e.ip.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(e.user.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(e.message.c_str());
            }
            ImGui::EndTable();
        }
        if (queryResults.size() > 2000)
            ImGui::TextWrapped("Showing first 2000 of %zu results.",
                               queryResults.size());
    }
}

// Alerts screen: filterable table, click for detail.
void LogLensApp::renderAlerts() {
    ImGui::TextUnformatted("Security alerts");
    ImGui::Separator();

    ImGui::InputText("filter", alertsFilter.text, sizeof(alertsFilter.text));
    ImGui::SameLine();
    const char* sevs[] = {"All", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    ImGui::Combo("severity", &alertsFilter.severity, sevs, 5);

    static int selected = -1;
    int visible = 0;
    if (ImGui::BeginTable("alerts", 4,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV |
                              ImGuiTableFlags_ScrollY |
                              ImGuiTableFlags_SizingStretchProp,
                          ImVec2(0, 380))) {
        ImGui::TableSetupColumn("Time");
        ImGui::TableSetupColumn("Severity");
        ImGui::TableSetupColumn("Rule");
        ImGui::TableSetupColumn("Message");
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < currentAlerts.size(); ++i) {
            const Alert& a = currentAlerts[i];
            if (!alertVisible(a, alertsFilter)) continue;
            ++visible;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(epochToString(a.epoch).c_str());
            ImGui::TableNextColumn();
            severityBadge(a.severity);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(a.type.c_str());
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::Selectable(a.message.c_str(), selected == (int)i))
                selected = static_cast<int>(i);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    char countBuf[64];
    std::snprintf(countBuf, sizeof(countBuf), "%d of %zu alerts shown", visible,
                  currentAlerts.size());
    ImGui::TextUnformatted(countBuf);

    // Detail inspector for the clicked alert.
    if (selected >= 0 && (size_t)selected < currentAlerts.size()) {
        ImGui::Separator();
        const Alert& a = currentAlerts[(size_t)selected];
        ImGui::TextUnformatted("Alert detail");
        ImGui::TextWrapped("%s", a.message.c_str());
        if (ImGui::BeginTable("alert_detail", 2, ImGuiTableFlags_BordersV)) {
            ImGui::TableSetupColumn("Field");
            ImGui::TableSetupColumn("Value");
            auto row = [](const char* k, const std::string& v) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(k);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(v.c_str());
            };
            row("rule", a.type);
            row("severity", a.severity);
            row("ip", a.ip.empty() ? "-" : a.ip);
            row("user", a.user.empty() ? "-" : a.user);
            row("epoch", a.epoch ? std::to_string(a.epoch) : std::string("-"));
            row("time", a.epoch ? epochToString(a.epoch) : std::string("-"));
            char scoreBuf[32];
            std::snprintf(scoreBuf, sizeof(scoreBuf), "%d (%s)",
                          scoreForAlertType(a.type),
                          riskTier(scoreForAlertType(a.type)).c_str());
            row("risk", scoreBuf);
            ImGui::EndTable();
        }
    }
}

void LogLensApp::renderAbout() {
    if (showAbout) {
        ImGui::OpenPopup("About LogLens");
        showAbout = false;
    }
    ImGui::SetNextWindowSize(ImVec2(420, 0), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal("About LogLens", nullptr,
                               ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("LogLens — log analysis workbench");
        ImGui::Separator();
        ImGui::TextWrapped(
            "Parses log files, validates every line, runs 16 detection rules, "
            "scores risk per IP/user, correlates incidents, and exports "
            "TXT/JSON/CSV reports. Includes a live file-tail monitor.");
        ImGui::TextWrapped("Built with Dear ImGui + GLFW + OpenGL3, C++17.");
        if (ImGui::Button("Close", ImVec2(120, 0)))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}
