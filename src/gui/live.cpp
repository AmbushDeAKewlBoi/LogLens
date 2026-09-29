// LogLens GUI — live log monitor screen (block 13).
//
// Tails a growing file: polls for appended bytes, parses new lines with the
// real library parser/validator, re-runs the enabled detectors on the growing
// entry set, and streams new alerts into the alert panel. Pause/resume,
// active-file display, clear/reset, and a click-to-inspect alert detail view.
#include "app.h"

#include <sstream>

// Tail engine (no ImGui calls).
void LogLensApp::startLive(const std::string& path) {
    stopLive();
    live.path = path;
    std::error_code ec;
    auto sz = std::filesystem::file_size(path, ec);
    live.offset = ec ? 0 : sz;  // tail -f semantics: start at EOF
    live.watching = true;
    live.paused = false;
    live.lastPoll = 0.0;
    live.lastRefresh = 0.0;
    statusMessage = "Tailing " + path;
}

void LogLensApp::stopLive() {
    live.watching = false;
    live.paused = false;
}

void LogLensApp::resetLive() {
    live.entries.clear();
    live.stream.clear();
    live.seen.clear();
    live.selected = -1;
    live.invalidSkipped = 0;
    std::error_code ec;
    auto sz = std::filesystem::file_size(live.path, ec);
    live.offset = ec ? 0 : sz;
    statusMessage = "Live view cleared; watching " + live.path;
}

void LogLensApp::pollLive(double now) {
    if (!live.watching || live.paused) return;
    if (now - live.lastPoll < 0.5) return;  // poll the file twice a second
    live.lastPoll = now;

    std::error_code ec;
    auto sz = std::filesystem::file_size(live.path, ec);
    if (ec) return;
    if (sz < live.offset) {
        // File shrank: rotation or truncation — start over at the beginning.
        live.offset = 0;
        live.entries.clear();
        live.stream.clear();
        live.seen.clear();
        live.selected = -1;
    }
    if (sz > live.offset) {
        std::ifstream f(live.path, std::ios::binary);
        if (f) {
            f.seekg(static_cast<std::streamoff>(live.offset));
            std::string data((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
            live.offset = sz;
            std::istringstream ss(data);
            std::string line;
            bool grew = false;
            while (std::getline(ss, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty()) continue;
                LogEntry e = parseLogLine(line);
                e.sourceFile = live.path;
                if (invalidReason(e) != InvalidReason::OK) {
                    live.invalidSkipped++;
                    continue;
                }
                live.entries.push_back(e);
                grew = true;
            }
            if (grew) live.lastRefresh = 0.0;  // re-run detectors immediately
        }
    }

    // Full detector refresh at most every 2s, only when there is data.
    if (!live.entries.empty() && now - live.lastRefresh >= 2.0) {
        live.lastRefresh = now;
        std::vector<Alert> fresh;
        runEnabledDetectorsInto(live.entries, fresh);
        for (const auto& a : fresh) {
            if (live.seen.insert(alertKey(a)).second)
                live.stream.push_back(a);
        }
    }
}

// Live screen rendering.
void LogLensApp::renderLive() {
    ImGui::TextUnformatted("Live monitor");
    ImGui::Separator();

    // --- control bar ---
    if (!live.watching) {
        if (ImGui::Button("Tail current file", ImVec2(160, 0))) {
            if (!state.sourcePath.empty())
                startLive(state.sourcePath);
            else
                statusMessage = "Load a log file first (File > Open log…).";
        }
        ImGui::SameLine();
        if (ImGui::Button("Choose file...", ImVec2(160, 0))) {
            openBrowser(false, ".log", "", [this](const std::string& p) {
                startLive(p);
                screen = Screen::Live;
            });
        }
    } else {
        if (ImGui::Button(live.paused ? "Resume" : "Pause", ImVec2(120, 0))) {
            live.paused = !live.paused;
            statusMessage = live.paused ? "Live monitor paused."
                                        : "Live monitor resumed.";
        }
        ImGui::SameLine();
        if (ImGui::Button("Stop", ImVec2(120, 0))) {
            stopLive();
            statusMessage = "Live monitor stopped.";
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear / Reset", ImVec2(120, 0))) resetLive();
        ImGui::SameLine();
        ImGui::Checkbox("Auto-scroll", &live.autoScroll);
    }

    ImGui::Text("File: %s",
                live.watching ? live.path.c_str() : "(not watching)");
    if (live.watching) {
        char info[128];
        std::snprintf(info, sizeof(info), "%zu lines tailed, %zu alerts, %d "
                                          "invalid skipped%s",
                      live.entries.size(), live.stream.size(),
                      live.invalidSkipped, live.paused ? " [PAUSED]" : "");
        ImGui::TextUnformatted(info);
    }
    ImGui::Separator();

    // --- scrolling log console ---
    ImGui::TextUnformatted("Log console");
    ImGui::BeginChild("live_console", ImVec2(0, 260),
                      false, ImGuiWindowFlags_HorizontalScrollbar);
    {
        // Cap the rendered window so giant tails stay responsive.
        const size_t cap = 2000;
        size_t start =
            live.entries.size() > cap ? live.entries.size() - cap : 0;
        if (start > 0) ImGui::TextDisabled("... %zu earlier lines hidden ...", start);
        for (size_t i = start; i < live.entries.size(); ++i) {
            const LogEntry& e = live.entries[i];
            severityBadge(e.severity);
            ImGui::SameLine();
            ImGui::Text("%s %s  %s", e.date.c_str(), e.time.c_str(),
                        e.message.c_str());
        }
        if (live.autoScroll && !live.paused) ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndChild();

    ImGui::Spacing();
    ImGui::Separator();

    // --- alert stream ---
    ImGui::TextUnformatted("Alert stream");
    if (ImGui::BeginTable("live_alerts", 4,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV |
                              ImGuiTableFlags_ScrollY |
                              ImGuiTableFlags_SizingStretchProp,
                          ImVec2(0, 180))) {
        ImGui::TableSetupColumn("Time");
        ImGui::TableSetupColumn("Severity");
        ImGui::TableSetupColumn("Rule");
        ImGui::TableSetupColumn("Message");
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < live.stream.size(); ++i) {
            const Alert& a = live.stream[i];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(epochToString(a.epoch).c_str());
            ImGui::TableNextColumn();
            severityBadge(a.severity);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(a.type.c_str());
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::Selectable(a.message.c_str(), live.selected == (int)i))
                live.selected = static_cast<int>(i);
            ImGui::PopID();
        }
        ImGui::EndTable();
        if (live.autoScroll && !live.paused && !live.stream.empty())
            ImGui::SetScrollHereY(1.0f);
    }

    // --- alert detail inspector ---
    if (live.selected >= 0 && (size_t)live.selected < live.stream.size()) {
        ImGui::Separator();
        const Alert& a = live.stream[(size_t)live.selected];
        ImGui::TextUnformatted("Alert inspector");
        ImGui::TextWrapped("%s", a.message.c_str());
        if (ImGui::BeginTable("live_detail", 2, ImGuiTableFlags_BordersV)) {
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
        if (ImGui::SmallButton("Close inspector")) live.selected = -1;
    }
}
