// LogLens GUI — analytics dashboard screen (block 12).
//
// Summary cards, severity distribution bars (custom draw-list), recent-alert
// panel with filter/search, counters table, top talkers and top alert IPs
// with risk tiers. All state lives in LogLensApp::dash so it survives frames.
#include "app.h"

#include <sstream>

namespace {

// Horizontal bar drawn with the window draw list: label, filled portion of
// `fraction`, and a count at the right.
void distBar(const char* label, int count, int maxCount, const ImVec4& color) {
    ImGui::TextUnformatted(label);
    ImGui::SameLine(140);
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    float width = ImGui::GetContentRegionAvail().x - 70.0f;
    if (width < 40.0f) width = 40.0f;
    const float h = ImGui::GetFrameHeight() * 0.7f;
    ImVec2 p1(p0.x + width, p0.y + h);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p0, p1, ImGui::GetColorU32(ImVec4(0.25f, 0.25f, 0.30f, 1.0f)),
                      3.0f);
    float frac = maxCount > 0 ? static_cast<float>(count) / maxCount : 0.0f;
    if (frac > 0.0f)
        dl->AddRectFilled(p0, ImVec2(p0.x + width * frac, p1.y),
                          ImGui::GetColorU32(color), 3.0f);
    ImGui::Dummy(ImVec2(width, h));
    ImGui::SameLine();
    ImGui::Text("%d", count);
}

}  // namespace

void LogLensApp::renderDashboard() {
    ImGui::TextUnformatted("Dashboard");
    if (!state.sourcePath.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "(%s)",
                           state.sourcePath.c_str());
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Re-analyze")) {
        refreshAnalysis();
        statusMessage = "Analysis refreshed.";
    }
    ImGui::Separator();

    SummaryCounts c = computeCounts(state.entries, state.invalidCount, settings());

    // --- summary cards ---
    statCard("Total logs", c.total, ImVec4(0.8f, 0.8f, 0.8f, 1.0f));
    ImGui::SameLine();
    statCard("INFO", c.info, severityColor("INFO"));
    ImGui::SameLine();
    statCard("WARN", c.warn, severityColor("WARN"));
    ImGui::SameLine();
    statCard("ERROR", c.error, severityColor("ERROR"));
    ImGui::SameLine();
    statCard("Alerts", static_cast<int>(currentAlerts.size()),
             ImVec4(1.0f, 0.45f, 0.2f, 1.0f));
    ImGui::SameLine();
    statCard("Invalid lines", c.invalid, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));

    ImGui::Spacing();
    ImGui::TextUnformatted("Severity distribution");
    int sevMax = std::max({c.info, c.warn, c.error, 1});
    distBar("INFO", c.info, sevMax, severityColor("INFO"));
    distBar("WARN", c.warn, sevMax, severityColor("WARN"));
    distBar("ERROR", c.error, sevMax, severityColor("ERROR"));

    ImGui::Spacing();
    ImGui::Separator();

    // --- recent alerts panel with filter/search ---
    ImGui::TextUnformatted("Recent alerts");
    ImGui::InputText("filter", dash.filter.text, sizeof(dash.filter.text));
    ImGui::SameLine();
    const char* sevs[] = {"All", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    ImGui::Combo("severity", &dash.filter.severity, sevs, 5);

    int shown = 0;
    if (ImGui::BeginTable("recent_alerts", 4,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV |
                              ImGuiTableFlags_ScrollY |
                              ImGuiTableFlags_SizingStretchProp,
                          ImVec2(0, 220))) {
        ImGui::TableSetupColumn("Time");
        ImGui::TableSetupColumn("Severity");
        ImGui::TableSetupColumn("Rule");
        ImGui::TableSetupColumn("Message");
        ImGui::TableHeadersRow();
        // Most recent first: iterate from the back, cap at 500 rows.
        int budget = 500;
        for (size_t i = currentAlerts.size(); i-- > 0 && budget > 0;) {
            const Alert& a = currentAlerts[i];
            if (!alertVisible(a, dash.filter)) continue;
            --budget;
            ++shown;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(epochToString(a.epoch).c_str());
            ImGui::TableNextColumn();
            severityBadge(a.severity);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(a.type.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(a.message.c_str());
        }
        ImGui::EndTable();
    }
    char alertBuf[64];
    std::snprintf(alertBuf, sizeof(alertBuf), "%d alerts shown", shown);
    ImGui::TextUnformatted(alertBuf);

    ImGui::Spacing();
    ImGui::Separator();

    // --- counters table ---
    if (ImGui::BeginTable("counters", 2,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV,
                          ImVec2(330, 0))) {
        ImGui::TableSetupColumn("Counter");
        ImGui::TableSetupColumn("Value");
        ImGui::TableHeadersRow();
        auto row = [](const char* k, int v) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(k);
            ImGui::TableNextColumn();
            ImGui::Text("%d", v);
        };
        row("Total logs", c.total);
        row("INFO", c.info);
        row("WARN", c.warn);
        row("ERROR", c.error);
        row("Invalid lines", c.invalid);
        row("Suspicious IPs", c.suspiciousIps);
        row("Suspicious users", c.suspiciousUsers);
        row("Rapid brute force", c.rapidBruteForce);
        for (const auto& kv : state.invalidReasons) {
            char label[64];
            std::snprintf(label, sizeof(label), "Invalid: %s", kv.first.c_str());
            row(label, kv.second);
        }
        ImGui::EndTable();
    }

    ImGui::SameLine();

    // --- top talkers + top alert IPs ---
    ImGui::BeginChild("topstats", ImVec2(0, 0));
    {
        std::unordered_map<std::string, int> ipHits, ipScores, userScores;
        for (const auto& e : state.entries) {
            if (!e.ip.empty()) ipHits[e.ip]++;
        }
        for (const auto& a : currentAlerts) {
            int pts = scoreForAlertType(a.type);
            if (!a.ip.empty()) ipScores[a.ip] += pts;
            if (!a.user.empty()) userScores[a.user] += pts;
        }
        auto topN = [](std::unordered_map<std::string, int>& m, size_t n) {
            std::vector<std::pair<std::string, int>> v(m.begin(), m.end());
            std::sort(v.begin(), v.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            if (v.size() > n) v.resize(n);
            return v;
        };

        ImGui::TextUnformatted("Top talkers (by log lines)");
        if (ImGui::BeginTable("toptalkers", 2,
                              ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV)) {
            ImGui::TableSetupColumn("IP");
            ImGui::TableSetupColumn("Lines");
            ImGui::TableHeadersRow();
            for (const auto& kv : topN(ipHits, 5)) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(kv.first.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("%d", kv.second);
            }
            ImGui::EndTable();
        }

        ImGui::Spacing();
        ImGui::TextUnformatted("Top alert IPs (risk)");
        if (ImGui::BeginTable("toprisk", 3,
                              ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV)) {
            ImGui::TableSetupColumn("IP");
            ImGui::TableSetupColumn("Score");
            ImGui::TableSetupColumn("Tier");
            ImGui::TableHeadersRow();
            for (const auto& kv : topN(ipScores, 5)) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(kv.first.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("%d", kv.second);
                ImGui::TableNextColumn();
                riskBadge(riskTier(kv.second));
            }
            ImGui::EndTable();
        }

        if (!userScores.empty()) {
            ImGui::Spacing();
            ImGui::TextUnformatted("Top alert users (risk)");
            if (ImGui::BeginTable("topusers", 3,
                                  ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV)) {
                ImGui::TableSetupColumn("User");
                ImGui::TableSetupColumn("Score");
                ImGui::TableSetupColumn("Tier");
                ImGui::TableHeadersRow();
                for (const auto& kv : topN(userScores, 5)) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(kv.first.c_str());
                    ImGui::TableNextColumn();
                    ImGui::Text("%d", kv.second);
                    ImGui::TableNextColumn();
                    riskBadge(riskTier(kv.second));
                }
                ImGui::EndTable();
            }
        }
    }
    ImGui::EndChild();
}
