#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <filesystem>

struct LogEntry { 
    std::string date;
    std::string time;
    std::string severity;
    std::string message;
    std::string user;
    std::string ip;
};

std::string extractValue(const std::string& text, const std::string& key) {
    std::string target = key + "=";
    size_t start = text.find(target);

    if (start == std::string::npos) {
        return "";
    }

    start += target.length();
    size_t end = text.find(' ', start);
    if (end == std::string::npos) {
        return text.substr(start);
    }
    return text.substr(start, end - start);

}

std::string toLower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return std::tolower(c); });
    return text;
}

std::string getRiskLevel(int failedAttempts) {
    if (failedAttempts >= 10) {
        return "HIGH";
    } else if (failedAttempts >= 5) {
        return "MEDIUM";
    } else {
        return "LOW";
    }
}

int main() {
    std::string filePath;

    std::cout << "Enter log file path: [default: data/sample.log]";
    std::getline(std::cin, filePath);

    if (filePath.empty()) {
        filePath = "data/sample.log";
    }

    std::ifstream file(filePath);



    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        return 1;
    }

    std::string line;
    std::unordered_map<std::string, int> failedLoginCounts;
    std::vector<LogEntry> entries;

    int totalLogs = 0;
    int infoCount = 0;
    int warningCount = 0;
    int errorCount = 0;
    int suspiciousCount = 0;

    while (std::getline(file, line)) {
        
        std::istringstream parser(line);

        LogEntry entry;

        parser >> entry.date;
        parser >> entry.time;
        parser >> entry.severity;
        totalLogs++;

        if (entry.severity == "INFO") {
            infoCount++;
        } else if (entry.severity == "WARN") {
            warningCount++;
        } else if (entry.severity == "ERROR") {
            errorCount++;
        }
        std::getline(parser, entry.message);

        if (!entry.message.empty() && entry.message[0] == ' ') {
            entry.message.erase(0, 1);
        }

        entry.user = extractValue(entry.message, "user");
        entry.ip = extractValue(entry.message, "ip");
        entries.push_back(entry);

        if (entry.message.find("Login failed") != std::string::npos && !entry.ip.empty()) {
            failedLoginCounts[entry.ip]++;
        }
        std::cout << "Date: " << entry.date
                    << " | Time: " << entry.time
                    << " | Severity: " << entry.severity 
                    << " | Message: " << entry.message;
if (!entry.user.empty()) {

    std::cout << " | User: " << entry.user;
}
if (!entry.ip.empty()) {
    std::cout << " | IP: " << entry.ip;
}

std::cout << '\n';


    }


    std:: cout << "\n --- Sec Alerts --- \n";

    for (const auto& pair : failedLoginCounts) {
        if (pair.second >= 3) {
            suspiciousCount++;
            
            std::string riskLevel = getRiskLevel(pair.second);

            std::cout << "[" << riskLevel << "] IP "
                << pair.first
                << " had " 
                << pair.second
                << " failed login attempts.\n";
        
        }
    }

    std::cout << "\n --- Log Summary --- \n";
    std::cout << "Total logs " << totalLogs << '\n';
    std::cout << "INFO: " << infoCount << '\n';
    std::cout << "WARN: " << warningCount << '\n';
    std::cout << "ERROR: " << errorCount << '\n';
    std::cout << "Suspicious IPs: " << suspiciousCount << '\n';
    
    std::filesystem::create_directory("reports");

    std::ofstream report("reports/report.txt");

    if (!report.is_open()) {
        std::cerr << "Could not create report file.\n";
    }
    else{
        report << "LogLens Analysis Report\n";
        report << "=======================\n";
        report << "Total logs: " << totalLogs << "\n";
        report << "INFO: " << infoCount << "\n";
        report << "WARN: " << warningCount << "\n";
        report << "ERROR: " << errorCount << "\n";
        report << "Suspicious IPs: " << suspiciousCount << "\n\n";

        report << "Alerts:\n";

        for (const auto& pair : failedLoginCounts) {
            if (pair.second >= 3) {

                std::string riskLevel = getRiskLevel(pair.second);

                report << "[" << riskLevel << "] IP "
                    << pair.first
                    << " had " 
                    << pair.second
                    << " failed login attempts.\n";
            }


        }

        report.close();

        std::cout << "\nReport saved to reports/report.txt\n";
    }
    std::string filterChoice;

std::cout << "\nWould you like to filter logs? (y/n): ";
std::getline(std::cin, filterChoice);

if (filterChoice == "y" || filterChoice == "Y") {

    std::string filterType;
    std::string filterValue;

    std::cout << "Filter by severity, user, ip, or keyword: ";
    std::getline(std::cin, filterType);

    std::cout << "Enter value to filter by: ";
    std::getline(std::cin, filterValue);

    std::cout << "\n--- Filter Results ---\n";

    bool found = false;

    for (const auto& entry : entries) {

        bool match = false;

        std::string type = toLower(filterType);
        std::string value = toLower(filterValue);

        if (type == "severity" && toLower(entry.severity) == value) {
            match = true;
        }
        else if (type == "user" && toLower(entry.user) == value) {
            match = true;
        }
        else if (type == "ip" && entry.ip == filterValue) {
            match = true;
        }
        else if (type == "keyword" && toLower(entry.message).find(value) != std::string::npos) {
            match = true;
        }

        if (match) {
            found = true;

            std::cout << entry.date
                      << " | " << entry.time
                      << " | " << entry.severity
                      << " | " << entry.message
                      << '\n';
        }
    }

    if (!found) {
        std::cout << "No matching logs found.\n";
    }
}

file.close();

return 0;
}