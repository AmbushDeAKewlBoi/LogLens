#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unordered_map>
#include <vector>

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
            
            std::string riskLevel;

            if (pair.second >= 10) {
                riskLevel = "HIGH";
            }
            else if  (pair.second >= 5) {
                riskLevel = "MEDIUM";
            }
            else {
                riskLevel = "LOW";
            }

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
    
    std::string filterChoice;

std::cout << "\nWould you like to filter logs? (y/n): ";
std::getline(std::cin, filterChoice);

if (filterChoice == "y" || filterChoice == "Y") {

    std::string filterType;
    std::string filterValue;

    std::cout << "Filter by severity, user, or ip: ";
    std::getline(std::cin, filterType);

    std::cout << "Enter value to filter by: ";
    std::getline(std::cin, filterValue);

    std::cout << "\n--- Filter Results ---\n";

    bool found = false;

    for (const auto& entry : entries) {

        bool match = false;

        if (filterType == "severity" && entry.severity == filterValue) {
            match = true;
        }
        else if (filterType == "user" && entry.user == filterValue) {
            match = true;
        }
        else if (filterType == "ip" && entry.ip == filterValue) {
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