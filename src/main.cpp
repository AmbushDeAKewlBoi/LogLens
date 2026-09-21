#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unordered_map>

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
    std::ifstream file("data/sample.log");

    if (!file.is_open()) {
        std::cerr << "Error opening file." << std::endl;
        return 1;
    }

    std::string line;
    std::unordered_map<std::string, int> failedLoginCounts;

    while (std::getline(file, line)) {
        
        std::istringstream parser(line);

        LogEntry entry;

        parser >> entry.date;
        parser >> entry.time;
        parser >> entry.severity;
        std::getline(parser, entry.message);

        if (!entry.message.empty() && entry.message[0] == ' ') {
            entry.message.erase(0, 1);
        }

        entry.user = extractValue(entry.message, "user");
        entry.ip = extractValue(entry.message, "ip");

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
            std::cout << "[SUSSY] IP "
            << pair.first
            << " had "
            << pair.second
            << " failed login attempts. \n";
        }
    }
    file.close();

    return 0;
}