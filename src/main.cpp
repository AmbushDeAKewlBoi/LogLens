#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

struct LogEntry { 
    std::string date;
    std::string time;
    std::string severity;
    std::string message;
};
int main() {
    std::ifstream file("data/sample.log");

    if (!file.is_open()) {
        std::cerr << "Error opening file." << std::endl;
        return 1;
    }

    std::string line;

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
        std::cout << "Date: " << entry.date
                    << " | Time: " << entry.time
                    << " | Severity: " << entry.severity 
                    << " | Message: " << entry.message
                    << '\n';

    }

    file.close();

    return 0;
}