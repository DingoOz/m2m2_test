#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstring>
#include <cerrno>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <nlohmann/json.hpp>

class SlamtecMapper {
private:
    int sockfd_;
    int request_id_ = 0;
    static constexpr const char* REQUEST_DELIM = "\r\n\r\n";

    bool sendRequest(const std::string& command, const nlohmann::json& args = nullptr) {
        nlohmann::json request = {
            {"command", command},
            {"request_id", request_id_++}
        };
        
        if (!args.is_null()) {
            request["args"] = args;
        }

        std::string json_str = request.dump();
        std::vector<uint8_t> data_ascii(json_str.begin(), json_str.end());
        
        // Append delimiters
        data_ascii.push_back('\r');
        data_ascii.push_back('\n');
        data_ascii.push_back('\r');
        data_ascii.push_back('\n');
        data_ascii.push_back('\r');
        data_ascii.push_back('\n');

        ssize_t sent = send(sockfd_, data_ascii.data(), data_ascii.size(), 0);
        if (sent <= 0) {
            std::cerr << "Send failed: " << strerror(errno) << std::endl;
            return false;
        }
        std::cout << "Sent: " << json_str << std::endl;
        return true;
    }

    nlohmann::json receiveResponse() {
        std::vector<uint8_t> buffer(4096);
        std::vector<uint8_t> received;
        bool found_delim = false;

        while (!found_delim) {
            ssize_t bytes = recv(sockfd_, buffer.data(), buffer.size(), 0);
            if (bytes <= 0) {
                std::cerr << "Receive error: " << strerror(errno) << std::endl;
                return {};
            }

            received.insert(received.end(), buffer.begin(), buffer.begin() + bytes);
            
            // Check for end delimiter
            if (received.size() >= 4 && 
                received[received.size()-4] == '\r' &&
                received[received.size()-3] == '\n' &&
                received[received.size()-2] == '\r' &&
                received[received.size()-1] == '\n') {
                found_delim = true;
            }
        }

        // Convert to string and parse JSON
        std::string response_str(received.begin(), received.end());
        try {
            return nlohmann::json::parse(response_str);
        } catch (const std::exception& e) {
            std::cerr << "JSON parse error: " << e.what() << std::endl;
            return {};
        }
    }

public:
    SlamtecMapper() : sockfd_(-1) {}
    ~SlamtecMapper() { disconnect(); }

    bool connect(const std::string& host, int port) {
        sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_ < 0) {
            std::cerr << "Socket creation failed" << std::endl;
            return false;
        }

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) <= 0) {
            std::cerr << "Invalid address" << std::endl;
            return false;
        }

        if (::connect(sockfd_, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            std::cerr << "Connection failed" << std::endl;
            return false;
        }

        std::cout << "Connected to " << host << ":" << port << std::endl;
        return true;
    }

    void disconnect() {
        if (sockfd_ >= 0) {
            close(sockfd_);
            sockfd_ = -1;
        }
    }

    nlohmann::json getLaserScan() {
        if (!sendRequest("getlaserscan")) {
            return {};
        }
        return receiveResponse();
    }

    nlohmann::json getDeviceInfo() {
        if (!sendRequest("getdeviceinfo")) {
            return {};
        }
        return receiveResponse();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <host> <port>\n";
        return 1;
    }

    SlamtecMapper client;
    if (!client.connect(argv[1], std::stoi(argv[2]))) {
        return 1;
    }

    // Get laser scan
    auto laser_scan = client.getLaserScan();
    if (!laser_scan.empty()) {
        std::cout << "Laser scan received: " << laser_scan.dump(2) << std::endl;
    }

    // Get device info
    auto device_info = client.getDeviceInfo();
    if (!device_info.empty()) {
        std::cout << "Device info: " << device_info.dump(2) << std::endl;
    }

    client.disconnect();
    return 0;
}
