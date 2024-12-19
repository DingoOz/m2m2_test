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
#include <cmath>

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

    std::vector<std::tuple<float, float, bool>> decodeLaserPoints(const std::string& base64_encoded) {
        // Placeholder for actual base64 and RLE decoding
        // In a real implementation, you'd need to add base64 decoding and RLE decompression
        std::vector<std::tuple<float, float, bool>> points;
        return points;
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

    void continuousLaserScan() {
        while (true) {
            auto scan_response = getLaserScan();
            
            if (scan_response.empty() || 
                scan_response["result"].is_null() || 
                !scan_response["result"].contains("laser_points")) {
                std::cerr << "Failed to get laser scan" << std::endl;
                sleep(1);
                continue;
            }

            // Get base64 encoded laser points
            std::string base64_points = scan_response["result"]["laser_points"];
            
            // Print some basic information
            std::cout << "Laser Scan:" << std::endl;
            std::cout << "Base64 Encoded Points Length: " << base64_points.length() << std::endl;
            
            // In a real implementation, you'd decode base64 and RLE here
            // This is a placeholder for actual decoding
            
            // Wait a bit before next scan
            sleep(1);
        }
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

    // Continuously get laser scans
    client.continuousLaserScan();

    client.disconnect();
    return 0;
}
