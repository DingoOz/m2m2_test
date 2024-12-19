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
#include <cstdint>
#include <openssl/bio.h>
#include <openssl/evp.h>

class Base64Decoder {
public:
    static std::vector<uint8_t> decode(const std::string& encoded) {
        BIO *bio, *b64;
        std::vector<uint8_t> decoded;
        
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_mem_buf(encoded.c_str(), encoded.length());
        bio = BIO_push(b64, bio);
        
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        
        char buffer[1024];
        int len;
        while ((len = BIO_read(bio, buffer, sizeof(buffer))) > 0) {
            decoded.insert(decoded.end(), buffer, buffer + len);
        }
        
        BIO_free_all(bio);
        return decoded;
    }
};

class SlamtecMapper {
private:
    int sockfd_;
    int request_id_;
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
            
            if (received.size() >= 4 && 
                received[received.size()-4] == '\r' &&
                received[received.size()-3] == '\n' &&
                received[received.size()-2] == '\r' &&
                received[received.size()-1] == '\n') {
                found_delim = true;
            }
        }

        std::string response_str(received.begin(), received.end());
        try {
            return nlohmann::json::parse(response_str);
        } catch (const std::exception& e) {
            std::cerr << "JSON parse error: " << e.what() << std::endl;
            return {};
        }
    }

    std::vector<std::tuple<float, float, bool>> decodeLaserPoints(const std::string& base64_encoded) {
        std::vector<std::tuple<float, float, bool>> points;
        
        // Decode base64
        std::vector<uint8_t> decoded = Base64Decoder::decode(base64_encoded);
        
        // Check for RLE header
        if (decoded.size() < 9 || 
            decoded[0] != 'R' || 
            decoded[1] != 'L' || 
            decoded[2] != 'E') {
            std::cerr << "Invalid RLE header" << std::endl;
            return points;
        }

        // RLE decompression (simplified)
        std::vector<uint8_t> decompressed;
        uint8_t sentinel1 = decoded[3];
        uint8_t sentinel2 = decoded[4];
        
        size_t pos = 9;
        while (pos < decoded.size()) {
            uint8_t b = decoded[pos];
            
            if (b == sentinel1) {
                if (pos + 2 < decoded.size() && 
                    decoded[pos+1] == 0 && 
                    decoded[pos+2] == sentinel2) {
                    // Swap sentinels
                    std::swap(sentinel1, sentinel2);
                    pos += 2;
                } else if (pos + 2 < decoded.size()) {
                    // Repeat next byte
                    uint8_t repeat_val = decoded[pos+2];
                    uint8_t repeat_count = decoded[pos+1];
                    for (uint8_t i = 0; i < repeat_count; ++i) {
                        decompressed.push_back(repeat_val);
                    }
                    pos += 2;
                }
            } else {
                decompressed.push_back(b);
            }
            ++pos;
        }

        // Parse points (12 bytes each: float distance, float angle, short flags, short reserved)
        for (size_t i = 0; i < decompressed.size(); i += 12) {
            if (i + 12 > decompressed.size()) break;

            float distance, angle;
            memcpy(&distance, &decompressed[i], sizeof(float));
            memcpy(&angle, &decompressed[i+4], sizeof(float));

            bool valid = distance != 100000.0;
            points.emplace_back(angle, distance, valid);
        }

        return points;
    }

public:
    SlamtecMapper() : sockfd_(-1), request_id_(0) {}
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
            
            // Decode points
            auto points = decodeLaserPoints(base64_points);
            
            // Output in ROS2-like LaserScan format
            std::cout << "sensor_msgs/LaserScan:" << std::endl;
            std::cout << "  header:" << std::endl;
            std::cout << "    stamp: " << std::fixed << std::setprecision(9) << scan_response["result"]["timestamp"] << std::endl;
            std::cout << "    frame_id: base_link" << std::endl;
            std::cout << "  angle_min: " << std::fixed << std::setprecision(4) << std::get<0>(points.front()) << " rad" << std::endl;
            std::cout << "  angle_max: " << std::fixed << std::setprecision(4) << std::get<0>(points.back()) << " rad" << std::endl;
            std::cout << "  angle_increment: " << std::fixed << std::setprecision(4) << (std::get<0>(points.back()) - std::get<0>(points.front())) / (points.size() - 1) << " rad" << std::endl;
            std::cout << "  time_increment: 0.0" << std::endl;
            std::cout << "  scan_time: 0.0" << std::endl;
            std::cout << "  range_min: 0.0" << std::endl;
            std::cout << "  range_max: 100.0" << std::endl;
            std::cout << "  ranges: [";
            for (const auto& [angle, distance, valid] : points) {
                std::cout << (valid ? distance : 0.0) << ", ";
            }
            std::cout << "]" << std::endl;
            std::cout << "  intensities: []" << std::endl << std::endl;
            
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

    client.continuousLaserScan();
    client.disconnect();
    return 0;
}
