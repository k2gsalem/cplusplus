#include "tls_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include <openssl/err.h>

namespace tls_demo {

namespace {
constexpr int kBacklog = 1;          // The server only needs a single client for the demo.
constexpr std::size_t kBufferSize = 4096;  // Buffer size for reading client messages.

void PrintSSLError(const std::string& message) {
    std::cerr << message << std::endl;
    ERR_print_errors_fp(stderr);
}

}  // namespace

TLSServer::TLSServer(int port, std::string certificate_file, std::string private_key_file)
    : port_(port),
      certificate_file_(std::move(certificate_file)),
      private_key_file_(std::move(private_key_file)),
      context_(nullptr),
      initialized_(false) {
    InitializeOpenSSL();
    CreateContext();
    ConfigureContext();
}

TLSServer::~TLSServer() {
    if (context_ != nullptr) {
        SSL_CTX_free(context_);
        context_ = nullptr;
    }
    CleanupOpenSSL();
}

void TLSServer::InitializeOpenSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    initialized_ = true;
}

void TLSServer::CleanupOpenSSL() {
    if (initialized_) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ERR_free_strings();
        EVP_cleanup();
#endif
        initialized_ = false;
    }
}

void TLSServer::CreateContext() {
    const SSL_METHOD* method = TLS_server_method();
    context_ = SSL_CTX_new(method);
    if (context_ == nullptr) {
        PrintSSLError("Unable to create SSL context");
        throw std::runtime_error("Unable to create SSL context");
    }
}

void TLSServer::ConfigureContext() {
    // Configure ECDH automatically for better security defaults.
#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(context_, 1);
#endif

    if (SSL_CTX_use_certificate_file(context_, certificate_file_.c_str(), SSL_FILETYPE_PEM) <= 0) {
        PrintSSLError("Failed to load server certificate");
        throw std::runtime_error("Failed to load server certificate");
    }

    if (SSL_CTX_use_PrivateKey_file(context_, private_key_file_.c_str(), SSL_FILETYPE_PEM) <= 0) {
        PrintSSLError("Failed to load server private key");
        throw std::runtime_error("Failed to load server private key");
    }

    if (!SSL_CTX_check_private_key(context_)) {
        throw std::runtime_error("Server certificate and key do not match");
    }
}

void TLSServer::Run() {
    int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        ::close(server_fd);
        throw std::runtime_error("Failed to set socket options");
    }

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(server_fd);
        throw std::runtime_error("Failed to bind socket");
    }

    if (listen(server_fd, kBacklog) < 0) {
        ::close(server_fd);
        throw std::runtime_error("Failed to listen on socket");
    }

    std::cout << "[Server] Listening on port " << port_ << "..." << std::endl;

    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client_fd < 0) {
        ::close(server_fd);
        throw std::runtime_error("Failed to accept client connection");
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    std::cout << "[Server] Client connected from " << client_ip << std::endl;

    SSL* ssl = SSL_new(context_);
    if (ssl == nullptr) {
        ::close(client_fd);
        ::close(server_fd);
        throw std::runtime_error("Failed to create SSL object");
    }

    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        PrintSSLError("[Server] TLS handshake failed");
        SSL_free(ssl);
        ::close(client_fd);
        ::close(server_fd);
        throw std::runtime_error("TLS handshake failed");
    }

    std::cout << "[Server] TLS handshake successful" << std::endl;

    std::array<char, kBufferSize> buffer{};
    int bytes_read = SSL_read(ssl, buffer.data(), buffer.size());
    if (bytes_read <= 0) {
        PrintSSLError("[Server] Failed to read from client");
    } else {
        std::string message(buffer.data(), bytes_read);
        std::cout << "[Server] Received message: " << message << std::endl;

        const std::string response = "Hello from TLS server!";
        int bytes_written = SSL_write(ssl, response.data(), static_cast<int>(response.size()));
        if (bytes_written <= 0) {
            PrintSSLError("[Server] Failed to write response to client");
        } else {
            std::cout << "[Server] Sent response" << std::endl;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    ::close(client_fd);
    ::close(server_fd);

    std::cout << "[Server] Connection closed" << std::endl;
}

}  // namespace tls_demo

int main() {
    try {
        const std::string certificate_path = "certs/server.crt";
        const std::string key_path = "certs/server.key";
        constexpr int port = 5555;

        tls_demo::TLSServer server(port, certificate_path, key_path);
        server.Run();
    } catch (const std::exception& ex) {
        std::cerr << "[Server] Fatal error: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
