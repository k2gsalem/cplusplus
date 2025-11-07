#include "tls_client.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <cstdlib>

#include <openssl/err.h>
#include <openssl/x509.h>

namespace tls_demo {

namespace {
constexpr std::size_t kBufferSize = 4096;

void PrintSSLError(const std::string& message) {
    std::cerr << message << std::endl;
    ERR_print_errors_fp(stderr);
}

}  // namespace

TLSClient::TLSClient(std::string host, int port, std::string ca_certificate_file)
    : host_(std::move(host)),
      port_(port),
      ca_certificate_file_(std::move(ca_certificate_file)),
      context_(nullptr),
      initialized_(false) {
    InitializeOpenSSL();
    CreateContext();
    ConfigureContext();
}

TLSClient::~TLSClient() {
    if (context_ != nullptr) {
        SSL_CTX_free(context_);
        context_ = nullptr;
    }
    CleanupOpenSSL();
}

void TLSClient::InitializeOpenSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    initialized_ = true;
}

void TLSClient::CleanupOpenSSL() {
    if (initialized_) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ERR_free_strings();
        EVP_cleanup();
#endif
        initialized_ = false;
    }
}

void TLSClient::CreateContext() {
    const SSL_METHOD* method = TLS_client_method();
    context_ = SSL_CTX_new(method);
    if (context_ == nullptr) {
        PrintSSLError("Unable to create SSL context");
        throw std::runtime_error("Unable to create SSL context");
    }
}

void TLSClient::ConfigureContext() {
    if (SSL_CTX_load_verify_locations(context_, ca_certificate_file_.c_str(), nullptr) != 1) {
        PrintSSLError("Failed to load CA certificate");
        throw std::runtime_error("Failed to load CA certificate");
    }

    SSL_CTX_set_verify(context_, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(context_, 4);
}

void TLSClient::Run() {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;
    const std::string port_string = std::to_string(port_);
    if (getaddrinfo(host_.c_str(), port_string.c_str(), &hints, &result) != 0) {
        throw std::runtime_error("Failed to resolve host");
    }

    int sock = -1;
    for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) {
            continue;
        }

        if (::connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;  // Successfully connected
        }

        ::close(sock);
        sock = -1;
    }

    freeaddrinfo(result);

    if (sock == -1) {
        throw std::runtime_error("Unable to connect to server");
    }

    SSL* ssl = SSL_new(context_);
    if (ssl == nullptr) {
        ::close(sock);
        throw std::runtime_error("Failed to create SSL object");
    }

    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        PrintSSLError("[Client] TLS handshake failed");
        SSL_free(ssl);
        ::close(sock);
        throw std::runtime_error("TLS handshake failed");
    }

    std::cout << "[Client] Connected to " << host_ << ":" << port_ << std::endl;

    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert != nullptr) {
        char* line = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        if (line != nullptr) {
            std::cout << "[Client] Server certificate subject: " << line << std::endl;
            OPENSSL_free(line);
        }
        X509_free(cert);
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        std::cerr << "[Client] Certificate verification failed" << std::endl;
    }

    const std::string message = "Hello from TLS client!";
    if (SSL_write(ssl, message.data(), static_cast<int>(message.size())) <= 0) {
        PrintSSLError("[Client] Failed to send message");
    } else {
        std::cout << "[Client] Sent message" << std::endl;
    }

    std::string response(kBufferSize, '\0');
    int bytes_read = SSL_read(ssl, response.data(), static_cast<int>(response.size()));
    if (bytes_read <= 0) {
        PrintSSLError("[Client] Failed to read response");
    } else {
        response.resize(bytes_read);
        std::cout << "[Client] Received response: " << response << std::endl;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    ::close(sock);
}

}  // namespace tls_demo

int main() {
    try {
        const std::string host = "127.0.0.1";
        constexpr int port = 5555;
        const std::string ca_certificate_path = "certs/ca.crt";

        tls_demo::TLSClient client(host, port, ca_certificate_path);
        client.Run();
    } catch (const std::exception& ex) {
        std::cerr << "[Client] Fatal error: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
