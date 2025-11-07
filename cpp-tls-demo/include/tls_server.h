#ifndef CPP_TLS_DEMO_TLS_SERVER_H
#define CPP_TLS_DEMO_TLS_SERVER_H

#include <openssl/ssl.h>

#include <string>

namespace tls_demo {

// TLSServer encapsulates the setup and execution of a simple TLS-enabled TCP server.
// The server listens for a single client, performs a TLS handshake, and then
// exchanges a short text message before closing the connection.
class TLSServer {
public:
    TLSServer(int port, std::string certificate_file, std::string private_key_file);
    ~TLSServer();

    // Disallow copying to avoid double freeing OpenSSL resources.
    TLSServer(const TLSServer&) = delete;
    TLSServer& operator=(const TLSServer&) = delete;

    // Starts the server loop. This call blocks while the server waits for a single client
    // and performs a TLS handshake.
    void Run();

private:
    void InitializeOpenSSL();
    void CleanupOpenSSL();
    void CreateContext();
    void ConfigureContext();

    int port_;
    std::string certificate_file_;
    std::string private_key_file_;
    SSL_CTX* context_;
    bool initialized_;
};

}  // namespace tls_demo

#endif  // CPP_TLS_DEMO_TLS_SERVER_H
