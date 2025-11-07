#ifndef CPP_TLS_DEMO_TLS_CLIENT_H
#define CPP_TLS_DEMO_TLS_CLIENT_H

#include <openssl/ssl.h>

#include <string>

namespace tls_demo {

// TLSClient encapsulates a TLS-enabled TCP client that connects to a server,
// sends a text message, and reads the server response.
class TLSClient {
public:
    TLSClient(std::string host, int port, std::string ca_certificate_file);
    ~TLSClient();

    TLSClient(const TLSClient&) = delete;
    TLSClient& operator=(const TLSClient&) = delete;

    void Run();

private:
    void InitializeOpenSSL();
    void CleanupOpenSSL();
    void CreateContext();
    void ConfigureContext();

    std::string host_;
    int port_;
    std::string ca_certificate_file_;
    SSL_CTX* context_;
    bool initialized_;
};

}  // namespace tls_demo

#endif  // CPP_TLS_DEMO_TLS_CLIENT_H
