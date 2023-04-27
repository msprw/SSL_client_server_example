#include <iostream>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <json/json.h>
#include <string>

#define BUF_SIZE 1024

/* Function returns socket file descriptor on success or -1 on failure */
int create_socket(const int port, const char *ip)
{
    int s;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create a socket!\n");
    }
    else
    {
        if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            perror("Could not bind to the socket!\n");
            close(s);
            s = -1;
        }
        else
        {
            if (listen(s, 1) < 0) 
            {
                perror("Error in listening!\n");
                close(s);
                s = -1;
            }
        }
    }

    return s;
}


/* Function returns SSL context */
SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context!\n");
        exit(EXIT_FAILURE);
    }

    return ctx;
}
/* Function configures SSL context */
bool configure_context(SSL_CTX *ctx, const char *ca_path, const char *cert_path, const char* key_path)
{
    /* Load main cert */
    if (SSL_CTX_load_verify_locations(ctx, ca_path, nullptr) != 1) {
        perror("Unable to load ca certificate from file!\n");
        return false;
    }

    /* Load server cert and key */
    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        perror("Unable to load server certificate from file!\n");
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0 ) {
        perror("Unable to load private key from file!\n");
        return false;
    }

    /* Check if the key matches the certificate */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        perror("Server key does not match the provided certificate!\n");
        return false;
    }

    /* Set up peer verification */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

    return true;
}

/* Function receives data from SSL socket and saves it as a string. Returns empty string on error */
std::string SSL_recv_data(SSL *ssl)
{
    char buf[BUF_SIZE];
    ssize_t bytes_recv = 0;
    std::string recv_data;

    while ((bytes_recv = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        recv_data.append(buf, bytes_recv); 
    }
    /* Handle SSL errors */
    int ssl_error = SSL_get_error(ssl, bytes_recv);
    switch (ssl_error) {
        case SSL_ERROR_NONE:
            break;
        case SSL_ERROR_ZERO_RETURN:
            std::cerr << "SSL connection closed." << std::endl;
            break;
        default:
            std::cerr << "An SSL error has occured: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
            return "";
    }

    return recv_data;
}

int main(int argc, char **argv)
{
    
    if(argc != 6)
    {
        printf("Usage: %s <server_ip> <port> <ca_cert> <server_cert> <server_priv_key>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Ignore SIGPIPE signal, which randomly occurs at SSL_accept */
    signal(SIGPIPE, SIG_IGN);

    /* Create socket for listening */
    int sockfd;
    sockfd = create_socket(atoi(argv[2]), argv[1]);

    if(sockfd < 0)
        exit(EXIT_FAILURE);

    std::cout << "Socket created successfully!\n";

    SSL_CTX *ctx;

    /* Create SSL context */
    ctx = create_context(); 

    /* Configure SSL context */
    if(!configure_context(ctx, argv[3], argv[4], argv[5]))
    {
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }   

    while(1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        
        printf("Listening for a connection...\n");

        int client = accept(sockfd, (struct sockaddr*)&addr, &len);
        if (client < 0)
        {
            perror("Unable to accept the connection!");
            close(client);
            continue;
        }

        printf("Connection accepted...\n");

        SSL *ssl;
        ssl = SSL_new(ctx);

        if(!ssl)
        {
            printf("Could not create SSL object!");
            break;
        }

        if(SSL_set_fd(ssl, client) != 1)
        {
            printf("Could not attach socket to SSL context!");
            close(client);
            SSL_free(ssl);
            continue;
        }

        if (SSL_accept(ssl) <= 0) 
        {
            perror("Could not negotiate a secure connection!\n");
            close(client);
            SSL_free(ssl);
            continue;
        } 
        else //Connection correct and encrypted
        { 
            printf("Connection is encrypted...\n");

            std::string s = SSL_recv_data(ssl);

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);

            try{
                if(s.empty())
                    throw std::runtime_error("No data was received!\n");
                else
                {
                    Json::Reader reader;
                    Json::Value js;

                    if (!reader.parse(s, js))
                        throw std::runtime_error("Could not process the JSON: " + reader.getFormattedErrorMessages());
                    
                    if(!js.isMember("name") && js.isMember("main"))
                        throw std::runtime_error("Received data seems to be invalid!\n");

                    std::cout << "Data received form the client: " << std::endl;
                    std::cout << "Current weather for city " << js.get("name","undefined") << ":\n";
                    std::cout << "Temperature: \n" 
                              << "Air: " << js.get("main", 0).get("temp",0).asDouble() << "°C"
                              << ", Feels like: " << js.get("main", 0).get("feels_like",0).asDouble() << "°C" << std::endl;
                    std::cout << "Humidity: " << js.get("main", 0).get("humidity",0).asDouble() << "%" << std::endl;
                    std::cout << "Pressure: " << js.get("main", 0).get("pressure",0).asDouble() << "hPa" << std::endl;
                }
            } catch(const std::runtime_error& e) {
                std::cerr << "Could not process data: " << e.what() << "\n";
            }
        }        
    }

    close(sockfd);
    SSL_CTX_free(ctx);
}