#pragma comment(lib, "libcurl_imp.lib")
#pragma comment(lib, "jsoncpp.lib")

#include <curl/curl.h>
#include <json/json.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>

/* Function saves results from CURL request to string */
size_t writefunc(void *ptr, size_t size, size_t nmemb, std::string *s)
{
  s->append(static_cast<char *>(ptr), size*nmemb);
  return size*nmemb;
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();

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
        perror("Unable to load client certificate from file!\n");
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0 ) {
        perror("Unable to load private key from file!\n");
        return false;
    }

    /* Check if the key matches the certificate */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        perror("Client key does not match the provided certificate!\n");
        return false;
    }

    /* Set up peer verification */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    return true;
}

int main(int argc, char** argv)
{
    if (argc != 8) 
    {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <ca_cert> <client_cert> <client_priv_key> <city> <ow_api_key>" << "\n";
        return 1;
    }

    int sockfd;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    
    /* Create SSL context */
    ctx = create_context();

    /* Configure SSL context */
    if(!configure_context(ctx, argv[3], argv[4], argv[5]))
    {
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    } 

    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[2]));
    addr.sin_addr.s_addr = inet_addr(argv[1]);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cout << "Unable to create a socket!\n";
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    std::cout << "Socket created successfully!\n";

    CURL* curl;
    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        /* String keeps the returned JSON */
        std::string s;
        /* String keeps the full URL API */
        std::string url = "https://api.openweathermap.org/data/2.5/weather?q=";
        url.append(argv[6]);
        url.append("&lang=pl&units=metric&appid=");
        url.append(argv[7]);
        
        /* Prepare CURL request */
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

        /* Send prepared request */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        
        /* Clean up */
        curl_easy_cleanup(curl);
        
        Json::Reader reader;
        Json::Value js;

        /* Parse JSON */
        if (reader.parse(s, js))
        {
            /* If elements 'name' and 'main' are present, consider data is correct */
            if(js.isMember("name") && js.isMember("main"))
            {
                SSL *ssl;
                ssl = SSL_new(ctx);

                if(!ssl)
                {
                    printf("Could not create SSL object!");
                    exit(EXIT_FAILURE);
                }

                /* An attempt to connect to the server occures if the data is correct */
                if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
                    perror("Unable to connect to the server.\n");
                    close(sockfd);
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    exit(EXIT_FAILURE);
                }
                
                if(SSL_set_fd(ssl, sockfd) != 1)
                {
                    printf("Could not attatch socket to SSL context!");
                    close(sockfd);
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    exit(EXIT_FAILURE);
                }

                if (SSL_connect(ssl) <= 0) {
                    perror("Could not negotiate a secure connection!\n");
                    close(sockfd);
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    exit(EXIT_FAILURE);
                }

                if(SSL_write(ssl, s.c_str(), s.length()) <= 0)
                {
                    std::cout<< "An error occured during data transfer!" << "\n";
                    close(sockfd);
                    SSL_free(ssl);
                    SSL_shutdown(ssl);
                    SSL_CTX_free(ctx);
                    exit(EXIT_FAILURE);
                }

                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sockfd);

                std::cout << "Data sent to the server: " << "\n";
                std::cout << "Current weather for city " << js.get("name","undefined") << ":\n";
                std::cout << "Temperature: \n" 
                          << "Air: " << js.get("main", 0).get("temp",0).asDouble() << "°C"
                          << ", Feels like: " << js.get("main", 0).get("feels_like",0).asDouble() << "°C" << "\n";
                std::cout << "Humidity: " << js.get("main", 0).get("humidity",0).asDouble() << "%" << "\n";
                std::cout << "Pressure: " << js.get("main", 0).get("pressure",0).asDouble() << "hPa" << "\n";
            }
            else
            {
                std::cout << "Incorrect response from API! Check your API key and/or your provided city." << "\n";
            }
        }
        else
        {
            throw std::runtime_error("Could not process the JSON: " + reader.getFormattedErrorMessages());
        }
    }

    SSL_CTX_free(ctx);
    return 0;
}