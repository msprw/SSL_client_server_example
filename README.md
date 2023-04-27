# SSL_client_server_example
This repo contains an example implementation of SSL communication. Programs exchange weather information of a selected city. Client gathers information from OpenWeather API and sends it to the server. Server displays sent data.

# Dependencies

 - CURL
 - OpenSSL
 - [jsoncpp](https://github.com/open-source-parsers/jsoncpp)
 - [OpenWeather API key](https://openweathermap.org/api)
 - easy-rsa(optional) for key generation

# Usage
**Server**

The syntax is as follows
   

     server <server_ip> <port> <ca_cert> <server_cert> <server_priv_key>

**Client**

    client <server_ip> <port> <ca_cert> <client_cert> <client_priv_key> <city> <ow_api_key>
