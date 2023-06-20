#include <iostream>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace
{
    const std::string g_certChainFile = "cert/certificate.pem";
    const std::string g_privateKeyFile = "cert/private_key.pem";
    const int g_bufferSize = 4096;
} // namespace

std::string resolveHostnameToIp(const std::string& hostname)
{
    std::string remoteIp;
    
    std::cout << "[DNS] Resolving " << hostname << std::endl;
    boost::asio::io_context ioContext;
    boost::asio::ip::tcp::resolver resolver(ioContext);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(hostname, "0");
    if (!endpoints.empty())
    {
        remoteIp = endpoints.begin()->endpoint().address().to_string();
        std::cout << "[DNS] IP: " << remoteIp << std::endl;
    }
    
    return remoteIp;
}

std::string readTcpData(boost::asio::ip::tcp::socket& socket)
{
    std::vector<char> buffer(g_bufferSize);
    boost::system::error_code error;
    std::string data;
    while (socket.available() > 0)
    {
        std::size_t bytesRead = socket.read_some(boost::asio::buffer(buffer), error);
        if (bytesRead == 0 || error == boost::asio::error::eof)
            break;
        data.append(buffer.data(), bytesRead);
    }
    
    std::cout << "[TCP] Read: " << data.length() << '\n';
    std::cout << "=============================================" << '\n';
    std::cout << data << '\n';
    std::cout << "=============================================" << '\n';
    return data;
}

void writeTcpData(boost::asio::ip::tcp::socket& socket, const std::string& data)
{
    std::cout << "[TCP] Write: " << data.length() << '\n';
    boost::asio::write(socket, boost::asio::buffer(data));
}

bool TLSValidationCallback(bool preverified, boost::asio::ssl::verify_context& ctx)
{
    return true;
}

std::string readTLSStream(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& tlsStream)
{
    std::vector<char> buffer(g_bufferSize);
    boost::system::error_code error;
    std::string data;
    
    while (tlsStream.lowest_layer().available())
    {
        std::size_t bytesRead = tlsStream.read_some(boost::asio::buffer(buffer), error);
        if (bytesRead == 0 || error == boost::asio::error::eof)
            break;
        data.append(buffer.data(), bytesRead);
    }
    
    if (error)
        std::cout << "[TLS] read_some error: " << error.message() << std::endl;
    
    std::cout << "[TLS] Read: " << data.length() << '\n';
    std::cout << "=============================================" << '\n';
    std::cout << data << '\n';
    std::cout << "=============================================" << '\n';
    return data;
}

void writeTLSStream(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& tlsStream, const std::string& data)
{
    std::cout << "[TLS] Write: " << data.length() << '\n';
    boost::asio::write(tlsStream, boost::asio::buffer(data));
}

void tlsCommunicationLoop(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& clientTLSStream,
                          boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& serverTLSStream)
{
    std::cout << "[Info] Start TLS communication loop" << '\n';
    
    while (true)
    {
        try
        {
            std::cout << "[TLS] Client read (request to server)" << '\n';
            std::string clientRequest = readTLSStream(clientTLSStream);
            if (clientRequest.empty())
                break;
            
            std::cout << "[TLS] Client write to server" << '\n';
            writeTLSStream(serverTLSStream, clientRequest);
            
            std::cout << "[TLS] Server read (response to client)" << '\n';
            std::string serverResponse = readTLSStream(serverTLSStream);
            if (serverResponse.empty())
                break;
            
            std::cout << "[TLS] Write response from server to client" << '\n';
            writeTLSStream(clientTLSStream, serverResponse);
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[Error] tlsCommunicationLoop: " << ex.what() << '\n';
            break;
        }
    }
    
    std::cout << "[Info] Stop TLS communication loop" << '\n';
}

void establishAndHandleTlsTunnel(boost::asio::io_context& ioContext,
                                 const std::string& remoteHostname,
                                 int remotePort,
                                 boost::asio::ip::tcp::socket& clientSocket)
{
    try
    {
        boost::asio::ssl::context tlsContext(boost::asio::ssl::context::tlsv12_server);
        tlsContext.use_certificate_chain_file(g_certChainFile);
        tlsContext.use_private_key_file(g_privateKeyFile, boost::asio::ssl::context::pem);
        
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> clientTLSStream(ioContext, tlsContext);
        clientTLSStream.set_verify_callback(TLSValidationCallback);
        clientTLSStream.lowest_layer() = std::move(clientSocket);
        std::cout << "[TLS] Establishing client TLS stream over existing TCP stream" << '\n';
        clientTLSStream.handshake(boost::asio::ssl::stream_base::server);
        std::cout << "[TLS] Client TLS stream established" << '\n';
        
        boost::asio::ssl::context proxyClientTLSContext(boost::asio::ssl::context::tlsv12_client);
        boost::asio::ip::tcp::socket serverSocket(ioContext);
        
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> serverTLSStream(ioContext, proxyClientTLSContext);
        std::cout << "[TCP] Establishing proxy TLS stream to remote endpoint" << '\n';
        std::string ip = resolveHostnameToIp(remoteHostname);
        std::cout << "[TCP] Connecting to " << ip << ", port " << remotePort << '\n';
        boost::asio::ip::tcp::resolver resolver(ioContext);
        boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(ip, std::to_string(remotePort));
        boost::asio::connect(serverSocket, endpoints);
        std::cout << "[TLS] Tunneling to TLS" << '\n';
        serverTLSStream.lowest_layer() = std::move(serverSocket);
        std::cout << "[TLS] Connecting to " << remoteHostname << " using SSL" << '\n';
        serverTLSStream.handshake(boost::asio::ssl::stream_base::client);
        std::cout << "[TLS] Proxy TLS stream to remote endpoint established" << '\n';
        
        
        tlsCommunicationLoop(clientTLSStream, serverTLSStream);
        
        
        std::cout << "[TLS] Closing TLS tunnels" << '\n';
        // Attempt to perform graceful shutdown
        boost::system::error_code shutdown_ec;
        clientTLSStream.shutdown(shutdown_ec);
        if (shutdown_ec && shutdown_ec != boost::asio::error::eof)
        {
            throw boost::system::system_error(shutdown_ec);
        }
        
        serverTLSStream.shutdown(shutdown_ec);
        if (shutdown_ec && shutdown_ec != boost::asio::error::eof)
        {
            throw boost::system::system_error(shutdown_ec);
        }
        std::cout << "[TLS] End" << '\n';
    }
    catch (const std::exception& ex)
    {
        std::cout << "[Error] establishAndHandleTlsTunnel: " << ex.what() << '\n';
    }
}

std::string getConnectionHostname(const std::string& data)
{
    std::string hostname;
    
    std::istringstream requestStream(data);
    std::string line;
    while (std::getline(requestStream, line))
    {
        if (line.compare(0, 7, "CONNECT") == 0)
        {
            std::string rawUrl = line.substr(8); // Remove "CONNECT " part
            std::size_t hostPos = rawUrl.find(':');
            if (hostPos != std::string::npos)
            {
                hostname = rawUrl.substr(0, hostPos);
                break;
            }
        }
    }
    
    return hostname;
}

void acceptConnection(boost::asio::ip::tcp::acceptor& acceptor)
{
    boost::asio::io_context& ioContext = static_cast<boost::asio::io_context&>(acceptor.get_executor().context());
    boost::asio::ip::tcp::socket clientSocket(ioContext);
    acceptor.accept(clientSocket);
    
    std::cout << "[TCP] TCP proxy server accepted a new connection" << '\n';
    std::string request = readTcpData(clientSocket);
    std::cout << request << '\n';
    
    std::string hostname = getConnectionHostname(request);
    if (!hostname.empty())
    {
        std::cout << "[Info] Server remote hostname: " << hostname << '\n';
        writeTcpData(clientSocket, "HTTP/1.1 200 Connection established\r\n\r\n");
        establishAndHandleTlsTunnel(ioContext, hostname, 443, clientSocket);
    }
    else
    {
        std::cout << "[Info] TCP Connection don't contain CONNECT field" << '\n';
        std::cout << "[Info] Turn back to receiving next connections" << '\n';
    }
}

int main()
{
    const int port = 55123;
    
    boost::asio::io_context ioContext;
    boost::asio::ip::tcp::acceptor acceptor(ioContext,
                                            boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(),
                                            port));
    std::cout << "[Info] Start MITM-Proxy server on port: " << port << '\n';
    acceptor.listen();
    
    while (true)
    {
        try
        {
            acceptConnection(acceptor);
        }
        catch (const std::exception& ex)
        {
            std::cout << "[Error] acceptConnection: " << ex.what() << std::endl;
            return -1;
        }
    }
    
    return 0;
}
