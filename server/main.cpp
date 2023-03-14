#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>

const char *_CERT = NULL;
const char *_PRIV = NULL;
const char *_DH   = NULL;
size_t _CERT_SIZE = 0;
size_t _PRIV_SIZE = 0;
size_t _DH_SIZE   = 0;

void
init_server ()
{
    uid_t uid  = getuid();
    uid_t euid = geteuid();
    if (uid <= 0 || uid != euid) {
        fputs("Please don't run this program as root.\n", stderr);
        exit(1);
    }

    _CERT = getenv("cert");
    _PRIV = getenv("priv");
    _DH   = getenv("dh");
    if (!(_CERT || _PRIV || _DH)) {
        fputs("Environment error. Please start me by running `./launch.sh`.\n", stderr);
        exit(1);
    }
    _CERT_SIZE = strlen(_CERT);
    _PRIV_SIZE = strlen(_PRIV);
    _DH_SIZE = strlen(_DH);
}

#define ASIO_STANDALONE
#define _WEBSOCKETPP_CPP11_THREAD_
#define _WEBSOCKETPP_CPP11_RANDOM_DEVICE_
#define _WEBSOCKETPP_CPP11_STRICT_
#define _WEBSOCKETPP_CPP11_TYPE_TRAITS_

#include <iostream>
#include <set>
#include "websocketpp/config/asio.hpp"
#include "websocketpp/server.hpp"
#include "websocketpp/common/thread.hpp"

typedef websocketpp::server<websocketpp::config::asio_tls> server;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

using websocketpp::connection_hdl;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

using websocketpp::lib::thread;
using websocketpp::lib::mutex;
using websocketpp::lib::lock_guard;
using websocketpp::lib::unique_lock;
using websocketpp::lib::condition_variable;

enum action_type {
    SUBSCRIBE,
    UNSUBSCRIBE,
    MESSAGE
};

struct action {
    action(action_type t, connection_hdl h) : type(t), hdl(h) {}
    action(action_type t, connection_hdl h, server::message_ptr m)
      : type(t), hdl(h), msg(m) {}

    action_type type;
    websocketpp::connection_hdl hdl;
    server::message_ptr msg;
};

enum tls_mode {
    MOZILLA_INTERMEDIATE = 1,
    MOZILLA_MODERN = 2
};

class Broadcast {
public:
    Broadcast ()
    {
        m_server.init_asio();

        /*
         * on_open - insert connection_hdl into channel
         * on_close - remove connection_hdl from channel
         * on_message - queue send to all channels
         * on_http handle - http requests (index.html)
         * on_tls_init - setup https connection using certs/keys
         */
        auto on_open  = bind(&Broadcast::on_open, this, ::_1);
        auto on_close = bind(&Broadcast::on_close, this, ::_1);
        auto on_msg   = bind(&Broadcast::on_message, this, ::_1, ::_2);
        auto on_http  = bind(&Broadcast::on_http, this, ::_1);
        auto on_tls   = bind(&Broadcast::on_tls_init, this, ::_1);
        m_server.set_open_handler(on_open);
        m_server.set_close_handler(on_close);
        m_server.set_message_handler(on_msg);
        m_server.set_http_handler(on_http);
        m_server.set_tls_init_handler(on_tls);
    }

    void
    on_http (websocketpp::connection_hdl hdl)
    {
        server::connection_ptr con = m_server.get_con_from_hdl(hdl);

        con->set_body("Hello World!");
        con->set_status(websocketpp::http::status_code::ok);
    }

    context_ptr
    on_tls_init (websocketpp::connection_hdl hdl)
    {
        namespace asio = websocketpp::lib::asio;

        // Just use Mozilla Modern which disables TLSv1
        const tls_mode mode = MOZILLA_MODERN;
        std::cout << "on_tls_init called with hdl: " << hdl.lock().get() << std::endl;
        std::cout << "using TLS mode: " << (mode == MOZILLA_MODERN ? "Mozilla Modern" : "Mozilla Intermediate") << std::endl;

        context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);

        try {
            ctx->set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::no_tlsv1 |
                             asio::ssl::context::single_dh_use);

            ctx->use_certificate_chain(asio::const_buffer(_CERT, _CERT_SIZE));
            ctx->use_private_key(asio::const_buffer(_PRIV, _PRIV_SIZE),
                    asio::ssl::context::pem);
            ctx->use_tmp_dh(asio::const_buffer(_DH, _DH_SIZE));

            if (SSL_CTX_set_cipher_list(ctx->native_handle(),
                                        Broadcast::ciphers.c_str()) != 1) {
                std::cerr << "Error setting cipher list" << std::endl;
            }
        } catch (std::exception& e) {
            std::cerr << "Exception: " << e.what() << std::endl;
        }

        return ctx;
    }

    void
    run (uint16_t port)
    {
        m_server.listen(port);
        m_server.start_accept();

        try {
            m_server.run();
        } catch (const std::exception & e) {
            std::cerr << e.what() << std::endl;
        }
    }

    void
    on_open (connection_hdl hdl)
    {
        {
            lock_guard<mutex> guard(m_action_lock);
            std::cout << "on_open" << std::endl;
            m_actions.push(action(SUBSCRIBE, hdl));
        }
        m_action_cond.notify_one();
    }

    void
    on_close (connection_hdl hdl)
    {
        {
            lock_guard<mutex> guard(m_action_lock);
            std::cout << "on_close" << std::endl;
            m_actions.push(action(UNSUBSCRIBE, hdl));
        }
        m_action_cond.notify_one();
    }

    void
    on_message (connection_hdl hdl, server::message_ptr msg)
    {
        // queue message up for sending by processing thread
        {
            lock_guard<mutex> guard(m_action_lock);
            std::cout << "on_message" << std::endl;
            m_actions.push(action(MESSAGE, hdl, msg));
        }
        m_action_cond.notify_one();
    }

    void
    process_messages ()
    {
        while(1) {
            unique_lock<mutex> lock(m_action_lock);

            while (m_actions.empty()) {
                m_action_cond.wait(lock);
            }

            action a = m_actions.front();
            m_actions.pop();

            lock.unlock();

            if (a.type == SUBSCRIBE) {
                lock_guard<mutex> guard(m_connection_lock);
                m_connections.insert(a.hdl);
            } else if (a.type == UNSUBSCRIBE) {
                lock_guard<mutex> guard(m_connection_lock);
                m_connections.erase(a.hdl);
            } else if (a.type == MESSAGE) {
                lock_guard<mutex> guard(m_connection_lock);

                con_list::iterator it;
                for (it = m_connections.begin(); it != m_connections.end(); ++it) {
                    m_server.send(*it,a.msg);
                }
            } else {
                // undefined.
                std::cerr << "Undefined message in process_message loop!\n";
            }
        }
    }

private:
    typedef std::set<connection_hdl,std::owner_less<connection_hdl> > con_list;

    server m_server;
    con_list m_connections;
    std::queue<action> m_actions;

    mutex m_action_lock;
    mutex m_connection_lock;
    condition_variable m_action_cond;

    static const std::string ciphers;
};

const std::string Broadcast::ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";

int
main()
{
    init_server();

    try {
    Broadcast server_instance;

    // starts a separate thread which processes messages
    thread t(bind(&Broadcast::process_messages, &server_instance));

    // main thread turns into server loop
    server_instance.run(8086);

    t.join();

    } catch (websocketpp::exception const & e) {
        std::cerr << e.what() << std::endl;
    }
}
