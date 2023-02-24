#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <strings.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>

//#include <linux/types.h>
//#include <linux/socket.h>
//#include <linux/param.h>
//#include <linux/time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define LISTEN_BACKLOG 80

#define CAROOT_FILE  "/system/xbin/sslca.pem"
#define PUBKEY_FILE  "/system/xbin/public.key"
#define PRIKEY_FILE  "/system/xbin/private.key"
#define KEYLOG_FILES "/system/xbin/sslkeys.txt"
#define KEYLOG_FILEC "/system/xbin/sslkeyc.txt"
#define IP_KEY_FILE  "/system/xbin/ip_key.dat"

#define warning(msg) \
    do { fprintf(stderr, "%lu pid:%u t:%d, ", getcurtimestamp(), getpid(), sum); perror(msg); } while(0)

#define error(msg) \
    do { fprintf(stderr, "%lu pid:%u t:%d, ", getcurtimestamp() getpid(), sum); perror(msg); exit(EXIT_FAILURE); } while (0)

#define info(format, args...) \
    do { printf("%lu pid:%u t:%d, ", getcurtimestamp() getpid(), sum); printf(format, ##args); } while (0)

#define log(format, args...) \
    do { printf(format, ##args); } while (0)

int sum = 1;
X509* root_x509 = NULL;
char gSuite[1024] = { 0 };

#define S2MS(s) ((s) * 1000)
#define MS2S(ms) ((ms) / 1000)
#define US2MS(us) ((us) / 1000)
unsigned long getcurtimestamp(void) {
    struct timeval timeVal;
    time_t curTs;

    if (gettimeofday(&timeVal, NULL) != 0) {
        warning("gettimeofday error.");
        return 0;
    }

    curTs = (S2MS(timeVal.tv_sec)) + (US2MS(timeVal.tv_usec));
    return (unsigned long)curTs;
}


/* �ж�Ϊ����IP��ַ */
bool is_private_ipaddr(struct sockaddr_in* original_server_addr) {
    unsigned long serverip = htonl(original_server_addr->sin_addr.s_addr);

    //info("***is private server address: [%08lx]***\n", serverip);

    if (((serverip & 0xFF000000) == 0x7F000000)
        || ((serverip & 0xFFFF0000) == 0xC0A80000)) {
        info("*** is private server = true. maybe CONNECT/GET proxy tobe fixed [%s:%d]\n",
            inet_ntoa(original_server_addr->sin_addr), ntohs(original_server_addr->sin_port));
        return true;
    }
    return false;
}

/* ����ͻ��˴��������˿� */
int socket_to_client_init(short int port) {
    int sockfd;
    int on = 1;
    struct sockaddr_in addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        error("Fail to initial socket to client!");

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0)
        error("reuseaddr error!");

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr*) &addr, sizeof(struct sockaddr)) < 0) {
        shutdown(sockfd, SHUT_RDWR);
        error("Fail to bind socket to client!");
    }
    if (listen(sockfd, LISTEN_BACKLOG) < 0) {
        shutdown(sockfd, SHUT_RDWR);
        error("Fail to listen socket to client!");
    }
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags|O_NONBLOCK);
    return sockfd;
}


/* ��Ŀ��Դվ����������socket���� */
int get_socket_to_server(struct sockaddr_in* original_server_addr) {
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        error("Fail to initial socket to server!");

    if (connect(sockfd, (struct sockaddr*) original_server_addr,
    sizeof(struct sockaddr)) < 0)
        error("Fail to connect to server!");

    info("Connect to server [%s:%d]\n",
        inet_ntoa(original_server_addr->sin_addr), ntohs(original_server_addr->sin_port));
    return sockfd;
}
 
/* ���ܿͻ��˷��ͽ���socket���� */
int get_socket_to_client(int socket, struct sockaddr_in* original_server_addr) {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_size = sizeof(struct sockaddr);
    socklen_t server_size = sizeof(struct sockaddr);
    char buf1[32] = { 0 };
    char buf2[32] = { 0 };

    fd_set fd_read;
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    FD_SET(socket, &fd_read);
    select(socket + 1, &fd_read, NULL, NULL, &timeout);
    if (!FD_ISSET(socket, &fd_read)) {
        return -1;
    }

    memset(&client_addr, 0, client_size);
    memset(original_server_addr, 0, server_size);
    client_fd = accept(socket, (struct sockaddr *) &client_addr, &client_size);
    if (client_fd < 0) {
        warning("Fail to accept socket to client!");
        return -1;
    }
    if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, original_server_addr, &server_size) < 0) {
        warning("Fail to get original server address of socket to client!");;
    }
    inet_ntop(AF_INET, &client_addr.sin_addr, buf1, sizeof(buf1));
    inet_ntop(AF_INET, &original_server_addr->sin_addr, buf2, sizeof(buf2));
    info("New SSL connection fdsock(%u) from client [%s:%d] to server [%s:%d]\n", client_fd,
        buf1, ntohs(client_addr.sin_port),
        buf2, ntohs(original_server_addr->sin_port));
    return client_fd;
}

/* ��ȡCA��֤���ļ������ڻ�ȡski����֤��aki */
X509 *get_root_cert(void) {
    BIO *bio;
    X509 *x509;

    if ((bio = BIO_new(BIO_s_file())) == NULL) {
        warning("get_root_cert BIO_new fail.");
        return 0;
    }

    if (BIO_read_filename(bio, CAROOT_FILE) <= 0) {
        warning("get_root_cert BIO_read_filename fail.");
        log("%s\n", CAROOT_FILE);
        BIO_free(bio);
        return 0;
    }

    //��ȷ���Ƿ�������
    while ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        return x509;
    }
    return 0;
} 

/* ����CA��֤����֤���� */
int set_root_cert_chain(SSL_CTX *ctx) {
    BIO *bio;
    X509 *x509;
    int n;

    if ((bio = BIO_new(BIO_s_file())) == NULL) {
        warning("set_root_cert_chain BIO_new fail.\n");
        return 0;
    }

    if (BIO_read_filename(bio, CAROOT_FILE) <= 0) {
        warning("set_root_cert_chain BIO_read_filename fail.");
        log("%s\n", CAROOT_FILE);
        BIO_free(bio);
        return 0;
    }

    n = 0;
    while ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        if (!SSL_CTX_add_extra_chain_cert(ctx, x509)) {
            X509_free(x509);
            BIO_free(bio);
            return 0;
        }
        n++;
    }
    return 1;
} 

/* ����SSL�� */
void SSL_init() {
    SSL_library_init();
    SSL_load_error_strings();
}

void SSL_Warning(char *custom_string) {
    char error_buffer[256] = { 0 };
    ERR_error_string(ERR_get_error(), error_buffer); // err lib 8bits,  func 12bits, reason 12bits
    info("%s %s\n", custom_string, error_buffer);
}

void SSL_Error(char *custom_string) {
    SSL_Warning(custom_string);
    exit(EXIT_FAILURE);
}

#define writes(fp, context, length) fwrite(context, 1, length, fp)

void write_file(FILE *fp, const char *line) {
    char *enter = "\r\n";
    fwrite(enter, sizeof(unsigned char), strlen(enter), fp);
    fwrite(line, sizeof(unsigned char), strlen(line), fp);
    fclose(fp);
}

FILE *create_file(const char *path) {
    FILE *fp;
    fp = fopen(path, "ab+");
    return fp;
}

static void client_keylog_callback(const SSL *ssl, const char *line) {
    FILE *fp = create_file(KEYLOG_FILES); //��ʱ��д����������ļ���
    if (fp != NULL) {
        write_file(fp, line);
    }
    log("C KEYLOG: %s\n", line);
}

static void server_keylog_callback(const SSL *ssl, const char *line) {
    FILE *fp = create_file(KEYLOG_FILES);
    if (fp != NULL) {
        write_file(fp, line);
    }
    log("S KEYLOG: %s\n", line);
}

/* ��Ŀ��Դ����������SSL���� */ 
SSL* SSL_to_server_init(int socket) {
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
        SSL_Error("Fail to init ssl ctx!");

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
        SSL_Error("Create ssl error");
    if (SSL_set_fd(ssl, socket) != 1)
        SSL_Error("Set fd error");
    SSL_CTX_set_keylog_callback(ctx, server_keylog_callback);
    return ssl;
}
 
/* ��ͻ��˽���SSL���ӣ���ҪΪ׼����֤���ļ���˽Կ */ 
SSL* SSL_to_client_init(int socket, X509 *cert, EVP_PKEY *key) {
    SSL_CTX *ctx;
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
        SSL_Error("Fail to init ssl ctx!");
    if (cert && key) {
        if (SSL_CTX_use_certificate(ctx, cert) != 1)
            SSL_Error("Certificate error");

        if (set_root_cert_chain(ctx) != 1)
            SSL_Error("Certificate chain error");

        if (SSL_CTX_use_PrivateKey(ctx, key) != 1)
            SSL_Error("key error");

        if (SSL_CTX_check_private_key(ctx) != 1)
            SSL_Error("Private key does not match the certificate public key");
    }

    SSL_CTX_set_cipher_list(ctx, gSuite);
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
        SSL_Error("Create ssl error");
    if (SSL_set_fd(ssl, socket) != 1)
        SSL_Error("Set fd error");
    SSL_CTX_set_keylog_callback(ctx, client_keylog_callback); 

    return ssl;
}

/* �ر�SSL���� */  
void SSL_terminal(SSL *ssl) {
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    if (ctx)
        SSL_CTX_free(ctx);
}

/* ��ȡ֤���˽Կ�͹�Կ��Ϣ����֤��͸�֤�鹫�ã�����ʵҲ����root��֤��ǩ��˽Կ */ 
EVP_PKEY* create_key() {
    EVP_PKEY *key = EVP_PKEY_new();
    RSA *rsa = RSA_new();
    FILE *fp;

    if ((fp = fopen(PRIKEY_FILE, "r")) == NULL)
        error(PRIKEY_FILE);
    PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);

    if ((fp = fopen(PUBKEY_FILE, "r")) == NULL)
        error(PUBKEY_FILE);
    PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);

    EVP_PKEY_assign_RSA(key,rsa);
    return key;
}

/* α����֤�飬�ӷ�������ȡ��֤����Ϊģ�壬�ų�������Ϣ�����ø�֤��˽Կǩ�� */ 
X509* create_fake_certificate(SSL* ssl_to_server, EVP_PKEY *key) {
    //unsigned char buffer[128] = { 0 };
    int location;
    int NID; 
    unsigned char *leaf_aki = NULL;
    unsigned char *leaf_ski = NULL;
    unsigned char *root_ski = NULL;
    int root_ski_len, root_aki_len;
    X509_EXTENSION *ex;
    X509 *server_x509 = SSL_get_peer_certificate(ssl_to_server);
    X509 *fake_x509 = X509_dup(server_x509);

    if (server_x509 == NULL)
        SSL_Error("Fail to get the certificate from server!");

    X509_set_version(fake_x509, X509_get_version(server_x509));

    // huangtest begin
    /* �Ӹ�֤���ȡski */
    if (root_x509 != NULL) {
        for (location = X509_get_ext_count(root_x509) - 1; location >= 0; location--)
        {
            ex = X509_get_ext(root_x509, location);
            NID = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
            if (NID == NID_subject_key_identifier) {
                root_ski = (unsigned char *)(X509_EXTENSION_get_data(ex)->data);
                root_ski_len = X509_EXTENSION_get_data(ex)->length;

                // root_ski = (unsigned char *)ex->value->data;
                // root_ski_len = ex->value->length;
            }
        }
    }

    for (location = X509_get_ext_count(fake_x509) - 1; location >= 0; location--) {
        ex = X509_get_ext(fake_x509, location);
        NID = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
        #if 0
        /* ��ȡ��֤���ski��ʵ�ʲ��������Ϣ */
        if (NID == NID_subject_key_identifier) {
            leaf_ski = (unsigned char *)ex->value->data;
            log("ski length:%d, string:%08x%08x%08x%08x%08x%04x\n", ex->value->length
                , ntohl(*(unsigned int *)leaf_ski)
                , ntohl(*(unsigned int *)(leaf_ski+4))
                , ntohl(*(unsigned int *)(leaf_ski+8))
                , ntohl(*(unsigned int *)(leaf_ski+12))
                , ntohl(*(unsigned int *)(leaf_ski+16))
                , ntohs(*(unsigned short *)(leaf_ski+20)));
        }
        #endif
        /* ��ȡ��֤��aki��Ϣ�������滻�¸�֤���ski��Ϣ */
        if ((NID == NID_authority_key_identifier) && (root_ski != NULL)) {
            leaf_aki = (unsigned char *)(X509_EXTENSION_get_data(ex)->data);
            root_aki_len = X509_EXTENSION_get_data(ex)->length;

            // leaf_aki = (unsigned char *)ex->value->data;
            // root_aki_len = ex->value->length;
            #if 0
            log("aki length:%d, string:%08x%08x%08x%08x%08x%04x\n", ex->value->length
                , ntohl(*(unsigned int *)leaf_aki)
                , ntohl(*(unsigned int *)(leaf_aki+4))
                , ntohl(*(unsigned int *)(leaf_aki+8))
                , ntohl(*(unsigned int *)(leaf_aki+12))
                , ntohl(*(unsigned int *)(leaf_aki+16))
                , ntohs(*(unsigned short *)(leaf_aki+20)));
            #endif
            /* ��ʽ��̫�ã���ħ��������ȷ�����滻��Ϣ */
            if ((root_aki_len == 24) && (root_ski_len == 22)) {
                memcpy(leaf_aki + 4, root_ski + 2, 20);
            } else {
                log("replace aki failure. length(aki,ski):%d, %d\n", root_aki_len, root_ski_len);
            }
        }

        /* ��������չ��Ϣ */
        if ((NID == NID_key_usage)             //�̳�
            || (NID == NID_basic_constraints)  //�̳�
            || (NID == NID_subject_alt_name)   //�̳�
            || (NID == NID_ext_key_usage)      //�̳�
            || (NID == NID_authority_key_identifier) //��Ҫ�޸�
            || (NID == NID_subject_key_identifier)   //������ʵ��Ӧ������֤��Ĺ�Կɢ�У�Э��Ҫ��������ظ�����
            || (NID == NID_ct_precert_scts))  //��֪���Ƿ���Ҫ����
            continue;
        X509_delete_ext(fake_x509, location);     //ȫ��������ʱ���� todo
    }
    // huangtest end

    /* �޸����к� */    
    ASN1_INTEGER *a = X509_get_serialNumber(fake_x509);
    a->data[0] = a->data[0] + 1;
    //    ASN1_INTEGER_set(X509_get_serialNumber(fake_x509), 4);

    /* ��дCA��������Ϣ��ʵ����ô�֤�������ȡ������д��˵������͸�֤��һһ�� */
    X509_NAME *issuer = X509_NAME_new();
    //    length = X509_NAME_get_text_by_NID(issuer, NID_organizationalUnitName, buffer, 128);
    //    buffer[length] = ' ';
    //    loc = X509_NAME_get_index_by_NID(issuer, NID_organizationalUnitName, -1);
    //    X509_NAME_delete_entry(issuer, loc);

    X509_NAME_add_entry_by_txt(issuer, "C", MBSTRING_ASC, (const unsigned char *)"CN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(issuer, "ST", MBSTRING_ASC, (const unsigned char *)"Guangdong", -1, -1, 0);
    X509_NAME_add_entry_by_txt(issuer, "L", MBSTRING_ASC, (const unsigned char *)"Shenzhen", -1, -1, 0);
    X509_NAME_add_entry_by_txt(issuer, "O",  MBSTRING_ASC, (const unsigned char *)"AAAAAAAA CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(issuer, "OU", MBSTRING_ASC, (const unsigned char *)"AAAAAAAA CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_ASC, (const unsigned char *)"AAAA", -1, -1, 0);

    //    X509_NAME_add_entry_by_txt(issuer, "C", MBSTRING_ASC, "CN", -1, -1, 0);
    //    X509_NAME_add_entry_by_txt(issuer, "ST", MBSTRING_ASC, "Some", -1, -1, 0);
    //    X509_NAME_add_entry_by_txt(issuer, "L", MBSTRING_ASC, "Shenzhen", -1, -1, 0);
    //    X509_NAME_add_entry_by_txt(issuer, "O",  MBSTRING_ASC, "ASGC_CA", -1, -1, 0);
    //    X509_NAME_add_entry_by_txt(issuer, "OU", MBSTRING_ASC, "ASGC_CA", -1, -1, 0);
    //    X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_ASC, "ASGC_CA", -1, -1, 0);
    //    X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_ASC, (unsigned char *)"QUIC Server Root CA", -1, -1, 0);
    X509_set_issuer_name(fake_x509, issuer);

    //    X509_set_notBefore(fake_x509, X509_get_notBefore(server_x509));
    //    X509_set_notAfter(fake_x509, X509_get_notAfter(server_x509));
    //    X509_set_subject_name(fake_x509, X509_get_subject_name(server_x509));

    /* ��Ҫд�빫Կ */    
    X509_set_pubkey(fake_x509, key);
    //    X509_add_ext(fake_x509, X509_get_ext(server_x509, -1), -1);
    /* ��CA˽Կǩ����ʵ��Ӧ�����ֹ�Կ����֤�鹫Կ��˽Կ�Ǹ�֤��˽Կ����proxy����˵������һ�� */
    X509_sign(fake_x509, key, EVP_sha256());

    //    X509_print_fp(stderr, fake_x509);

    return fake_x509;
}

void print_connectinfo(int socket_to_client, int socket_to_server) {
    char buf1[32] = { 0 };
    char buf2[32] = { 0 };
    struct sockaddr_in localaddr,peeraddr;
    socklen_t len = sizeof(struct sockaddr_in);

    bzero(&localaddr, sizeof(localaddr));
    getsockname(socket_to_server, (struct sockaddr*)&localaddr, &len);
    inet_ntop(AF_INET, &localaddr.sin_addr, buf1, sizeof(buf1));

    bzero(&peeraddr, sizeof(peeraddr));
    getpeername(socket_to_server, (struct sockaddr*)&peeraddr, &len);
    inet_ntop(AF_INET, &peeraddr.sin_addr, buf2, sizeof(buf2));
    info("toServer[%s:%d][%s:%d]\n", buf1, ntohs(localaddr.sin_port), buf2, ntohs(peeraddr.sin_port));

    bzero(&localaddr,sizeof(localaddr));
    getsockname(socket_to_client,(struct sockaddr*)&localaddr,&len);
    inet_ntop(AF_INET, &localaddr.sin_addr, buf1, sizeof(buf1));

    bzero(&peeraddr,sizeof(peeraddr));
    getpeername(socket_to_client,(struct sockaddr*)&peeraddr,&len);
    inet_ntop(AF_INET, &peeraddr.sin_addr, buf2, sizeof(buf2));
    info("toClient[%s:%d][%s:%d]\n", buf1, ntohs(localaddr.sin_port), buf2, ntohs(peeraddr.sin_port));
}

void write_connectinfo(int socket_to_client, int socket_to_server) {
    char buffer[1024] = { 0 };
    char *c, *s;
    struct sockaddr_in client_addr, server_addr;
    socklen_t len = sizeof(struct sockaddr_in);
    int ip127 = ntohl(0x7F000001);
    int ip10 = ntohl(0x0a0a0a0a);
    short port8888 = ntohs(8888);
    short port443 = ntohs(443);

    bzero(&client_addr, sizeof(client_addr));
    getpeername(socket_to_client, (struct sockaddr*)&client_addr, &len);
    //info("client[%s:%d]\n",
    //    inet_ntop(AF_INET, &client_addr.sin_addr, buffer, sizeof(buffer)), ntohs(client_addr.sin_port));

    bzero(&server_addr, sizeof(server_addr));
    getpeername(socket_to_server, (struct sockaddr*)&server_addr, &len);
    //info("server[%s:%d]\n",
    //    inet_ntop(AF_INET, &server_addr.sin_addr, buffer, sizeof(buffer)), ntohs(server_addr.sin_port));

    c = (char*)&client_addr;
    s = (char*)&server_addr;
    FILE *fp = create_file(IP_KEY_FILE);
    writes(fp, c + 4, 4);  writes(fp, &ip127, sizeof(int));  writes(fp, c + 2, 2);  writes(fp, &port8888, sizeof(short));
    writes(fp, c + 4, 4);  writes(fp, &ip10, sizeof(int));   writes(fp, c + 2, 2);  writes(fp, &port443, sizeof(short));

    writes(fp, s + 4, 4);             writes(fp, c + 4, 4);  writes(fp, &port443, sizeof(short));  writes(fp, c + 2, 2);
    writes(fp, &ip10, sizeof(int));   writes(fp, c + 4, 4);  writes(fp, &port443, sizeof(short));  writes(fp, c + 2, 2);
    fclose(fp);
}

/* ����ͻ��˺ͷ�����֮����Ϣ���ݣ�ֱ�����ӹرջ��쳣 */ 
int transfer(SSL *ssl_to_client, SSL *ssl_to_server, bool looped) {
    int c_out = 0;
    int c_bytes = 0;
    int s_out = 0;
    int s_bytes = 0;
    int socket_to_client = SSL_get_fd(ssl_to_client);
    int socket_to_server = SSL_get_fd(ssl_to_server);
    int ret;
    char buffer[128 * 1024] = { 0 }; // ���ﻺ�岻�������ܵ���SSL_read��������
    int maxloop = 0;
    int maxloop2 = 0;
    int maxloop3 = 0;
    bool firstread = true;

    fd_set fd_read;

    info("SSL Builded. Waiting for transfer\n");
    print_connectinfo(socket_to_client, socket_to_server);
    write_connectinfo(socket_to_client, socket_to_server);
    info("socket_to_client:%u, socket_to_server:%u\n", socket_to_client, socket_to_server);
    while (looped) {
        int max;
        struct timeval timeout;
        bool isRead = false;

        FD_ZERO(&fd_read);
        FD_SET(socket_to_server, &fd_read);
        FD_SET(socket_to_client, &fd_read);
        max = socket_to_client > socket_to_server ? socket_to_client + 1 : socket_to_server + 1;
        if (firstread) {
            timeout.tv_sec =0;
            timeout.tv_usec=5;
        } else {
            timeout.tv_sec =3;
            timeout.tv_usec=0;
        }
        //info("select begin\n");
        ret = select(max, &fd_read, NULL, NULL, &timeout);
        //        ret = select(max, &fd_read, NULL, NULL, NULL);
        if (ret < 0) {
        //            if (errno == EINTR) {
        //                continue;
        //            }
            log("Fail to select(%d) errno: %s!\n", ret, "strerror(errno)\n");
            SSL_Warning("Fail to select!");
            break;
        } else if (ret == 0) {
            maxloop++;
            if (maxloop > 5) {
                maxloop = 0;
                info("*****maxloop ret = 0\n");
                break; //����û���ݣ��˳��������� 20211029
            }
            //continue;
        }        
        /* �ӿͻ����շ��͵������� */
        if (FD_ISSET(socket_to_client, &fd_read) || firstread) {
            isRead = true;
            memset(buffer, 0, sizeof(buffer));
            ret = SSL_read(ssl_to_client, buffer, sizeof(buffer));
            if (ret > 127 * 1024)
            info("****Big data from client recv:%d\n", ret);
            if (ret > 0) {
                firstread = false;
                c_out++; c_bytes += ret;
                if (ret != SSL_write(ssl_to_server, buffer, ret)) {
                    SSL_Warning("Fail to write to server!\n");
                    break;
                } else {
                    info("client send %d bytes to server\n", ret);
                    if (  ((buffer[0] == 'G') && (buffer[1] == 'E')) 
                        ||((buffer[0] == 'P') && (buffer[1] == 'O')) 
                        ||((buffer[0] == 'H') && (buffer[1] == 'T')))
                        ;
                    //log("%s\n", buffer);
                }
            } else if (ret < 0){ // �����ret = 0 �Ƿ����쳣��������ʱ���������
                SSL_Warning("Fail to read from client!");
                info("ret:%d, %d\n", ret, SSL_get_error(ssl_to_client, ret));
                break;
            } else {
                maxloop2++;
                if (maxloop2 > 10000) {
                    maxloop2 = 0;
                    info("read client length = %d\n", ret);
                    break;
                }
            }
        }

        /* �ӷ��������͵��ͻ��� */
        if (FD_ISSET(socket_to_server, &fd_read) || firstread) {
            isRead = true;
            memset(buffer, 0, sizeof(buffer));
            ret = SSL_read(ssl_to_server, buffer, sizeof(buffer));
            if (ret > 0) {
                firstread = false;
                s_out++; s_bytes += ret;
                if (ret > 127 * 1024)
                    info("****Big data from server recv:%d\n", ret);
                if (ret != SSL_write(ssl_to_client, buffer, ret)) {
                    SSL_Warning("Fail to write to client!\n");
                    break;
                } else {
                    info("server send %d bytes to client\n", ret);
                    if (  ((buffer[0] == 'G') && (buffer[1] == 'E')) 
                        ||((buffer[0] == 'P') && (buffer[1] == 'O')) 
                        ||((buffer[0] == 'H') && (buffer[1] == 'T')))
                        ;
                    //log("%s\n", buffer);
                }
            } else if (ret < 0){ // �����ret = 0 �Ƿ����쳣��������ʱ���������
                SSL_Warning("Fail to read from server!\n");
                info("ret:%d, %d\n", ret, SSL_get_error(ssl_to_server, ret));
                break;
            } else {
                maxloop3++;
                if (maxloop3 > 10000) {
                    maxloop3 = 0;
                    info("read server length = %d\n", ret);
                    break;
                }
            }
        }

        if (!isRead) {
            info("select ret:%d firstread:%d\n", ret, firstread);
        }
    }
    info("c(%d,%d), s(%d,%d)\n", c_out, c_bytes, s_out, s_bytes);
    return -1;
}


char *get_server_name(char *buff, int len) {
    char *p   = NULL;
    char *ret = NULL;
    int type;
    int length = 0;
    int loop = 0;

    //    log("0 :%08x,%d\n", buff, length);
    p = buff;
    if (*p++ != 0x16)  //content type shakehand
        return NULL;

    p += 4;            //skip version + length
    if (*p++ != 0x1)   //shake hand type clienthello
        return 0;

    p += (3 + 2 + 32);          //skip length + version + Random
    length = *p++; p += length; //skip SessionId
    length = ntohs(*(unsigned short *)p); p += (2 + length); //skip Cipher Suites
    length = *p++; p += length; //skip Compression Methods

    p += 2;            //skip Extensions length
    while (loop++ < 16) {
        type = ntohs(*(unsigned short *)p); p += 2;   //skip Entension type
        length = ntohs(*(unsigned short *)p); p += 2; //skip Entension length

        if (type == 0)     // Enten type is server_name
        {
            p += 2;        // skip server_name list length
            if (*p++ != 0) // server_name type is hostname
                return NULL;

            length = ntohs(*(unsigned short *)p); p += 2; //skip server_name length
            ret = p;

            p += length; *p = 0; // fillin end \0
            return ret;
        }
        p += length; // skip Eetension content
    }

    info("not find server-name :%08x,%d\n", (int)p, length);
    return NULL;
}

int get_proxy_type(char* p, int len) {
    if (len < 0)
        return 0;

    if ((len > 1) && (p[0] == 0x16))
        return 1; // TLS proxy

    if ((len > 3) && (p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T'))
        return 2; // GET proxy

    if ((len > 7) && (p[0] == 'C') && (p[1] == 'O')
        && (p[2] == 'N') && (p[3] == 'N') 
        && (p[4] == 'E') && (p[5] == 'C') && (p[6] == 'T'))
        return 3; // GET proxy

    return 0;
}


int conn_get_server(char* p, int len, struct sockaddr_in* original_server_addr) {
    original_server_addr->sin_family = AF_INET;
    char* name_start;
    char* name_end;
    char* port_start;
    char portstring[10] = { 0 };
    char namestring[128] = { 0 };
    int portlen;
    int namelen;

    name_start = p + 7;
    name_end = strstr(name_start + 1, " ");
    port_start = strstr(name_start + 1, ":");

    //��url���ƶ��˷������˿�
    memset(portstring, 0, 10);
    if (port_start != NULL)
    {
        portlen = name_end - port_start - 1;
        memcpy(portstring, port_start + 1, portlen);
        original_server_addr->sin_port = htons((short)atoi(portstring));
    }
    else//��url�У�û���ƶ��������˿ڣ�Ĭ��80�˿�
    {
        original_server_addr->sin_port = htons(80);
        port_start = name_end;
        portlen = 0;
    }

    //�õ���������Ϣ
    //�����ַ��Ϣ����IP��ַ(202.194.7.1)����ʽ���ֵ�
    namelen = port_start - name_start - 1;
    memset(namestring, 0, 128);
    memcpy(namestring, name_start + 1, namelen);

    info("connect url:%s(%d) , port:%s(%d)\n", namestring, namelen, portstring, portlen);
    if (namestring[0] >= '0' && namestring[0] <= '9')
    {
        original_server_addr->sin_addr.s_addr = inet_addr(namestring);
    }
    //����������ʽ���ֵ�(www.sina.com.cn)
    else
    {
        struct hostent* pHost = (struct hostent* )gethostbyname(namestring);
        if (!pHost)
        {
            info("get ip failed. %s\n", namestring);
            return false;
        }
        memcpy(&original_server_addr->sin_addr, pHost->h_addr_list[0], sizeof(original_server_addr->sin_addr));
    }
    return true;
}


int conn_transfer(int socket_to_client, int socket_to_server) {
    int c_out = 0;
    int c_bytes = 0;
    int s_out = 0;
    int s_bytes = 0;
    //int socket_to_client = SSL_get_fd(ssl_to_client);
    //int socket_to_server = SSL_get_fd(ssl_to_server);
    int ret;
    char buffer[128 * 1024] = { 0 }; // ���ﻺ�岻�������ܵ���SSL_read��������
    int maxloop = 0;
    int maxloop2 = 0;
    int maxloop3 = 0;
    bool firstread = true;
    char* respone = "HTTP/1.1 200 Connection Established\r\nFiddlerGateway: Direct\r\nStartTime: 22:30:02.203\r\nConnection: close\r\n\r\n";

    fd_set fd_read;

    info("CONNECT PROXY Builded.Waiting for transfer\n");
    print_connectinfo(socket_to_client, socket_to_server);
    ret = recv(socket_to_client, buffer, 4096, 0);
    ret = send(socket_to_client, respone, strlen(respone), 0);

#if 1
    while (1) {
        int max;
        struct timeval timeout;
        bool isRead = false;

        FD_ZERO(&fd_read);
        FD_SET(socket_to_server, &fd_read);
        FD_SET(socket_to_client, &fd_read);
        max = socket_to_client > socket_to_server ? socket_to_client + 1 : socket_to_server + 1;
        if (firstread) {
            timeout.tv_sec = 0;
            timeout.tv_usec = 5;
        }
        else {
            timeout.tv_sec = 3;
            timeout.tv_usec = 0;
        }
        //info("select begin\n");
        ret = select(max, &fd_read, NULL, NULL, &timeout);
        //        ret = select(max, &fd_read, NULL, NULL, NULL);
        if (ret < 0) {
            //            if (errno == EINTR) {
            //                continue;
            //            }
            log("Fail to select(%d) errno: %s!\n", ret, "strerror(errno)\n");
            SSL_Warning("Fail to select!");
            break;
        }
        else if (ret == 0) {
            maxloop++;
            if (maxloop > 5) {
                maxloop = 0;
                info("*****maxloop ret = 0\n");
                break; //����û���ݣ��˳��������� 20211029
            }
            //continue;
        }
        /* �ӿͻ����շ��͵������� */
        if (FD_ISSET(socket_to_client, &fd_read) || firstread) {
            isRead = true;
            memset(buffer, 0, sizeof(buffer));
            ret = recv(socket_to_client, buffer, sizeof(buffer), 0);
            if (ret > 127 * 1024)
                info("****Big data from client recv:%d\n", ret);
            if (ret > 0) {
                firstread = false;
                c_out++; c_bytes += ret;
                if (ret != send(socket_to_server, buffer, ret, 0)) {
                    SSL_Warning("Fail to write to server!\n");
                    break;
                }
                else {
                    info("client send %d bytes to server\n", ret);
                    if (((buffer[0] == 'G') && (buffer[1] == 'E'))
                        || ((buffer[0] == 'P') && (buffer[1] == 'O'))
                        || ((buffer[0] == 'H') && (buffer[1] == 'T')))
                        ;
                    //log("%s\n", buffer);
                }
            }
            else if (ret < 0) { // �����ret = 0 �Ƿ����쳣��������ʱ���������
                SSL_Warning("Fail to read from client!");
                //info("ret:%d, %d\n", ret, SSL_get_error(ssl_to_client, ret));
                break;
            }
            else {
                maxloop2++;
                if (maxloop2 > 10000) {
                    maxloop2 = 0;
                    info("read client length = %d\n", ret);
                    break;
                }
            }
        }

        /* �ӷ��������͵��ͻ��� */
        if (FD_ISSET(socket_to_server, &fd_read) || firstread) {
            isRead = true;
            memset(buffer, 0, sizeof(buffer));
            ret = recv(socket_to_server, buffer, sizeof(buffer), 0);
            if (ret > 0) {
                firstread = false;
                s_out++; s_bytes += ret;
                if (ret > 127 * 1024)
                    info("****Big data from server recv:%d\n", ret);
                if (ret != send(socket_to_client, buffer, ret, 0)) {
                    SSL_Warning("Fail to write to client!\n");
                    break;
                }
                else {
                    info("server send %d bytes to client\n", ret);
                    if (((buffer[0] == 'G') && (buffer[1] == 'E'))
                        || ((buffer[0] == 'P') && (buffer[1] == 'O'))
                        || ((buffer[0] == 'H') && (buffer[1] == 'T')))
                        ;
                    //log("%s\n", buffer);
                }
            }
            else if (ret < 0) { // �����ret = 0 �Ƿ����쳣��������ʱ���������
                SSL_Warning("Fail to read from server!\n");
                //info("ret:%d, %d\n", ret, SSL_get_error(ssl_to_server, ret));
                break;
            }
            else {
                maxloop3++;
                if (maxloop3 > 10000) {
                    maxloop3 = 0;
                    info("read server length = %d\n", ret);
                    break;
                }
            }
        }

        if (!isRead) {
            info("select ret:%d firstread:%d\n", ret, firstread);
        }
    }
#endif
    info("c(%d,%d), s(%d,%d)\n", c_out, c_bytes, s_out, s_bytes);
    return -1;
}


int main(int argc, char* argv[]) {
    pid_t forkid = 1;
    errno = 0;
    log("\nsslproxy program (Version: %s %s).\nopenssl-version: %s\nargv_num: %d\n", __DATE__, __TIME__, OpenSSL_version(OPENSSL_VERSION), argc);
    for (int i = 0; i < argc; i++)
    log("argv[%d]: %s\n", i, argv[i]);
    memset(gSuite, 0, sizeof(gSuite));

    if (argc >= 2) {
        strcpy(gSuite, argv[1]);
    } else {
        strcpy(gSuite, "ALL");
    }
    log("gSuite: %s\n", gSuite);

    // ��ʼ��һ��socket������socket�󶨵�8888�˿ڣ�������
    int socket = socket_to_client_init(8888);
    // ���ļ���ȡα��SSL֤��ʱ��Ҫ��RAS˽Կ�͹�Կ
    EVP_PKEY* key = create_key();
    //X509* root_x509 = NULL;
    // ��ʼ��openssl��
    SSL_init();
    root_x509 = get_root_cert();
    info("father:%u\n", getpid());

    while (1) {
        int st;
        struct sockaddr_in original_server_addr;
        // �Ӽ����Ķ˿ڻ��һ���ͻ��˵����ӣ����������ӵ�ԭʼĿ�ĵ�ַ�洢��original_server_addr��
        int socket_to_client = get_socket_to_client(socket, &original_server_addr);
        if (socket_to_client < 0) {
            pid_t pid = waitpid(0, &st, WNOHANG);
            while (pid > 0) {
                info("waitpid pid:%u, st:%u\n", pid, st);
                pid = waitpid(0, &st, WNOHANG);
            }
            fflush(stdout);
            continue;
        }
        if (is_private_ipaddr(&original_server_addr)) {
            //shutdown(socket_to_client, SHUT_RDWR);
            //continue;
        }
        fflush(stdout);

        //        if (forkid)
        forkid = fork();

        // �½�һ���ӽ��̴���������ˣ������̼��������˿ڵȴ���������
        if (!forkid) {
            X509* fake_x509;
            SSL* ssl_to_client, * ssl_to_server;
            char buff[4096] = { 0 };
            char* p = NULL;
            int length;
            errno = 0;

            info("child:%u\n", getpid());

            //���Ի�ȡ ClientHello ��Ϣͷ�� ServerName
            length = recv(socket_to_client, buff, 4096, MSG_PEEK);
            int type = get_proxy_type(buff, length);

            if ((type == 0) || (type == 2) || (type == 3)) {
                info("***connection unsupport. con-type: %d\n", type);
                if (type > 0) {
                    log("%s\n", buff);
                    if (conn_get_server(buff, length, &original_server_addr)) {
                        int socket_to_server = get_socket_to_server(&original_server_addr);
                        print_connectinfo(socket_to_client, socket_to_server);
                        conn_transfer(socket_to_client, socket_to_server);
                    }
                }
                shutdown(socket_to_client, SHUT_RDWR); 
                exit(0);
            }

            p = get_server_name(buff, length);
            // ͨ����õ�ԭʼĿ�ĵ�ַ�����������ķ����������һ���ͷ��������ӵ�socket
            int socket_to_server = get_socket_to_server(&original_server_addr);
            // ͨ���ͷ��������ӵ�socket����һ���ͷ�������SSL����
            ssl_to_server = SSL_to_server_init(socket_to_server);

            if (p != NULL) {
                char data[10];
                info("set sname: %s\n", p);
                SSL_set_tlsext_host_name(ssl_to_server, p); //������������������ƣ���ֹͬһIP��ַ�ж��������
                memcpy(data, "\x08http/1.1", 9);           
                SSL_set_alpn_protos(ssl_to_server, (unsigned char *)data, 9);  //����ALPN�������
            } else {
                info("set sname len:%d, none\n", length);
            }

            if (SSL_connect(ssl_to_server) < 0)
                SSL_Error("Fail to connect server with ssl!");

            info("SSL to server\n");

            // �ӷ��������֤�飬��ͨ�����֤��α��һ���ٵ�֤��
            fake_x509 = create_fake_certificate(ssl_to_server, key);
            // ʹ�üٵ�֤��������Լ�����Կ���Ϳͻ��˽���һ��SSL���ӡ����ˣ�SSL�м��˹����ɹ�
            ssl_to_client = SSL_to_client_init(socket_to_client, fake_x509, key);
            if (SSL_accept(ssl_to_client) <= 0) {
                transfer(ssl_to_client, ssl_to_server, false); //只为打印转换的ip_dat
                SSL_Error("Fail to accept client with ssl!");
            }

            info("SSL to client\n");
 
            // �ڷ�����SSL���ӺͿͻ���SSL����֮��ת�����ݣ�������������Ϳͻ���֮��ͨ�ŵ�����
            if (transfer(ssl_to_client, ssl_to_server, true) < 0) {
                SSL_terminal(ssl_to_client);
                SSL_terminal(ssl_to_server);
                info("ssl connection shutdown:%d,%d,%d,%d\n",
                    shutdown(socket_to_client, SHUT_RDWR),
                    shutdown(socket_to_server, SHUT_RDWR),
                    close(socket_to_client),
                    close(socket_to_server));
                X509_free(fake_x509);
            }
            exit(0);
        } else {
            //set_fdsock_fid(forkid, socket_to_client);
            close(socket_to_client);
            ++sum;
        }
    }

    EVP_PKEY_free(key);
    return 0;
}
