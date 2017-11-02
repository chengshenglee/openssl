#ifndef _CONN_H_
#define _CONN_H_

#include "openssl/ssl.h"  
#include "openssl/err.h"
#include "openssl/bio.h"
#include "string.h"
#include <map>
#include "sys/epoll.h"

#ifdef WIN32
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#else
#include <sys/socket.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_PATH_LEN                    256
#define MAX_CIPHER_FILTER_LENGTH        1024

typedef struct
{
    char CACertPath[MAX_PATH_LEN];
    char priCertPath[MAX_PATH_LEN];
    char priKeyPath[MAX_PATH_LEN];
    char cipherFilter[MAX_CIPHER_FILTER_LENGTH];        //加密套件筛选条件
    int connType;           //连接方式：SSL或者NOSSL
    int verifyType;         //证书验证方式
    int statusType;         //身份：Server | Client
    int keyUpdateInterval;
    SSL_CTX* ctx;
} SSLConnInfo;

//Server | Client
enum StatusType
{
    CLIENT = 0x00,
    SERVER = 0x01,
};

//SSL or NOT
enum ConnType
{
	NOSSL_CONN = 0x00,
	SSL_CONN = 0x01,
};

typedef struct
{
    SSL *ssl;
    int events;
    int isSSLConnected;
    int sessionKeyUpdateTime;
}SSLInfo;

typedef map<int, SSLConnInfo> ConnectedSSLInfo;

SSLConnInfo* GetDefaultSSLConn(); 

int SSL_AddSsl(int socket, SSLInfo *sslInfo);
int SSL_DeleteSsl(int sockfd);
SSLInfo* SSL_FindSsl(int sockfd);
int SSL_ModSsl(int sockfd);

int SSL_SetCACertPath(const char *pCACertPath);
int SSL_SetPriCertPath(const char *pPriCertPath);  
int SSL_SetPriKeyPath(const char *pPriKeyPath);
int SSL_SetCipherFilter(const char *pCipherFilter);  
int SSL_SetConnType(int connType);
int SSL_SetVerifyType(int verifyType);
int SSL_SetKeyUpdateInterval(int keyUpdateInterval);
int SSL_SetStatus(int statusType);

int SSL_Init(int statusType, 
             int verifyType, 
             int connType, 
             const char *pPriCertPath, 
             const char *pPriKeyPath, 
             const char *pCACertPath, 
             const char *pCipherFilter);
SSL_CTX* SSL_CTXNew();
int SSL_FreeSsl(SSL* ssl);
void SSL_FreeCTX();
void DJSSL_Free();

int SSL_SendMsg(int sockfd, const char* buf, int len);
int SSL_RecvMsg(int sockfd, char* buf, int len);
int SSL_HandShake(int sockfd);
int SSL_UpdateSessionKey(int sockfd);
int SSL_Connect(int sockfd);
int SSL_Accept(int sockfd);

int SSL_EpollUpdateSessionKey();
int SSL_EpollConnect();
int SSL_EpollAccept();

int SSL_SelectUpdateSessionKey();
int SSL_SelectConnect();
int SSL_SelectAccept();

#ifdef __cplusplus
}
#endif

#endif
