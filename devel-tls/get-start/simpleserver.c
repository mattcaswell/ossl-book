#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>

static int listen_for_connection(const char *serveraddr, int port);

int main(void)
{
   SSL_CTX *ctx = NULL;
   SSL *ssl = NULL;
   int sock = -1, ret = 1, len;
   char msg[80];

   /* Prior to 1.1.0 use SSLv23_server_method() */
   ctx = SSL_CTX_new(TLS_server_method());
   if (ctx == NULL) goto err;
   if (SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM) <= 0)
      goto err;
   if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
      goto err;
   if (SSL_CTX_check_private_key(ctx) <= 0)
      goto err;

   /* Listen for a TCP connection to 127.0.01:1443 */
   sock = listen_for_connection("127.0.0.1", 1443);
   if (sock == -1) goto err;

   /* Create an SSL object for the connection */
   ssl = SSL_new(ctx);
   if (ssl == NULL || SSL_set_fd(ssl, sock) == 0) goto err;

   /* Create an SSL/TLS connection to the client */
   if (SSL_accept(ssl) <= 0) goto err;

   /* Read some data from the client */
   if ((len = SSL_read(ssl, msg, sizeof(msg) - 1)) <= 0) goto err;
   msg[len] = '\0';
   printf("%s\n", msg);
   ret = 0; /* Success! */
 err:
   if (ret != 0) ERR_print_errors_fp(stderr);
   /* Clean up */
   if (ssl != NULL && SSL_shutdown(ssl) == 0)
          SSL_shutdown(ssl);
   SSL_free(ssl);
   if (sock != -1) close(sock);
   SSL_CTX_free(ctx);
   return ret;
}

static int listen_for_connection(const char *serveraddr, int port)
{
   int servsock, clientsock = -1;
   struct sockaddr_in serv, client;
   socklen_t clientlen = sizeof(client);
   int optval = 1;

   if((servsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) return -1;
   if (setsockopt(servsock, SOL_SOCKET, SO_REUSEADDR,
                  (void *)&optval, sizeof(optval)) < 0)
      goto err;
   memset(&serv, 0, sizeof(serv));
   serv.sin_family = AF_INET;
   serv.sin_addr.s_addr = inet_addr(serveraddr);
   serv.sin_port = htons(port);
   if (bind(servsock, (struct sockaddr *)&serv, sizeof(serv)) < 0
        || listen(servsock, 1) < 0)
      goto err;

   clientsock = accept(servsock, (struct sockaddr *)&client,
                       &clientlen);
err:
   close(servsock);
   return clientsock;
}
