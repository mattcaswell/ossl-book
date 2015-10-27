#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>

static int create_tcp_connection(const char *servername, int port);

int main(void)
{
   SSL_CTX *ctx = NULL;
   SSL *ssl = NULL;
   int sock = -1, ret = 1;
   X509_VERIFY_PARAM *param;
   const char *servername = "127.0.0.1", *msg = "Hello World!";

   /* Initialise libssl */
   SSL_load_error_strings();
   SSL_library_init();

   /* Prior to 1.1.0 use SSLv23_client_method() */
   ctx = SSL_CTX_new(TLS_client_method());
   if (ctx == NULL) goto err;
   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   SSL_CTX_load_verify_locations(ctx, "server.pem", NULL);

   /* Create a TCP connection to 127.0.01:1443 */
   sock = create_tcp_connection(servername, 1443);
   if (sock == -1) goto err;

   /* Create an SSL object for the connection */
   ssl = SSL_new(ctx);
   if (ssl == NULL || SSL_set_fd(ssl, sock) == 0) goto err;

   /* Set the server hostname for this SSL object */
   param = SSL_get0_param(ssl);
   if (X509_VERIFY_PARAM_set1_host(param, servername, 0) == 0)
      goto err;

   /* Create an SSL/TLS connection to the server */
   if (SSL_connect(ssl) <= 0) goto err;

   /* Send some data to the server */
   if (SSL_write(ssl, msg, strlen(msg)) <= 0) goto err;

   printf("Success!\n");
   ret = 0; /* Success! */
 err:
   if (ret != 0) ERR_print_errors_fp(stderr);
   /* Clean up */
   if (ssl != NULL && SSL_shutdown(ssl) == 0)
          SSL_shutdown(ssl);
   SSL_free(ssl);
   if (sock != -1) close(sock);
   SSL_CTX_free(ctx);
   /* Unitialise libssl */
   CRYPTO_cleanup_all_ex_data();
   EVP_cleanup();
   ERR_remove_thread_state(NULL);
   ERR_free_strings();
   return ret;
}

static int create_tcp_connection(const char *servername, int port)
{
   int sock;
   struct sockaddr_in serv;

   sock = socket(AF_INET, SOCK_STREAM, 0);
   if (sock == -1) return -1;
   memset(&serv, 0, sizeof(serv));
   serv.sin_family = AF_INET;
   serv.sin_addr.s_addr = inet_addr(servername);
   serv.sin_port = htons(port);
   if (connect(sock, (struct sockaddr *)&serv,
               sizeof(serv)) == -1) {
      close(sock);
      return -1;
   }

   return sock;
}
