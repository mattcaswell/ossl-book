#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>

int main(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int sock = -1;
    int ret = 1;
    struct sockaddr_in servaddr;
    X509_VERIFY_PARAM *param;
    const char *servername = "127.0.0.1";
    const char *msg = "Hello World!";

    /* Initialise libssl */
    SSL_load_error_strings();
    SSL_library_init();

    /*
     * In versions prior to 1.1.0 you should use SSLv23_client_method() instead
     * of TLS_client_method(). They are equivalent but the new name is
     * preferred.
     */
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        goto err;

    /* Create a TCP connection to 127.0.01:443 */
    /* TODO: CHECK FOR ERRORS */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        goto err;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(servername);
    servaddr.sin_port = htons(443);
    if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
        goto err;

    /* Create an SSL object for the connection */
    ssl = SSL_new(ctx);
    if (ssl == NULL || SSL_set_fd(ssl, sock) == 0)
        goto err;

    /* Set up the checks that we require on the server certificate */
    param = SSL_get0_param(ssl);
    if (X509_VERIFY_PARAM_set1_host(param, servername, 0) == 0)
        goto err;
    SSL_set_verify(ssl, SSL_VERIFY_PEER, 0);

    /* Create an SSL/TLS connection to the server */
    if (SSL_connect(ssl) <= 0)
        goto err;

    /* Send some data to the server */
    if (SSL_write(ssl, msg, strlen(msg)) <= 0)
        goto err;

    /* Success! */
    ret = 0;
 err:
    if (ret != 0)
        ERR_print_errors_fp(stderr);

    /* Clean up */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (sock != -1)
        close(sock);
    SSL_CTX_free(ctx);

    return ret;
}
