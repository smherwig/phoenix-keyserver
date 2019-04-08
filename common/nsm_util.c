#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <rho/rho.h>
#include <rpc.h>

#include "nsm_util.h"

/**********************************************************
 * INIT
 *********************************************************/
void
nsm_openssl_init(void)
{
    SSL_library_init(); /* same as OpenSSL_add_all_algorithms */
    SSL_load_error_strings();
}

/**********************************************************
 * OPENSSL ERROR REPORTING
 *********************************************************/
/* print the contents of the SSL error queue */
static void
nsm_openssl_clear_ssl_queue(void)
{
    unsigned long sslcode = ERR_get_error();

    do {
        static const char sslfmt[] = "SSL Error: %s:%s:%s\n";
        fprintf(stderr, sslfmt,
                ERR_lib_error_string(sslcode),
                ERR_func_error_string(sslcode),
                ERR_reason_error_string(sslcode));
    } while ((sslcode = ERR_get_error()) != 0);
}

void
nsm_openssl_warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputs("\n", stderr);
    va_end(ap);

    nsm_openssl_clear_ssl_queue();
}

void
nsm_openssl_die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputs("\n", stderr);
    va_end(ap);

    nsm_openssl_clear_ssl_queue();
    exit(EXIT_FAILURE);
}

/**********************************************************
 * RSA KEY GENERATION
 *********************************************************/
RSA *
nsm_genrsa(int mod, int e)
{
    BIGNUM *bne = NULL;
    RSA *rsa = NULL;

    RHO_TRACE_ENTER();

    bne = BN_new();
    if (bne == NULL) {
        nsm_openssl_warn("%s: BN_new", __func__);
        goto fail;
    }
    BN_set_word(bne, e);

    rsa = RSA_new();
    if (rsa == NULL) {
        nsm_openssl_warn("%s: BN_new", __func__);
        goto fail;
    }

    if (RSA_generate_key_ex(rsa, mod, bne, NULL) != 1) {
        nsm_openssl_warn("%s: RSA_generate_key_ex", __func__);
        goto fail;
    }

    if (RSA_check_key(rsa) != 1) {
        nsm_openssl_warn("%s: RSA_check_key", __func__);
        goto fail;
    }

    goto succeed;

fail:
    if (rsa != NULL) {
        RSA_free(rsa);
        rsa = NULL;
    }

succeed:
    if (bne != NULL)
        BN_free(bne);

    RHO_TRACE_EXIT();
    return (rsa);
}

/**********************************************************
 * DER -> PEM, PEM -> DER CONVERSIONS
 *********************************************************/
int 
nsm_rsa_priv_to_der(RSA *rsa, uint8_t **der, size_t *der_len)
{
    int error = 0;
    int len = 0;
    unsigned char *tmp = NULL;

    RHO_TRACE_ENTER();

    len = i2d_RSAPrivateKey(rsa, NULL);
    if (len < 0) {
        nsm_openssl_warn("pem2ddr: i2d_RSAPrivateKey(rsa, NULL)");
        error = -1;
        goto done;
    }

    *der = rhoL_malloc(len);
    tmp = *der;
    len = i2d_RSAPrivateKey(rsa, &tmp);
    if (len < 0) {
        nsm_openssl_warn("pem2ddr: i2d_RSAPrivateKey");
        rhoL_free(*der);
        *der = NULL;
        error = -1;
        goto done;
    }

    *der_len = len; 
    error = 0;

done:
    RHO_TRACE_EXIT();
    return (error); 
}

int
nsm_pem_to_der_rsa_priv(const uint8_t *pem, size_t pem_len, uint8_t **der,
        size_t *der_len)
{
    int error = 0;
    RSA *rsa = NULL;
    BIO *bio = NULL;

    RHO_TRACE_ENTER();

    bio = BIO_new_mem_buf(pem, pem_len);
    rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (rsa == NULL) {
        nsm_openssl_warn("%s: PEM_read_bio_RSAPrivateKey", __func__);
        error = -1;
        goto done;
    }

    error = nsm_rsa_priv_to_der(rsa, der, der_len);

done:
    BIO_free(bio);
    RSA_free(rsa);

    RHO_TRACE_EXIT();
    return (error);
}

int
nsm_der_to_pem_rsa_priv(const uint8_t *der, size_t der_len, uint8_t **pem,
        size_t *pem_len)
{
    int error = 0;
    RSA *rsa = NULL;
    const unsigned char *tmp = NULL;
    BIO *bio = NULL;
    char *p = NULL;
    long len = 0;

    RHO_TRACE_ENTER();

    tmp = der;
    rsa = d2i_RSAPrivateKey(NULL, &tmp, der_len);
    if (rsa == NULL) {
        nsm_openssl_warn("%s: d2i_RSAPrivateKey", __func__);
        error = -1;
        goto done;
    } 

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        nsm_openssl_warn("%s: BIO_new", __func__);
        error = -1;
        goto done;
    }

    //BIO_set_close(BIO_no_close);  -- would this avoid need to copy mem? */
    error = PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    if (error != 1) {
        nsm_openssl_warn("%s: PEM_write_bio_RSAPrivateKey", __func__);
        error = -1;
        goto done;

    }

    len = BIO_get_mem_data(bio, &p);
    *pem = rhoL_memdup(p, len);
    *pem_len = len;
    error = 0;

done:
    if (bio != NULL)
     BIO_free(bio);

    RHO_TRACE_EXIT();
    return (error);
}

/**********************************************************
 * PACKING/UNPACKING OPENSSL OBJECTS
 *********************************************************/
void
nsm_pack_bignum(struct rho_buf *buf, BIGNUM *b)
{
    int n = 0;
    unsigned char * data = NULL;

    RHO_TRACE_ENTER();

    n = BN_num_bytes(b);
    data = rhoL_zalloc(n);
    BN_bn2bin(b, data);
    rho_buf_write_u32size_blob(buf, data, n);
    rhoL_free(data);

    RHO_TRACE_EXIT();
}

int
nsm_unpack_bignum(struct rho_buf *buf, BIGNUM *b)
{
    int error = 0;
    uint32_t len = 0;
    const unsigned char *bin = NULL;
    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &len);
    if (error == -1)
        goto done;

    bin = rho_buf_raw(buf, 0, SEEK_CUR);
    BN_bin2bn(bin,(int)len,b);
    rho_buf_seek(buf, len, SEEK_CUR);

done:
    RHO_TRACE_EXIT();
    return (error);
}

void
nsm_pack_rsa_pub(struct rho_buf *buf, RSA *rsa)
{
    int der_size_est = 0;
    int der_size_real = 0;
    unsigned char *der = NULL;
    unsigned char *tmp = NULL;

    RHO_TRACE_ENTER();


    der_size_est = i2d_RSAPublicKey(rsa, NULL);
    rho_debug("der_size_est=%d", der_size_est);
    der = rhoL_malloc(der_size_est);

    tmp = der;
    der_size_real = i2d_RSAPublicKey(rsa, &tmp);
    if (der_size_real < 0)
        nsm_openssl_warn("i2d_RSAPublicKey");
    rho_debug("der_size_real=%d", der_size_real);
    rho_hexdump(der, der_size_real, "der");

    rho_buf_write_u32size_blob(buf, der, der_size_real);
    rhoL_free(der);

    RHO_TRACE_EXIT();
    return;
}

int
nsm_unpack_rsa_pub(struct rho_buf *buf, RSA *rsa)
{
    int error = 0;
    uint32_t der_size = 0;
    unsigned char *der = NULL;
    const unsigned char *tmp = NULL;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &der_size);
    if (error == -1)
        goto done;

    if (rho_buf_left(buf) < der_size) {
        error = -1;
        rho_warn("want %"PRIu32" bytes of der payload, but only %zu bytes left\n",
                der_size, rho_buf_left(buf));
        goto done;
    }

    rho_debug("der_size is %"PRIu32, der_size);
    der = rhoL_zalloc(der_size);
    rho_buf_read(buf, der, der_size);
    rho_hexdump(der, der_size, "der");

    tmp = der;
    if (d2i_RSAPublicKey(&rsa, &tmp, der_size) == NULL)
        nsm_openssl_warn("d2i_RSAPublicKey");

    rhoL_free(der);

done:
    RHO_TRACE_EXIT();
    return (error);
}

void
nsm_pack_rsa_priv(struct rho_buf *buf, RSA *rsa)
{
    unsigned char *der = NULL;
    size_t der_len = 0;

    RHO_TRACE_ENTER();

    (void)nsm_rsa_priv_to_der(rsa, &der, &der_len);
    rho_buf_write_u32size_blob(buf, der, der_len);
    rhoL_free(der);

    RHO_TRACE_EXIT();
    return;
}

int
nsm_unpack_rsa_priv(struct rho_buf *buf, RSA *rsa)
{
    int error = 0;
    uint32_t der_size = 0;
    unsigned char *der = NULL;
    const unsigned char *tmp = NULL;


    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &der_size);
    if (error == -1)
        goto done;

    if (rho_buf_left(buf) < der_size) {
        error = -1;
        rho_warn("want read %"PRIu32" bytes of der payload, but only %zu bytes left\n",
                der_size, rho_buf_left(buf));
        goto done;
    }

    rho_debug("der_size is %"PRIu32, der_size);
    der = rhoL_zalloc(der_size);
    rho_buf_read(buf, der, der_size);
    rho_hexdump(der, der_size, "der");

    tmp = der;
    if (d2i_RSAPrivateKey(&rsa, &tmp, der_size) == NULL) {
        nsm_openssl_warn("d2i_RSAPrivateKey");
    }

    rhoL_free(der);

done:
    RHO_TRACE_EXIT();
    return (error);
}
