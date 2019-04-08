#ifndef _NSM_UTIL_H_
#define _NSM_UTIL_H_

#include <stddef.h>
#include <stdint.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <rho/rho_decls.h>
#include <rho/rho_buf.h>

RHO_DECLS_BEGIN

void nsm_openssl_init(void);

void nsm_openssl_warn(const char *fmt, ...);
void nsm_openssl_die(const char *fmt, ...);

RSA * nsm_genrsa(int mod, int e);

int nsm_rsa_priv_to_der(RSA *rsa, uint8_t **der, size_t *der_len);
int nsm_pem_to_der_rsa_priv(const uint8_t *pem, size_t pem_len, uint8_t **der,
        size_t *der_len);
int nsm_der_to_pem_rsa_priv(const uint8_t *der, size_t der_len, uint8_t **pem,
        size_t *pem_len);

void nsm_pack_bignum(struct rho_buf *buf, BIGNUM *b);
int nsm_unpack_bignum(struct rho_buf *buf, BIGNUM *b);
void nsm_pack_rsa_pub(struct rho_buf *buf, RSA *rsa);
int nsm_unpack_rsa_pub(struct rho_buf *buf, RSA *rsa);
void nsm_pack_rsa_priv(struct rho_buf *buf, RSA *rsa);
int nsm_unpack_rsa_priv(struct rho_buf *buf, RSA *rsa);

RHO_DECLS_END

#endif /* _NSM_UTIL_H_ */
