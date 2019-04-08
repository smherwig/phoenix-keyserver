#include <sys/types.h>

#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <rho/rho_array.h>
#include <rho/rho_log.h>
#include <rho/rho_mem.h>
#include <rho/rho_rand.h>
#include <rho/rho_str.h>
#include <rho/rho_tree.h>
#include <rho/rho_url.h>

#include <rpc.h>

#include <nsm.h>
#include <nsm_util.h>

/* OpenSSL usually returns 1 for success and 0 for failure */

/**********************************************************
 * DEFINES
 **********************************************************/
#define NSM_ENGINE_ID   "nsm-engine"
#define NSM_ENGINE_NAME "nsm-engine - network security module engine"

/* OpenSSL ctrls */
#define NSM_ENGINE_CMD_SERVER   ENGINE_CMD_BASE

/**********************************************************
 * TYPES
 **********************************************************/
struct nsm_client {
    struct rpc_agent   *cli_agent;
    pid_t               cli_pid;
    int                 cli_refcnt;
};

RHO_ARRAY_DECLARE(nsm_client_array, struct nsm_client *); 

/*
 * Each RSA key has a pointer to one of these structs as application data.
 */
struct nsm_key_conns {
    const char *kc_url;
    struct nsm_client_array *kc_client_array;
};

/*
 * MAPS IPPORT to an nsm_client
 */

struct nsm_conn_entry {
    const char  *ce_conn_id;        /* id = pid:ip:port */
    struct nsm_client  *ce_client; /* value */
    RHO_RB_ENTRY(nsm_conn_entry) ce_entry;
};

RHO_RB_HEAD(nsm_conn_tree, nsm_conn_entry);

/**********************************************************
 * FORWARD DECLARATIONS
 **********************************************************/
static EVP_PKEY * nsm_load_private_key(ENGINE *e, const char *key_id,
        UI_METHOD *ui_method, void *callback_data);

static int nsm_rsa_init(RSA *rsa);
static int nsm_rsa_finish(RSA *rsa);

static int nsm_rsa_priv_enc(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding);

static int nsm_rsa_priv_dec(int flen, const unsigned char *from,
        unsigned char *to, RSA *rs, int padding);

static int nsm_rsa_sign(int type, const unsigned char *m, unsigned int m_length,
        unsigned char *sigret, unsigned int *siglen, const RSA *rsa);

static int nsm_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

static int nsm_engine_init(ENGINE *e);
static int nsm_engine_finish(ENGINE *e);
static int nsm_engine_ctrl(ENGINE *e, int cmd, long i, void *p,
        void (*f)(void));

static int nsm_engine_bind(ENGINE *e, const char *id);

/**********************************************************
 * GLOBALS
 **********************************************************/
static const ENGINE_CMD_DEFN nsm_engine_cmd_defns[] = {
    { 
        NSM_ENGINE_CMD_SERVER, 
        "NSM_SERVER",
        "url for nsmserver (e.g., tcp://127.0.0.1:9000)",
        ENGINE_CMD_FLAG_STRING
    },

    {0, NULL, NULL, 0}
};

static bool g_nsm_inited = false;
static char *g_nsm_default_url = NULL;
static int g_nsm_data_idx = -1;
struct nsm_conn_tree g_nsm_conn_tree_root = RHO_RB_INITIALIZER(&g_nsm_conn_tree_root);

/**********************************************************
 * GLOBALS
 *
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes
 *
 * https://wiki.openssl.org/images/e/ed/Openssl-compat.tar.gz
 **********************************************************/
#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <string.h>
#include <openssl/engine.h>

static void *OPENSSL_zalloc(size_t num)
{
    void *ret = OPENSSL_malloc(num);

    if (ret != NULL)
        memset(ret, 0, num);
    return ret;
}

static RSA_METHOD *
RSA_meth_new(const char *name, int flags)
{
    RSA_METHOD *meth = OPENSSL_zalloc(sizeof(*meth));

    if (meth != NULL) {
        meth->flags = flags;

        meth->name = OPENSSL_strdup(name);
        if (meth->name != NULL)
            return (meth);

        OPENSSL_free(meth);
    }

    return (NULL);
}

#if 0
static RSA_METHOD *
RSA_meth_dup(const RSA_METHOD *meth)
{
    RSA_METHOD *ret;

    ret = OPENSSL_malloc(sizeof(RSA_METHOD));

    if (ret != NULL) {
        memcpy(ret, meth, sizeof(*meth));
        ret->name = OPENSSL_strdup(meth->name);
        if (ret->name == NULL) {
            OPENSSL_free(ret);
            return NULL;
        }
    }

    return ret;
}
#endif

static int
RSA_meth_set_init(RSA_METHOD *meth, int (*init) (RSA *rsa))
{
    meth->init = init;
    return 1;
}

static int
RSA_meth_set_finish(RSA_METHOD *meth, int (*finish) (RSA *rsa))
{
    meth->finish = finish;
    return 1;
}


static int
(*RSA_meth_get_mod_exp(const RSA_METHOD *meth))
        (BIGNUM *r0, const BIGNUM *i, RSA *rsa, BN_CTX *ctx)
{
    return meth->rsa_mod_exp;
}

static int
RSA_meth_set_mod_exp(RSA_METHOD *meth,
        int (*mod_exp) (BIGNUM *r0, const BIGNUM *i, RSA *rsa, BN_CTX *ctx))
{
    meth->rsa_mod_exp = mod_exp;
    return 1;
}

static int
(*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))
    (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    return meth->bn_mod_exp;
}

static int
RSA_meth_set_bn_mod_exp(RSA_METHOD *meth,
        int (*bn_mod_exp) (BIGNUM *r,
            const BIGNUM *a,
            const BIGNUM *p,
            const BIGNUM *m,
            BN_CTX *ctx,
            BN_MONT_CTX *m_ctx))
{
    meth->bn_mod_exp = bn_mod_exp;
    return 1;
}

static int
RSA_meth_set_priv_enc(RSA_METHOD *meth,
        int (*priv_enc) (int flen, const unsigned char *from,
            unsigned char *to, RSA *rsa, int padding))
{
    meth->rsa_priv_enc = priv_enc;
    return 1;
}

static int
RSA_meth_set_priv_dec(RSA_METHOD *meth,
        int (*priv_dec) (int flen, const unsigned char *from,
            unsigned char *to, RSA *rsa, int padding))
{
    meth->rsa_priv_dec = priv_dec;
    return 1;
}

static int 
(*RSA_meth_get_pub_enc(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding)
{
    return meth->rsa_pub_enc;
}

static int
RSA_meth_set_pub_enc(RSA_METHOD *meth,
        int (*pub_enc)(int flen, const unsigned char *from,
            unsigned char *to, RSA *rsa, int padding))
{
    meth->rsa_pub_enc = pub_enc;
    return 1;
}

static int
(*RSA_meth_get_pub_dec(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding)
{
    return meth->rsa_pub_dec;
}

static int
RSA_meth_set_pub_dec(RSA_METHOD *meth,
        int (*pub_dec) (int flen, const unsigned char *from,
            unsigned char *to, RSA *ra, int padding))
{
    meth->rsa_pub_dec = pub_dec;
    return 1;
}

static int
RSA_meth_set_sign(RSA_METHOD *meth,
        int (*sign) (int type, const unsigned char *m,
            unsigned int m_length, unsigned char *sigret, unsigned int *siglen,
            const RSA *rsa))
{
    meth->rsa_sign = sign;
    return 1;
}

static int
(*RSA_meth_get_verify(const RSA_METHOD *meth))
    (int dtype, const unsigned char *m,
     unsigned int m_length, const unsigned char *sigbuf,
     unsigned int siglen, const RSA *rsa)
{
    return meth->rsa_verify;
}

static int
RSA_meth_set_verify(RSA_METHOD *meth,
        int (*verify)(int dtype, const unsigned char *m,
            unsigned int m_length, const unsigned char *sigbuf,
            unsigned int siglen, const RSA *rsa))
{
    meth->rsa_verify = verify;
    return 1;
}

static int
RSA_meth_set_keygen(RSA_METHOD *meth,
        int (*keygen) (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb))
{
    meth->rsa_keygen = keygen;
    return 1;
}

#if 0
static void
RSA_meth_free(RSA_METHOD *meth)
{
    if (meth != NULL) {
        OPENSSL_free((char *)meth->name);
        OPENSSL_free(meth);
    }
}
#endif

int RSA_bits(const RSA *r)
{
    return (BN_num_bits(r->n));
}

static RSA *
EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_RSA) {
        return NULL;
    }
    return pkey->pkey.rsa;
}
#endif /* OPENSSL_VERSION_NUMBER */


/**********************************************************
 * NSM CLIENT
 **********************************************************/

static struct nsm_client *
nsm_client_create(const char *url)
{
    struct nsm_client *client = NULL;
    struct rho_sock *sock = NULL;

    RHO_TRACE_ENTER("url=\"%s\"", url);

    sock = rho_sock_from_url(url);
    rho_sock_connect_url(sock, url);

    client = rhoL_zalloc(sizeof(*client));
    client->cli_agent = rpc_agent_create(sock, NULL);
    client->cli_pid = getpid();
    client->cli_refcnt = 1;

    RHO_TRACE_EXIT("pid=%lu", (unsigned long)client->cli_pid);
    return (client);
}

#if 0
static void
nsm_client_destroy(struct nsm_client *client)
{
    struct rpc_agent *agent = client->cli_agent;

    RHO_TRACE_ENTER();

    rpc_agent_destroy(agent);
    rhoL_free(client);

    RHO_TRACE_EXIT();
}
#endif

/**********************************************************
 * NSM CLIENT ARRAY
 **********************************************************/
static struct nsm_client_array *
nsm_client_array_create(void)
{
    struct nsm_client_array *array = NULL;

    RHO_TRACE_ENTER();

    RHO_ARRAY_ALLOC_INIT(array, struct nsm_client);

    RHO_TRACE_EXIT();
    return (array);
}

static struct nsm_client *
nsm_client_array_find(struct nsm_client_array *array)
{
    struct nsm_client *client = NULL;
    size_t i = 0;
    bool found = false;

    RHO_ASSERT(array != NULL);

    RHO_TRACE_ENTER("array size = %zu, pid=%lu",
            RHO_ARRAY_SIZE(array), (unsigned long)getpid());

    for (i = 0; i < RHO_ARRAY_SIZE(array); i++) {
        RHO_ARRAY_GET(client, array, i);
        rho_debug("array[%zu] = client {pid=%lu}",
                i, (unsigned long)client->cli_pid);
        if (client->cli_pid == getpid()) {
            rho_debug("found client");
            found = true;
            break;
        }
    }

    if (!found) {
        rho_debug("client not found");
        client = NULL;
    }
    
    RHO_TRACE_EXIT();
    return (client);
}

/**********************************************************
 * NSM KEY CONNS
 **********************************************************/
struct nsm_key_conns *
nsm_key_conns_create(const char *url)
{
    struct nsm_key_conns *conns = NULL;

    conns = rhoL_zalloc(sizeof(*conns));
    conns->kc_client_array = nsm_client_array_create();
    conns->kc_url = rhoL_strdup(url);

    return (conns);
}

/**********************************************************
 * CONN ID
 **********************************************************/
static char *
nsm_make_conn_id(const char *ip, const char *port)
{
    char *conn_id = NULL;
    pid_t pid = 0;

    RHO_TRACE_ENTER();

    pid = getpid();
    conn_id = rho_str_sprintf("%lu:%s:%s", pid, ip, port);

    RHO_TRACE_ENTER();
    return (conn_id);
}

static const char *
nsm_make_conn_id_from_url(const char *url)
{
    char *conn_id = NULL;
    struct rho_url *purl = NULL;

    RHO_TRACE_ENTER();

    purl = rho_url_parse(url);
    conn_id = nsm_make_conn_id(purl->host, purl->port);
    rhoL_free(purl);

    RHO_TRACE_ENTER();
    return (conn_id);
}

/**********************************************************
 * NSM_CONN_ENTRY
 **********************************************************/
static struct nsm_conn_entry *
nsm_conn_entry_create(const char *conn_id, struct nsm_client *client)
{
    struct nsm_conn_entry *entry = NULL;
    
    RHO_TRACE_ENTER();

    entry = rhoL_zalloc(sizeof(*entry));
    entry->ce_conn_id = rhoL_strdup(conn_id);
    entry->ce_client = client;

    RHO_TRACE_EXIT();
    return (entry);
}

/**********************************************************
 * NSM CONN TREE
 **********************************************************/
static int
nsm_conn_entry_cmp(struct nsm_conn_entry *a, struct nsm_conn_entry *b)
{
    return (strcmp(a->ce_conn_id, b->ce_conn_id));
}

RHO_RB_GENERATE_STATIC(nsm_conn_tree, nsm_conn_entry, ce_entry,
        nsm_conn_entry_cmp);

static struct nsm_conn_entry *
nsm_conn_tree_find(const char *conn_id)
{
    struct nsm_conn_entry key;
    struct nsm_conn_entry *entry = NULL;

    RHO_TRACE_ENTER();
    
    key.ce_conn_id = conn_id;
    entry = RHO_RB_FIND(nsm_conn_tree, &g_nsm_conn_tree_root, &key);

    RHO_TRACE_EXIT("entry=%p", entry);
    return (entry);
}

/**********************************************************
 * UTILITIES
 **********************************************************/
static struct nsm_client *
nsm_url_to_client(const char *url)
{
    struct rho_url *purl = NULL;
    struct nsm_client *client = NULL;
    struct nsm_conn_entry *entry = NULL;
    char *conn_id = NULL;

    RHO_TRACE_ENTER();

    purl = rho_url_parse(url);
    conn_id = nsm_make_conn_id(purl->host, purl->port);
    rho_debug("searching for conn with id=\"%s\"", conn_id);
    entry = nsm_conn_tree_find(conn_id);

    if (entry != NULL) {
        rho_debug("found existing conn for id=\"%s\"", conn_id);
        client = entry->ce_client;
    } else {
        rho_debug("creating new conn for id=\"%s\"", conn_id);
        client = nsm_client_create(url);
        entry = nsm_conn_entry_create(conn_id, client);
        RHO_RB_INSERT(nsm_conn_tree, &g_nsm_conn_tree_root, entry);
    }

    rhoL_free(purl);
    rhoL_free(conn_id);

    RHO_TRACE_EXIT();
    return (client);
}

static struct nsm_client *
nsm_rsa_to_client(const RSA *rsa)
{
    struct nsm_client * client = NULL;
    struct nsm_key_conns *conns = NULL;
    struct nsm_conn_entry *entry = NULL;
    const char *conn_id = NULL;

    conns = RSA_get_ex_data(rsa, g_nsm_data_idx);
    if (conns == NULL) {
        nsm_openssl_warn("RSA_get_ex_data failed(idx=%d)\n", g_nsm_data_idx);
        /* TODO: what error should we return? */
        goto done;
    }

    client = nsm_client_array_find(conns->kc_client_array);
    if (client == NULL) {
        client = nsm_url_to_client(conns->kc_url);
        if (client == NULL) {
            client = nsm_client_create(conns->kc_url);
            conn_id = nsm_make_conn_id_from_url(conns->kc_url);
            entry = nsm_conn_entry_create(conn_id, client);
            RHO_RB_INSERT(nsm_conn_tree, &g_nsm_conn_tree_root, entry);
        }
        RHO_ARRAY_INSERT(conns->kc_client_array, 0, client);
    }

done:
    return (client);
}

/**********************************************************
 * KEY LOADING METHODS
 **********************************************************/
static EVP_PKEY *
nsm_load_private_key(ENGINE *e, const char *key_id, UI_METHOD *ui_method,
        void *cbdata)
{
    int error = 0;
    struct rho_url *purl = NULL;
    struct nsm_key_conns *conns = NULL;
    struct nsm_client *client = NULL;
    struct rpc_agent *agent = NULL ;
    struct rho_buf *buf = NULL;
    struct rpc_hdr *hdr = NULL;
    uint8_t *der = NULL;
    uint32_t der_len = 0;
    uint8_t *pem = NULL;
    size_t pem_len = 0;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;

    RHO_TRACE_ENTER("key_id=\"%s\"", key_id);

    (void)e;
    (void)ui_method;
    (void)cbdata;

    purl = rho_url_parse(key_id); 
    if (purl == NULL) {
        rho_warn("rho_url_parse(\"%s\") failed", key_id);
        goto done;
    }
    
    rho_debug("url: scheme=\"%s\", host=\"%s\", port=\"%s\", path=\"%s\"",
            purl->scheme, purl->host, purl->port, purl->path);

    client = nsm_url_to_client(key_id);
    agent = client->cli_agent;
    buf = agent->ra_bodybuf;
    hdr = &agent->ra_hdr;

    rpc_agent_new_msg(agent, NSM_OP_LOAD_PRIVATE_KEY);
    rho_buf_write_u32size_str(buf, purl->path);
    rpc_agent_autoset_bodylen(agent);

    /* make request */
    error = rpc_agent_request(agent);
    if (error != 0) {
        /* RPC/transport error */
        goto done;
    }

    if (hdr->rh_code != 0) {
        /* method error */
        goto done;
    }

    rho_buf_readu32be(buf, &der_len);
    rho_debug("der_len=%"PRIu32, der_len);
    der = rho_buf_raw(buf, 0, SEEK_CUR);

    nsm_der_to_pem_rsa_priv(der, der_len, &pem, &pem_len);
    bio = BIO_new_mem_buf(pem, pem_len);
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        nsm_openssl_warn("PEM_read_bio_PrivateKey failed");
    }

    rsa = EVP_PKEY_get0_RSA(pkey);
    if (rsa == NULL) {
        nsm_openssl_warn("EVP_PKEY_get0_RSA failed");
    }

    conns = nsm_key_conns_create(key_id);
    RHO_ARRAY_INSERT(conns->kc_client_array, 0, client);
    RSA_set_ex_data(rsa, g_nsm_data_idx, conns);

done:
    if (bio != NULL)
        BIO_free(bio);
    if (pem != NULL)
        rhoL_free(pem);
    if (purl)
        rhoL_free(purl);

    RHO_TRACE_EXIT();
    return (pkey);
}

/**********************************************************
 * RSA METHODS
 **********************************************************/
static int
nsm_rsa_init(RSA *rsa)
{
    RHO_TRACE_ENTER();

#ifdef NSM_DO_BENCH
    struct nsm_client *client = NULL;
    uint64_t key_id = 0;
    char *url = NULL;
    struct nsm_key_conns *conns = NULL;

    client = nsm_url_to_client(g_nsm_default_url);
    key_id = rho_rand_u64();
    url = rho_str_sprintf("%s/%"PRIx64, g_nsm_default_url, key_id);
    conns = nsm_key_conns_create(url);
    RHO_ARRAY_INSERT(conns->kc_client_array, 0, client);
    RSA_set_ex_data(rsa, g_nsm_data_idx, conns);
    rhoL_free(url);
#else
    (void)rsa;
#endif

    RHO_TRACE_EXIT();
    return (1);
}

/* called at free */
static int
nsm_rsa_finish(RSA *rsa)
{
    RHO_TRACE_ENTER();
    (void)rsa;
    RHO_TRACE_EXIT();
    return (1);
}

static int
nsm_rsa_cipher_proxy(int rpc_opcode, int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding)
{
    int error = 0;
    struct nsm_client *client = NULL;
    struct rpc_agent *agent = NULL;
    struct rho_buf *buf = NULL;
    struct rpc_hdr *hdr = NULL;
    size_t tlen = 0;

    RHO_TRACE_ENTER();

    client = nsm_rsa_to_client(rsa);

    agent = client->cli_agent;
    buf = agent->ra_bodybuf;
    hdr = &agent->ra_hdr;

    rho_debug("padding=%d", padding);

    /*  build request */
    rpc_agent_new_msg(agent, rpc_opcode);
    nsm_pack_rsa_priv(buf, rsa);
    rho_buf_write_u32size_blob(buf, from, flen);
    rho_buf_writeu32be(buf, padding);
    rpc_agent_autoset_bodylen(agent);

    /* make request */
    error = rpc_agent_request(agent);
    if (error != 0) {
        /* RPC/transport error */
        goto done;
    }

    if (hdr->rh_code != 0) {
        /* method error */
        goto done;
    }

    if (to == NULL)
        rho_debug("`to' is NULL");

    /* XXX: how do we know how big `to' is? */
    rho_buf_read_u32size_blob(buf, to, 256, &tlen);
    rho_debug("tlen=%zu", tlen);

    error = (int)tlen;

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
nsm_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
        RSA *rsa, int padding)
{
    int error = 0;

    RHO_TRACE_ENTER();

    error = nsm_rsa_cipher_proxy(NSM_OP_RSA_PRIV_ENC, flen, from, to, rsa,
            padding);

    RHO_TRACE_EXIT();
    return (error);
}

static int
nsm_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to,
        RSA *rsa, int padding)
{
    int error = 0;

    RHO_TRACE_ENTER();

    error = nsm_rsa_cipher_proxy(NSM_OP_RSA_PRIV_DEC, flen, from, to, rsa,
            padding);

    RHO_TRACE_EXIT();
    return (error);
}

static int
nsm_rsa_sign(int type, const unsigned char *m, unsigned int m_length,
        unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    int error = 0;
    struct nsm_client *client = NULL;
    struct rpc_agent *agent = NULL;
    struct rho_buf *buf = NULL;
    struct rpc_hdr *hdr = NULL;

    RHO_TRACE_ENTER();                 

    client = nsm_rsa_to_client(rsa);

    agent = client->cli_agent;
    buf = agent->ra_bodybuf;
    hdr = &agent->ra_hdr;

    rpc_agent_new_msg(agent, NSM_OP_RSA_SIGN);
    rho_buf_writeu32be(buf, (uint32_t)type);
    rho_buf_write_u32size_blob(buf, m, m_length);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error == -1) {
        rho_warn("rpc_agent_request returned %d", error);
        error = 0;
        goto done;
    }

    if (hdr->rh_code != 0) {
        error = 0;
        rho_warn("rh_code=%d", hdr->rh_code);
        /* TODO: set openssl error queue */
        goto done;
    }
    
    rho_buf_read_u32size_blob(buf, sigret, RSA_size(rsa), (size_t *)siglen); 

    error = 1;

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
nsm_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    int error = 0;
    struct nsm_client *client = NULL;
    struct rpc_agent *agent = NULL;
    struct rho_buf *buf = NULL;
    struct rpc_hdr *hdr = NULL;
    uint64_t key_id = 0;
    char *url = NULL;
    struct nsm_key_conns *conns = NULL;

    RHO_TRACE_ENTER();                 

    /* TODO: figure out how we call this */
    (void)cb;

    if (g_nsm_default_url == NULL) {
        rho_warn("default nsm url not set\n");
        goto done;
    }

    client = nsm_url_to_client(g_nsm_default_url);
    agent = client->cli_agent;
    buf = agent->ra_bodybuf;
    hdr = &agent->ra_hdr;

    rpc_agent_new_msg(agent, NSM_OP_RSA_KEYGEN);
    rho_buf_writeu32be(buf, bits);
    nsm_pack_bignum(buf, e);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error == -1) {
        rho_warn("rpc_agent_request returned %d", error);
        error = 0;
        goto done;
    }

    if (hdr->rh_code != 0) {
        error = 0;
        rho_warn("rh_code=%d", hdr->rh_code);
        /* TODO: set openssl error queue */
        goto done;
    }

    if (rsa == NULL)
        rho_debug("rsa is NULL");


    rho_buf_readu64be(buf, &key_id);
    rho_debug("got key_id=%"PRIx64, key_id);
    nsm_unpack_rsa_pub(buf, rsa);
    nsm_unpack_rsa_priv(buf, rsa);

    url = rho_str_sprintf("%s/%"PRIx64, g_nsm_default_url, key_id);
    conns = nsm_key_conns_create(url);
    RHO_ARRAY_INSERT(conns->kc_client_array, 0, client);
    RSA_set_ex_data(rsa, g_nsm_data_idx, conns);
    rhoL_free(url);

    error = 1;
    
done:
    RHO_TRACE_EXIT();
    return (error);
}

/**********************************************************
 * ENGINE METHODS
 **********************************************************/
static int
nsm_engine_set_rsa_method(ENGINE *e)
{
    /* perhaps make this a static global */
    RSA_METHOD *meth = NULL;
    const RSA_METHOD *def = NULL;

    /* TODO: all return 1 on success; check return value */

    meth = RSA_meth_new("nsm RSA metho", RSA_METHOD_FLAG_NO_CHECK);
    RSA_meth_set_init(meth, nsm_rsa_init);
    RSA_meth_set_finish(meth, nsm_rsa_finish);
    RSA_meth_set_priv_enc(meth, nsm_rsa_priv_enc);
    RSA_meth_set_priv_dec(meth, nsm_rsa_priv_dec);
    RSA_meth_set_sign(meth, nsm_rsa_sign);
    RSA_meth_set_keygen(meth, nsm_rsa_keygen);


    /* 
     * use OpenSSL's defaults for the public key functions.
     * I believe RSA_get_default_method() and RSA_PKCS1_SSLeay()
     * are equivalent.
     */
    def = RSA_PKCS1_SSLeay();
    RSA_meth_set_mod_exp(meth, RSA_meth_get_mod_exp(def));
    RSA_meth_set_bn_mod_exp(meth, RSA_meth_get_bn_mod_exp(def));
    RSA_meth_set_pub_enc(meth, RSA_meth_get_pub_enc(def));
    RSA_meth_set_pub_dec(meth, RSA_meth_get_pub_dec(def));
    RSA_meth_set_verify(meth, RSA_meth_get_verify(def)); 

    if (!ENGINE_set_RSA(e, meth))
        rho_warn("ENGINE_set_RSA for engine id=\"%s\" failed", NSM_ENGINE_ID);

    return (1);
}

/* 
 * TODO: I don't understand when this gets called.
 */
static int
nsm_engine_init(ENGINE *e)
{
    RHO_TRACE_ENTER();

    (void)e;

    if (g_nsm_inited)
        goto done;

    g_nsm_data_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (g_nsm_data_idx == -1) {
        nsm_openssl_warn("RSA_get_ex_new_data failed");
        /* TODO: what should this function return to indicate failure? */
    }

    rho_debug("set g_nsm_data_idx to %d\n", g_nsm_data_idx);
    g_nsm_inited = true;

done:
    RHO_TRACE_EXIT();
    return (1);
}

static int
nsm_engine_finish(ENGINE *e)
{
    RHO_TRACE_ENTER();

    (void)e;

#if 0
    if (g_nsm_client != NULL)
        nsm_client_destroy(g_nsm_client);
#endif

    RHO_TRACE_EXIT();
    return (1);
}

static int
nsm_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    RHO_TRACE_ENTER();

    (void)e;
    (void)i;
    (void)p;
    (void)f;

    switch (cmd) {
    case NSM_ENGINE_CMD_SERVER:
        rho_debug("setting default NSM url to \"%s\"", (char *)p);
        g_nsm_default_url = rhoL_strdup(p);
        return (1);
    default:
        break;
    };

    RHO_TRACE_EXIT();
    return (0);
}

static int
nsm_engine_bind(ENGINE *e, const char *id)
{
    int error = 0;

    RHO_TRACE_ENTER();

    if ((id != NULL) && (rho_str_equal(id, NSM_ENGINE_ID))) {
        rho_warn("engine \"%s\" already registered", NSM_ENGINE_ID);
        goto done;
    }
    
    if (!ENGINE_set_id(e, NSM_ENGINE_ID)) {
        rho_warn("ENGINE_set_id(\"%s\") failed", NSM_ENGINE_ID);
        goto done;
    }

    if (!ENGINE_set_name(e, NSM_ENGINE_NAME)) {
        rho_warn("ENGINE_set_name(\"%s\") failed", NSM_ENGINE_NAME);
        goto done;
    }

    if (!ENGINE_set_init_function(e, nsm_engine_init)) {
        rho_warn("ENGINE_set_init_function failed for engine id=\%s\"",
                NSM_ENGINE_ID);
        goto done;
    };

    if (!ENGINE_set_finish_function(e, nsm_engine_finish)) {
        rho_warn("ENGINE_set_finish_function failed for engine id=\%s\"",
                NSM_ENGINE_ID);
        goto done;
    }

    if (!ENGINE_set_cmd_defns(e, nsm_engine_cmd_defns)) {
        rho_warn("ENGINE_set_cmd_defns for engine id=\"%s\" failed",
                NSM_ENGINE_ID);
        goto done;
    }

    if (!ENGINE_set_ctrl_function(e, nsm_engine_ctrl)) {
        rho_warn("ENGINE_set_ctrl for engine id=\"%s\" failed", NSM_ENGINE_ID);
        goto done;
    }

    if (!ENGINE_set_load_privkey_function(e, nsm_load_private_key)) {
        rho_warn("ENGINE_set_load_privkey for engine id=\"%s\" failed",
                NSM_ENGINE_ID);
        goto done;
    }

    nsm_engine_set_rsa_method(e);

    error = 1;

done:
    RHO_TRACE_EXIT();
    return (error);
}

IMPLEMENT_DYNAMIC_BIND_FN(nsm_engine_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
