#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include <rho/rho.h>
#include <rpc.h>

#include <nsm.h>
#include <nsm_util.h>

#ifdef NSM_DO_BENCH
#include "testrsa.h"
#endif

/* 
 * TODO: 
 *  - seed random number generator? (RAND_seed?)
 *  - when can we destroy a key_entry?
 *  - if the same key is loaded twice, should the one or two
 *    key_entry's exist?
 */

/* 
 * NB:
 *  - keys are stored as pem on disk.  Currently,
 *    the rbtree and the rpcs operate on the der
 *    encoding, however.
 */

/**************************************
 * TYPES
 **************************************/

/*
 * Contains the real private key and the dummy private key
 * that is granted to the application.  When an application loads
 * a private key, the nsmserver returns generates and returns a
 * dummy key.  For subsequent RSA operations the application passes
 * along the dummy key as a sort of identifier.  Thus, the dummy private
 * key  is effectively a cookie
 *
 * The key_entrys are stored in  a red-black tree for fast lookup.
 */
struct nsm_key_entry {
    RSA *ke_rsa;
    uint8_t *ke_dummy_der;
    size_t ke_dummy_der_len;

    RHO_RB_ENTRY(nsm_key_entry) entry;
};

RHO_RB_HEAD(nsm_key_tree, nsm_key_entry);

typedef int (*nsm_rsa_cipher)(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding);

struct nsm_server {
    struct rho_sock *srv_sock;
    struct rho_ssl_ctx *srv_sc;
    /* TODO: don't hardcode 108 */
    uint8_t srv_udspath[108];
};

struct nsm_client {
    RHO_LIST_ENTRY(nsm_client) cli_next_client;
    struct rpc_agent *cli_agent;
    uint64_t cli_id;
    /* FOR testing only */
    RSA *cli_rsa;
};

/* 
 * defines struct nsm_client_list; 
 * (head of list of clients)
 */
RHO_LIST_HEAD(nsm_client_list, nsm_client); 

typedef void (*nsm_opcall)(struct nsm_client *client);

/**************************************
 * FORWARD DECLARATIONS
 **************************************/
static struct nsm_key_entry * nsm_key_entry_from_keyfile(const char *path);
static struct nsm_key_entry * nsm_key_entry_from_rsa(RSA *rsa);
#if 0
static void nsm_key_entry_destroy(struct nsm_key_entry *entry);
#endif

static int nsm_key_entry_cmp(struct nsm_key_entry *a, struct nsm_key_entry *b);

#ifndef NSM_DO_BENCH
static struct nsm_key_entry * nsm_key_tree_find(uint8_t *dummy_der,
        size_t der_len);
#endif

static void nsm_load_private_key(struct nsm_client *client);
static void nsm_rsa_keygen(struct nsm_client *client);
static void nsm_rsa_priv_enc(struct nsm_client *client);
static void nsm_rsa_priv_dec(struct nsm_client *client);
static void nsm_rsa_sign(struct nsm_client *client);
static void nsm_rsa_verify(struct nsm_client *client);

static void nsm_client_add(struct nsm_client *client);
#if 0
static struct nsm_client * nsm_client_find(uint64_t id);
#endif

static struct nsm_client * nsm_client_alloc(void);
static struct nsm_client * nsm_client_create(struct rho_sock *sock);
static void nsm_client_destroy(struct nsm_client *client);

static void nsm_client_dispatch_call(struct nsm_client *client);
static void nsm_client_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

static struct nsm_server * nsm_server_alloc(void);
static void nsm_server_destroy(struct nsm_server *server);
static void nsm_server_config_ssl(struct nsm_server *server,
        const char *cafile, const char *certfile, const char *keyfile);
static void nsm_server_socket_create(struct nsm_server *server,
        const char *url, bool anonymous);
static void nsm_server_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

static void nsm_log_init(const char *logfile, bool verbose);

static void usage(int exitcode);

/**************************************
 * GLOBALS
 **************************************/

struct rho_log *nsm_log = NULL;
const char *nsm_root = NULL;

struct nsm_client_list nsm_clients = 
        RHO_LIST_HEAD_INITIALIZER(nsm_clients);

struct nsm_key_tree nsm_key_tree_root = RHO_RB_INITIALIZER(&nsm_key_tree_root);

static nsm_opcall nsm_opcalls[] = {
    [NSM_OP_LOAD_PRIVATE_KEY]   = nsm_load_private_key,
    [NSM_OP_RSA_KEYGEN]         = nsm_rsa_keygen,
    [NSM_OP_RSA_PRIV_ENC]       = nsm_rsa_priv_enc,
    [NSM_OP_RSA_PRIV_DEC]       = nsm_rsa_priv_dec,
    [NSM_OP_RSA_SIGN]           = nsm_rsa_sign,
    [NSM_OP_RSA_VERIFY]         = nsm_rsa_verify
};

#ifdef NSM_DO_BENCH
static RSA *g_nsm_test_rsa2048 = NULL;
#endif

/************************************************************ 
 * NSM_KEY_ENTRY
 ************************************************************/
static struct nsm_key_entry *
nsm_key_entry_from_keyfile(const char *path)
{
    int error = 0;
    struct nsm_key_entry *entry = NULL;
    FILE *fp = NULL;
    RSA *rsa = NULL;
    RSA *dummy_rsa = NULL;
    uint8_t *der = NULL;
    size_t der_len = 0;
    char keypath[256] = { 0 };  /* FIXME */

    RHO_TRACE_ENTER();

    /* XXX: check for errors, bounds detection */
    if (nsm_root != NULL)
        rho_path_join(nsm_root, path, keypath, sizeof(keypath));
    else
        memcpy(keypath, path, strlen(path));

    rho_log_debug(nsm_log, "opening private key file: \"%s\"", keypath);

    fp = fopen(keypath, "rb");
    if (fp == NULL) {
        rho_errno_warn(errno, "fopen(\"%s\", \"rb\")", keypath);
        goto done;
    }

    rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if (rsa == NULL) {
        nsm_openssl_warn("PEM_read_RSAPrivateKey(\"%s\"", keypath);
        goto done;
    }

    dummy_rsa = nsm_genrsa(2048, 65537);
    error = nsm_rsa_priv_to_der(dummy_rsa, &der, &der_len);
    if (error != 0) {
        goto done;
    }

    entry = rhoL_zalloc(sizeof(*entry));
    entry->ke_rsa = rsa;
    entry->ke_dummy_der = der;
    entry->ke_dummy_der_len = der_len;

done:
    if (fp != NULL)
        (void)fclose(fp);
    if (dummy_rsa != NULL)
        RSA_free(dummy_rsa);

    RHO_TRACE_EXIT();
    return (entry);
}

static struct nsm_key_entry *
nsm_key_entry_from_rsa(RSA *rsa)
{
    int error = 0;
    struct nsm_key_entry *entry = NULL;
    RSA *dummy_rsa = NULL;
    uint8_t *der = NULL;
    size_t der_len = 0;

    RHO_TRACE_ENTER();

    dummy_rsa = nsm_genrsa(2048, 65537);
    error = nsm_rsa_priv_to_der(dummy_rsa, &der, &der_len);
    if (error != 0) {
        goto done;
    }

    entry = rhoL_zalloc(sizeof(*entry));
    entry->ke_rsa = rsa;
    entry->ke_dummy_der = der;
    entry->ke_dummy_der_len = der_len;

done:
    if (dummy_rsa != NULL)
        RSA_free(dummy_rsa);

    RHO_TRACE_EXIT();
    return (entry);
}

#if 0
static void
nsm_key_entry_destroy(struct nsm_key_entry *entry)
{
    RHO_TRACE_ENTER();

    RSA_free(entry->ke_rsa);
    rhoL_free(entry->ke_dummy_der);
    rhoL_free(entry);

    RHO_TRACE_EXIT();
}
#endif

/************************************************************ 
 * RED-BLACK TREE 
 * MAPS DUMMY PRIVATE KEY => REAL PRIVATE KEY
 ************************************************************/
static int
nsm_key_entry_cmp(struct nsm_key_entry *a, struct nsm_key_entry *b)
{
    return memcmp(a->ke_dummy_der, b->ke_dummy_der, 
            RHO_MIN(a->ke_dummy_der_len, b->ke_dummy_der_len));
}

RHO_RB_GENERATE_STATIC(nsm_key_tree, nsm_key_entry, entry, nsm_key_entry_cmp);

#ifndef NSM_DO_BENCH
static struct nsm_key_entry *
nsm_key_tree_find(uint8_t *dummy_der, size_t der_len)
{
    struct nsm_key_entry key;
    struct nsm_key_entry *entry = NULL;

    RHO_TRACE_ENTER();
    
    key.ke_dummy_der = rhoL_memdup(dummy_der, der_len);
    key.ke_dummy_der_len = der_len;
    entry = RHO_RB_FIND(nsm_key_tree, &nsm_key_tree_root, &key);
    rhoL_free(key.ke_dummy_der);

    RHO_TRACE_EXIT("entry=%p", entry);
    return (entry);
}
#endif

/**************************************
 * RSA RPCS
 **************************************/
static void
nsm_load_private_key(struct nsm_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char path[NSM_KEY_ID_MAX_SIZE + 1] = { 0 };
    struct nsm_key_entry *entry = NULL;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, path, sizeof(path));
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    rho_log_debug(nsm_log, "id=0x%"PRIx64" load_private_key(\"%s\")",
            client->cli_id, path);

    /* FIXME: we skip over the '/' */
    entry = nsm_key_entry_from_keyfile(path + 1);
    if (entry == NULL) {
        error = EPROTO;
        goto done;
    }

    RHO_RB_INSERT(nsm_key_tree, &nsm_key_tree_root, entry);

done:
    rpc_agent_new_msg(agent, error);
    if (!error) {
        rho_buf_write_u32size_blob(buf, entry->ke_dummy_der,
                entry->ke_dummy_der_len);
        rpc_agent_autoset_bodylen(agent);
        rho_debug("rh_bodylen=%"PRIu32, agent->ra_hdr.rh_bodylen);
    }

    RHO_TRACE_EXIT();
    return;
}

static void
nsm_rsa_keygen(struct nsm_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    int bits;
    BIGNUM *e = NULL;
    RSA *rsa = NULL;
    uint64_t key_id = 0;
    struct nsm_key_entry *entry = NULL;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, (uint32_t*)&bits);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    e = BN_new();
    error = nsm_unpack_bignum(buf, e);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, bits, e, NULL) != 1) {
        nsm_openssl_warn("RSA_generate_key_ex");
    }

    if (RSA_check_key(rsa) != 1) {
        nsm_openssl_warn("RSA_check_key");
    }

    rho_log_info(nsm_log, "nsm_rsa_keygen");
    client->cli_rsa = rsa;

    /*
     * TODO: persist the key to disk.
     */

    key_id = rho_rand_u64();
    rho_debug("generated key_id=%"PRIx64, key_id);
    entry = nsm_key_entry_from_rsa(rsa);
    RHO_RB_INSERT(nsm_key_tree, &nsm_key_tree_root, entry);

done:
    rpc_agent_new_msg(agent, error);
    if (!error) {
        rho_buf_writeu64be(buf, key_id); 
        nsm_pack_rsa_pub(buf, rsa);
        /* 
         * this is equivalent to pack_rsa_priv, but we use the
         * dummy key, instead
         */
        rho_buf_write_u32size_blob(buf, entry->ke_dummy_der,
                entry->ke_dummy_der_len);

        rpc_agent_autoset_bodylen(agent);
        rho_debug("rh_bodylen=%"PRIu32, agent->ra_hdr.rh_bodylen);
    }

    RHO_TRACE_EXIT(); 
    return;
}

static void
nsm_rsa_do_cipher(struct nsm_client *client, nsm_rsa_cipher cipher)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    unsigned char from[256] = { 0 };
    unsigned char to[256] = { 0 };
    unsigned char dummy_der[1200] = { 0 };  // XXX: don't assume 1200
    size_t dummy_der_len = 0;
    int flen = 0;
    int padding = 0;
    int tlen = 0;
    struct nsm_key_entry *entry = NULL;
    
    RHO_TRACE_ENTER();

    RHO_ASSERT(buf != NULL);

    error = rho_buf_read_u32size_blob(buf, &dummy_der, sizeof(dummy_der),
            &dummy_der_len);
    if (error == -1) {
        rho_warn("rho_buf_read_u32size_blob(der) failed");
        error = EPROTO;
        goto done;
    }

    rho_debug("dummy_der_len=%zu", dummy_der_len);

#ifdef NSM_DO_BENCH
    RHO_ASSERT(g_nsm_test_rsa2048 != NULL);
    entry = rhoL_zalloc(sizeof(*entry));
    entry->ke_rsa = g_nsm_test_rsa2048;
#else
    entry = nsm_key_tree_find(dummy_der, dummy_der_len);
    if (entry == NULL) {
        rho_warn("nsm_key_tree_find failed");
        error = EPROTO;
        goto done;
    }
#endif

    error = rho_buf_read_u32size_blob(buf, &from, sizeof(from),
            (size_t *)&flen);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    rho_debug("ngot=%d", flen);

    error = rho_buf_readu32be(buf, (uint32_t *)&padding);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    rho_debug("padding=%d\n", padding);

    tlen = cipher(flen, from, to, entry->ke_rsa, padding);
    if (tlen == -1) {
        nsm_openssl_warn("RSA cipher operation failed");
        error = EPROTO;
        goto done;
    }

done:
    rpc_agent_new_msg(agent, error);
    if (!error) { 
        rho_buf_write_u32size_blob(buf, to, tlen);
        rpc_agent_autoset_bodylen(agent);
    }
    RHO_TRACE_EXIT();
#ifdef NSM_DO_BENCH
    if (entry != NULL)
        rhoL_free(entry);
#endif
    return;
}

static void
nsm_rsa_priv_enc(struct nsm_client *client)
{
    RHO_TRACE_ENTER();

    rho_log_debug(nsm_log, "id=0x%"PRIx64" rsa_priv_enc()", client->cli_id);

    nsm_rsa_do_cipher(client, RSA_private_encrypt);

    RHO_TRACE_EXIT();
}

static void
nsm_rsa_priv_dec(struct nsm_client *client)
{
    RHO_TRACE_ENTER();

    rho_log_debug(nsm_log, "id=0x%"PRIx64" rsa_priv_dec()", client->cli_id);

    nsm_rsa_do_cipher(client, RSA_private_decrypt);
    RHO_TRACE_EXIT();
}

/*
 *  int
 *  RSA_sign(int type, unsigned char *m, unsigned int m_len,
 *           unsigned char *sigret, unsigned int *siglen, RSA *rsa);
 *
 *  signs the message digest of size m_len using the private key rsa as
 *  specifed in PCCS #1 v2.0.  It stores the signature in sigret
 *  and the signaure size in siglen.  sigret must point to RSA_size(rsa)
 *  bytes of memory.
 *
 *  type denostes the the digest algorith mtht was used to gerneate m:
 *  (e.g., NID_sha1, NID_md5).
 *
 *  returns 1 on success, 0 otherwise.  USe ERR_get_error().
 */
static void
nsm_rsa_sign(struct nsm_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    int type = 0;
    unsigned char m[256] = { 0 };
    unsigned int m_length;
    unsigned char sigret[256] = { 0 };
    unsigned int siglen = 0;

    RHO_TRACE_ENTER();

    rho_buf_readu32be(buf, (uint32_t*)&type);
    rho_buf_read_u32size_blob(buf, m, sizeof(m), (size_t *)&m_length);

    error = RSA_sign(type, m, m_length, sigret, &siglen, client->cli_rsa);
    if (error != 1)
        nsm_openssl_warn("RSA_sign");

    if (error == 1) {
        rpc_agent_new_msg(agent, 0);
        rho_buf_write_u32size_blob(buf, sigret, siglen);
        rpc_agent_autoset_bodylen(agent);
    } else {
        rpc_agent_new_msg(agent, EPROTO);
    }

    RHO_TRACE_EXIT();
}

/* 
 *  int
 *  RSA_verify(int type, unsigned char *m, unsigned int m_len,
 *      unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
 *
 *  verifies that signature signbu of size siglen matches a given
 *  message digest m of size mlen.  type denotes the message digest
 *  algorithm that was used to generate the signature.  rsa is the
 *  signer's public key.
 *
 *  returns 1 on success, 0 otherwise.  Use ERR_get_error().
 */
static void
nsm_rsa_verify(struct nsm_client *client)
{
    RHO_TRACE_ENTER();
    (void)client;
    RHO_TRACE_EXIT();
}

/**************************************
 * CLIENT
 **************************************/
static void
nsm_client_add(struct nsm_client *client)
{
    uint64_t id = 0;
    struct nsm_client *iter = NULL;

    RHO_TRACE_ENTER();

    /* find a unique client id */
    do {
again:
        id = rho_rand_u64();
        RHO_LIST_FOREACH(iter, &nsm_clients, cli_next_client) {
            if (iter->cli_id == id)
                goto again;
        }
        break;
    } while (1);

    client->cli_id = id;
    RHO_LIST_INSERT_HEAD(&nsm_clients, client, cli_next_client);

    RHO_TRACE_EXIT();
    return;
}

#if 0
static struct nsm_client *
nsm_client_find(uint64_t id)
{
    struct nsm_client *iter = NULL;

    RHO_TRACE_ENTER();

    RHO_LIST_FOREACH(iter, &nsm_clients, cli_next_client) {
        if (iter->cli_id == id)
            goto done;
    }

    iter = NULL;

done:
    RHO_TRACE_EXIT();
    return (iter);
}
#endif

/*********************************************************
 * CLIENT
 *********************************************************/
static struct nsm_client *
nsm_client_alloc(void)
{
    struct nsm_client *client = NULL;

    RHO_TRACE_ENTER();

    client = rhoL_zalloc(sizeof(*client));
    client->cli_agent = rpc_agent_create(NULL, NULL);

    RHO_TRACE_EXIT();
    return (client);
}

static struct nsm_client *
nsm_client_create(struct rho_sock *sock)
{
    struct nsm_client *client = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER();

    client = nsm_client_alloc();
    agent = client->cli_agent;
    agent->ra_sock = sock;

    /* has an ssl_ctx */
    if (sock->ssl != NULL)
        agent->ra_state = RPC_STATE_HANDSHAKE;
    else
        agent->ra_state = RPC_STATE_RECV_HDR;

    RHO_TRACE_EXIT();
    return (client);
}

static void
nsm_client_destroy(struct nsm_client *client)
{
    RHO_ASSERT(client != NULL);

    RHO_TRACE_ENTER();

    rpc_agent_destroy(client->cli_agent);
    rhoL_free(client);

    RHO_TRACE_EXIT();
}

static void
nsm_client_dispatch_call(struct nsm_client *client)
{
    struct rpc_agent *agent = client->cli_agent;
    uint32_t opcode = agent->ra_hdr.rh_code;
    nsm_opcall opcall = NULL;

    RHO_ASSERT(agent->ra_state == RPC_STATE_DISPATCHABLE);
    RHO_ASSERT(rho_buf_tell(agent->ra_bodybuf) == 0);

    RHO_TRACE_ENTER("fd=%d, opcode=%d", agent->ra_sock->fd, opcode);

    if (opcode >= RHO_C_ARRAY_SIZE(nsm_opcalls)) {
        rho_log_warn(nsm_log, "bad opcode (%"PRIu32")", opcode);
        rpc_agent_new_msg(agent, ENOSYS);
        goto done;
    } 

    opcall = nsm_opcalls[opcode];
    opcall(client);

done:
    rpc_agent_ready_send(agent);
    RHO_TRACE_EXIT();
    return;
}

static void
nsm_client_cb(struct rho_event *event, int what, struct rho_event_loop *loop)
{
    int ret = 0;
    struct nsm_client *client = NULL;
    struct rpc_agent *agent = NULL;

    RHO_ASSERT(event != NULL);
    RHO_ASSERT(event->userdata != NULL);
    RHO_ASSERT(loop != NULL);

    (void)what;

    client = event->userdata;
    agent = client->cli_agent;

#if 0
    RHO_TRACE_ENTER("fd=%d, what=%08x, state=%s",
            event->fd,
            what,
            nsm_client_state_tostring(client->cli_state));
#endif
            
    if (agent->ra_state == RPC_STATE_HANDSHAKE) {
        ret = rho_ssl_do_handshake(agent->ra_sock);
        if (ret == 0) {
            /* ssl handshake complete */
            agent->ra_state  = RPC_STATE_RECV_HDR;
        } else if (ret == 1) {
            /* ssl handshake still in progress */
            goto again;
        } else {
            /* an error occurred during the handshake */
            agent->ra_state = RPC_STATE_ERROR; /* not needed */
            goto done;
        }
    }

    if (agent->ra_state == RPC_STATE_RECV_HDR)
        rpc_agent_recv_hdr(agent);

    if (agent->ra_state == RPC_STATE_RECV_BODY) 
        rpc_agent_recv_body(agent);

    if (agent->ra_state == RPC_STATE_DISPATCHABLE)
        nsm_client_dispatch_call(client);

    if (agent->ra_state == RPC_STATE_SEND_HDR)
        rpc_agent_send_hdr(agent);

    if (agent->ra_state == RPC_STATE_SEND_BODY)
        rpc_agent_send_body(agent);

    if ((agent->ra_state == RPC_STATE_ERROR) ||
            (agent->ra_state == RPC_STATE_CLOSED)) {
        goto done;
    }

again:
    rho_event_loop_add(loop, event, NULL); 
#if 0
    RHO_TRACE_EXIT("reschedule callback; state=%s", 
            nsm_client_state_tostring(client->cli_state));
#endif
    return;

done:
    RHO_LIST_REMOVE(client, cli_next_client);
    rho_log_info(nsm_log, "id=0x%"PRIx64" disconnected", client->cli_id);
    nsm_client_destroy(client);

#if 0
    RHO_TRACE_EXIT("client done");
#endif
    return;
}

/**************************************
 * SERVER
 **************************************/
static struct nsm_server *
nsm_server_alloc(void)
{
    struct nsm_server *server = NULL;
    server = rhoL_zalloc(sizeof(*server));
    return (server);
}

static void
nsm_server_destroy(struct nsm_server *server)
{
    int error = 0;

    if (server->srv_sock != NULL) {
        if (server->srv_udspath[0] != '\0') {
            error = unlink((const char *)server->srv_udspath);
            if (error != 0)
                rho_errno_warn(errno, "unlink('%s') failed", server->srv_udspath);
        }
        rho_sock_destroy(server->srv_sock);
    }

    rhoL_free(server);
}

static void
nsm_server_config_ssl(struct nsm_server *server,
        const char *cafile, const char *certfile, const char *keyfile)
{
    struct rho_ssl_params *params = NULL;
    struct rho_ssl_ctx *sc = NULL;

    RHO_TRACE_ENTER("cafile=%s, certfile=%s, keyfile=%s",
            cafile, certfile, keyfile);

    params = rho_ssl_params_create();
    rho_ssl_params_set_mode(params, RHO_SSL_MODE_SERVER);
    rho_ssl_params_set_protocol(params, RHO_SSL_PROTOCOL_TLSv1_2);
    rho_ssl_params_set_private_key_file(params, keyfile);
    rho_ssl_params_set_certificate_file(params, certfile);
    rho_ssl_params_set_ca_file(params, cafile);
    rho_ssl_params_set_verify(params, true);
    sc = rho_ssl_ctx_create(params);

    server->srv_sc = sc;

    /* TODO: destroy params? */

    RHO_TRACE_EXIT();
}

static void
nsm_server_socket_create(struct nsm_server *server, const char *url,
        bool anonymous)
{
    size_t pathlen = 0;
    struct rho_sock *sock = NULL;
    struct rho_url *purl = NULL;
    short port = 0;

    purl = rho_url_parse(url);
    if (purl == NULL)
        rho_die("invalid url \"%s\"", url);

    /* TODO: add rho_sock_server_create_from_url function */
    if (rho_str_equal(purl->scheme, "tcp")) {
        port = rho_str_toshort(purl->port, 10);
        sock = rho_sock_tcp4server_create(purl->host, port, 5);
    } else if (rho_str_equal(purl->scheme, "unix")) {
        pathlen = strlen(purl->path) + 1;
        if (anonymous) {
            strcpy((char *)(server->srv_udspath + 1), purl->path);
            pathlen += 1;
        } else {
            strcpy((char *)server->srv_udspath, purl->path);
        }
        sock = rho_sock_unixserver_create(server->srv_udspath, pathlen, 5);
    } else {
        rho_die("invalid url scheme \"%s\" (url=\"%s\")", purl->scheme, url);
    }

    rho_sock_setnonblocking(sock);
    
    if (rho_str_startswith(url, "tcp:") || rho_str_startswith(url, "tcp4:"))
        rhoL_setsockopt_disable_nagle(sock->fd);
    server->srv_sock = sock;
}

static void
nsm_server_cb(struct rho_event *event, int what, struct rho_event_loop *loop)
{
    int cfd = 0;
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);
    struct rho_event *cevent = NULL;
    struct nsm_client *client = NULL;
    struct nsm_server *server = NULL;
    struct rho_sock *csock = NULL;

    RHO_ASSERT(event != NULL);
    RHO_ASSERT(loop != NULL);
    RHO_ASSERT(event->userdata != NULL);
    server = event->userdata;

    (void)what;
    //fprintf(stderr, "server callback (fd=%d, what=%08x)\n", event->fd, what);

    cfd = accept(event->fd, (struct sockaddr *)&addr, &addrlen);
    if (cfd == -1)
        rho_errno_die(errno, "accept failed");
    /* TODO: check that addrlen == sizeof struct soackaddr_un */

    csock = rho_sock_unix_from_fd(cfd);
    rho_sock_setnonblocking(csock);
    if (server->srv_sc != NULL)
        rho_ssl_wrap(csock, server->srv_sc);
    client = nsm_client_create(csock);
    nsm_client_add(client);
    rho_log_info(nsm_log, "new connection: id=0x%"PRIx64, client->cli_id);
    /* 
     * XXX: do we have a memory leak with event -- where does it get destroyed?
     */
    cevent = rho_event_create(cfd, RHO_EVENT_READ, nsm_client_cb, client);
    client->cli_agent->ra_event = cevent;
    rho_event_loop_add(loop, cevent, NULL); 
}

/**************************************
 * LOG
 **************************************/
static void
nsm_log_init(const char *logfile, bool verbose)
{
    int fd = STDERR_FILENO;

    RHO_TRACE_ENTER();

    if (logfile != NULL) {
        fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT,
                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH,S_IWOTH);
        if (fd == -1)
            rho_errno_die(errno, "can't open or creat logfile \"%s\"", logfile);
    }

    nsm_log = rho_log_create(fd, RHO_LOG_INFO, rho_log_default_writer, NULL);

    if (verbose) 
        rho_log_set_level(nsm_log, RHO_LOG_DEBUG);

    if (logfile != NULL) {
        rho_log_redirect_stderr(nsm_log);
        (void)close(fd);
    }

    RHO_TRACE_EXIT();
}

#define NEXTFSSERVER_USAGE \
    "usage: nsmserver [options] URL\n" \
    "\n" \
    "OPTIONS:\n" \
    "   -a\n" \
    "       Treat URL path as an abstract socket\n" \
    "       (adds a leading nul byte to path)\n" \
    "\n" \
    "   -d\n" \
    "       Daemonize\n" \
    "\n" \
    "   -h\n" \
    "       Show this help message and exit\n" \
    "\n" \
    "   -l LOG_FILE\n" \
    "       Log file to use.  If not specified, logs are printed to stderr.\n" \
    "       If specified, stderr is also redirected to the log file.\n" \
    "\n" \
    "   -r ROOTDIR\n" \
    "       The directory where the keys are stored\n" \
    "       If not specified, the default is the current working directory\n" \
    "\n" \
    "   -v\n" \
    "       Verbose logging.\n" \
    "\n" \
    "   -Z  CACERT CERT PRIVKEY\n" \
    "       Sets the path to the server certificate file and private key\n" \
    "       in PEM format.  This also causes the server to start SSL mode\n" \
    "\n" \
    "\n" \
    "ARGUMENTS:\n" \
    "   URL\n" \
    "       The URL to listen to connection on.\n" \
    "       (e.g., unix:///tmp/foo, tcp://127.0.0.1:8089)\n"

static void
usage(int exitcode)
{
    fprintf(stderr, "%s\n", NEXTFSSERVER_USAGE);
    exit(exitcode);
}

int
main(int argc, char *argv[])
{
    int c = 0;
    struct nsm_server *server = NULL;
    struct rho_event *event = NULL;
    struct rho_event_loop *loop = NULL;
    /* options */
    bool anonymous = false;
    bool daemonize  = false;
    const char *logfile = NULL;
    bool verbose = false;

    server  = nsm_server_alloc();
    while ((c = getopt(argc, argv, "adhl:r:vZ:")) != -1) {
        switch (c) {
        case 'a':
            anonymous = true;
            break;
        case 'd':
            daemonize = true;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 'l':
            logfile = optarg;
            break;
        case 'r':
            nsm_root = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        case 'Z':
            /* make sure there's three arguments */
            if ((argc - optind) < 2)
                usage(EXIT_FAILURE);
            nsm_server_config_ssl(server, optarg, argv[optind],
                    argv[optind + 1]);
            optind += 2;
            break;
        default:
            usage(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc != 1)
        usage(EXIT_FAILURE);

    if (daemonize)
        rho_daemon_daemonize(NULL, 0);

    nsm_log_init(logfile, verbose);
    nsm_openssl_init();

#ifdef NSM_DO_BENCH
    const unsigned char *p = test2048;
    g_nsm_test_rsa2048 = d2i_RSAPrivateKey(NULL, &p, sizeof(test2048)); 
    if (g_nsm_test_rsa2048 == NULL)
        rho_die("failed to read test RSA 2048 key");
#endif

    nsm_server_socket_create(server, argv[0], anonymous);

    event = rho_event_create(server->srv_sock->fd,
            RHO_EVENT_READ | RHO_EVENT_PERSIST, 
            nsm_server_cb, server); 

    loop = rho_event_loop_create();
    rho_event_loop_add(loop, event, NULL); 
    rho_event_loop_dispatch(loop);

    /* TODO: destroy event and event_loop */
    fprintf(stderr, "HERE\n");

    nsm_server_destroy(server);

    return (0);
}
