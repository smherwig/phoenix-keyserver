#ifndef _NSM_H_
#define _NSM_H_

/* RPC opcodes */
#define NSM_OP_LOAD_PRIVATE_KEY 0
#define NSM_OP_RSA_KEYGEN       1
#define NSM_OP_RSA_PRIV_ENC     2
#define NSM_OP_RSA_PRIV_DEC     3
#define NSM_OP_RSA_PUB_ENC      4
#define NSM_OP_RSA_PUB_DEC      5
#define NSM_OP_RSA_SIGN         6
#define NSM_OP_RSA_VERIFY       7

#define NSM_KEY_ID_MAX_SIZE     255

#endif /* _NSM_H_ */
