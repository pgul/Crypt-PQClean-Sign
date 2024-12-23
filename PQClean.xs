#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "pqclean/crypto_sign/falcon-512/clean/api.h"

MODULE = Crypt::PQClean::Sign  PACKAGE = Crypt::PQClean::Sign

void
falcon512_keypair()
    PPCODE:
        unsigned char pk[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
        unsigned char sk[PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
        int ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
        if (ret != 0) {
            croak("Key pair generation failed");
        }
        SV* pk_sv = newSVpvn((const char*)pk, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES);
        SV* sk_sv = newSVpvn((const char*)sk, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES);
        XPUSHs(sv_2mortal(pk_sv));
        XPUSHs(sv_2mortal(sk_sv));
        XSRETURN(2);

void
falcon512_sign(message, sk)
    SV* message
    SV* sk
    PPCODE:
        STRLEN msg_len, sk_len;
        const unsigned char* msg = (unsigned char*)SvPVbyte(message, msg_len);
        const unsigned char* sk_bytes = (unsigned char*)SvPVbyte(sk, sk_len);

        if (sk_len != PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES) {
            croak("Invalid secret key size");
        }

        unsigned char sig[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
        size_t sig_len = sizeof(sig);
        int ret = PQCLEAN_FALCON512_CLEAN_crypto_sign(
            sig, &sig_len, msg, msg_len, sk_bytes
        );
        if (ret != 0) {
            croak("Signing failed");
        }
        XPUSHs(sv_2mortal(newSVpvn((const char*)sig, sig_len)));
        XSRETURN(1);

int
falcon512_verify(signature, message, pk)
    SV* signature
    SV* message
    SV* pk
    PPCODE:
        STRLEN sig_len, msg_len, pk_len;
        const unsigned char* sig = (unsigned char*)SvPVbyte(signature, sig_len);
        const unsigned char* msg = (unsigned char*)SvPVbyte(message, msg_len);
        const unsigned char* pk_bytes = (unsigned char*)SvPVbyte(pk, pk_len);

        if (pk_len != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES) {
            croak("Invalid public key size");
        }

        if (sig_len > PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES) {
            croak("Invalid signature size");
        }

        int ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
            (unsigned char*)msg, &msg_len, sig, sig_len, pk_bytes
        );

        XSRETURN_IV(ret == 0 ? 1 : 0);
