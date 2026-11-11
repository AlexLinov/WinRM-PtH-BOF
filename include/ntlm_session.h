/* NTLM session signing and sealing. */

#ifndef NTLM_SESSION_H
#define NTLM_SESSION_H

#include "ntlm_auth.h"

typedef struct {
    BYTE s[256];
    BYTE i;
    BYTE j;
} NTLM_RC4_STATE;

typedef struct {
    DWORD flags;
    BYTE clientSigningKey[16];
    BYTE serverSigningKey[16];
    NTLM_RC4_STATE clientSeal;
    NTLM_RC4_STATE serverSeal;
    DWORD sendSeq;
    DWORD recvSeq;
    BOOL ready;
} NTLM_SESSION_SECURITY;

static void ntlm_rc4_init(NTLM_RC4_STATE *state,
                          const BYTE *key, DWORD keyLen)
{
    int i;
    int j = 0;

    for (i = 0; i < 256; i++)
        state->s[i] = (BYTE)i;
    for (i = 0; i < 256; i++) {
        BYTE tmp;
        j = (j + state->s[i] + key[i % keyLen]) & 0xff;
        tmp = state->s[i];
        state->s[i] = state->s[j];
        state->s[j] = tmp;
    }
    state->i = 0;
    state->j = 0;
}

static void ntlm_rc4_update(NTLM_RC4_STATE *state, BYTE *data, DWORD dataLen)
{
    DWORD n;

    for (n = 0; n < dataLen; n++) {
        BYTE tmp;
        state->i = (BYTE)(state->i + 1);
        state->j = (BYTE)(state->j + state->s[state->i]);
        tmp = state->s[state->i];
        state->s[state->i] = state->s[state->j];
        state->s[state->j] = tmp;
        data[n] ^= state->s[(BYTE)(state->s[state->i] + state->s[state->j])];
    }
}

static void ntlm_md5_key_magic(const BYTE *key, DWORD keyLen,
                               const char *magic, DWORD magicLen,
                               BYTE output[16])
{
    MD5CTX ctx;
    md5_init(&ctx);
    md5_update(&ctx, key, keyLen);
    md5_update(&ctx, (const BYTE *)magic, magicLen);
    md5_final(&ctx, output);
}

/* Hash both buffers without a copy. */
static void ntlm_hmac_md5_two(const BYTE *key, DWORD keyLen,
                              const BYTE *first, DWORD firstLen,
                              const BYTE *second, DWORD secondLen,
                              BYTE output[16])
{
    MD5CTX ctx;
    BYTE kblock[64];
    BYTE ipad[64];
    BYTE opad[64];
    BYTE inner[16];
    DWORD i;

    for (i = 0; i < 64; i++)
        kblock[i] = 0;
    if (keyLen > 64) {
        md5_init(&ctx);
        md5_update(&ctx, key, keyLen);
        md5_final(&ctx, kblock);
        keyLen = 16;
    } else {
        for (i = 0; i < keyLen; i++)
            kblock[i] = key[i];
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = kblock[i] ^ 0x36;
        opad[i] = kblock[i] ^ 0x5c;
    }

    md5_init(&ctx);
    md5_update(&ctx, ipad, 64);
    md5_update(&ctx, first, firstLen);
    md5_update(&ctx, second, secondLen);
    md5_final(&ctx, inner);

    md5_init(&ctx);
    md5_update(&ctx, opad, 64);
    md5_update(&ctx, inner, 16);
    md5_final(&ctx, output);
}

static BOOL ntlm_bytes_equal(const BYTE *a, const BYTE *b, DWORD len)
{
    BYTE diff = 0;
    DWORD i;
    for (i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static BOOL ntlm_session_init(NTLM_SESSION_SECURITY *session,
                              const BYTE exportedSessionKey[16],
                              DWORD flags)
{
    static const char clientSignMagic[] =
        "session key to client-to-server signing key magic constant";
    static const char serverSignMagic[] =
        "session key to server-to-client signing key magic constant";
    static const char clientSealMagic[] =
        "session key to client-to-server sealing key magic constant";
    static const char serverSealMagic[] =
        "session key to server-to-client sealing key magic constant";
    BYTE clientSealingKey[16];
    BYTE serverSealingKey[16];
    DWORD sealSourceLen;

    if (!session || !exportedSessionKey)
        return FALSE;
    if ((flags & (NF_NTLM2_SESS | NF_SIGN | NF_SEAL)) !=
        (NF_NTLM2_SESS | NF_SIGN | NF_SEAL))
        return FALSE;

    if (flags & NF_128)
        sealSourceLen = 16;
    else if (flags & NF_56)
        sealSourceLen = 7;
    else
        sealSourceLen = 5;

    ntlm_md5_key_magic(exportedSessionKey, 16,
        clientSignMagic, sizeof(clientSignMagic), session->clientSigningKey);
    ntlm_md5_key_magic(exportedSessionKey, 16,
        serverSignMagic, sizeof(serverSignMagic), session->serverSigningKey);
    ntlm_md5_key_magic(exportedSessionKey, sealSourceLen,
        clientSealMagic, sizeof(clientSealMagic), clientSealingKey);
    ntlm_md5_key_magic(exportedSessionKey, sealSourceLen,
        serverSealMagic, sizeof(serverSealMagic), serverSealingKey);

    ntlm_rc4_init(&session->clientSeal, clientSealingKey, 16);
    ntlm_rc4_init(&session->serverSeal, serverSealingKey, 16);
    session->flags = flags;
    session->sendSeq = 0;
    session->recvSeq = 0;
    session->ready = TRUE;
    return TRUE;
}

static BOOL ntlm_session_wrap(NTLM_SESSION_SECURITY *session,
                              const BYTE *plain, DWORD plainLen,
                              BYTE signature[16], BYTE *sealed)
{
    BYTE seq[4];
    BYTE checksum[16];
    DWORD n;

    if (!session || !session->ready || !plain || !signature || !sealed)
        return FALSE;

    seq[0] = (BYTE)session->sendSeq;
    seq[1] = (BYTE)(session->sendSeq >> 8);
    seq[2] = (BYTE)(session->sendSeq >> 16);
    seq[3] = (BYTE)(session->sendSeq >> 24);
    ntlm_hmac_md5_two(session->clientSigningKey, 16,
        seq, 4, plain, plainLen, checksum);

    for (n = 0; n < plainLen; n++)
        sealed[n] = plain[n];
    ntlm_rc4_update(&session->clientSeal, sealed, plainLen);
    if (session->flags & NF_KEY_EXCH)
        ntlm_rc4_update(&session->clientSeal, checksum, 8);

    signature[0] = 1;
    signature[1] = signature[2] = signature[3] = 0;
    for (n = 0; n < 8; n++)
        signature[4 + n] = checksum[n];
    for (n = 0; n < 4; n++)
        signature[12 + n] = seq[n];
    session->sendSeq++;
    return TRUE;
}

static BOOL ntlm_session_unwrap(NTLM_SESSION_SECURITY *session,
                                const BYTE signature[16],
                                const BYTE *sealed, DWORD sealedLen,
                                BYTE *plain)
{
    BYTE seq[4];
    BYTE checksum[16];
    DWORD n;

    if (!session || !session->ready || !signature || !sealed || !plain)
        return FALSE;
    if (signature[0] != 1 || signature[1] || signature[2] || signature[3])
        return FALSE;

    seq[0] = (BYTE)session->recvSeq;
    seq[1] = (BYTE)(session->recvSeq >> 8);
    seq[2] = (BYTE)(session->recvSeq >> 16);
    seq[3] = (BYTE)(session->recvSeq >> 24);
    if (!ntlm_bytes_equal(signature + 12, seq, 4))
        return FALSE;

    for (n = 0; n < sealedLen; n++)
        plain[n] = sealed[n];
    ntlm_rc4_update(&session->serverSeal, plain, sealedLen);
    ntlm_hmac_md5_two(session->serverSigningKey, 16,
        seq, 4, plain, sealedLen, checksum);
    if (session->flags & NF_KEY_EXCH)
        ntlm_rc4_update(&session->serverSeal, checksum, 8);
    if (!ntlm_bytes_equal(signature + 4, checksum, 8))
        return FALSE;

    session->recvSeq++;
    return TRUE;
}

#endif
