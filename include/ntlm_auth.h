/* NTLMv2 authentication helpers. */

#ifndef NTLM_AUTH_H
#define NTLM_AUTH_H

#include <windows.h>

WINBASEAPI HANDLE  WINAPI KERNEL32$GetProcessHeap(VOID);
WINBASEAPI LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI WINBOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
WINBASEAPI VOID    WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
WINBASEAPI BOOLEAN WINAPI ADVAPI32$SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);

#define MD5_F(x,y,z) (((x)&(y))|((~(x))&(z)))
#define MD5_G(x,y,z) (((x)&(z))|((y)&(~(z))))
#define MD5_H(x,y,z) ((x)^(y)^(z))
#define MD5_I(x,y,z) ((y)^((x)|(~(z))))
#define MD5_ROT(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define MD5_STEP(f,a,b,c,d,x,t,s) \
    (a) += f((b),(c),(d)) + (x) + (DWORD)(t); \
    (a) = MD5_ROT((a),(s)); \
    (a) += (b);

typedef struct { DWORD state[4]; DWORD count[2]; BYTE buffer[64]; } MD5CTX;

static void md5_transform(DWORD st[4], const BYTE blk[64])
{
    DWORD a = st[0], b = st[1], c = st[2], d = st[3];
    DWORD x[16];
    for (int i = 0; i < 16; i++)
        x[i] = (DWORD)blk[i*4] | ((DWORD)blk[i*4+1]<<8) |
               ((DWORD)blk[i*4+2]<<16) | ((DWORD)blk[i*4+3]<<24);

    MD5_STEP(MD5_F, a,b,c,d, x[ 0], 0xd76aa478,  7)
    MD5_STEP(MD5_F, d,a,b,c, x[ 1], 0xe8c7b756, 12)
    MD5_STEP(MD5_F, c,d,a,b, x[ 2], 0x242070db, 17)
    MD5_STEP(MD5_F, b,c,d,a, x[ 3], 0xc1bdceee, 22)
    MD5_STEP(MD5_F, a,b,c,d, x[ 4], 0xf57c0faf,  7)
    MD5_STEP(MD5_F, d,a,b,c, x[ 5], 0x4787c62a, 12)
    MD5_STEP(MD5_F, c,d,a,b, x[ 6], 0xa8304613, 17)
    MD5_STEP(MD5_F, b,c,d,a, x[ 7], 0xfd469501, 22)
    MD5_STEP(MD5_F, a,b,c,d, x[ 8], 0x698098d8,  7)
    MD5_STEP(MD5_F, d,a,b,c, x[ 9], 0x8b44f7af, 12)
    MD5_STEP(MD5_F, c,d,a,b, x[10], 0xffff5bb1, 17)
    MD5_STEP(MD5_F, b,c,d,a, x[11], 0x895cd7be, 22)
    MD5_STEP(MD5_F, a,b,c,d, x[12], 0x6b901122,  7)
    MD5_STEP(MD5_F, d,a,b,c, x[13], 0xfd987193, 12)
    MD5_STEP(MD5_F, c,d,a,b, x[14], 0xa679438e, 17)
    MD5_STEP(MD5_F, b,c,d,a, x[15], 0x49b40821, 22)

    MD5_STEP(MD5_G, a,b,c,d, x[ 1], 0xf61e2562,  5)
    MD5_STEP(MD5_G, d,a,b,c, x[ 6], 0xc040b340,  9)
    MD5_STEP(MD5_G, c,d,a,b, x[11], 0x265e5a51, 14)
    MD5_STEP(MD5_G, b,c,d,a, x[ 0], 0xe9b6c7aa, 20)
    MD5_STEP(MD5_G, a,b,c,d, x[ 5], 0xd62f105d,  5)
    MD5_STEP(MD5_G, d,a,b,c, x[10], 0x02441453,  9)
    MD5_STEP(MD5_G, c,d,a,b, x[15], 0xd8a1e681, 14)
    MD5_STEP(MD5_G, b,c,d,a, x[ 4], 0xe7d3fbc8, 20)
    MD5_STEP(MD5_G, a,b,c,d, x[ 9], 0x21e1cde6,  5)
    MD5_STEP(MD5_G, d,a,b,c, x[14], 0xc33707d6,  9)
    MD5_STEP(MD5_G, c,d,a,b, x[ 3], 0xf4d50d87, 14)
    MD5_STEP(MD5_G, b,c,d,a, x[ 8], 0x455a14ed, 20)
    MD5_STEP(MD5_G, a,b,c,d, x[13], 0xa9e3e905,  5)
    MD5_STEP(MD5_G, d,a,b,c, x[ 2], 0xfcefa3f8,  9)
    MD5_STEP(MD5_G, c,d,a,b, x[ 7], 0x676f02d9, 14)
    MD5_STEP(MD5_G, b,c,d,a, x[12], 0x8d2a4c8a, 20)

    MD5_STEP(MD5_H, a,b,c,d, x[ 5], 0xfffa3942,  4)
    MD5_STEP(MD5_H, d,a,b,c, x[ 8], 0x8771f681, 11)
    MD5_STEP(MD5_H, c,d,a,b, x[11], 0x6d9d6122, 16)
    MD5_STEP(MD5_H, b,c,d,a, x[14], 0xfde5380c, 23)
    MD5_STEP(MD5_H, a,b,c,d, x[ 1], 0xa4beea44,  4)
    MD5_STEP(MD5_H, d,a,b,c, x[ 4], 0x4bdecfa9, 11)
    MD5_STEP(MD5_H, c,d,a,b, x[ 7], 0xf6bb4b60, 16)
    MD5_STEP(MD5_H, b,c,d,a, x[10], 0xbebfbc70, 23)
    MD5_STEP(MD5_H, a,b,c,d, x[13], 0x289b7ec6,  4)
    MD5_STEP(MD5_H, d,a,b,c, x[ 0], 0xeaa127fa, 11)
    MD5_STEP(MD5_H, c,d,a,b, x[ 3], 0xd4ef3085, 16)
    MD5_STEP(MD5_H, b,c,d,a, x[ 6], 0x04881d05, 23)
    MD5_STEP(MD5_H, a,b,c,d, x[ 9], 0xd9d4d039,  4)
    MD5_STEP(MD5_H, d,a,b,c, x[12], 0xe6db99e5, 11)
    MD5_STEP(MD5_H, c,d,a,b, x[15], 0x1fa27cf8, 16)
    MD5_STEP(MD5_H, b,c,d,a, x[ 2], 0xc4ac5665, 23)

    MD5_STEP(MD5_I, a,b,c,d, x[ 0], 0xf4292244,  6)
    MD5_STEP(MD5_I, d,a,b,c, x[ 7], 0x432aff97, 10)
    MD5_STEP(MD5_I, c,d,a,b, x[14], 0xab9423a7, 15)
    MD5_STEP(MD5_I, b,c,d,a, x[ 5], 0xfc93a039, 21)
    MD5_STEP(MD5_I, a,b,c,d, x[12], 0x655b59c3,  6)
    MD5_STEP(MD5_I, d,a,b,c, x[ 3], 0x8f0ccc92, 10)
    MD5_STEP(MD5_I, c,d,a,b, x[10], 0xffeff47d, 15)
    MD5_STEP(MD5_I, b,c,d,a, x[ 1], 0x85845dd1, 21)
    MD5_STEP(MD5_I, a,b,c,d, x[ 8], 0x6fa87e4f,  6)
    MD5_STEP(MD5_I, d,a,b,c, x[15], 0xfe2ce6e0, 10)
    MD5_STEP(MD5_I, c,d,a,b, x[ 6], 0xa3014314, 15)
    MD5_STEP(MD5_I, b,c,d,a, x[13], 0x4e0811a1, 21)
    MD5_STEP(MD5_I, a,b,c,d, x[ 4], 0xf7537e82,  6)
    MD5_STEP(MD5_I, d,a,b,c, x[11], 0xbd3af235, 10)
    MD5_STEP(MD5_I, c,d,a,b, x[ 2], 0x2ad7d2bb, 15)
    MD5_STEP(MD5_I, b,c,d,a, x[ 9], 0xeb86d391, 21)

    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

static void md5_init(MD5CTX *c)
{
    c->state[0] = 0x67452301; c->state[1] = 0xefcdab89;
    c->state[2] = 0x98badcfe; c->state[3] = 0x10325476;
    c->count[0] = c->count[1] = 0;
}

static void md5_update(MD5CTX *c, const BYTE *data, DWORD len)
{
    DWORD idx = (c->count[0] >> 3) & 0x3F;
    c->count[0] += len << 3;
    if (c->count[0] < (len << 3)) c->count[1]++;
    c->count[1] += len >> 29;
    DWORD part = 64 - idx;
    DWORD i = 0;
    if (len >= part) {
        for (DWORD j = 0; j < part; j++) c->buffer[idx+j] = data[j];
        md5_transform(c->state, c->buffer);
        for (i = part; i + 63 < len; i += 64)
            md5_transform(c->state, data + i);
        idx = 0;
    }
    for (DWORD j = 0; j < len - i; j++)
        c->buffer[idx + j] = data[i + j];
}

static void md5_final(MD5CTX *c, BYTE digest[16])
{
    BYTE bits[8];
    for (int i = 0; i < 4; i++) { bits[i]   = (BYTE)(c->count[0] >> (i*8)); }
    for (int i = 0; i < 4; i++) { bits[4+i] = (BYTE)(c->count[1] >> (i*8)); }
    DWORD idx = (c->count[0] >> 3) & 0x3F;
    DWORD padLen = (idx < 56) ? (56 - idx) : (120 - idx);
    BYTE pad[64];
    pad[0] = 0x80;
    for (DWORD i = 1; i < 64; i++) pad[i] = 0;
    md5_update(c, pad, padLen);
    md5_update(c, bits, 8);
    for (int i = 0; i < 4; i++) {
        digest[i*4]   = (BYTE)(c->state[i]);
        digest[i*4+1] = (BYTE)(c->state[i] >> 8);
        digest[i*4+2] = (BYTE)(c->state[i] >> 16);
        digest[i*4+3] = (BYTE)(c->state[i] >> 24);
    }
}

static void hmac_md5(const BYTE *key, DWORD keyLen,
                     const BYTE *data, DWORD dataLen, BYTE out[16])
{
    MD5CTX ctx;
    BYTE kblock[64], ipad[64], opad[64], inner[16];

    if (keyLen > 64) {
        md5_init(&ctx); md5_update(&ctx, key, keyLen); md5_final(&ctx, kblock);
        keyLen = 16;
    } else {
        for (DWORD i = 0; i < keyLen; i++) kblock[i] = key[i];
    }
    for (DWORD i = keyLen; i < 64; i++) kblock[i] = 0;

    for (int i = 0; i < 64; i++) { ipad[i] = kblock[i] ^ 0x36; opad[i] = kblock[i] ^ 0x5c; }

    md5_init(&ctx); md5_update(&ctx, ipad, 64); md5_update(&ctx, data, dataLen); md5_final(&ctx, inner);
    md5_init(&ctx); md5_update(&ctx, opad, 64); md5_update(&ctx, inner, 16); md5_final(&ctx, out);
}

static void rc4_crypt(BYTE *data, DWORD dataLen, const BYTE *key, DWORD keyLen)
{
    BYTE S[256];
    int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (BYTE)i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) & 0xFF;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
    }
    int a = 0, b = 0;
    for (DWORD k = 0; k < dataLen; k++) {
        a = (a + 1) & 0xFF;
        b = (b + S[a]) & 0xFF;
        BYTE t = S[a]; S[a] = S[b]; S[b] = t;
        data[k] ^= S[(S[a] + S[b]) & 0xFF];
    }
}

#define AV_EOL           0x0000
#define AV_FLAGS         0x0006
#define AV_TIMESTAMP     0x0007
#define AV_FLAG_MIC      0x00000002

static PBYTE FindAvPair(PBYTE ti, DWORD tiLen, WORD avId, WORD *valLen)
{
    DWORD off = 0;
    if (!ti && tiLen)
        return NULL;
    while (off + 4 <= tiLen) {
        WORD id  = *(WORD*)(ti + off);
        WORD len = *(WORD*)(ti + off + 2);
        if ((DWORD)len > tiLen - off - 4)
            return NULL;
        if (id == avId) { if (valLen) *valLen = len; return ti + off + 4; }
        if (id == AV_EOL) break;
        off += 4 + len;
    }
    return NULL;
}

/* Return a copy of TargetInfo with the MIC flag set. */
static PBYTE AddMicFlag(PBYTE ti, DWORD tiLen, DWORD *outLen)
{
    WORD fLen = 0;
    PBYTE fv = FindAvPair(ti, tiLen, AV_FLAGS, &fLen);
    if (fv && fLen >= 4) {

        *outLen = tiLen;
        PBYTE out = (PBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, tiLen);
        if (!out) return NULL;
        for (DWORD i = 0; i < tiLen; i++) out[i] = ti[i];
        *(DWORD*)(out + (fv - ti)) |= AV_FLAG_MIC;
        return out;
    }

    DWORD eolOff = 0, off = 0;
    while (off + 4 <= tiLen) {
        WORD id = *(WORD*)(ti + off);
        WORD len = *(WORD*)(ti + off + 2);
        if (id == AV_EOL) { eolOff = off; break; }
        if ((DWORD)len > tiLen - off - 4) return NULL;
        off += 4 + len;
    }
    if (off + 4 > tiLen) return NULL;
    DWORD newLen = eolOff + 8 + 4;
    PBYTE out = (PBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, newLen);
    if (!out) return NULL;
    for (DWORD i = 0; i < eolOff; i++) out[i] = ti[i];
    *(WORD*)(out + eolOff)     = AV_FLAGS;
    *(WORD*)(out + eolOff + 2) = 4;
    *(DWORD*)(out + eolOff + 4) = AV_FLAG_MIC;
    *(DWORD*)(out + eolOff + 8) = 0;
    *outLen = newLen;
    return out;
}

static int hex_val(WCHAR c) {
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}

static BOOL is_nt_hash(const WCHAR *s)
{
    int n = 0;
    if (!s) return FALSE;
    for (const WCHAR *p = s; *p; p++) { if (hex_val(*p) < 0) return FALSE; n++; }
    return n == 32;
}

static BOOL parse_nt_hash(const WCHAR *hex, BYTE out[16])
{
    for (int i = 0; i < 16; i++) {
        int hi = hex_val(hex[i*2]), lo = hex_val(hex[i*2+1]);
        if (hi < 0 || lo < 0) return FALSE;
        out[i] = (BYTE)((hi << 4) | lo);
    }
    return TRUE;
}

#define NF_UNICODE      0x00000001
#define NF_REQUEST_TGT  0x00000004
#define NF_SIGN         0x00000010
#define NF_SEAL         0x00000020
#define NF_NTLM         0x00000200
#define NF_ALWAYS_SIGN  0x00008000
#define NF_NTLM2_SESS  0x00080000
#define NF_TARGET_INFO  0x00800000
#define NF_VERSION      0x02000000
#define NF_128          0x20000000
#define NF_KEY_EXCH     0x40000000
#define NF_56           0x80000000

#define TYPE1_FLAGS (NF_UNICODE | NF_REQUEST_TGT | NF_SIGN | NF_SEAL | \
                     NF_NTLM | NF_ALWAYS_SIGN | NF_NTLM2_SESS | \
                     NF_VERSION | NF_128 | NF_KEY_EXCH | NF_56)

typedef struct {
    BYTE  challenge[8];
    PBYTE targetInfo;
    DWORD targetInfoLen;
    DWORD flags;
} TYPE2_PARSED;

static DWORD BuildType1(BYTE *buf)
{

    buf[0]='N'; buf[1]='T'; buf[2]='L'; buf[3]='M';
    buf[4]='S'; buf[5]='S'; buf[6]='P'; buf[7]=0;
    *(DWORD*)(buf+ 8) = 1;
    *(DWORD*)(buf+12) = TYPE1_FLAGS;
    *(DWORD*)(buf+16) = 0;
    *(DWORD*)(buf+20) = 0;
    *(DWORD*)(buf+24) = 0;
    *(DWORD*)(buf+28) = 0;

    *(DWORD*)(buf+32) = 0;
    *(DWORD*)(buf+36) = 0;
    return 40;
}

static BOOL ParseType2(const BYTE *msg, DWORD msgLen, TYPE2_PARSED *t)
{
    if (msgLen < 32) return FALSE;
    if (msg[0]!='N'||msg[1]!='T'||msg[2]!='L'||msg[3]!='M'||
        msg[4]!='S'||msg[5]!='S'||msg[6]!='P'||msg[7]!=0)  return FALSE;
    if (*(const DWORD*)(msg+8) != 2) return FALSE;

    t->flags = *(const DWORD*)(msg+20);
    for (int i = 0; i < 8; i++) t->challenge[i] = msg[24+i];

    t->targetInfo = NULL; t->targetInfoLen = 0;
    if (msgLen >= 48) {
        WORD tiLen  = *(const WORD*)(msg+40);
        DWORD tiOff = *(const DWORD*)(msg+44);
        if (tiOff <= msgLen && tiLen <= msgLen - tiOff) {
            t->targetInfo    = (PBYTE)(msg + tiOff);
            t->targetInfoLen = tiLen;
        }
    }
    return TRUE;
}

static BOOL ComputeNtlmV2(
    BYTE ntHash[16], LPCWSTR user, LPCWSTR domain,
    BYTE serverChallenge[8], PBYTE targetInfo, DWORD tiLen,
    PBYTE *pResp, DWORD *pRespLen,
    BYTE lmResp[24],
    BYTE sessionBaseKey[16])
{
    DWORD uLen = 0, dLen = 0;
    for (const WCHAR *p = user;   *p; p++) uLen++;
    for (const WCHAR *p = domain; *p; p++) dLen++;

    /* Response key: HMAC-MD5(NT hash, uppercase user + domain). */
    DWORD udBytes = (uLen + dLen) * 2;
    BYTE *ud = (BYTE*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, udBytes ? udBytes : 1);
    if (!ud) return FALSE;
    WCHAR *w = (WCHAR*)ud;
    for (DWORD i = 0; i < uLen; i++) {
        WCHAR c = user[i]; if (c >= L'a' && c <= L'z') c -= 32; w[i] = c;
    }
    for (DWORD i = 0; i < dLen; i++) w[uLen + i] = domain[i];

    BYTE respKey[16];
    hmac_md5(ntHash, 16, ud, udBytes, respKey);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ud);

    /* A server timestamp requires a MIC in the response. */
    PBYTE useTI = targetInfo;
    DWORD useTILen = tiLen;
    BOOL hasTimestamp = FALSE;
    BYTE avTime[8] = {0};
    {
        WORD tsLen = 0;
        PBYTE ts = FindAvPair(targetInfo, tiLen, AV_TIMESTAMP, &tsLen);
        if (ts && tsLen == 8) {
            hasTimestamp = TRUE;
            for (int i = 0; i < 8; i++) avTime[i] = ts[i];
            useTI = AddMicFlag(targetInfo, tiLen, &useTILen);
            if (!useTI) return FALSE;
        }
    }

    DWORD blobLen = 28 + useTILen + 4;
    BYTE *blob = (BYTE*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, blobLen);
    if (!blob) { if (useTI != targetInfo) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, useTI); return FALSE; }
    blob[0] = 1; blob[1] = 1;
    if (hasTimestamp) {

        for (int i = 0; i < 8; i++) blob[8+i] = avTime[i];
    } else {
        FILETIME ft;
        KERNEL32$GetSystemTimeAsFileTime(&ft);
        *(DWORD*)(blob+ 8) = ft.dwLowDateTime;
        *(DWORD*)(blob+12) = ft.dwHighDateTime;
    }
    ADVAPI32$SystemFunction036(blob+16, 8);
    for (DWORD i = 0; i < useTILen; i++) blob[28+i] = useTI[i];
    if (useTI != targetInfo) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, useTI);

    DWORD catLen = 8 + blobLen;
    BYTE *cat = (BYTE*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, catLen);
    if (!cat) { KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, blob); return FALSE; }
    for (int i = 0; i < 8; i++) cat[i] = serverChallenge[i];
    for (DWORD i = 0; i < blobLen; i++) cat[8+i] = blob[i];
    BYTE proof[16];
    hmac_md5(respKey, 16, cat, catLen, proof);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, cat);

    hmac_md5(respKey, 16, proof, 16, sessionBaseKey);

    if (hasTimestamp) {
        /* The LM response is zero when a timestamp is present. */
        for (int i = 0; i < 24; i++) lmResp[i] = 0;
    } else {

        BYTE lmCat[16];
        for (int i = 0; i < 8; i++) lmCat[i] = serverChallenge[i];
        for (int i = 0; i < 8; i++) lmCat[8+i] = blob[16+i];
        hmac_md5(respKey, 16, lmCat, 16, lmResp);
        for (int i = 0; i < 8; i++) lmResp[16+i] = blob[16+i];
    }

    *pRespLen = 16 + blobLen;
    *pResp = (BYTE*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, *pRespLen);
    if (!*pResp) { KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, blob); return FALSE; }
    for (int i = 0; i < 16; i++) (*pResp)[i] = proof[i];
    for (DWORD i = 0; i < blobLen; i++) (*pResp)[16+i] = blob[i];

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, blob);
    return TRUE;
}

static DWORD BuildType3(
    BYTE *buf, DWORD bufSize,
    LPCWSTR domain, LPCWSTR user,
    PBYTE ntResp, DWORD ntRespLen,
    PBYTE lmResp, DWORD lmRespLen,
    PBYTE encSessKey, DWORD encSessKeyLen,
    DWORD flags,
    DWORD *micOffset)
{
    DWORD dLen = 0, uLen = 0;
    for (const WCHAR *p = domain; *p; p++) dLen++;
    for (const WCHAR *p = user;   *p; p++) uLen++;
    DWORD domBytes  = dLen * 2;
    DWORD userBytes = uLen * 2;

    DWORD hdr = micOffset ? 88 : 72;
    DWORD lmOff   = hdr;
    DWORD ntOff   = lmOff  + lmRespLen;
    DWORD domOff  = ntOff  + ntRespLen;
    DWORD usrOff  = domOff + domBytes;
    DWORD eskOff  = usrOff + userBytes;
    DWORD total   = eskOff + encSessKeyLen;
    if (total > bufSize) return 0;

    for (DWORD i = 0; i < total; i++) buf[i] = 0;

    buf[0]='N'; buf[1]='T'; buf[2]='L'; buf[3]='M';
    buf[4]='S'; buf[5]='S'; buf[6]='P'; buf[7]=0;
    *(DWORD*)(buf+8) = 3;

    *(WORD*)(buf+12) = (WORD)lmRespLen; *(WORD*)(buf+14) = (WORD)lmRespLen;
    *(DWORD*)(buf+16) = lmOff;

    *(WORD*)(buf+20) = (WORD)ntRespLen; *(WORD*)(buf+22) = (WORD)ntRespLen;
    *(DWORD*)(buf+24) = ntOff;

    *(WORD*)(buf+28) = (WORD)domBytes; *(WORD*)(buf+30) = (WORD)domBytes;
    *(DWORD*)(buf+32) = domOff;

    *(WORD*)(buf+36) = (WORD)userBytes; *(WORD*)(buf+38) = (WORD)userBytes;
    *(DWORD*)(buf+40) = usrOff;

    *(DWORD*)(buf+48) = hdr;

    *(WORD*)(buf+52) = (WORD)encSessKeyLen; *(WORD*)(buf+54) = (WORD)encSessKeyLen;
    *(DWORD*)(buf+56) = eskOff;

    *(DWORD*)(buf+60) = flags;

    /* The caller fills the MIC at byte 72. */
    if (micOffset) *micOffset = 72;

    for (DWORD i = 0; i < lmRespLen; i++) buf[lmOff+i] = lmResp[i];

    for (DWORD i = 0; i < ntRespLen; i++) buf[ntOff+i] = ntResp[i];

    WCHAR *pd = (WCHAR*)(buf + domOff);
    for (DWORD i = 0; i < dLen; i++) pd[i] = domain[i];

    WCHAR *pu = (WCHAR*)(buf + usrOff);
    for (DWORD i = 0; i < uLen; i++) pu[i] = user[i];

    for (DWORD i = 0; i < encSessKeyLen; i++) buf[eskOff+i] = encSessKey[i];

    return total;
}

#endif
