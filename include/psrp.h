/* PSRP (PowerShell Remoting Protocol) message construction and parsing.
 *
 * Self-contained header following the project convention (see ntlm_auth.h,
 * ntlm_session.h).  All functions are static so the compiler keeps only
 * what the single translation unit actually calls.
 *
 * References:
 *   [MS-PSRP] https://learn.microsoft.com/openspecs/windows_protocols/ms-psrp/
 *   [MS-WSMV] https://learn.microsoft.com/openspecs/windows_protocols/ms-wsmv/  */

#ifndef PSRP_H
#define PSRP_H

#include <windows.h>

/* BOF runtime imports used by this header.  Duplicate compatible
 * declarations are harmless in a single translation unit.               */
DECLSPEC_IMPORT int     __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strstr(const char*, const char*);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

#ifndef heap_alloc
#define heap_alloc(sz)  KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), \
                                           HEAP_ZERO_MEMORY, (sz))
#define heap_free(p)    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))
#endif

/* -----------------------------------------------------------
 * Constants
 * ----------------------------------------------------------- */

/* PSRP destinations (big-endian on wire). */
#define PSRP_DEST_CLIENT 0x00000001
#define PSRP_DEST_SERVER 0x00000002

/* PSRP message types (big-endian on wire). */
#define PSRP_SESSION_CAPABILITY     0x00010002
#define PSRP_INIT_RUNSPACEPOOL      0x00010004
#define PSRP_APPLICATION_PRIVATE    0x00021002
#define PSRP_RUNSPACEPOOL_STATE     0x00010005
#define PSRP_CREATE_PIPELINE        0x00021006
#define PSRP_PIPELINE_INPUT         0x00041002
#define PSRP_PIPELINE_INPUT_END     0x00041003
#define PSRP_PIPELINE_OUTPUT        0x00041004
#define PSRP_ERROR_RECORD           0x00041005
#define PSRP_PIPELINE_STATE         0x00041006
#define PSRP_DEBUG_RECORD           0x00041007
#define PSRP_VERBOSE_RECORD         0x00041008
#define PSRP_WARNING_RECORD         0x00041009
#define PSRP_PROGRESS_RECORD        0x00041010
#define PSRP_INFORMATION_RECORD     0x00041011
#define PSRP_PIPELINE_HOST_CALL     0x00041100
#define PSRP_PIPELINE_HOST_RESPONSE 0x00041101

/* Pipeline states (from [MS-PSRP] 2.2.3.5). */
#define PSRP_PS_NOT_STARTED  0
#define PSRP_PS_RUNNING      1
#define PSRP_PS_STOPPING     2
#define PSRP_PS_STOPPED      3
#define PSRP_PS_COMPLETED    4
#define PSRP_PS_FAILED       5
#define PSRP_PS_DISCONNECTED 6

/* RunspacePool states (from [MS-PSRP] 2.2.3.4). */
#define PSRP_RS_BEFORE_OPEN  0
#define PSRP_RS_OPENING      1
#define PSRP_RS_OPENED       2
#define PSRP_RS_CLOSED       3
#define PSRP_RS_CLOSING      4
#define PSRP_RS_BROKEN       5

/* Fragment header flags: S=bit 0, E=bit 1 ([MS-PSRP] 2.2.4). */
#define PSRP_FRAG_START 0x01
#define PSRP_FRAG_END   0x02

/* Fixed sizes. */
#define PSRP_MSG_HDR_SIZE  40   /* Destination+MessageType+RPID+PID */
#define PSRP_FRAG_HDR_SIZE 21   /* ObjectId+FragmentId+Flags+BlobLen */

/* -----------------------------------------------------------
 * Big-endian byte helpers (x86/x64 is little-endian)
 * ----------------------------------------------------------- */

static void psrp_write_be32(BYTE *dst, DWORD val)
{
    dst[0] = (BYTE)(val >> 24);
    dst[1] = (BYTE)(val >> 16);
    dst[2] = (BYTE)(val >> 8);
    dst[3] = (BYTE)(val);
}

static DWORD psrp_read_be32(const BYTE *src)
{
    return ((DWORD)src[0] << 24) | ((DWORD)src[1] << 16) |
           ((DWORD)src[2] << 8)  | (DWORD)src[3];
}

static void psrp_write_le32(BYTE *dst, DWORD val)
{
    dst[0] = (BYTE)(val);
    dst[1] = (BYTE)(val >> 8);
    dst[2] = (BYTE)(val >> 16);
    dst[3] = (BYTE)(val >> 24);
}

static DWORD psrp_read_le32(const BYTE *src)
{
    return (DWORD)src[0] | ((DWORD)src[1] << 8) |
           ((DWORD)src[2] << 16) | ((DWORD)src[3] << 24);
}

static void psrp_write_be64(BYTE *dst, UINT64 val)
{
    dst[0] = (BYTE)(val >> 56);
    dst[1] = (BYTE)(val >> 48);
    dst[2] = (BYTE)(val >> 40);
    dst[3] = (BYTE)(val >> 32);
    dst[4] = (BYTE)(val >> 24);
    dst[5] = (BYTE)(val >> 16);
    dst[6] = (BYTE)(val >> 8);
    dst[7] = (BYTE)(val);
}

/* -----------------------------------------------------------
 * PSRP message construction
 *
 * Each PSRP message is:
 *   Destination(4) MessageType(4) RPID(16) PID(16) Data(variable)
 * All multi-byte fields are big-endian on the wire.
 * ----------------------------------------------------------- */

/* Build a raw PSRP message (header + data).
 * |rpid| and |pid| are 16-byte GUIDs.
 * |data| is UTF-8 CLIXML content.
 * Returns heap-allocated bytes; caller frees. */
static BYTE *psrp_build_message(DWORD destination, DWORD messageType,
                                const BYTE rpid[16], const BYTE pid[16],
                                const char *data, DWORD dataLen,
                                DWORD *outLen)
{
    DWORD totalLen = PSRP_MSG_HDR_SIZE + dataLen;
    BYTE *msg = (BYTE *)heap_alloc(totalLen);
    if (!msg) return NULL;

    psrp_write_le32(msg,     destination);
    psrp_write_le32(msg + 4, messageType);
    MSVCRT$memcpy(msg + 8,  rpid, 16);
    MSVCRT$memcpy(msg + 24, pid,  16);
    if (dataLen > 0)
        MSVCRT$memcpy(msg + PSRP_MSG_HDR_SIZE, data, dataLen);

    *outLen = totalLen;
    return msg;
}

/* Wrap a PSRP message in a single fragment (Start + End).
 * |objectId| must be unique per message in the session (> 0).
 * Returns heap-allocated bytes; caller frees. */
static BYTE *psrp_build_fragment(UINT64 objectId, const BYTE *blob,
                                 DWORD blobLen, DWORD *outLen)
{
    DWORD totalLen = PSRP_FRAG_HDR_SIZE + blobLen;
    BYTE *frag = (BYTE *)heap_alloc(totalLen);
    if (!frag) return NULL;

    psrp_write_be64(frag,      objectId);
    psrp_write_be64(frag + 8,  0);         /* FragmentId = 0 */
    frag[16] = PSRP_FRAG_START | PSRP_FRAG_END;
    psrp_write_be32(frag + 17, blobLen);
    MSVCRT$memcpy(frag + PSRP_FRAG_HDR_SIZE, blob, blobLen);

    *outLen = totalLen;
    return frag;
}

/* -----------------------------------------------------------
 * CLIXML content builders
 *
 * Each returns a heap-allocated UTF-8 string and its length.
 * Namespace: http://schemas.microsoft.com/powershell/2004/04
 * (implicit in the PSRP message context).
 * ----------------------------------------------------------- */

/* SESSION_CAPABILITY: protocol 2.2, PS 2.0. */
static char *psrp_session_capability_xml(DWORD *outLen)
{
    static const char xml[] =
        "<Obj RefId=\"0\"><MS>"
          "<Version N=\"protocolversion\">2.2</Version>"
          "<Version N=\"PSVersion\">2.0</Version>"
          "<Version N=\"SerializationVersion\">1.1.0.1</Version>"
        "</MS></Obj>";
    DWORD len = (DWORD)(sizeof(xml) - 1);
    char *buf = (char *)heap_alloc(len + 1);
    if (!buf) return NULL;
    MSVCRT$memcpy(buf, xml, len + 1);
    *outLen = len;
    return buf;
}

/* INIT_RUNSPACEPOOL: single runspace, no host, default options. */
static char *psrp_init_runspacepool_xml(DWORD *outLen)
{
    static const char xml[] =
        "<Obj RefId=\"0\"><MS>"
          "<I32 N=\"MinRunspaces\">1</I32>"
          "<I32 N=\"MaxRunspaces\">1</I32>"
          "<Obj N=\"PSThreadOptions\" RefId=\"1\">"
            "<TN RefId=\"0\">"
              "<T>System.Management.Automation.Runspaces.PSThreadOptions</T>"
              "<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T>"
            "</TN><ToString>Default</ToString><I32>0</I32>"
          "</Obj>"
          "<Obj N=\"ApartmentState\" RefId=\"2\">"
            "<TN RefId=\"1\">"
              "<T>System.Threading.ApartmentState</T>"
              "<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T>"
            "</TN><ToString>Unknown</ToString><I32>2</I32>"
          "</Obj>"
          "<Obj N=\"HostInfo\" RefId=\"3\"><MS>"
            "<B N=\"_isHostNull\">true</B>"
            "<B N=\"_isHostUINull\">true</B>"
            "<B N=\"_isHostRawUINull\">true</B>"
            "<B N=\"_useRunspaceHost\">true</B>"
          "</MS></Obj>"
          "<Nil N=\"ApplicationArguments\" />"
        "</MS></Obj>";
    DWORD len = (DWORD)(sizeof(xml) - 1);
    char *buf = (char *)heap_alloc(len + 1);
    if (!buf) return NULL;
    MSVCRT$memcpy(buf, xml, len + 1);
    *outLen = len;
    return buf;
}

/* CREATE_PIPELINE: single script command.
 * |escapedCmd| must already be XML-escaped. */
static char *psrp_create_pipeline_xml(const char *escapedCmd, DWORD *outLen)
{
    static const char prefix[] =
        "<Obj RefId=\"0\"><MS>"
        "<Obj N=\"PowerShell\" RefId=\"1\"><MS>"
          "<Obj N=\"Cmds\" RefId=\"2\">"
            "<TN RefId=\"0\">"
              "<T>System.Collections.Generic.List`1"
              "[[System.Management.Automation.PSObject, "
              "System.Management.Automation, Version=3.0.0.0, "
              "Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T>"
              "<T>System.Object</T>"
            "</TN><LST><Obj RefId=\"3\"><MS>"
              "<S N=\"Cmd\">";

    static const char suffix[] =
              "</S>"
              "<B N=\"IsScript\">true</B>"
              "<Nil N=\"UseLocalScope\" />"
              "<Obj N=\"MergeMyResult\" RefId=\"4\">"
                "<TN RefId=\"1\">"
                  "<T>System.Management.Automation.Runspaces.PipelineResultTypes</T>"
                  "<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T>"
                "</TN><ToString>None</ToString><I32>0</I32>"
              "</Obj>"
              "<Obj N=\"MergeToResult\" RefId=\"5\">"
                "<TNRef RefId=\"1\" /><ToString>None</ToString><I32>0</I32>"
              "</Obj>"
              "<Obj N=\"MergePreviousResults\" RefId=\"6\">"
                "<TNRef RefId=\"1\" /><ToString>None</ToString><I32>0</I32>"
              "</Obj>"
              "<Obj N=\"MergeError\" RefId=\"7\">"
                "<TNRef RefId=\"1\" /><ToString>None</ToString><I32>0</I32>"
              "</Obj>"
              "<Obj N=\"MergeWarning\" RefId=\"8\">"
                "<TNRef RefId=\"1\" /><ToString>None</ToString><I32>0</I32>"
              "</Obj>"
              "<Obj N=\"MergeVerbose\" RefId=\"9\">"
                "<TNRef RefId=\"1\" /><ToString>None</ToString><I32>0</I32>"
              "</Obj>"
              "<Obj N=\"MergeDebug\" RefId=\"10\">"
                "<TNRef RefId=\"1\" /><ToString>None</ToString><I32>0</I32>"
              "</Obj>"
              "<Obj N=\"MergeInformation\" RefId=\"11\">"
                "<TNRef RefId=\"1\" /><ToString>None</ToString><I32>0</I32>"
              "</Obj>"
              "<Obj N=\"Args\" RefId=\"12\">"
                "<TNRef RefId=\"0\" /><LST />"
              "</Obj>"
            "</MS></Obj></LST>"
          "</Obj>"
          "<B N=\"IsNested\">false</B>"
          "<Nil N=\"History\" />"
          "<B N=\"RedirectShellErrorOutputPipe\">true</B>"
        "</MS></Obj>"
        "<B N=\"NoInput\">true</B>"
        "<Obj N=\"ApartmentState\" RefId=\"13\">"
          "<TN RefId=\"2\">"
            "<T>System.Threading.ApartmentState</T>"
            "<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T>"
          "</TN><ToString>Unknown</ToString><I32>2</I32>"
        "</Obj>"
        "<Obj N=\"RemoteStreamOptions\" RefId=\"14\">"
          "<TN RefId=\"3\">"
            "<T>System.Management.Automation.RemoteStreamOptions</T>"
            "<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T>"
          "</TN><ToString>0</ToString><I32>0</I32>"
        "</Obj>"
        "<B N=\"AddToHistory\">false</B>"
        "<Obj N=\"HostInfo\" RefId=\"15\"><MS>"
          "<B N=\"_isHostNull\">true</B>"
          "<B N=\"_isHostUINull\">true</B>"
          "<B N=\"_isHostRawUINull\">true</B>"
          "<B N=\"_useRunspaceHost\">true</B>"
        "</MS></Obj>"
        "<B N=\"IsNested\">false</B>"
        "</MS></Obj>";

    DWORD prefixLen = (DWORD)(sizeof(prefix) - 1);
    DWORD suffixLen = (DWORD)(sizeof(suffix) - 1);
    DWORD cmdLen    = (DWORD)MSVCRT$strlen(escapedCmd);
    DWORD totalLen  = prefixLen + cmdLen + suffixLen;

    char *buf = (char *)heap_alloc(totalLen + 1);
    if (!buf) return NULL;

    MSVCRT$memcpy(buf, prefix, prefixLen);
    MSVCRT$memcpy(buf + prefixLen, escapedCmd, cmdLen);
    MSVCRT$memcpy(buf + prefixLen + cmdLen, suffix, suffixLen + 1);

    *outLen = totalLen;
    return buf;
}

/* -----------------------------------------------------------
 * Response fragment parsing
 * ----------------------------------------------------------- */

/* Parsed PSRP message extracted from a single fragment. */
typedef struct {
    DWORD destination;
    DWORD messageType;
    BYTE  rpid[16];
    BYTE  pid[16];
    char *data;       /* heap-allocated UTF-8 CLIXML, NUL-terminated */
    DWORD dataLen;
} PSRP_MESSAGE;

/* Parse one single-fragment PSRP message from raw bytes.
 * Returns TRUE on success; |msg->data| must be freed by the caller
 * via psrp_message_free(). */
static BOOL psrp_parse_fragment(const BYTE *raw, DWORD rawLen,
                                PSRP_MESSAGE *msg)
{
    DWORD blobLen;
    const BYTE *blob;

    if (!raw || !msg || rawLen < PSRP_FRAG_HDR_SIZE)
        return FALSE;

    MSVCRT$memset(msg, 0, sizeof(*msg));

    /* Accept only single-fragment messages (both S and E set). */
    if ((raw[16] & (PSRP_FRAG_START | PSRP_FRAG_END)) !=
        (PSRP_FRAG_START | PSRP_FRAG_END))
        return FALSE;

    blobLen = psrp_read_be32(raw + 17);
    if (blobLen < PSRP_MSG_HDR_SIZE ||
        PSRP_FRAG_HDR_SIZE + blobLen > rawLen)
        return FALSE;

    blob = raw + PSRP_FRAG_HDR_SIZE;
    msg->destination = psrp_read_le32(blob);
    msg->messageType = psrp_read_le32(blob + 4);
    MSVCRT$memcpy(msg->rpid, blob + 8,  16);
    MSVCRT$memcpy(msg->pid,  blob + 24, 16);

    msg->dataLen = blobLen - PSRP_MSG_HDR_SIZE;
    if (msg->dataLen > 0) {
        msg->data = (char *)heap_alloc(msg->dataLen + 1);
        if (!msg->data) return FALSE;
        MSVCRT$memcpy(msg->data, blob + PSRP_MSG_HDR_SIZE, msg->dataLen);
        msg->data[msg->dataLen] = 0;
    }
    return TRUE;
}

static void psrp_message_free(PSRP_MESSAGE *msg)
{
    if (msg && msg->data) {
        heap_free(msg->data);
        msg->data    = NULL;
        msg->dataLen = 0;
    }
}

/* -----------------------------------------------------------
 * CLIXML text extraction helpers
 * ----------------------------------------------------------- */

static int clixml_hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode CLIXML _xHHHH_ escape sequences in-place.
 * Skips \r so output uses plain \n line endings. */
static void clixml_decode_escapes(char *text)
{
    char *r, *w;
    if (!text) return;
    for (r = w = text; *r; ) {
        if (r[0] == '_' && r[1] == 'x' && r[6] == '_') {
            int d0 = clixml_hex_digit(r[2]);
            int d1 = clixml_hex_digit(r[3]);
            int d2 = clixml_hex_digit(r[4]);
            int d3 = clixml_hex_digit(r[5]);
            if (d0 >= 0 && d1 >= 0 && d2 >= 0 && d3 >= 0) {
                unsigned val = (d0 << 12) | (d1 << 8) | (d2 << 4) | d3;
                if (val != 0x0D && val < 128) *w++ = (char)val;
                r += 7;
                continue;
            }
        }
        *w++ = *r++;
    }
    *w = 0;
}

/* Extract display text from a PIPELINE_OUTPUT CLIXML payload.
 * Tries <S>text</S> first, then <ToString>text</ToString>.
 * Returns a heap-allocated string, or NULL if nothing found. */
static char *psrp_extract_text(const char *clixml)
{
    const char *start, *end;
    int len;
    char *text;

    if (!clixml) return NULL;

    /* Simple string: <S>text</S> */
    start = MSVCRT$strstr(clixml, "<S>");
    if (start) {
        start += 3;
        end = MSVCRT$strstr(start, "</S>");
        if (end && (len = (int)(end - start)) > 0) {
            text = (char *)heap_alloc(len + 1);
            if (text) {
                MSVCRT$memcpy(text, start, len); text[len] = 0;
                clixml_decode_escapes(text);
            }
            return text;
        }
    }

    /* Object string representation: <ToString>text</ToString> */
    start = MSVCRT$strstr(clixml, "<ToString>");
    if (start) {
        start += 10;
        end = MSVCRT$strstr(start, "</ToString>");
        if (end && (len = (int)(end - start)) > 0) {
            text = (char *)heap_alloc(len + 1);
            if (text) {
                MSVCRT$memcpy(text, start, len); text[len] = 0;
                clixml_decode_escapes(text);
            }
            return text;
        }
    }

    return NULL;
}

/* Extract the pipeline state value from PIPELINE_STATE CLIXML.
 * Returns the integer state (PSRP_PS_*), or -1 on parse failure. */
static int psrp_extract_pipeline_state(const char *clixml)
{
    const char *p;
    int state = 0;

    if (!clixml) return -1;

    p = MSVCRT$strstr(clixml, "N=\"PipelineState\">");
    if (!p) return -1;
    p += 18;

    if (*p < '0' || *p > '9') return -1;
    while (*p >= '0' && *p <= '9') {
        state = state * 10 + (*p - '0');
        p++;
    }
    return state;
}

/* Extract the runspace pool state from RUNSPACEPOOL_STATE CLIXML.
 * Returns the integer state (PSRP_RS_*), or -1 on parse failure. */
__attribute__((unused))
static int psrp_extract_runspace_state(const char *clixml)
{
    const char *p;
    int state = 0;

    if (!clixml) return -1;

    p = MSVCRT$strstr(clixml, "N=\"RunspaceState\">");
    if (!p) return -1;
    p += 18;

    if (*p < '0' || *p > '9') return -1;
    while (*p >= '0' && *p <= '9') {
        state = state * 10 + (*p - '0');
        p++;
    }
    return state;
}

/* Extract error text from an ERROR_RECORD CLIXML payload.
 * Returns a heap-allocated string, or NULL. */
static char *psrp_extract_error_text(const char *clixml)
{
    const char *start, *end;
    int len;
    char *text;

    if (!clixml) return NULL;

    /* Try the exception message first. */
    start = MSVCRT$strstr(clixml, "N=\"Message\">");
    if (start) {
        start += 12;
        /* Find the next closing element (could be </S> or similar). */
        end = MSVCRT$strstr(start, "</");
        if (end && (len = (int)(end - start)) > 0) {
            text = (char *)heap_alloc(len + 1);
            if (text) { MSVCRT$memcpy(text, start, len); text[len] = 0; }
            return text;
        }
    }

    /* Fall back to <ToString>. */
    return psrp_extract_text(clixml);
}

#endif /* PSRP_H */
