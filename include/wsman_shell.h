/* WSMan shell backend types and SOAP fault classification.
 *
 * Data types only -- parsing functions live in winrm_pth.c where
 * they can share existing helpers (find_xml_value, etc.).           */

#ifndef WSMAN_SHELL_H
#define WSMAN_SHELL_H

#include <windows.h>

/* -----------------------------------------------------------
 * SOAP fault classification
 * ----------------------------------------------------------- */

#define WSMAN_FAULT_UNKNOWN       0
#define WSMAN_FAULT_ACCESS_DENIED 1

typedef struct {
    char  code[128];        /* e.g. "s:Sender"                     */
    char  subcodeNs[256];   /* subcode namespace URI                */
    char  subcodeName[128]; /* subcode local name (e.g. AccessDenied) */
    char  reason[512];      /* human-readable reason text           */
    int   kind;             /* WSMAN_FAULT_* convenience constant   */
} WSMAN_FAULT;

/* -----------------------------------------------------------
 * Shell result model
 * ----------------------------------------------------------- */

#define SHELL_BACKEND_CMD   0  /* shell/cmd (text command shell) */
#define SHELL_BACKEND_PSRP  1  /* PowerShell Remoting Protocol   */

#define SHELL_OK            0
#define SHELL_ERR_TRANSPORT 1
#define SHELL_ERR_AUTH      2
#define SHELL_ERR_DENIED    3
#define SHELL_ERR_PROTOCOL  4
#define SHELL_ERR_TIMEOUT   5
#define SHELL_ERR_ALLOC     6

typedef struct {
    int   backend;     /* SHELL_BACKEND_CMD or SHELL_BACKEND_PSRP  */
    int   status;      /* SHELL_OK or SHELL_ERR_*                  */
    DWORD httpStatus;  /* last HTTP status code                    */
    int   exitCode;    /* process exit code (-1 if unknown)        */
    BOOL  hasOutput;   /* TRUE if stdout/stderr were delivered     */
    WSMAN_FAULT fault; /* populated on SOAP fault responses        */
} SHELL_RESULT;

/* -----------------------------------------------------------
 * WSMan resource URIs
 * ----------------------------------------------------------- */

#define CMD_RESOURCE_URI \
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
#define PS_RESOURCE_URI \
    "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"

#endif /* WSMAN_SHELL_H */
