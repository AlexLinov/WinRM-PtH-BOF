/* BOF API declarations. */
#ifndef WINRM_PTH_BEACON_H
#define WINRM_PTH_BEACON_H

#include <windows.h>

DECLSPEC_IMPORT void  BeaconPrintf(int type, const char *format, ...);

#define CALLBACK_OUTPUT 0x00
#define CALLBACK_ERROR  0x0d

#endif
