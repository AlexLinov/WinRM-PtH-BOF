/* BOF API declarations. */
#ifndef WINRM_PTH_BEACON_H
#define WINRM_PTH_BEACON_H

#include <windows.h>

DECLSPEC_IMPORT void  BeaconPrintf(int type, const char *format, ...);

/* Data-parsing API (works across CS, Sliver, Mythic, etc.) */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

DECLSPEC_IMPORT void  BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *parser, int *size);
DECLSPEC_IMPORT int   BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int   BeaconDataLength(datap *parser);

#define CALLBACK_OUTPUT 0x00
#define CALLBACK_ERROR  0x0d

#endif
