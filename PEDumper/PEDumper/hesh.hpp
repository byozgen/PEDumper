#pragma once

#include <stdio.h>
#include "windows.h"

#include <stdio.h>

DWORD updateCRC32(unsigned char ch, DWORD crc);
DWORD crc32buf(char *buf, size_t len);

#define UPDC32(b, c) (crc_32_tab[((int)c ^ b) & 0xff] ^ ((c >> 8) & 0x00FFFFFF))