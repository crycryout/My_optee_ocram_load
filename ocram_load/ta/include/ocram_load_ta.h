#ifndef TA_OCRAM_LOAD_H
#define TA_OCRAM_LOAD_H

#include <stdint.h>

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_OCRAM_LOAD_UUID \
    { 0x8aaaf200, 0x2450, 0x11e4, \
        { 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }

/* The function IDs implemented in this TA */
#define TA_OCRAM_LOAD_CMD_INC_VALUE        0
#define TA_OCRAM_LOAD_CMD_DEC_VALUE        1
#define TA_OCRAM_LOAD_CMD_MAP_MEMORY       2
#define TA_OCRAM_LOAD_CMD_LOAD             3
#define TA_OCRAM_LOAD_CMD_STORE            4

#endif /*TA_OCRAM_LOAD_H*/
