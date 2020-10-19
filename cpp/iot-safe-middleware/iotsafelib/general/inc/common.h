#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <iostream>
#include "ROT.h"

#define TIMEOUT_SEC 2 // To avoid hangs on the middleware side

// The following are log levels that can be passed by the Python application to facilitate
// debugging. Note that the order is important as they represent the level.
#define PY_LOG_LEVEL_DEBUG   0
#define PY_LOG_LEVEL_INFO    1
#define PY_LOG_LEVEL_NOTICE  2
#define PY_LOG_LEVEL_WARNING 3
#define PY_LOG_LEVEL_ERROR   4

extern int PY_LOG_LEVEL;


/******************************* Logging functions *******************************/


// The following is used to provide a time stamp
#include <time.h>
static inline const char *__timestamp( void ) {
    static char tsbuf[64];
    struct timespec tsnow;
    clock_gettime(CLOCK_REALTIME, &tsnow );
    struct tm *tm_now = localtime( (time_t *) &tsnow.tv_sec );
    strftime( tsbuf, sizeof(tsbuf), "%Y%m%d-%H:%M:%S", tm_now );
    sprintf( &tsbuf[17], ".%03d", (unsigned)(tsnow.tv_nsec / 1000000) );
    return &tsbuf[0];
}

// This function is used to log various events to report to Python to facilitate
// debugging. The interface is almost equivalent to that of "printf()", but the
// first argument is a log level. E.g.:
// _log( PY_LOG_LEVEL_INFO, "Show some info: %s", someString );
#define _log( u8LogLevel, ...) do{ _logPrintf( u8LogLevel, __VA_ARGS__ ); } while(0)
#define _logPrintf( u8LogLevel, ... )                                       \
    do {                                                                    \
        if( u8LogLevel >= PY_LOG_LEVEL ) {                                  \
            switch( u8LogLevel ){                                           \
                case PY_LOG_LEVEL_DEBUG:                                    \
                    fprintf(stderr, "[ DEBUG ]  ");                         \
                    break;                                                  \
                case PY_LOG_LEVEL_INFO:                                     \
                    fprintf(stderr, "[ INFO ]   ");                         \
                    break;                                                  \
                case PY_LOG_LEVEL_NOTICE:                                   \
                    fprintf(stderr, "[ NOTICE ] ");                         \
                    break;                                                  \
                case PY_LOG_LEVEL_WARNING:                                  \
                    fprintf(stderr, "[ WARNING ]");                         \
                    break;                                                  \
                case PY_LOG_LEVEL_ERROR:                                    \
                    fprintf(stderr, "[ ERROR ]  ");                         \
                    break;                                                  \
                default:                                                    \
                    fprintf(stderr, "[ DEBUG ]  ");                         \
            }                                                               \
            fprintf(stderr, "%s: ", __timestamp());                         \
            fprintf(stderr, __VA_ARGS__);                                   \
            fprintf(stderr, "\n");                                          \
        }                                                                   \
    } while(0)                                                              \

// This doesn't have much of an effect. It just makes things a little prettier
typedef int PY_ERR;


/******************************* Useful constants *******************************/


// FIXME: Still need to check documentation for these. Would be better to obtain
// some of these by querying the SIM card.
#define MIN_CONTAINER_ID    1
#define MAX_CONTAINER_ID    10
#define MAX_CERTIFICATE_LEN 2048
#define MAX_SIGNATURE_LEN   72
#define MAX_HASH_LEN        0x20
#define MAX_SIZE_URL_PORT   0x100


/******************************* ASN.1 Values *******************************/
#define ASN1_OCTET_STRING_ID 0x30


/******************************* Declaration of functions *******************************/
void initLogLevel( uint8_t u8LogLevel );
