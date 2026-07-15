#ifndef _LWEXT4_SHIM_STDIO_H
#define _LWEXT4_SHIM_STDIO_H
#include <stddef.h>
#include <stdarg.h>
int printf(const char *, ...);
int snprintf(char *, size_t, const char *, ...);
int vsnprintf(char *, size_t, const char *, va_list);
int puts(const char *);
#endif
