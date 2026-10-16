#pragma once

#ifdef __x86_64

#define WINAPI __attribute__((ms_abi))
#define WINAPIV __attribute__((ms_abi))

#else

#define WINAPI __attribute__((stdcall)) // callee pops
#define WINAPIV __attribute__((cdecl))  // caller pops

#endif
