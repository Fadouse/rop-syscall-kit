#ifndef _SHARED_HPP_
#define _SHARED_HPP_

#include <Windows.h>
#include <winternl.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS 0x00000000

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)-1)
#endif

#ifndef SEC_NO_CHANGE
#define SEC_NO_CHANGE 0x00400000
#endif

#ifndef ViewShare
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;
#endif

#endif