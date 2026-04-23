# FreeImage-BMP-Crash

Crash samples and analysis for a crafted BMP parsing vulnerability in FreeImage.

# Out-of-Bounds Write Vulnerability in FreeImage (PluginBMP)

**Author**: MiracleWolf  
**Date**: 2026-04-23  
**Vendor**: FreeImage Project  
**Product**: FreeImage  
**Version**: 3.18.0  
**Vulnerability Type**: Out-of-Bounds Write / Integer Handling Bug  
**Platform**: Windows  

## 1. Summary

An out-of-bounds write vulnerability was identified in FreeImage 3.18.0 while parsing crafted BMP files in the Windows BMP loader (`PluginBMP.cpp`).

The issue occurs when a malicious BMP image provides a negative `biWidth` value in the `BITMAPINFOHEADER`. The loader uses this signed value directly when calculating `pitch` inside `LoadWindowsBMP`. The computed value wraps into a very large unsigned integer and is later consumed by `LoadPixelData`, which uses it as the row-read size. As a result, FreeImage performs an invalid memory write during bitmap loading, causing a crash and potentially enabling further memory corruption.

## 2. Root Cause Analysis

**Affected file**: `Source/FreeImage/PluginBMP.cpp`

### 2.1 Vulnerable control flow

The vulnerable path is:

```cpp
FreeImage_LoadU
  -> FreeImage_LoadFromHandle
    -> Load
      -> LoadWindowsBMP
        -> LoadPixelData
          -> _ReadProc
            -> fread
              -> memcpy
```

### 2.2 Root cause

Inside `LoadWindowsBMP`, FreeImage reads the BMP header fields and directly uses the signed `biWidth` value to derive `pitch`:

```cpp
int width             = bih.biWidth;
int height            = bih.biHeight;
unsigned bit_count    = bih.biBitCount;
unsigned pitch        = CalculatePitch(CalculateLine(width, bit_count));
```

If `bih.biWidth` is negative, the intermediate line/pitch calculation becomes negative and is then converted to an unsigned value. For the crashing sample analyzed here:

- `biWidth = -255`
- `biHeight = -3`
- `biBitCount = 24`
- `pitch = 0xFFFFFD04`

The computed `pitch` is then passed into `LoadPixelData`:

```cpp
LoadPixelData(io, handle, dib, height, pitch, bit_count);
```

Inside `LoadPixelData`, when `height < 0`, FreeImage treats the BMP as a top-down bitmap and performs per-row reads using the wrapped `pitch` value:

```cpp
count = io->read_proc(
    (void *)FreeImage_GetScanLine(dib, positiveHeight - c - 1),
    pitch,
    1,
    handle
);
```

This causes an oversized read into a much smaller heap-backed image buffer and results in an out-of-bounds write.

### 2.3 Why this is distinct from prior FreeImage issues

This issue is not the same as previously disclosed FreeImage vulnerabilities affecting other paths.

- It is **not** the BMP `LoadPixelDataRLE4` issue.
- It is **not** a direct `FreeImage_AllocateBitmap` excessive-allocation issue.
  A key observation is that `FreeImage_AllocateBitmap` normalizes dimensions using `abs(width)` and `abs(height)`, meaning allocation proceeds using positive dimensions, while the BMP loading logic still uses the original signed header values to compute `pitch`. This mismatch between allocation semantics and load semantics is central to this bug.

## 3. Proof of Concept (PoC)

### 3.1 Reproduction environment

- **OS**: Windows 10 / Windows 11 x64
- **Compiler**: MSVC (Visual Studio)
- **Library build**: FreeImage 3.18.0
- **Target**: BMP loader (`PluginBMP.cpp`)

### 3.2 Trigger condition

The crafted BMP sample contains a malicious `BITMAPINFOHEADER` with:

- `biSize = 0x28`
- `biWidth = -255`
- `biHeight = -3`
- `biBitCount = 24`
- `biCompression = BI_RGB`

These values cause pitch wraparound during loading.

### 3.3 Example debugger evidence

The header fields observed in WinDbg:

```text
dt tagBITMAPINFOHEADER 001af94c
   +0x000 biSize           : 0x28
   +0x004 biWidth          : 0n-255
   +0x008 biHeight         : 0n-3
   +0x00c biPlanes         : 1
   +0x00e biBitCount       : 0x18
   +0x010 biCompression    : 0
```

The corresponding local variables inside `LoadWindowsBMP`:

```text
width       = 0n-255
height      = 0n-3
bit_count   = 0x18
compression = 0
pitch       = 0xfffffd04
```

The crash path observed in WinDbg:

```text
FreeImaged!memcpy
FreeImaged!fread
FreeImaged!_ReadProc
FreeImaged!LoadPixelData
FreeImaged!LoadWindowsBMP
FreeImaged!Load
FreeImaged!FreeImage_LoadFromHandle
FreeImaged!FreeImage_LoadU
```

## 4. Crash Evidence

### 4.1 WinDbg summary

```text
ExceptionCode: c0000005 (Access violation)
AV.Type: Write
Failure.Bucket: INVALID_POINTER_WRITE_AVRF_c0000005_FreeImaged.dll!memcpy
```

### 4.2 Faulting write

```text
Attempt to write to address 06c71000
```

### 4.3 Relevant stack

```text
FreeImaged!memcpy
FreeImaged!memcpy_s
FreeImaged!_fread_nolock_s
FreeImaged!fread_s
FreeImaged!fread
FreeImaged!_ReadProc
FreeImaged!LoadPixelData
FreeImaged!LoadWindowsBMP
FreeImaged!Load
FreeImaged!FreeImage_LoadFromHandle
FreeImaged!FreeImage_LoadU
```

## 5. Security Impact

The immediate impact is denial of service through a controlled crash during BMP parsing.

Because the issue is an out-of-bounds write caused by attacker-controlled image metadata, the vulnerability also represents a memory corruption primitive. Depending on allocator behavior, surrounding heap layout, and target application integration, more serious impacts may be possible,such as RCE.

## 6. Why the Bug Happens

This bug is caused by inconsistent handling of signed image dimensions across the BMP loading pipeline.

- `LoadWindowsBMP` uses the raw signed `biWidth` to compute `pitch`.
- `LoadPixelData` consumes the resulting wrapped unsigned `pitch`.
- `FreeImage_AllocateBitmap` separately normalizes dimensions using `abs(width)` / `abs(height)`.
  This means the allocated image buffer size and the subsequent row-read size are derived under different assumptions, making memory corruption possible.

## 7. details of windbg

g
ModLoad: 10000000 107df000   C:\Users\Administrator\source\repos\Freeimage_test\Debug\FreeImaged.dll
ModLoad: 77a80000 77ae9000   C:\WINDOWS\SysWOW64\WS2_32.dll
ModLoad: 75180000 75290000   C:\WINDOWS\SysWOW64\ucrtbase.dll
ModLoad: 75e20000 75edc000   C:\WINDOWS\SysWOW64\RPCRT4.dll
(5848.256c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.

eax=06cd0ff8 ebx=00227000 ecx=00000c7a edx=00000f8a esi=06cd037e edi=06cd5000
eip=10429fee esp=001af44c ebp=001af47c iopl=0         nv up ei pl nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010207
FreeImaged!memcpy+0x4e:
10429fee f3a4            rep movs byte ptr es:[edi],byte ptr [esi]

!analyze -v
Reloading current modules
..*** WARNING: Unable to verify checksum for C:\Users\Administrator\source\repos\Freeimage_test\Debug\FreeImaged.dll
...........

*******************************************************************************

*                                                                             *
*                                                                             Exception Analysis                                   *
*                                                                             *

*******************************************************************************

*** WARNING: Unable to verify checksum for Freeimage_test.exe

KEY_VALUES_STRING: 1

    Key  : AV.Type
    Value: Write
    
    Key  : Analysis.CPU.mSec
    Value: 703
    
    Key  : Analysis.Elapsed.mSec
    Value: 2420
    
    Key  : Analysis.IO.Other.Mb
    Value: 0
    
    Key  : Analysis.IO.Read.Mb
    Value: 1
    
    Key  : Analysis.IO.Write.Mb
    Value: 0
    
    Key  : Analysis.Init.CPU.mSec
    Value: 531
    
    Key  : Analysis.Init.Elapsed.mSec
    Value: 78363
    
    Key  : Analysis.Memory.CommitPeak.Mb
    Value: 69
    
    Key  : Analysis.Version.DbgEng
    Value: 10.0.29547.1002
    
    Key  : Analysis.Version.Description
    Value: 10.2602.27.2 x86fre
    
    Key  : Analysis.Version.Ext
    Value: 1.2602.27.2
    
    Key  : Failure.Bucket
    Value: INVALID_POINTER_WRITE_AVRF_c0000005_FreeImaged.dll!memcpy
    
    Key  : Failure.Exception.Code
    Value: 0xc0000005
    
    Key  : Failure.Exception.IP.Address
    Value: 0x10429fee
    
    Key  : Failure.Exception.IP.Module
    Value: FreeImaged
    
    Key  : Failure.Exception.IP.Offset
    Value: 0x429fee
    
    Key  : Failure.Hash
    Value: {74238755-fb5e-bef2-03b3-df2a4e5fc2b9}
    
    Key  : Failure.ProblemClass.Primary
    Value: INVALID_POINTER_WRITE
    
    Key  : Faulting.IP.Type
    Value: Paged
    
    Key  : Timeline.OS.Boot.DeltaSec
    Value: 590445
    
    Key  : Timeline.Process.Start.DeltaSec
    Value: 78
    
    Key  : WER.OS.Branch
    Value: ge_release
    
    Key  : WER.OS.Version
    Value: 10.0.26100.1


NTGLOBALFLAG:  2000000

APPLICATION_VERIFIER_FLAGS:  0

APPLICATION_VERIFIER_LOADED: 1

EXCEPTION_RECORD:  (.exr -1)
ExceptionAddress: 10429fee (FreeImaged!memcpy+0x0000004e)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000001
   Parameter[1]: 06cd5000
Attempt to write to address 06cd5000

FAULTING_THREAD:  256c

PROCESS_NAME:  Freeimage_test.exe

WRITE_ADDRESS:  06cd5000 

ERROR_CODE: (NTSTATUS) 0xc0000005 - 0x%p            0x%p                    %s

EXCEPTION_CODE_STR:  c0000005

EXCEPTION_PARAMETER1:  00000001

EXCEPTION_PARAMETER2:  06cd5000

STACK_TEXT:  
001af450 10430de1     06cd4cf0 06cd006e 00000f8a FreeImaged!memcpy+0x4e
001af47c 104455b5     06cd4cf0 ffffffff 06cd006e FreeImaged!memcpy_s+0x101
001af508 104459e2     06cd4cf0 ffffffff fffffd04 FreeImaged!_fread_nolock_s+0x395
001af558 104458bc     06cd4cf0 ffffffff fffffd04 FreeImaged!fread_s+0x112
001af574 1000f95c     06cd4cf0 fffffd04 00000001 FreeImaged!fread+0x1c
001af658 1001b3cf     06cd4cf0 fffffd04 00000001 FreeImaged!_ReadProc+0x2c
001af760 1001c58a     001afcd0 06cc2fc0 06cd2ff8 FreeImaged!LoadPixelData+0xaf
001af9a4 1001a4dc     001afcd0 06cc2fc0 00000000 FreeImaged!LoadWindowsBMP+0x70a
001afac4 10019bb8     001afcd0 06cc2fc0 ffffffff FreeImaged!Load+0x15c
001afbd0 10019c56     00000000 001afcd0 06cc2fc0 FreeImaged!FreeImage_LoadFromHandle+0x88
001afce4 0041253f     00000000 05d50fe0 00000000 FreeImaged!FreeImage_LoadU+0x56
001afdd0 00412e13     10000000 05d50fe0 00411028 Freeimage_test!FreeImage_test+0x4f
001afee8 004137e3     00000002 05d4cf90 05c0bee8 Freeimage_test!main+0x383
001aff08 00413637     c7d360e1 00411028 00411028 Freeimage_test!invoke_main+0x33
001aff64 004134cd     001aff74 00413868 001aff84 Freeimage_test!__scrt_common_main_seh+0x157
001aff6c 00413868     001aff84 77205d49 00227000 Freeimage_test!__scrt_common_main+0xd
001aff74 77205d49     00227000 77205d30 001affdc Freeimage_test!mainCRTStartup+0x8
001aff84 77e7d83b     00227000 4be8a31b 00000000 KERNEL32!BaseThreadInitThunk+0x19
001affdc 77e7d7c1     ffffffff 77ec480b 00000000 ntdll!__RtlUserThreadStart+0x2b
001affec 00000000     00411028 00227000 00000000 ntdll!_RtlUserThreadStart+0x1b


STACK_COMMAND: ~0s; .ecxr ; kb

IP_IN_PAGED_CODE: 
FreeImaged!memcpy+4e [D:\a\_work\1\s\src\vctools\crt\vcruntime\src\string\i386\memcpy.asm @ 194]
10429fee f3a4            rep movs byte ptr es:[edi],byte ptr [esi]

FAULTING_SOURCE_LINE:  D:\a\_work\1\s\src\vctools\crt\vcruntime\src\string\i386\memcpy.asm

FAULTING_SOURCE_FILE:  D:\a\_work\1\s\src\vctools\crt\vcruntime\src\string\i386\memcpy.asm

FAULTING_SOURCE_LINE_NUMBER:  194

FAULTING_SOURCE_CODE:  
No source found for 'D:\a\_work\1\s\src\vctools\crt\vcruntime\src\string\i386\memcpy.asm'


SYMBOL_NAME:  FreeImaged!memcpy+4e

MODULE_NAME: FreeImaged

IMAGE_NAME:  FreeImaged.dll

FAILURE_BUCKET_ID:  INVALID_POINTER_WRITE_AVRF_c0000005_FreeImaged.dll!memcpy

OS_VERSION:  10.0.26100.1

BUILDLAB_STR:  ge_release

OSPLATFORM_TYPE:  x86

OSNAME:  Windows 10

IMAGE_VERSION:  3.18.0.0

FAILURE_ID_HASH:  {74238755-fb5e-bef2-03b3-df2a4e5fc2b9}

Followup:     MachineOwner
---------

0:000> kp

 # ChildEBP RetAddr      

00 001af450 10430de1     FreeImaged!memcpy(unsigned char * dst = 0x06cd4cf0 "???", unsigned char * src = 0xffffffff "--- memory read error at address 0xffffffff ---", unsigned long count = 0x6cd006e)+0x4e [D:\a\_work\1\s\src\vctools\crt\vcruntime\src\string\i386\memcpy.asm @ 194] 
01 001af47c 104455b5     FreeImaged!memcpy_s(void * _Destination = 0x06cd4cf0, unsigned int _DestinationSize = 0xffffffff, void * _Source = 0x06cd006e, unsigned int _SourceSize = 0xf8a)+0x101 [minkernel\crts\ucrt\inc\corecrt_memcpy_s.h @ 63] 
02 001af508 104459e2     FreeImaged!_fread_nolock_s(void * buffer = 0x06cd4cf0, unsigned int buffer_size = 0xffffffff, unsigned int element_size = 0xfffffd04, unsigned int element_count = 1, struct _iobuf * public_stream = 0x06cc2fc0)+0x395 [minkernel\crts\ucrt\src\appcrt\stdio\fread.cpp @ 131] 
03 001af558 104458bc     FreeImaged!fread_s(void * buffer = 0x06cd4cf0, unsigned int buffer_size = 0xffffffff, unsigned int element_size = 0xfffffd04, unsigned int element_count = 1, struct _iobuf * stream = 0x06cc2fc0)+0x112 [minkernel\crts\ucrt\src\appcrt\stdio\fread.cpp @ 56] 
04 001af574 1000f95c     FreeImaged!fread(void * buffer = 0x06cd4cf0, unsigned int element_size = 0xfffffd04, unsigned int element_count = 1, struct _iobuf * stream = 0x06cc2fc0)+0x1c [minkernel\crts\ucrt\src\appcrt\stdio\fread.cpp @ 239] 
05 001af658 1001b3cf     FreeImaged!_ReadProc(void * buffer = 0x06cd4cf0, unsigned int size = 0xfffffd04, unsigned int count = 1, void * handle = 0x06cc2fc0)+0x2c [D:\FreeImage\Source\FreeImage\FreeImageIO.cpp @ 32] 
06 001af760 1001c58a     FreeImaged!LoadPixelData(struct FreeImageIO * io = 0x001afcd0, void * handle = 0x06cc2fc0, struct FIBITMAP * dib = 0x06cd2ff8, int height = 0n-3, unsigned int pitch = 0xfffffd04, unsigned int bit_count = 0x18)+0xaf [D:\FreeImage\Source\FreeImage\PluginBMP.cpp @ 165] 
07 001af9a4 1001a4dc     FreeImaged!LoadWindowsBMP(struct FreeImageIO * io = 0x001afcd0, void * handle = 0x06cc2fc0, int flags = 0n0, unsigned int bitmap_bits_offset = 0x76, int type = 0n40)+0x70a [D:\FreeImage\Source\FreeImage\PluginBMP.cpp @ 650] 
08 001afac4 10019bb8     FreeImaged!Load(struct FreeImageIO * io = 0x001afcd0, void * handle = 0x06cc2fc0, int page = 0n-1, int flags = 0n0, void * data = 0x00000000)+0x15c [D:\FreeImage\Source\FreeImage\PluginBMP.cpp @ 1135] 
09 001afbd0 10019c56     FreeImaged!FreeImage_LoadFromHandle(FREE_IMAGE_FORMAT fif = FIF_BMP (0n0), struct FreeImageIO * io = 0x001afcd0, void * handle = 0x06cc2fc0, int flags = 0n0)+0x88 [D:\FreeImage\Source\FreeImage\Plugin.cpp @ 388] 
0a 001afce4 0041253f     FreeImaged!FreeImage_LoadU(FREE_IMAGE_FORMAT fif = FIF_BMP (0n0), wchar_t * filename = 0x05d50fe0 "id_000001_00", int flags = 0n0)+0x56 [D:\FreeImage\Source\FreeImage\Plugin.cpp @ 428] 
0b 001afdd0 00412e13     Freeimage_test!FreeImage_test(struct HINSTANCE__ * hinstLib = 0x10000000, wchar_t * pathfile = 0x05d50fe0 "id_000001_00")+0x4f [C:\Users\Administrator\source\repos\Freeimage_test\main.cpp @ 159] 
0c 001afee8 004137e3     Freeimage_test!main(int argc = 0n2, char  argv = 0x05d4cf90)+0x383 [C:\Users\Administrator\source\repos\Freeimage_test\main.cpp @ 142] 
0d 001aff08 00413637     Freeimage_test!invoke_main(void)+0x33 [D:\a\_work\1\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 78] 
0e 001aff64 004134cd     Freeimage_test!scrt_common_main_seh(void)+0x157 [D:\a\_work\1\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 288] 
0f 001aff6c 00413868     Freeimage_test!scrt_common_main(void)+0xd [D:\a\_work\1\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 331] 
10 001aff74 77205d49     Freeimage_test!mainCRTStartup(void * formal = 0x00227000)+0x8 
12 001affdc 77e7d7c1     ntdll!RtlUserThreadStart+0x2b
13 001affec 00000000     ntdll!_RtlUserThreadStart+0x1b



