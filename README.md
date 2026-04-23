# FreeImage-BMP-Crash
PoC, crash samples, and root-cause analysis for a FreeImage 3.18.0 BMP out-of-bounds write caused by negative biWidth and pitch wraparound.

# FreeImage BMP Crash

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

Because the issue is an out-of-bounds write caused by attacker-controlled image metadata, the vulnerability also represents a memory corruption primitive. Depending on allocator behavior, surrounding heap layout, and target application integration, more serious impacts may be possible.

At minimum, the issue should be treated as a security-relevant memory corruption bug in a file parser.

## 6. Why the Bug Happens

This bug is caused by inconsistent handling of signed image dimensions across the BMP loading pipeline.

- `LoadWindowsBMP` uses the raw signed `biWidth` to compute `pitch`.
- `LoadPixelData` consumes the resulting wrapped unsigned `pitch`.
- `FreeImage_AllocateBitmap` separately normalizes dimensions using `abs(width)` / `abs(height)`.

This means the allocated image buffer size and the subsequent row-read size are derived under different assumptions, making memory corruption possible.
