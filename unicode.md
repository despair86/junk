# MSJ Dec 1997: Under the Hood

by Matt Pietrek

Let’s have a quick show of hands. How many of you have ignored Unicode? If you’re like me, you haven’t taken the time to really understand it (at least not until recently). After all, Unicode is completely supported only on Windows NT®, meaning a Unicode-based program almost certainly won’t run on Windows® 95. In addition, all those funky Unicode macros are a pain to work with and make your code harder to read. Well, if you’ve been holding out on using Unicode, I’ve got some pretty interesting test results that might make you reconsider. 

If you’re up on the architecture of Windows NT, you’ve probably heard that, under the skin, Windows NT uses Unicode through-and-through. If you use the ANSI (single character) version of an API function, Windows NT converts ANSI to Unicode strings and uses the Unicode version to do the real work. When passing a string to an ANSI-based API (for example, `SetComputerNameA(2)`), Windows NT converts the ANSI input string to Unicode before calling the Unicode version of the API (for instance, `SetComputerNameW(2)`). When calling an API where an ANSI string buffer is filled in (for example, `GetCurrentDirectoryA(2)`), Windows NT uses a Unicode string internally and converts it to ANSI before the API returns.

This month I’ll show you how Windows NT supports ANSI-based functions. Then I’ll run through a small test program I whipped up to give you an idea of the overhead involved in using ANSI functions with Windows NT. Afterward, it should be pretty clear why all of the programs that come with Windows NT are compiled to use the Unicode APIs. Surprised? Even the omnipresent `CALC.EXE` is a Unicode program.

To say that Windows NT supports Unicode is a misnomer. A more accurate description is that Windows NT uses Unicode strings natively, and that it also supports ANSI (8-bit) strings. But using ANSI APIs will cost you performance. As you’ll see, the ANSI APIs spend a great deal of time in code unrelated to their primary purpose. I’ll spend the bulk of this column describing the Windows NT support functions for APIs that use ANSI strings.

Where does Windows NT keep the strings that it’s translated between ANSI and Unicode? A quick answer might be, “On the stack!” But you’d be wrong if you guessed this. For one thing, it would be a real pain to handle APIs that pass in null-terminated strings. Without knowing in advance how long a string will be, you can’t declare a local variable buffer that you know will be big enough to handle all input strings.

Windows NT manages the ANSI/Unicode translation strings in two ways. For starters, every thread has a buffer reserved for the purpose of holding Unicode strings translated from ANSI strings. In situations where the maximum string length is known in advance, the ANSI APIs use this buffer. When you step through a system DLL and see code that looks like this

```
MOV EAX,FS:[00000018]
LEA ESI,[EAX+00000BF8]
```

you’ve encountered the per-thread Unicode string buffer in action. In my May 1996 Under the Hood column I described how `FS:[00000018]` contains a pointer to a per-thread data structure. In the code snippet above, the Unicode string buffer is at offset `0xBF8` in this structure.

The other way Windows NT manages ANSI/Unicode string translation is by allocating memory for the buffer. This is most likely to occur in situations where an API takes multiple string parameters or works with strings that may be longer than the per-thread Unicode string buffer can accommodate. I’ll show you some examples of this later.

Before digging into the ANSI support runtime library functions, the concept of the `RTL_STRING` needs to be explained. An `RTL_STRING` structure is used to represent both ANSI and Unicode strings. It looks something like this:

```c
typedef struct _RTL_STRING
{
    WORD    len;
    WORD    maxLen;
    PVOID   pBuffer;
} RTL_STRING, * PRTL_STRING;
```

Although the names I use here are probably not exactly what’s in the Windows NT sources, they’re good enough to understand what’s going on. The `len` field describes how long a string currently is, in bytes. The `maxLen` field tells the size of the biggest possible string (in bytes) that could fit into this `RTL_STRING`. The last field, `pBuffer`, is a pointer to a buffer containing the string. The buffer is at least `maxLen` bytes in length. Now let’s move to the APIs and functions that translate strings using `RTL_STRING`.

## The Windows NT ANSI String Support Library

Many of the internal Windows NT functions that work with strings expect those strings to be in the `RTL_STRING` format. On the other hand, the Win32® APIs typically work with null-terminated strings. As you’d expect, there’s an API to create an `RTL_STRING` from a null-terminated ANSI or Unicode string. It’s called `RtlInitAnsiString(2)` and, like all of the APIs I’ll describe here, the API is exported from `NTDLL.DLL`.

Figure 1 shows the code for `RtlInitAnsiString(2)`. It takes a pointer to where the `RTL_STRING` should be created, as well as a pointer to the null-terminated ANSI string. The API points the `pBuffer` field directly at the null-terminated string. It then uses an optimized inline version of the `strlen(3)` function to set the `len` and `maxLen` fields accordingly. The `maxLen` field is always set to one more than the `len` field to account for the null terminator.

### Figure 1: `RtlInitAnsiString(2)`

```c
void RtlInitAnsiString( RTL_STRING * pRtlString, PSTR psz )
{
    pRtlString->len = 0;
    pRtlString->maxLen = 0;
    pRtlString->pBuffer = psz;

    if ( psz )
    {
        DWORD cChars = strlen( psz ) + 1;   // This strlen is done inline
        pRtlString->maxLen = cChars;
        pRtlString->len = cChars - 1;
    }
}
```

On the Unicode side of things, the equivalent API is `RtlInitUnicodeString(2)` shown in Figure 2. It looks exactly like the ANSI version except that when calculating the length of the string it uses an inlined version of `wcslen(3)` rather than `strlen(3)`. (`wcslen(3)` is the wide character version of `strlen(3)`?the wcs prefix is short for `wide character string`.) If you dig through `STRING.H`, you’ll see that most of the wide character equivalents to the str functions simply replace the `str` in their name with `wcs`.

### Figure 2: `RtlInitUnicodeString(2)`

```c
void RtlInitUnicodeString( RTL_STRING * pRtlString, PWSTR pwsz )
{
    pRtlString->len = 0;
    pRtlString->maxLen = 0;
    pRtlString->pBuffer = pwsz;

    if ( pwsz )
    {
        DWORD cChars = wcslen( pwsz ) + 1;  // This wcslen is done inline
        pRtlString->maxLen = cChars;
        pRtlString->len = cChars - 1;
    }
}
```

Converting between Unicode and ANSI strings is handled via a pair of NTDLL APIs: `RtlUnicodeStringToAnsiString(2)` and `RtlAnsiStringToUnicodeString(2)`. Both APIs take two `RTL_STRING`s as their first two parameters. One of the `RTL_STRING`s is the source and the other is the destination. The third parameter tells the APIs if they should allocate memory for the destination `RTL_STRING`’s buffer. Passing `FALSE` (don’t allocate) means that the destination `RTL_STRING` has a valid `pBuffer` field and that the `len` and `maxLen` fields are initialized. Passing `TRUE` indicates that the API should determine how big the destination buffer should be, allocate enough memory for it, and set the `len` and `maxLen` fields accordingly.

Figure 3 provides pseudocode for `RtlUnicodeStringToAnsiString(2)`. The code is pretty simple, so I won’t give a blow-by-blow account. A few things are worth highlighting, though. Near the beginning of the function, it checks how long the destination string would be. If this size exceeds 64KB, the function bails out. The implication is that at least some parts of Windows NT won’t deal with strings greater than 64KB (I know, a real killer limitation for most of you).

### Figure 3: `RtlUnicodeStringToAnsiString(2)`

```c
DWORD RtlUnicodeStringToAnsiString( RTL_STRING * pAnsiRtlString,
                                    RTL_STRING * pUniRtlString, 
                                    BOOL fAlloc )
{
    DWORD size;
    DWORD retCode;
    DWORD retValue;

    retValue = ERROR_SUCCESS;   // Assume this function will succeed

    //
    // Figure out how big the Unicode string is
    //              
    if ( NlsMbCodePageTag )
        size = RtlxUnicodeStringToAnsiSize( pUniRtlString ); 
    else
        size = (pUniRtlString->len + 2) / 2;

    //=========================================================================
    // Bail out if the string is > 64KB
    //=========================================================================
    if ( size > 0xFFFF )
        return STATUS_INVALID_PARAMETER_2;

    pAnsiRtlString->len = size-1;

    if ( fAlloc )   // Allocate memory for the destination ANSI string
    {               // (if requested)
        pAnsiRtlString->maxLen = size;
        
        pAnsiRtlString->pBuffer = NtdllpAllocateStringRoutine( size );

        if ( !pAnsiRtlString->pBuffer )
            return STATUS_NO_MEMORY;
    }
    else          // Use the existing buffer from the ANSI RTL_STRING passed in
    {
                  // Sanity check to make sure the destination is big enough
        WORD maxLen = pAnsiRtlString->maxLen;
        
        if ( maxLen <= size )
        {
            if ( 0 == maxLen )
                return STATUS_BUFFER_OVERFLOW;
                
            maxLen--;
            retValue = STATUS_BUFFER_OVERFLOW;
            pAnsiRtlString->len = maxLen;
        }
    }
    
    //=========================================================
    // Do the actual Unicode to Multibyte (8bit) translation
    //=========================================================
    retCode = RtlUnicodeToMultiByteN(   pAnsiRtlString->pBuffer,
                                        pAnsiRtlString->len,
                                        &size,
                                        pUniRtlString->pBuffer,
                                        pUniRtlString->len);
    
    if ( FAILED(retCode) )
    {
        if ( fAlloc )
            NtdllpFreeStringRoutine( pAnsiRtlString->pBuffer );

        return retCode; 
    }

        
    pAnsiRtlString->pBuffer[ size ] = 0;

    return retValue;
}
```

If the caller has requested that the API allocate memory for the destination string, the code calls an internal `NTDLL` function called `NtdllpAllocateStringRoutine`. This function is just a wrapper around a call to `RtlAllocateHeap(2)`. You may know of `RtlAllocateHeap(2)` through its documented name, `HeapAlloc(2)`. The `NtdllpAllocateStringRoutine` function uses the default process heap for the allocation. (See the `GetProcessHeap(2)` documentation for details on the default heap.) After preparing everything, `RtlUnicodeStringToAnsiString(2)` finally makes the critical call to `RtlUnicodeToMultiByteN(2)`.

The `RtlUnicodeToMultiByteN(2)` function is ground zero for converting Unicode to ANSI. Figure 4 shows pseudocode for this function. Since this function is so heavily used, it’s optimized to the hilt. When you’re not using a National Language Support (NLS) code page (as is the case on my system), the function converts the string in chunks, 16 characters at a time.

### Figure 4: `RtlUnicodeToMultiByteN(2)`

```c
DWORD RtlUnicodeToMultiByteN(   LPSTR pDest, DWORD cDestLen,
                                DWORD * pSize,
                                LPWSTR pSrc, DWORD cSrcLen )
{
    if ( 0 == NlsMbCodePageTag )
    {
        cSrcLen >> 1;   // Convert byte count to characters
        if ( cSrcLen >= cDestLen )
            cSrcLen = cDestLen;
    
        if ( pSize )
            *pSize = cSrcLen;
            
        DWORD charsThisTime = cSrcLen & 0xF;
                
        PBYTE pSrcCurr = pSrc + charsThisTime*2;
        PBYTE pDestCurr = pDest + charsThisTime;
        
        if ( charsThisTime < 0xF )
        {
            // JMP table to that transfers to the appropriate spot in the
            // else clause code below
        }
        else
        {
          do    // Loop through the string, translating 16 chars at a time
          {
            pSrcCurr  += 0x20;  // Point to the end of the next Src region
            pDestCur += 0x10;   // point to the end of the next Dest region
            
            // Translate 16 characters at a time.  Code is an unrolled loop
            // to eliminate cache flushing EIP transfers
            pDestCurr[-0x10]= (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0x10]];
            pDestCurr[-0xF] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0xF] ];
            pDestCurr[-0xE] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0xE] ];
            pDestCurr[-0xD] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0xD] ];
            pDestCurr[-0xC] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0xC] ];
            pDestCurr[-0xB] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0xB] ];
            pDestCurr[-0xA] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0xA] ];
            pDestCurr[-0x9] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0x9] ];
            pDestCurr[-0x8] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0x8] ];
            pDestCurr[-0x7] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0x7] ];
            pDestCurr[-0x6] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0x6] ];
            pDestCurr[-0x5] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0x5] ];
            pDestCurr[-0x4] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0x4] ];
            pDestCurr[-0x3] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0x3] ];
            pDestCurr[-0x2] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0x2] ];
            pDestCurr[-0x1] = (BYTE)NlsUnicodeDataToAnsiData[pSrcCurr[-0x1] ];
                                                             
            cSrcLen -= charsThisTime;
            charsTimeTime = 10;             
          } while ( cSrcLen != 0 )
        }
    }
    else    // NlsMbCodePageTag is non-zero
    {
        cSrcLen >> 1;   // Convert byte count to characters

        if ( cSrcLen )  // Anything to convert?
        {
            pDestCurr = pDest;
                
            while ( cDestLen )  // While not at the end of the string...
            {
                srcChar = *(PWORD)pSrc;
                destChar = CodePage[ srcChar ]; // Do the character translation
                pSrc += 2;
                
                if ( HIBYTE(destChar) )     // Check to see if the high BYTE is
                {                           // set.  If so, it's a MultiByte
                    cDestLen--;             // character that takes 2 BYTEs
                    if ( cDestLen < 2 )
                        break;
                                                
                    *pDestCurr = HIBYTE(destChar);
                    pDestCurr++;
                }
                
                *pDestCurr = LOWBYTE(destChar);     // Copy the low BYTE to the
                                                    // destination string
                cDestLen--;
                pDestCurr++;        // Prepare for the next character
                cSrcLen--;
                if ( cSrcLen == 0 )
                    break;
            }
        }

        if ( pSize )    // If this param is non-zero, fill in as requested
            *pSize =  pDestCurr - pSrc;
    }
    
    return 0;
}
```

Why go to the hassle of converting chunks 16 characters at a time? The `RtlUnicodeToMultiByteN(2)` function is written this way to cut down on the number of jumps that would occur if every character was converted individually in a loop. At the CPU level, every jump or call instruction is expensive because the processor’s prefetch queue is flushed. On newer processors such as the Pentium, branch prediction and multiple pipelines help alleviate this problem. However, this function was most likely written before the Pentium arrived on the scene.

When an NLS table is used, `RtlUnicodeToMultiByteN(2)` there translates the characters one at a time. For each iteration of the loop, the Unicode character is used to look up a `WORD` in the NLS table. If the high `BYTE` is nonzero, that character requires two bytes in the destination string (that is, it’s a multibyte character.) If the high `BYTE` is zero, only the low `BYTE` is copied to the destination string.

I’m going to skip a detailed description of the inverse functions of `RtlAnsiStringToUnicodeString(2)` and `RtlUnicodeToMultiByteN(2)` since they’re not terribly different. In summary, there is an `RtlAnsiStringToUnicodeString(2)` function that uses the `RtlMultiByteToUnicodeN(2)` function. They look like mirror images of the functions I’ve just examined.

Sometimes `RtlAnsiStringToUnicodeString(2)` and `RtlUnicodeStringToAnsiString(2)` are directly invoked from the ANSI API wrapper code. Other times, another layer is interposed and sits above them. This layer is used by the file system APIs, which may be using an OEM character set. APIs that work with file names use the `Basep8BitStringToUnicodeString(2)` and `BasepUnicodeStringTo8BitString(2)` functions rather than the `RtlXXXStringToYYYString` APIs.

Figure 5 shows pseudocode for `Basep8BitStringToUnicodeString(2)` and `BasepUnicodeStringTo8BitString(2)`. As you can see, they’re really just wrappers around the `RtlXXXStringToYYYString` APIs described earlier, even down to the parameters they accept. The main logic in the code simply determines whether the file APIs are using OEM strings, and then calls the appropriate `RtlXXXStringToYYYString` API. The `SetFileApisToOEM(2)` and `SetFileApisToANSI(2)` APIs tweak an `NTDLL` global variable called `BasepFileApisAreOem` in the pseudocode. If this variable is nonzero, the `BasepXXX` functions use `RtlOemStringToUnicodeString(2)` and `RtlUnicodeStringToOemString(2)`. Otherwise, they use the ANSI/Unicode APIs.

### Figure 5: `BasepXXXStringToYYYString(2)`

```c
DWORD
Basep8BitStringToUnicodeString( RTL_STRING * pUniRtlString, 
                                RTL_STRING * pAnsiRtlString,
                                BOOL fAlloc )
{
    if ( BasepFileApisAreOem )
    {
        return RtlOemStringToUnicodeString( pUniRtlString,
                                            pAnsiRtlString,
                                            fAlloc );
    }
    else
    {
        return RtlAnsiStringToUnicodeString(pUniRtlString,
                                            pAnsiRtlString,
                                            fAlloc );
    }
}

DWORD
BasepUnicodeStringTo8BitString( RTL_STRING * pAnsiRtlString,
                                RTL_STRING * pUniRtlString, 
                                BOOL fAlloc )
{
    if ( BasepFileApisAreOem )
    {
        return RtlUnicodeStringToOemString( pAnsiRtlString,
                                            pUniRtlString
                                            fAlloc );
    }
    else
    {
        return RtlUnicodeStringToAnsiString(pAnsiRtlString,
                                            pUniRtlString
                                            fAlloc );
    }
}
```

Earlier I mentioned the `NtdllpAllocateStringRoutine`, which the string translation code uses to dynamically allocate memory for a temporary string. There’s a corresponding set of functions for releasing a string’s memory when the system is finished with it. Figure 6 shows pseudocode for `RtlFreeAnsiString(2)` and `RtlFreeUnicodeString(2)`. 

The functions are identical in implementation. They both take an `RTL_STRING` as input, and if the pBuffer field is nonzero, they pass that pointer to an internal `NTDLL` function called `NtdllpFreeStringRoutine`. This function (also shown in Figure 6) is just a wrapper around the `RtlFreeHeap(2)` API, better known as `HeapFree(2)`.

### Figure 6: String Freeing Routines

```c
BOOL RtlFreeAnsiString( PRTL_STRING pRtlString )
{
    if ( pRtlString->pBuffer )
        return pfnNtdllpFreeStringRoutine( pRtlString->pBuffer )
    
    return 0;
}

BOOL RtlFreeUnicodeString( PRTL_STRING pRtlString )
{
    PVOID pTemp = pRtlString;
    
    if ( pTemp )
        return pfnNtdllpFreeStringRoutine( ptemp )
    
    return 0;
}

_NtdllpFreeStringRoutine( PVOID p )
{   
    return RtlFreeHeap( GetProcessHeap(), 0, p );
}
```

This wraps up my tour of the Windows NT ANSI/Unicode string translation code. While I haven’t shown every last detail, it’s sufficient that I can now demonstrate them in their natural habitat. Although they appear to be pretty efficient in their implementation, they add overhead to every API that uses ANSI strings. With that in mind, let’s check out how some well-known APIs use these string routines.

## Some APIs That Use String Translation 

The first API I’ll look at is `GetModuleHandleA(2)` (see Figure 7). I chose this API because it uses the string conversion functions in a rudimentary manner. The first block of code handles the special case where the `hModule` parameter is zero; it isn’t of interest here. The good part begins in the else clause, where the API creates an `RTL_STRING` from the null-terminated input string. Next, the code calls `Basep8BitStringToUnicodeString(2)` to translate the ANSI `RTL_STRING` into a Unicode `RTL_STRING`. The key thing to note here is that the thread’s static Unicode buffer (`pTeb->staticUnicodeRTL_STRING`) is where the Unicode string winds up. As a result, no memory is allocated. After the string is in Unicode form, `GetModuleHandleA(2)` simply passes it to `GetModuleHandleW(2)` and returns whatever that API returns.

### Figure 7: `GetModuleHandleA(2)`

```c
WINBASEAPI HMODULE WINAPI GetModuleHandleA( LPCSTR lpModuleName )
{
    if ( 0 == lpModuleName )    // Special case, where hModule = 0 returns
    {                           // HMODULE of the process EXE
        return pPEB->exeBaseAddress;
    }
    else
    {
        RTL_STRING rtlAnsiString;

        // Create an ANSI string from the input null-terminated string      
        RtlInitAnsiString( &rtlAnsiString, lpModuleName );

        // Convert to Unicode, using the function that takes into account
        // ANSI vs. OEM file APIs.
        DWORD retCode;
        retCode = Basep8BitStringToUnicodeString(pTEB->staticUnicodeRTL_STRING, 
                                                 &rtlAnsiString, FALSE );

        if ( FAILED(retCode) )  // Make sure the translation worked!
        {
            if ( retCode == STATUS_BUFFER_OVERFLOW )
                SetLastError( ERROR_FILENAME_EXCED_RANGE );
            else
                BaseSetLastNTError( retCode );  // Same as GetLastError

            return 0;
        }
        else    // Finally... Call the Unicode version of the function
            return GetModuleHandleW( rtlAnsiString->pBuffer );
    }
}
```

The next ANSI-based API to examine is `SetComputerNameA(2)` (see Figure 8). It has a few more twists than `GetModuleHandleA(2)`. Although it also starts with a call to `RtlInitAnsiString(2)`, it doesn’t use `Basep8BitStringToUnicodeString(2)`. After all, the computer name has nothing to do with file system names and that whole ANSI/OEM thing. Instead, the code uses the lower-level `RtlAnsiStringToUnicodeString(2)` API I described earlier. Another twist is that `SetComputerNameA(2)` allocates memory for the Unicode string, rather than using the thread’s static Unicode buffer area. When the Unicode `RTL_STRING` is ready, `SetComputerNameA(2)` calls its Unicode-equivalent API, `SetComputerNameW(2)`. Before returning, the API calls `RtlFreeUnicodeString(2)` to release the Unicode string it allocated earlier.

### Figure 8: `SetComputerNameA(2)`

```c
WINBASEAPI BOOL WINAPI SetComputerNameA( LPCSTR lpComputerName )
{
    RTL_STRING rtlUniString;
    RTL_STRING rtlAnsiString;
    DWORD retCode;

    // Create the RTL_STRING string from the input null-terminated string
    RtlInitAnsiString( &rtlAnsiString, lpComputerName );

    // Convert the ANSI string to Unicode.  Note the TRUE argument, which
    // indicates that the memory for the Unicode string should be allocated
    retCode = RtlAnsiStringToUnicodeString( &rtlAnsiString,
                                            &rtlUniString, TRUE );
    if ( FAILED(retCode) )
    {
        BaseSetLastNTError( retCode );  // See GetLastError()

        return FALSE;
    }
    
    // Call the Unicode version of the API
    retCode = SetComputerNameW( &rtlUniString.pBuffer );    

    RtlFreeUnicodeString( &rtlUniString );

    return (BOOL)retCode;
}
```

So much for dealing with ANSI strings on the input side. What about the case where an ANSI string needs to be returned to the caller? Let’s start by looking at `GetCurrentDirectoryA(2)` (see Figure 9). The code begins by calling the private `RtlGetCurrentDirectory_U` API, passing it the address of the per-thread static Unicode buffer. Next, `GetCurrentDirectoryA(2)` checks to see if the output ANSI string buffer is big enough to hold the complete directory string. If so, the code calls `BasepUnicodeStringTo8BitString(2)`, which translates the Unicode string into an ANSI or OEM string. Remember, `GetCurrentDirectoryA(2)` is a file system API, so ANSI versus OEM matters here.

If the output buffer isn’t big enough, the API returns the number of characters needed to hold the string. Likewise, if the buffer is big enough, the API returns the number of characters that were copied, not counting the null terminator. Now, here’s a conundrum: how do you tell if the API worked or didn’t based on just the return value? You can’t. Instead, you have to do something cheesy like call `GetLastError(2)` or verify that the output buffer was written to. Another alternative is to pass in a buffer that (you hope) will always be big enough.

### Figure 9: `GetCurrentDirectoryA(2)`

```c
WINBASEAPI DWORD WINAPI GetCurrentDirectoryA( DWORD nBufferLength, 
                                              LPSTR lpBuffer )
{
    RTL_STRING rtlAnsiString;
    WORD cbLen;
    DWORD retCode;

    // Get the Unicode version of the current directory, stored in the
    // per-thread static Unicode buffer     
    cbLen = RtlGetCurrentDirectory_U( pTEB->staticUnicodeRTL_STRING.maxLen,
                                      pTEB->staticUnicodeRTL_STRING.pBuffer );

    pTEB->staticUnicodeRTL_STRING.len = cbLen;
    
    if ( nBufferLength > (cbLen/2) )    // Will it fit into the output buffer?
    {
        rtlAnsiString->maxLen = nBufferLength + 1;
        rtlAnsiString->pBuffer = lpBuffer;

        retCode =BasepUnicodeStringTo8BitString(&rtlAnsiString,
                                                &pTEB->staticUnicodeRTL_STRING,
                                                FALSE);
        if ( FAILED(retCode) )
        {
            BaseSetLastNTError( retCode );  // See GetLastError
            return 0;
        }

        return rtlAnsiString.len;   // Success case - return chars copied
    }

    return cbLen + 1;   // Failure case - return size of buffer needed
}
```

The final API I’ll look at this month is `GetModuleFileNameA(2)` (see Figure 10). Like `GetCurrentDirectoryA(2)`, it fills in an output buffer with an ANSI string. The API begins by using `RtlAllocateHeap(2)` (`HeapAlloc(2)`) to create a buffer that will be used for a Unicode string. It then calls its Unicode equivalent, `GetModuleFileNameW(2)`, passing it the buffer it just allocated. Next, the code calls `BasepUnicodeStringTo8BitString(2)`, which translates the Unicode result from `GetModuleFileNameW(2)` into a temporary 8-bit string. Note that the call to `BasepUnicodeStringTo8BitString(2)` specifies that the output string buffer should be allocated. 

### Figure 10: `GetModuleFileNameA(2)`

```c
WINBASEAPI DWORD WINAPI GetModuleFileNameA( HMODULE hModule, LPSTR lpFilename,
                                            DWORD nSize )
{
    RTL_STRING rtlUniString;
    RTL_STRING rtlAnsiString;

    // Allocate memory for a Unicode string to pass to GetModuleFileNameW
    rtlUniString.pBuffer = RtlAllocateHeap( GetProcessHeap(),
                                            g_HeapFlags, nSize * 2 );
    
    if ( 0 == rtlUniString.pBuffer )
    {
        BaseSetLastNTError( STATUS_NO_MEMORY )
        return 0;
    }

    DWORD cChars;
            
    cChars = GetModuleFileNameW( hModule, rtlUniString.pBuffer, nSize );

    // Fix up the remaining Unicode RTL_STRING fields
    rtlUniString.maxLen = cChars * 2;
    rtlUniString.len = cChars * 2;
    rtlUniString.maxLen += 2;       // account for NULL terminator

    if ( cChars )
    {   
        DWORD retCode;
        
        retCode = BasepUnicodeStringTo8BitString(   &rtlAnsiString,
                                                    &rtlUniString, TRUE );
        if ( FAILED(retCode) )
        {
            BaseSetLastNTError( retCode );
            
            RtlFreeUnicodeString( &rtlUniString );
            
            return 0;
        }
        
        memmove( lpFilename, rtlAnsiString.pBuffer, retCode+1 );
        
        RtlFreeAnsiString( &rtlAnsiString );
    }

    RtlFreeUnicodeString( &rtlUniString );

    return retCode;     
}
```

If the Unicode string successfully converts to an 8-bit (ANSI or OEM) string, `GetModuleFileNameA(2)` uses the `memcpy(3)` function to copy the temporary 8-bit string into the output buffer that was passed in as a parameter. Before `GetModuleFileNameA(2)` can return, it’s important that it clean up. After all, it allocated two string buffers, one for a Unicode string and one for the 8-bit temporary string. The function releases them by calling `RtlFreeAnsiString(2)` and `RtlFreeUnicodeString(2)`. Remember from my earlier description these two private APIs are just wrappers around `RtlFreeHeap(2)` (`HeapFree(2)`).

You may be wondering how the ANSI string manipulation APIs (for example, `lstrlenA(2)` and `lstrcpyA(2)`) are implemented. These APIs are simple enough that they’re implemented without calls to lower-level system functions. As a result, the ANSI string APIs don’t need to translate their input and output parameters between ANSI and Unicode and, therefore, should be as fast as their Unicode equivalents.

## ANSI versus Unicode API Benchmarking 

So far I’ve shown you the APIs and functions that Windows NT uses to translate between ANSI and Unicode strings, as well as how they’re used by some Win32 APIs. With this understanding, it’s now worthwhile to take a look at the performance hit you can expect from using the ANSI APIs with Windows NT. I think you’ll be shocked at the results.

For my test I selected three of the APIs that I examined earlier: `GetModuleHandle(2)`, `GetModuleFileName(2)`, and `GetCurrentDirectory(2)`. I then wrote a test program that times the ANSI and Unicode versions of these APIs. (I didn’t include `SetComputerName(2)` because I didn’t want to be responsible for changing your computer’s name in case the program crashed.) Because each of these APIs is relatively fast to execute, the resolution of the system timer wouldn’t be granular enough. Instead, I relied on the standard trick of making multiple calls in a loop and timing how long it takes for the entire operation to complete.

Before I get to the benchmarking code and, more importantly, the results, let me say a few things about my efforts to make the timings reliable. I used the `QueryPerformanceCounter(2)` API, which provides timings at the microsecond level. According to the `QueryPerformanceFrequency(2)` API, the performance counter increments 1.19 million times a second, a number that corresponds to one of the traditional timers found on x86-based systems. To prevent the numbers from being skewed by too few samples, I executed the APIs 50,000 times in a loop.

Since the code I’m timing takes a relatively long time to execute, it’s virtually guaranteed that the thread’s time slice will end while the loop is still executing, thereby affecting the outcome. I took two steps to minimize this effect. First, I bumped the program’s thread priority up to `THREAD_PRIORITY_TIME_CRITICAL` to minimize the amount of time that other threads would have in the CPU. Second, I called `Sleep(0);` before both the ANSI and Unicode loops. The idea is to start the loop at the very beginning of a time slice. For all you performance/timing gurus out there, let me remind you that I’m not an actual performance profiling expert--I just play one on TV.

My ANSI/Unicode timing program is called `AnsiUniTiming`, and the code is shown in Figure 11. Function main consists of two nearly identical parts. The first part times the three ANSI functions in a loop and reports the amount of time they took to execute. The second part repeats the same basic steps, with the only difference being that the Unicode API equivalents are used. For the call to `GetModuleHandle(2)` I used `KERNEL32.DLL` since it’s guaranteed to be loaded in the process. Passing 0 would have bypassed the string handling code that I showed in the pseudocode for `GetModuleHandleA(2)`. For the call to `GetModuleFileNameA(2)`, I used the value returned by the prior call to `GetModuleHandle(2)`. The `GetCurrentDirectory(2)` call needs no explanation.

### Figure 11: `AnsiUniTiming.cpp`

```c
//==========================================
// Matt Pietrek
// Microsoft Systems Journal, December 1997
// FILE: AnsiUniTiming.CPP
// To compile: CL /O2 AnsiUniTiming.CPP
//==========================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#define LOOP_ITERATIONS 50000

int main()
{
    LARGE_INTEGER tBefore, tAfter, i64PerfFrequency;
    float tAnsi, tUnicode;
    char szAnsiBuffer[ MAX_PATH ];
    WCHAR wszUnicodeBuffer[ MAX_PATH ];
    unsigned i;

    // Figure out how often the performance counter increments
    QueryPerformanceFrequency( &i64PerfFrequency );

    // Set this thread's priority as high as reasonably possible to prevent
    // timeslice interruptions
    SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL );
    
    // ======================== ANSI Portion =================================

    Sleep( 0 ); // Try to start on a fresh timeslice

    // Get performance counter before the ANSI API loop
    QueryPerformanceCounter( &tBefore );

    // ANSI API loop    
    for ( i = 0; i < LOOP_ITERATIONS; i++ )
    {
        HMODULE hMod = GetModuleHandleA( "KERNEL32.DLL" );

        GetModuleFileNameA( hMod, szAnsiBuffer, sizeof(szAnsiBuffer) );
        
        GetCurrentDirectoryA( sizeof(szAnsiBuffer), szAnsiBuffer );
    }

    // Get performance counter after the ANSI API loop
    QueryPerformanceCounter( &tAfter );

    // "QuadPart" is a 64 bit integer (__int64).  VC++ supports them!
    tAnsi = tAfter.QuadPart - tBefore.QuadPart;
    tAnsi = tAnsi / i64PerfFrequency.QuadPart;
            
    printf( "ANSI version took %.4f seconds\n", tAnsi );

    // ====================== Unicode Portion =================================

    Sleep( 0 ); // Try to start on a fresh timeslice
        
    // Get performance counter before the Unicode API loop
    QueryPerformanceCounter( &tBefore );
    
    // unicode API loop 
    for ( i = 0; i < LOOP_ITERATIONS; i++ )
    {
        HMODULE hMod = GetModuleHandleW( L"KERNEL32.DLL" );

        GetModuleFileNameW( hMod, wszUnicodeBuffer, sizeof(wszUnicodeBuffer) );
        
        GetCurrentDirectoryW( sizeof(wszUnicodeBuffer), wszUnicodeBuffer );
    }

    // Get performance counter after the Unicode API loop
    QueryPerformanceCounter( &tAfter );

    tUnicode = tAfter.QuadPart - tBefore.QuadPart;
    tUnicode = tUnicode / i64PerfFrequency.QuadPart;
            
    printf( "Unicode version took %.4f seconds", tUnicode );
            
    return 0;
}
```

Before I tell you the results, stop and guess the difference between the ANSI and Unicode timings (no peeking!). On my system (a single-processor Pentium Pro 200 MHz running Windows NT 4.0), I obtained results that were remarkably similar no matter how many times I ran the program. Here’s the output from a typical run:

```sh
ANSI version took 0.5736 seconds
Unicode version took 0.1923 seconds
```

Wow! Stripping the least two significant digits, tossing the decimal points, and dividing gives 57/19, or 3. The ugly fact is that the ANSI versions of `GetModuleHandle(2)`, `GetModuleFileName(2)`, and `GetCurrentDirectory(2)` take three times as long as the equivalent Unicode versions. It’s likely that the relative performance hit of the ANSI APIs isn’t divided equally among them. If you feel ambitious, feel free to split them out into their own loops and time them independently. Still, the fact remains that commonly used ANSI APIs incur a large performance penalty over their Unicode equivalents.

The moral of this story is that if you’re writing exclusively for Windows NT, and if performance is an issue, you should consider becoming familiar with `TCHAR.H` and the other mechanisms used to write executables that use Unicode. It’s a bit of a pain at first, especially with all the compiler warnings and errors you’ll probably need to correct. In time, though, you should be able to write Unicode-ready code without giving it much thought. Even if you’re writing for other Win32 platforms, the benefits of Unicode may warrant creating and distributing multiple executables: one that uses ANSI and runs anywhere, and another using the Unicode APIs optimized for Windows NT.

To obtain complete source code listings, see the MSJ Web site at 
http://www.microsoft.com/msj.

Have a question about programming in Windows? Send it to Matt at mpietrek@tiac.com or http://www.tiac.com/users/mpietrek