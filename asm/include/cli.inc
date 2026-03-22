;; =============================================================================
;; cli.inc — Command line argument parsing
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Provides: CliParse — parse argc/argv style from GetCommandLineA
;; =============================================================================

IFNDEF NULL
NULL equ 0
ENDIF
IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF

GetCommandLineA PROTO
lstrlenA        PROTO :DWORD
lstrcmpA        PROTO :DWORD, :DWORD
lstrcmpiA       PROTO :DWORD, :DWORD
IFNDEF _RTLZEROMEMORY_DEFINED
_RTLZEROMEMORY_DEFINED equ 1
RtlZeroMemory   PROTO :DWORD, :DWORD
ENDIF

;; ---- Parsed CLI state ----
CLI_ARGS STRUCT
    lpHost      DWORD ?     ; -h <host> (NULL if not specified)
    wPort       WORD  ?     ; -p <port> (0 = auto-try)
    _pad        WORD  ?
    lpCommand   DWORD ?     ; first non-flag argument (command name)
    lpArg1      DWORD ?     ; second non-flag argument
    lpArg2      DWORD ?     ; third non-flag argument
    bInstall    DWORD ?     ; --install flag
    bUninstall  DWORD ?     ; --uninstall
    bService    DWORD ?     ; --service
    bTray       DWORD ?     ; --tray
    bConsole    DWORD ?     ; --console
    bHelp       DWORD ?     ; --help
    bVersion    DWORD ?     ; --version
    bPlain      DWORD ?     ; --plain (no TLS)
    bVerbose    DWORD ?     ; -v count
    lpProxy     DWORD ?     ; -J <proxy_host> (ProxyJump)
    lpDeviceId  DWORD ?     ; -d <device_id> (relay resolve)
    lpRdvServer DWORD ?     ; -r <rendezvous_server> (hbbs host:port)
    lpRdvKey    DWORD ?     ; -k <licence_key> (rendezvous auth)
CLI_ARGS ENDS

.data
    szFlagH     db "-h", 0
    szFlagP     db "-p", 0
    szFlagV     db "-v", 0
    szInstall   db "--install", 0
    szUninstall db "--uninstall", 0
    szService   db "--service", 0
    szTray      db "--tray", 0
    szConsole   db "--console", 0
    szHelp      db "--help", 0
    szVersionF  db "--version", 0
    szPlain     db "--plain", 0
    szFlagJ     db "-J", 0
    szFlagD     db "-d", 0
    szFlagR     db "-r", 0
    szFlagK     db "-k", 0

.data?
    cliArgs     CLI_ARGS <>

.code

;; =============================================================================
;; CliParse — Parse command line into CLI_ARGS structure
;; Args: pArgs (ptr to CLI_ARGS)
;; Returns: 0 = success
;; =============================================================================
CliParse PROC uses ebx esi edi pArgs:DWORD
    LOCAL   pCmdLine:DWORD
    LOCAL   argc:DWORD
    LOCAL   argv[32]:DWORD      ; max 32 args
    LOCAL   inQuote:DWORD

    invoke  RtlZeroMemory, pArgs, SIZEOF CLI_ARGS

    ;; Get command line
    invoke  GetCommandLineA
    mov     pCmdLine, eax

    ;; Tokenize: split on spaces, handle quotes
    mov     esi, pCmdLine
    mov     argc, 0
    mov     inQuote, 0

    ;; Skip the program name (first token)
@skip_prog:
    mov     al, byte ptr [esi]
    cmp     al, 0
    je      @parse_done
    cmp     al, '"'
    jne     @skip_nq
    xor     inQuote, 1
    inc     esi
    jmp     @skip_prog
@skip_nq:
    cmp     inQuote, 1
    je      @skip_next
    cmp     al, ' '
    je      @skip_spaces
@skip_next:
    inc     esi
    jmp     @skip_prog

@skip_spaces:
    ;; Skip whitespace between program name and first arg
@skip_ws:
    cmp     byte ptr [esi], ' '
    jne     @tokenize
    inc     esi
    jmp     @skip_ws

@tokenize:
    ;; Now tokenize remaining args
    mov     inQuote, 0
@tok_loop:
    mov     al, byte ptr [esi]
    cmp     al, 0
    je      @parse_done

    ;; Skip whitespace
    cmp     al, ' '
    jne     @tok_start
    inc     esi
    jmp     @tok_loop

@tok_start:
    ;; If starts with quote, skip it and enter quote mode
    cmp     byte ptr [esi], '"'
    jne     @tok_record
    mov     inQuote, 1
    inc     esi                 ; skip opening quote
@tok_record:
    ;; Record token pointer (after any opening quote)
    mov     ecx, argc
    cmp     ecx, 32
    jge     @parse_done
    lea     edx, argv
    mov     dword ptr [edx + ecx * 4], esi
    inc     argc

    ;; Find end of token
@tok_scan:
    mov     al, byte ptr [esi]
    cmp     al, 0
    je      @parse_done
    cmp     al, '"'
    jne     @tok_nq
    ;; Quote found — if in quote mode, null-terminate here (strip closing quote)
    cmp     inQuote, 1
    jne     @tok_toggle
    mov     byte ptr [esi], 0  ; strip closing quote
    mov     inQuote, 0
    inc     esi
    jmp     @tok_end_check
@tok_toggle:
    xor     inQuote, 1
    inc     esi
    jmp     @tok_scan
@tok_nq:
    cmp     inQuote, 1
    je      @tok_next
    cmp     al, ' '
    je      @tok_end
@tok_next:
    inc     esi
    jmp     @tok_scan
@tok_end:
    ;; Null-terminate this token
    mov     byte ptr [esi], 0
    inc     esi
    jmp     @tok_loop
@tok_end_check:
    ;; After stripping closing quote — skip whitespace then next token
    cmp     byte ptr [esi], ' '
    jne     @tok_loop       ; could be end of string or next char
    inc     esi
    jmp     @tok_loop

@parse_done:
    ;; Now process argv[0..argc-1]
    xor     ebx, ebx        ; index

@arg_loop:
    cmp     ebx, argc
    jge     @arg_done

    lea     edx, argv
    mov     esi, dword ptr [edx + ebx * 4]

    ;; Check flags
    invoke  lstrcmpA, esi, ADDR szFlagH
    test    eax, eax
    jnz     @chk_p
    ;; -h: next arg is host
    inc     ebx
    cmp     ebx, argc
    jge     @arg_done
    lea     edx, argv
    mov     eax, dword ptr [edx + ebx * 4]
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).lpHost, eax
    jmp     @arg_next

@chk_p:
    invoke  lstrcmpA, esi, ADDR szFlagP
    test    eax, eax
    jnz     @chk_v
    ;; -p: next arg is port
    inc     ebx
    cmp     ebx, argc
    jge     @arg_done
    lea     edx, argv
    mov     eax, dword ptr [edx + ebx * 4]
    ;; atoi for port
    push    eax
    call    _atoi_simple
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).wPort, ax
    jmp     @arg_next

@chk_v:
    invoke  lstrcmpA, esi, ADDR szFlagV
    test    eax, eax
    jnz     @chk_install
    mov     edx, pArgs
    inc     (CLI_ARGS PTR [edx]).bVerbose
    jmp     @arg_next

@chk_install:
    invoke  lstrcmpA, esi, ADDR szInstall
    test    eax, eax
    jnz     @chk_uninstall
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).bInstall, 1
    jmp     @arg_next

@chk_uninstall:
    invoke  lstrcmpA, esi, ADDR szUninstall
    test    eax, eax
    jnz     @chk_service
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).bUninstall, 1
    jmp     @arg_next

@chk_service:
    invoke  lstrcmpA, esi, ADDR szService
    test    eax, eax
    jnz     @chk_tray
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).bService, 1
    jmp     @arg_next

@chk_tray:
    invoke  lstrcmpA, esi, ADDR szTray
    test    eax, eax
    jnz     @chk_console
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).bTray, 1
    jmp     @arg_next

@chk_console:
    invoke  lstrcmpA, esi, ADDR szConsole
    test    eax, eax
    jnz     @chk_help
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).bConsole, 1
    jmp     @arg_next

@chk_help:
    invoke  lstrcmpA, esi, ADDR szHelp
    test    eax, eax
    jnz     @chk_version
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).bHelp, 1
    jmp     @arg_next

@chk_version:
    invoke  lstrcmpA, esi, ADDR szVersionF
    test    eax, eax
    jnz     @chk_plain
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).bVersion, 1
    jmp     @arg_next

@chk_plain:
    invoke  lstrcmpA, esi, ADDR szPlain
    test    eax, eax
    jnz     @chk_J
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).bPlain, 1
    jmp     @arg_next

@chk_J:
    invoke  lstrcmpA, esi, ADDR szFlagJ
    test    eax, eax
    jnz     @chk_d
    ;; -J: next arg is proxy host
    inc     ebx
    cmp     ebx, argc
    jge     @arg_done
    lea     edx, argv
    mov     eax, dword ptr [edx + ebx * 4]
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).lpProxy, eax
    jmp     @arg_next

@chk_d:
    invoke  lstrcmpA, esi, ADDR szFlagD
    test    eax, eax
    jnz     @chk_r
    inc     ebx
    cmp     ebx, argc
    jge     @arg_done
    lea     edx, argv
    mov     eax, dword ptr [edx + ebx * 4]
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).lpDeviceId, eax
    jmp     @arg_next

@chk_r:
    invoke  lstrcmpA, esi, ADDR szFlagR
    test    eax, eax
    jnz     @chk_k
    inc     ebx
    cmp     ebx, argc
    jge     @arg_done
    lea     edx, argv
    mov     eax, dword ptr [edx + ebx * 4]
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).lpRdvServer, eax
    jmp     @arg_next

@chk_k:
    invoke  lstrcmpA, esi, ADDR szFlagK
    test    eax, eax
    jnz     @chk_cmd
    inc     ebx
    cmp     ebx, argc
    jge     @arg_done
    lea     edx, argv
    mov     eax, dword ptr [edx + ebx * 4]
    mov     edx, pArgs
    mov     (CLI_ARGS PTR [edx]).lpRdvKey, eax
    jmp     @arg_next

@chk_cmd:
    ;; Not a flag — positional: command, arg1, arg2
    mov     edx, pArgs
    cmp     (CLI_ARGS PTR [edx]).lpCommand, 0
    jne     @set_arg1
    mov     (CLI_ARGS PTR [edx]).lpCommand, esi
    jmp     @arg_next
@set_arg1:
    cmp     (CLI_ARGS PTR [edx]).lpArg1, 0
    jne     @set_arg2
    mov     (CLI_ARGS PTR [edx]).lpArg1, esi
    jmp     @arg_next
@set_arg2:
    cmp     (CLI_ARGS PTR [edx]).lpArg2, 0
    jne     @arg_next
    mov     (CLI_ARGS PTR [edx]).lpArg2, esi

@arg_next:
    inc     ebx
    jmp     @arg_loop

@arg_done:
    xor     eax, eax
    ret
CliParse ENDP

;; ---- Simple atoi (ASCIIZ decimal string → EAX) ----
_atoi_simple PROC pStr:DWORD
    mov     esi, pStr
    xor     eax, eax
@atoi_loop:
    movzx   ecx, byte ptr [esi]
    cmp     ecx, '0'
    jb      @atoi_done
    cmp     ecx, '9'
    ja      @atoi_done
    imul    eax, 10
    sub     ecx, '0'
    add     eax, ecx
    inc     esi
    jmp     @atoi_loop
@atoi_done:
    ret
_atoi_simple ENDP

