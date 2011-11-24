unit JclSynch;

{$i jedi.inc}

interface

//--------------------------------------------------------------------------------------------------
// Locked Integer manipulation
//
// Routines to manipulate simple typed variables in a thread safe manner
//--------------------------------------------------------------------------------------------------

function LockedAdd(var Target: Integer; Value: Integer): Integer; overload;
function LockedCompareExchange(var Target: Integer; Exch, Comp: Integer): Integer; overload;
function LockedCompareExchange(var Target: TObject; Exch, Comp: TObject): TObject; overload;
function LockedCompareExchange(var Target: Pointer; Exch, Comp: Pointer): Pointer; overload;
function LockedDec(var Target: Integer): Integer; overload;
function LockedExchange(var Target: Integer; Value: Integer): Integer; overload;
function LockedExchangeAdd(var Target: Integer; Value: Integer): Integer; overload;
function LockedExchangeDec(var Target: Integer): Integer; overload;
function LockedExchangeInc(var Target: Integer): Integer; overload;
function LockedExchangeSub(var Target: Integer; Value: Integer): Integer; overload;
function LockedInc(var Target: Integer): Integer; overload;
function LockedSub(var Target: Integer; Value: Integer): Integer; overload;

{$IFDEF CPU64}
function LockedAdd(var Target: Int64; Value: Int64): Int64; overload;
function LockedCompareExchange(var Target: Int64; Exch, Comp: Int64): Int64; overload;
function LockedDec(var Target: Int64): Int64; overload;
function LockedExchange(var Target: Int64; Value: Int64): Int64; overload;
function LockedExchangeAdd(var Target: Int64; Value: Int64): Int64; overload;
function LockedExchangeDec(var Target: Int64): Int64; overload;
function LockedExchangeInc(var Target: Int64): Int64; overload;
function LockedExchangeSub(var Target: Int64; Value: Int64): Int64; overload;
function LockedInc(var Target: Int64): Int64; overload;
function LockedSub(var Target: Int64; Value: Int64): Int64; overload;
{$ENDIF CPU64}

implementation

// Locked Integer manipulation
function LockedAdd(var Target: Integer; Value: Integer): Integer;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        //     EDX Value
        // <-- EAX Result
        MOV     ECX, EAX
        MOV     EAX, EDX
        LOCK XADD [ECX], EAX
        ADD     EAX, EDX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        //     EDX Value
        // <-- EAX Result
        MOV     EAX, EDX
        LOCK XADD [RCX], EAX
        ADD     EAX, EDX
        {$ENDIF CPU64}
end;

function LockedCompareExchange(var Target: Integer; Exch, Comp: Integer): Integer;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        //     EDX Exch
        //     ECX Comp
        // <-- EAX Result
        XCHG    EAX, ECX
        //     EAX Comp
        //     EDX Exch
        //     ECX Target
        LOCK CMPXCHG [ECX], EDX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        //     EDX Exch
        //     R8  Comp
        // <-- EAX Result
        MOV    RAX, R8
        //     RCX Target
        //     EDX Exch
        //     RAX Comp
        LOCK CMPXCHG [RCX], EDX
        {$ENDIF CPU64}
end;

function LockedCompareExchange(var Target: Pointer; Exch, Comp: Pointer): Pointer;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        //     EDX Exch
        //     ECX Comp
        // <-- EAX Result
        XCHG    EAX, ECX
        //     EAX Comp
        //     EDX Exch
        //     ECX Target
        LOCK CMPXCHG [ECX], EDX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        //     RDX Exch
        //     R8  Comp
        // <-- RAX Result
        MOV     RAX, R8
        //     RCX Target
        //     RDX Exch
        //     RAX Comp
        LOCK CMPXCHG [RCX], RDX
        {$ENDIF CPU64}
end;

function LockedCompareExchange(var Target: TObject; Exch, Comp: TObject): TObject;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        //     EDX Exch
        //     ECX Comp
        // <-- EAX Result
        XCHG    EAX, ECX
        //     EAX Comp
        //     EDX Exch
        //     ECX Target
        LOCK CMPXCHG [ECX], EDX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        //     RDX Exch
        //     R8  Comp
        // <-- RAX Result
        MOV     RAX, R8
        // --> RCX Target
        //     RDX Exch
        //     RAX Comp
        LOCK CMPXCHG [RCX], RDX
        {$ENDIF CPU64}
end;

function LockedDec(var Target: Integer): Integer;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        // <-- EAX Result
        MOV     ECX, EAX
        MOV     EAX, -1
        LOCK XADD [ECX], EAX
        DEC     EAX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        // <-- EAX Result
        MOV     EAX, -1
        LOCK XADD [RCX], EAX
        DEC     EAX
        {$ENDIF CPU64}
end;

function LockedExchange(var Target: Integer; Value: Integer): Integer;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        //     EDX Value
        // <-- EAX Result
        MOV     ECX, EAX
        MOV     EAX, EDX
        //     ECX Target
        //     EAX Value
        LOCK XCHG [ECX], EAX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        //     EDX Value
        // <-- EAX Result
        MOV     EAX, EDX
        //     RCX Target
        //     EAX Value
        LOCK XCHG [RCX], EAX
        {$ENDIF CPU64}
end;

function LockedExchangeAdd(var Target: Integer; Value: Integer): Integer;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        //     EDX Value
        // <-- EAX Result
        MOV     ECX, EAX
        MOV     EAX, EDX
        //     ECX Target
        //     EAX Value
        LOCK XADD [ECX], EAX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        //     EDX Value
        // <-- EAX Result
        MOV     EAX, EDX
        //     RCX Target
        //     EAX Value
        LOCK XADD [RCX], EAX
        {$ENDIF CPU64}
end;

function LockedExchangeDec(var Target: Integer): Integer;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        // <-- EAX Result
        MOV     ECX, EAX
        MOV     EAX, -1
        LOCK XADD [ECX], EAX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        // <-- EAX Result
        MOV     EAX, -1
        LOCK XADD [RCX], EAX
        {$ENDIF CPU64}
end;

function LockedExchangeInc(var Target: Integer): Integer;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        // <-- EAX Result
        MOV     ECX, EAX
        MOV     EAX, 1
        LOCK XADD [ECX], EAX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        // <-- EAX Result
        MOV     EAX, 1
        LOCK XADD [RCX], EAX
        {$ENDIF CPU64}
end;

function LockedExchangeSub(var Target: Integer; Value: Integer): Integer;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        //     EDX Value
        // <-- EAX Result
        MOV     ECX, EAX
        NEG     EDX
        MOV     EAX, EDX
        //     ECX Target
        //     EAX -Value
        LOCK XADD [ECX], EAX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        //     EDX Value
        // <-- EAX Result
        NEG     EDX
        MOV     EAX, EDX
        //     RCX Target
        //     EAX -Value
        LOCK XADD [RCX], EAX
        {$ENDIF CPU64}
end;

function LockedInc(var Target: Integer): Integer;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        // <-- EAX Result
        MOV     ECX, EAX
        MOV     EAX, 1
        LOCK XADD [ECX], EAX
        INC     EAX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        // <-- EAX Result
        MOV     EAX, 1
        LOCK XADD [RCX], EAX
        INC     EAX
        {$ENDIF CPU64}
end;

function LockedSub(var Target: Integer; Value: Integer): Integer;
asm
        {$IFDEF CPU32}
        // --> EAX Target
        //     EDX Value
        // <-- EAX Result
        MOV     ECX, EAX
        NEG     EDX
        MOV     EAX, EDX
        LOCK XADD [ECX], EAX
        ADD     EAX, EDX
        {$ENDIF CPU32}
        {$IFDEF CPU64}
        // --> RCX Target
        //     EDX Value
        // <-- EAX Result
        NEG     EDX
        MOV     EAX, EDX
        LOCK XADD [RCX], EAX
        ADD     EAX, EDX
        {$ENDIF CPU64}
end;

{$IFDEF CPU64}

// Locked Int64 manipulation
function LockedAdd(var Target: Int64; Value: Int64): Int64;
asm
        // --> RCX Target
        //     RDX Value
        // <-- RAX Result
        MOV     RAX, RDX
        LOCK XADD [RCX], RAX
        ADD     RAX, RDX
end;

function LockedCompareExchange(var Target: Int64; Exch, Comp: Int64): Int64;
asm
        // --> RCX Target
        //     RDX Exch
        //     R8  Comp
        // <-- RAX Result
        MOV     RAX, R8
        LOCK CMPXCHG [RCX], RDX
end;

function LockedDec(var Target: Int64): Int64;
asm
        // --> RCX Target
        // <-- RAX Result
        MOV     RAX, -1
        LOCK XADD [RCX], RAX
        DEC     RAX
end;

function LockedExchange(var Target: Int64; Value: Int64): Int64;
asm
        // --> RCX Target
        //     RDX Value
        // <-- RAX Result
        MOV     RAX, RDX
        LOCK XCHG [RCX], RAX
end;

function LockedExchangeAdd(var Target: Int64; Value: Int64): Int64;
asm
        // --> RCX Target
        //     RDX Value
        // <-- RAX Result
        MOV     RAX, RDX
        LOCK XADD [RCX], RAX
end;

function LockedExchangeDec(var Target: Int64): Int64;
asm
        // --> RCX Target
        // <-- RAX Result
        MOV     RAX, -1
        LOCK XADD [RCX], RAX
end;

function LockedExchangeInc(var Target: Int64): Int64;
asm
        // --> RCX Target
        // <-- RAX Result
        MOV     RAX, 1
        LOCK XADD [RCX], RAX
end;

function LockedExchangeSub(var Target: Int64; Value: Int64): Int64;
asm
        // --> RCX Target
        //     RDX Value
        // <-- RAX Result
        NEG     RDX
        MOV     RAX, RDX
        LOCK XADD [RCX], RAX
end;

function LockedInc(var Target: Int64): Int64;
asm
        // --> RCX Target
        // <-- RAX Result
        MOV     RAX, 1
        LOCK XADD [RCX], RAX
        INC     RAX
end;

function LockedSub(var Target: Int64; Value: Int64): Int64;
asm
        // --> RCX Target
        //     RDX Value
        // <-- RAX Result
        NEG     RDX
        MOV     RAX, RDX
        LOCK XADD [RCX], RAX
        ADD     RAX, RDX
end;

{$ENDIF CPU64}


end.

