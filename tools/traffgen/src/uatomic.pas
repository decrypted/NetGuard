unit uAtomic;

interface

type
  { TAtomicMREW }

  TAtomicMREW = Class(TObject)
  private
    fReference: integer;
  public
    constructor Create;

    procedure BeginRead;
    procedure BeginWrite;
    procedure EndRead;
    procedure EndWrite;
  end;

implementation

uses
   JclSynch;

{ TAtomicMREW }

constructor TAtomicMREW.Create;
begin
  inherited Create;
  fReference := 0;
end;

procedure TAtomicMREW.BeginRead;
var
  aCurrRef : Integer;
begin
  repeat
    aCurrRef := fReference AND NOT 1;
  until aCurrRef = LockedCompareExchange(fReference, aCurrRef+2, aCurrRef);
end;

procedure TAtomicMREW.BeginWrite;
var
  aCurrRef : Integer;
begin
  repeat
    aCurrRef := fReference AND NOT 1;
  until aCurrRef = LockedCompareExchange(fReference, aCurrRef+1, aCurrRef);
  //So alle die lesen raus
  repeat
  until fReference = 1;
end;

procedure TAtomicMREW.EndRead;
begin
  InterlockedExchangeAdd(fReference, -2);
end;

procedure TAtomicMREW.EndWrite;
begin
  fReference := 0;
end;

end.
