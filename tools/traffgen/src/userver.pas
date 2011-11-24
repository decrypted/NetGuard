unit uServer;

interface

uses
  Classes, uAtomic,
  blcksock, synsock;

type
  TTraffServer = Class;

  { TTcpTraffClient }

  TTcpTraffClient = Class(TThread)
  protected
    fOwner : TTraffServer;
    fSock : TTCPBlockSocket;
    fTimeOut : Integer;

    procedure Execute; override;
  public
    constructor Create(aSock : TSocket; aOwner : TTraffServer);
    destructor Destroy; override;
  end;

  { TTraffServer }

  TTraffServer = Class(TThread)
  protected
    fPort : Word;
    fSock : TBlockSocket;

    function CreateBlockSocket : TBlockSocket; virtual; abstract;
    procedure AcceptClient(aSocket : TSocket); virtual; abstract;
    procedure Execute; override;
  public
    constructor Create(aPort : Word);
    destructor Destroy; override;
  end;

  { TTcpTraffServer }

  TTcpTraffServer = Class(TTraffServer)
  protected
    fTestLock : TAtomicMREW;
    fUpdTests : Array of PInteger;
    function CreateBlockSocket : TBlockSocket; override;
    procedure AcceptClient(aSocket : TSocket); override;
  public
    constructor Create(aPort : Word);
    destructor Destroy; override;

    function NewUdpTest : Integer;
    function GetPckgCnt(aIdx : Integer) : Integer;
    procedure IncPckgCnt(aIdx : Integer);
  end;

  TUdpTraffServer = Class(TTraffServer)
  protected
    function CreateBlockSocket : TBlockSocket; override;
    procedure AcceptClient(aSocket : TSocket); override;
    procedure Execute; override;
  end;

  procedure StartServer(aPort : Word);

implementation

uses
  SysUtils, JclSynch;

var
  TcpServ : TTcpTraffServer;
  UdpServ : TUdpTraffServer = nil;

procedure StartServer(aPort : Word);
begin
  UdpServ := TUdpTraffServer.Create(aPort);
  TcpServ := TTcpTraffServer.Create(aPort);
  TcpServ.WaitFor;
end;


{ TTcpTraffClient }

constructor TTcpTraffClient.Create(aSock : TSocket; aOwner : TTraffServer);
begin
  fOwner := aOwner;
  FreeOnTerminate := True;
  fTimeOut := 1200;
  fSock := TTCPBlockSocket.Create;
  fSock.Socket := aSock;
  inherited Create(false);
end;

destructor TTcpTraffClient.Destroy;
begin
  fSock.CloseSocket;
  fSock.Free;
  inherited Destroy;
end;

procedure TTcpTraffClient.Execute;
const
  BufferSize = 1024;
var
  aCmd : Byte;
  Buffer : String;
begin
  WriteLn('Client Accepted ', fSock.GetRemoteSinIP);
  try
    aCmd := fSock.RecvByte(fTimeOut);
    if fSock.LastError <> 0 then
      raise Exception.Create('TimeOut');
    case aCmd of
      1: //Endless Stream
        begin
          SetLength(Buffer, BufferSize);
          while fSock.LastError = 0 do
            fSock.RecvBufferEx(Pointer(Buffer), BufferSize , fTimeout);
        end;
      2: //Register UDP Stream
        begin
          fSock.SendInteger(TTcpTraffServer(fOwner).NewUdpTest);
        end;
      3:
        begin
          fSock.SendInteger(TTcpTraffServer(fOwner).GetPckgCnt(fSock.RecvInteger(fTimeOut)));
        end;
    end;
  except
    on E: Exception do
      WriteLn(E.Message);
  end;
  WriteLn('Client connection close');
end;

{ TTraffServer }

constructor TTraffServer.Create(aPort : Word);
begin
  fPort := aPort;
  fSock := CreateBlockSocket;
  inherited Create(false);
end;

destructor TTraffServer.Destroy; 
begin
  fSock.Free;
  inherited Destroy;
end;

procedure TTraffServer.Execute;
var
  ClientSock : TSocket;
begin
  try
    with fSock do
    begin
      CreateSocket;
      SetLinger(true, 10);
      Bind('0.0.0.0', IntToStr(fPort));
      Listen;
      if LastError <> 0 then
        raise Exception.Create(LastErrorDesc);
      WriteLn('Listen on port ', fPort);
      while not Terminated do
      begin
        if CanRead(1000) then
        begin
          ClientSock := Accept;
          if LastError = 0 then
          begin
            try
              AcceptClient(ClientSock);
            except
              on E: Exception do
                WriteLn(E.Message);
            end;
          end else
          begin
            WriteLn('Error Accept Client: ', LastErrorDesc);
          end;
        end;
      end;
    end;
  except
    on E: Exception do
      WriteLn(E.Message);
  end;
end;

{ TTcpTraffServer }

constructor TTcpTraffServer.Create(aPort : Word);
begin
  SetLength(fUpdTests, 0); 
  fTestLock := TAtomicMREW.Create;
  inherited Create(aPort);
end;

destructor TTcpTraffServer.Destroy;
begin
  fTestLock.Free;
  //TODO Free UpdTests Pointers
  inherited Destroy;
end;

function TTcpTraffServer.CreateBlockSocket  : TBlockSocket;
begin
  Result := TTcpBlockSocket.Create;
end;

function TTcpTraffServer.NewUdpTest : Integer;
Var
  aPtrInt : PInteger;
begin
//WriteLn(1);
//  fTestLock.BeginWrite;
  try
//WriteLn(2);
    Result := High(fUpdTests)+1;
WriteLn(Result);
    WriteLn('New UdpTest ', Result);
    SetLength(fUpdTests, Result +1);
    New(aPtrInt);
    aPtrInt^ := 0;
    fUpdTests[Result] := aPtrInt;
  finally
//    fTestLock.EndWrite;
  end;
end;

function TTcpTraffServer.GetPckgCnt(aIdx : Integer) : Integer;
begin
//  fTestLock.BeginRead;
  try 
    Result := fUpdTests[aIdx]^;
  finally
//    fTestLock.EndRead;
  end;
end;

procedure TTcpTraffServer.IncPckgCnt(aIdx : Integer);
begin
//  fTestLock.BeginRead;
  try
    fUpdTests[aIdx]^ := fUpdTests[aIdx]^ +1;
  finally
//    fTestLock.EndRead;
  end;
end;

procedure TTcpTraffServer.AcceptClient(aSocket : TSocket); 
begin
  TTcpTraffClient.Create(aSocket, Self);
end;

{ TUdpTraffServer }
function TUdpTraffServer.CreateBlockSocket : TBlockSocket; 
begin
  Result := TUdpBlockSocket.Create;
end;
    
procedure TUdpTraffServer.AcceptClient(aSocket : TSocket); 
begin
  WriteLn('Pckg');
end;

procedure TUdpTraffServer.Execute; 
Var
  aBuff : String;
  aRecv, aSeq, aPckgCnt : Integer;
begin
  fSock.bind('0.0.0.0', IntToStr(fPort));
  if fSock.LastError <> 0 then 
    raise Exception.Create(fSock.LastErrorDesc);
  WriteLn('Udp RecvBuffer: ', fSock.SizeRecvBuffer);
  fSock.SizeRecvBuffer := 1024*1024*10;
  WriteLn('Udp RecvBuffer: ', fSock.SizeRecvBuffer);
  
  setLength(aBuff, 50);
  while True do
  begin
    if terminated then break;
    
    aRecv := fSock.RecvBufferFrom(Pointer(aBuff), 50);
    if (fSock.lasterror=0) then
    begin
     // WriteLn(fSock.WaitingData);
      if Length(aBuff) <> 50 then
        WriteLn(Length(aBuff));
      Move(aBuff[1], aSeq, 4);
      Move(aBuff[5], aPckgCnt, 4);
//      WriteLn(aPckgCnt);
      try
        TcpServ.IncPckgCnt(aSeq);
      except
      end;
    end;
  end;
  fsock.CloseSocket;
end;

end.
