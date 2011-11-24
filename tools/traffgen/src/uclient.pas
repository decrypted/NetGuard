unit uClient;

interface

uses
  blcksock, synsock, synacode;

type
  { TSocketTraffClient }

  TSocketTraffClient = Class(TObject)
  protected
    fServer : String;
    fPort : Word;
  public
    constructor Create(aServ : String; aPort : Word);
  
    procedure Run; virtual; abstract;  
  end;

  { TUdpTraffClient }

  TUdpTraffClient = Class(TSocketTraffClient)
  protected
    function GetCommandResult(aCmd : Byte; aParam : Integer = -1) : Integer;
  public
    procedure Run; override;
  end;

  { TTcpTraffClient }

  TTcpTraffClient =  Class(TSocketTraffClient)
  public
    procedure Run; override;
  end;

implementation

uses
  SysUtils, Unix,
  uParamLib;

function GetTickCount: Cardinal;
var
  tv : Timeval;
begin
  fpgettimeofday(@tv, nil);
  Result := Int64(tv.tv_sec) * 1000 + tv.tv_usec div 1000;
end;


function GetSpeedLimit : Integer;
Var
  aParm : String;
  aLast : Char;
begin
  aParm := Params.Value('g', '');
  if aParm = '' then
    Result := 0
  else
  begin
    aLast := LowerCase(aParm[Length(aParm)]);
    if aLast = 'b' then 
      Result := StrToInt(Copy(aParm, 1, Length(aParm)-1))
    else if aLast = 'k' then 
      Result := StrToInt(Copy(aParm, 1, Length(aParm)-1))*1024
    else if aLast = 'm' then 
      Result := StrToInt(Copy(aParm, 1, Length(aParm)-1))*1024*1024
    else if aLast = 'g' then 
      Result := StrToInt(Copy(aParm, 1, Length(aParm)-1))*1024*1024*1024
    else
      Result := StrToInt(aParm);
  end;
end;

function HumanSpeed(aVal : Double) : String;
Var
  aSuff : String;
begin
  if aVal > 1024*1024*1024 then
  begin
    aSuff := 'g';
    aVal := aVal / 1024/ 1024/ 1024;
  end
  else if aVal > 1024*1024 then
  begin
    aSuff := 'm';
    aVal := aVal / 1024 / 1024;
  end
  else if aVal > 1024 then
  begin
    aSuff := 'k';
    aVal := aVal / 1024;
  end else
    aSuff := 'b';
  Result := Format('%.3f '+aSuff+'ps', [aVal]);
end;


constructor TSocketTraffClient.Create(aServ : String; aPort : Word);
begin
  inherited Create;
  fServer := aServ;
  fPort := aPort;
end;

{ TUcpTraffClient }

function TUdpTraffClient.GetCommandResult(aCmd : Byte; aParam : Integer = -1) : Integer;
Var
  aTcp : TTcpBlockSocket;
begin
  aTcp := TTcpBlockSocket.Create;
  try
    aTcp.Bind('0.0.0.0', cAnyPort);
    aTcp.Connect(fServer, IntToStr(fPort));
    if aTcp.LastError <> 0 then
      raise Exception.Create(aTcp.LastErrorDesc);
    aTcp.SendByte(aCmd);
    if aParam <> -1 then
      aTcp.SendInteger(aParam);
    Result := aTcp.RecvInteger(12000);
  finally
    aTcp.Free;
  end;
end;

procedure TUdpTraffClient.Run; 
const
  MinSleep = 50;
Var
  aUdp : TUdpBlockSocket;
  aStart, aStartPckg, aRun, aNow : Cardinal;
  aRecvPckg, aSeq, aMaxCnt : Integer;
  aSendPckg, aSend : Int64;
  BuffSize : Integer;
  aBuffer : String;
  aSpeedLimit, aPps, aPckgCnt : Integer;
begin
  WriteLn('UDP Test Client');
  aSeq := GetCommandResult(2);
  WriteLn('Test-sequence: ', aSeq);
  aUdp := TUdpBlockSocket.Create;
  try
    BuffSize := 50;
    aSpeedLimit := GetSpeedLimit;
    if aSpeedLimit <> 0 then
    begin
      WriteLn('SpeedLimit:   ', aSpeedLimit, ' bps');
      aPps := Trunc(aSpeedLimit / BuffSize);
      WriteLn('Pckg per s: ', aPps);
      aPps := aPps div Trunc(1000 / MinSleep);
    end else
      aPps := 0;
    
    aUdp.Bind('0.0.0.0', cAnyPort);
    aUdp.Connect(fServer, IntToStr(fPort));
    if aUdp.LastError <> 0 then
      raise Exception.Create(aUdp.LastErrorDesc);
    aMaxCnt := StrToInt(Params.Value('pc', '0'));
    SetLength(aBuffer, BuffSize);
    Move(aSeq, aBuffer[1], 4);
    aRun := StrToInt(Params.Value('t', '0'));
    aSend := 0;
    aSendPckg := 0;
    aPckgCnt := 0;
    aStart := GetTickCount;
    aStartPckg := GetTickCount;
    while true do 
    begin
      aNow := GetTickCount;
      if aRun <> 0 then
      begin
        if aNow >= aStart + (aRun*1000) then 
          Break;
      end;
      if (aMaxCnt <> 0) and (aSendPckg >= aMaxCnt) then
        Break;
      if aPps <> 0 then
      begin
        inc(aSendPckg);
        if(aSendPckg = aPps) then
        begin
          if (aNow - aStartPckg) < MinSleep then
            Sleep(MinSleep - (aNow - aStartPckg));
          aStartPckg := GetTickCount;
          aSendPckg := 0;
        end;
      end;
      Move(aPckgCnt, aBuffer[5], 4);
      aUdp.SendString(aBuffer);
      if aUdp.LastError <> 0 then
        raise Exception.Create(aUdp.LastErrorDesc);
      Inc(aPckgCnt);
      Inc(aSend, BuffSize);
    end;
    WriteLn('Wait...');
    Sleep(1000);
    WriteLn('Sended Pckg: ', aPckgCnt);
    aRecvPckg := GetCommandResult(3, aSeq);
    WriteLn('Recv Pckg  : ', aRecvPckg);
    WriteLn('Loss Pckg  : ', Format('%.2f', [100 - (aRecvPckg*100/aPckgCnt)])+'%');
  finally
    aUdp.Free;
  end;
end;

{ TTcpTraffClient }

procedure TTcpTraffClient.Run; 
const
  MinSleep = 50;
var
  BuffSize, i : Integer;
  aTcp : TTcpBlockSocket;
  aStart, aEnd, aRun, aStartPckg, aNow : Cardinal;
  aBuffer : String;
  aSend : Int64;
  aSendPckg : Integer;
  aPps, aSpeedLimit : Integer;
begin
  WriteLn('TCP Test Client');
  aTcp := TTcpBlockSocket.Create;
  try
    aTcp.Bind('0.0.0.0', cAnyPort);
    aTcp.Connect(fServer, IntToStr(fPort));
    if aTcp.LastError <> 0 then
      raise Exception.Create(aTcp.LastErrorDesc);
    aTcp.SendByte(1);

    BuffSize := 1024;
    aSpeedLimit := GetSpeedLimit;
    if aSpeedLimit <> 0 then
    begin
      if(aSpeedLimit < BuffSize) then
        aSpeedLimit := BuffSize;
      WriteLn('BuffSize  : ', BuffSize);
      WriteLn('SpeedLimit:   ', aSpeedLimit, ' bps');
      aPps := Trunc(aSpeedLimit / BuffSize);
      WriteLn('Pckg per s: ', aPps);
      aPps := aPps div Trunc(1000 / MinSleep);
    end else
      aPps := 0;

    aTcp.SendMaxChunk := BuffSize;
    SetLength(aBuffer, BuffSize);
    aRun := StrToInt(Params.Value('t', '0'));
    aSend := 0;
    aSendPckg := 0;
    aStart := GetTickCount;
    aStartPckg := GetTickCount;
    while true do 
    begin
      aNow := GetTickCount;
      if aRun <> 0 then
      begin
        if aNow >= aStart + (aRun*1000) then 
          Break;
      end;
      aTcp.SendString(aBuffer);
      if aPps <> 0 then
      begin
        inc(aSendPckg);
        if(aSendPckg = aPps) then
        begin
          if (aNow - aStartPckg) < MinSleep then
            Sleep(MinSleep - (aNow - aStartPckg));
          aStartPckg := GetTickCount;
          aSendPckg := 0;
        end;
      end;
      if aTcp.LastError <> 0 then
        raise Exception.Create(aTcp.LastErrorDesc);
      Inc(aSend, BuffSize);
    end;
    WriteLn('Sended bytes: ', aSend);
    aEnd := GetTickCount-aStart;
    WriteLn('Sended time : ', Format('%.2f sec', [aEnd/1000]));
    WriteLn('~', HumanSpeed( aSend / (aEnd / 1000)));
  finally
    aTcp.Free;
  end;
end;

end.
