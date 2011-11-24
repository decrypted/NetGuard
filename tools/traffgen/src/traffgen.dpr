program traffgen;

{$i jcl.inc}

uses
  {$ifdef linux}
  cthreads,
  {$endif}
  SysUtils,
  uServer, uClient, uParamLib, jclsynch; 

procedure WriteHelp;
begin
  WriteLn('TraffGen 0.1');
  WriteLn('All:');
  WriteLn('  -p <port>');
  WriteLn('Server:');
  WriteLn('  -S    StartServer');
  WriteLn('Client:');
  WriteLn('  -C <Server>');
  WriteLn('  -tcp  Generate Traffic with tcp (default)');
  WriteLn('  -udp  Generate Traffic with udp');
  WriteLn('     -ps <int> Pckg Size in byte only with udp (defaul:50)');
  WriteLn('     -pc <int> Pckg Count only with udp (defaul:0)');
  WriteLn('  -t <sec>  Howlong');
  WriteLn('  -g <int>  SendBandwidth  10 = 10 bps  10M = 10 Mps');
  WriteLn;
end;

var
  aServer : String;
  aPort : Word;
  aClient : TSocketTraffClient;
//  I : Integer;
begin
//  I := 0;
//WriteLn(LockedCompareExchange(i, 1, 0));

//exit;
WriteLn('TraffGen 0.2');
  if (ParamCount = 0) or Params.Error  then
    WriteHelp
  else
  begin
    aPort := StrToIntDef(Params.Value('p', '5001'), 5001);
    if Params.Present('S') then
      StartServer(aPort)
    else
    begin
      aServer := Params.Value('C', '');
      if aServer = '' then
        WriteHelp
      else
      begin
        if Params.Present('udp') then
          aClient := TUdpTraffClient.Create(aServer, aPort)
        else
          aClient := TTcpTraffClient.Create(aServer, aPort);
        try
          try
            aClient.Run;
          except
            on E: Exception do
            begin
              WriteLn;
              WriteLn('Error: ', E.Message);
            end;
          end;
        finally
          aClient.Free;
        end;
      end;
    end;
  end;
end.
