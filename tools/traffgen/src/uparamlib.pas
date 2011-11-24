unit uParamLib;

interface

uses
  Classes;

type
  TParamLib = class(TObject)
  private
    fParams : TStringList;
    fPresent : TStringList;
    fError : Boolean;

    procedure AddToParams(aName, aValue : String);
    procedure AddToPresent(aName : String);
  public
    constructor Create;
    destructor Destroy; override;

    function ParamsCount : Integer;
    function PresentCount : Integer;

    function Present(aName : string) : Boolean; overload;
    function Present(aIndex : integer) : String; overload;

    function HaveParam(aName : String) : Boolean;
    function Value(aName, aDefault : String) : String; overload;
    function Value(aName : String) : String; overload;
    function Value(aIndex : Integer) : String; overload;
    function NameValue(aIndex : Integer) : String;

    property Error : Boolean read fError;
  end;

var
  Params : TParamLib = nil;   

implementation


{ TParamLib }

constructor TParamLib.Create;
Var
  i : Integer;
  aName : String;
begin
  inherited Create;
  fParams := TStringList.Create;
  fPresent := TStringList.Create;
  fError := false;
  aName := '';
  for I := 1 to ParamCount do
  begin
    if (Copy(ParamStr(i), 1, 1) = '-') then
    begin
      if (aName <> '') then
        AddToPresent(aName);
      aName := ParamStr(i);
    end else
    begin
      if (aName = '') then
        fError := true
      else
      begin
        AddToParams(aName, ParamStr(I));
        aName := '';
      end;
    end;
  end;
  if (aName <> '') then
    AddToPresent(aName);
end;

destructor TParamLib.Destroy;
begin
  fParams.Free;
  inherited;
end;

procedure TParamLib.AddToParams(aName, aValue: String);
begin
  fParams.Add(Copy(aName,2,$FFF)+'='+aValue);
end;

procedure TParamLib.AddToPresent(aName: String);
begin
  fPresent.Add(Copy(aName,2,$FFF));
end;

function TParamLib.ParamsCount: Integer;
begin
  Result := fParams.Count;
end;

function TParamLib.PresentCount: Integer;
begin
  Result := fPresent.Count;
end;

function TParamLib.Present(aIndex: integer): String;
begin
  Result := fPresent[aIndex];
end;

function TParamLib.Present(aName: string): Boolean;
begin
  Result := fPresent.IndexOf(aName) <> -1;
end;

function TParamLib.Value(aName, aDefault: String): String;
Var
  aIdx : Integer;
begin
  aIdx := fParams.IndexOfName(aName);
  if aIdx = -1 then
    Result := aDefault
  else
    Result := fParams.ValueFromIndex[aIdx];
end;

function TParamLib.Value(aName: String): String;
begin
  Result := Value(aName, '');
end;

function TParamLib.Value(aIndex: Integer): String;
begin
  Result := fParams.ValueFromIndex[aIndex];
end;

function TParamLib.NameValue(aIndex: Integer): String;
begin
  Result := fParams.Names[aIndex];
end;


function TParamLib.HaveParam(aName: String): Boolean;
begin
  Result := fParams.IndexOfName(aName) <> -1;
end;

initialization
  Params := TParamLib.Create;

finalization
  Params.free;

end.
