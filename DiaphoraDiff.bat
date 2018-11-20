@echo off

set IDA_DIR=C:\Program Files\IDA 7.0
set DIAPHORA_DIR=g:\win\IDA\plugins\diaphora
set DIAPHORA_AUTO=1
set DIAPHORA_USE_DECOMPILER=HexRays

echo Exporting %1.sqlite
set DIAPHORA_EXPORT_FILE=%1.sqlite
"%IDA_DIR%\ida64.exe" -S%DIAPHORA_DIR%\diaphora.py %1

echo Exporting %2.sqlite
set DIAPHORA_EXPORT_FILE=%2.sqlite
"%IDA_DIR%\ida64.exe" -S%DIAPHORA_DIR%\diaphora.py %2

echo Generating Diff DB %1.db
%DIAPHORA_DIR%\diaphora.py -o %1.db %1.sqlite %2.sqlite