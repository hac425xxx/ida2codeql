@echo off

set bat_dir=%~dp0
set codeql_home=%bat_dir%\codeql
set extractor_path=%bat_dir%\ida-extractor.exe

set ida_path=%bat_dir%\IDA_PRO_7.7\ida.exe

cd /d "%~dp0"


if defined CODEQL_HOME (
    set codeql_home=%CODEQL_HOME%
) else (
    echo "使用目录下的 codeql"
)

set codeql_path=%codeql_home%\codeql.exe
set scheme_path=%codeql_home%\go\go.dbscheme


set binary_path=%1
set ast_path=%binary_path%\out
set db_path=%2

python ida-extractor.py "%ida_path%" "%binary_path%"
python ida2codeql.py "%codeql_path%" "%scheme_path%" "%extractor_path%" "%db_path%" "%ast_path%"