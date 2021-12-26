@echo off
cls

REM :: with console
REM :: go build

REM :: without console
REM :: https://stackoverflow.com/questions/36727740/how-to-hide-console-window-of-a-go-program-on-windows/36728885#36728885
REM :: go build -ldflags -H=windowsgui
REM :: without debug symbols
REM :: go build -ldflags "-s -H=windowsgui"
REM :: go build -ldflags "-s" -o %*
go build -ldflags "-s" %*
