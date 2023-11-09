@echo off
setlocal enabledelayedexpansion

rem Generate a random number between 1 and 100
set /a "random_number=!random! %% 100 + 1"

echo Random Number: %random_number%

endlocal
