@echo off
echo ========================================
echo   WEBSITE SECURITY TOOL UNINSTALLATION
echo ========================================
echo.
echo This will remove the Website Security Tool
echo shortcuts from your system.
echo.
echo Note: This will only remove shortcuts, not the application files.
echo.
set /p choice="Do you want to uninstall shortcuts? (Y/N): "
if /i "%choice%"=="Y" (
    echo.
    echo Removing shortcuts...
    
    REM Remove desktop shortcut
    if exist "%USERPROFILE%\Desktop\Website Security Tool.lnk" (
        del "%USERPROFILE%\Desktop\Website Security Tool.lnk"
        echo ✅ Desktop shortcut removed
    ) else (
        echo ℹ️  Desktop shortcut not found
    )
    
    REM Remove start menu shortcut
    if exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Website Security Tool\Website Security Tool.lnk" (
        del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Website Security Tool\Website Security Tool.lnk"
        echo ✅ Start menu shortcut removed
    ) else (
        echo ℹ️  Start menu shortcut not found
    )
    
    REM Remove start menu folder if empty
    if exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Website Security Tool" (
        rmdir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Website Security Tool" 2>nul
        echo ✅ Start menu folder removed
    )
    
    echo.
    echo ✅ Uninstallation completed!
    echo.
    echo The Website Security Tool shortcuts have been removed.
    echo The application files remain in this folder.
    echo.
) else (
    echo Uninstallation cancelled.
)
echo.
pause
