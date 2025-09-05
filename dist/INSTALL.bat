@echo off
echo ========================================
echo   WEBSITE SECURITY TOOL INSTALLATION
echo ========================================
echo.
echo This will install the Website Security Tool
echo to your system for easy access.
echo.
echo Features:
echo - Advanced threat detection
echo - File scanning for malware
echo - Website blocking/unblocking
echo - Multi-API security analysis
echo.
set /p choice="Do you want to install? (Y/N): "
if /i "%choice%"=="Y" (
    echo.
    echo Installing Website Security Tool...
    
    REM Create desktop shortcut
    echo Creating desktop shortcut...
    powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\Website Security Tool.lnk'); $Shortcut.TargetPath = '%~dp0WebsiteSecurityTool.exe'; $Shortcut.WorkingDirectory = '%~dp0'; $Shortcut.Description = 'Website Security Tool - Advanced threat detection and website blocking'; $Shortcut.Save()"
    
    REM Create start menu shortcut
    echo Creating start menu shortcut...
    if not exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Website Security Tool" mkdir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Website Security Tool"
    powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%APPDATA%\Microsoft\Windows\Start Menu\Programs\Website Security Tool\Website Security Tool.lnk'); $Shortcut.TargetPath = '%~dp0WebsiteSecurityTool.exe'; $Shortcut.WorkingDirectory = '%~dp0'; $Shortcut.Description = 'Website Security Tool - Advanced threat detection and website blocking'; $Shortcut.Save()"
    
    echo.
    echo ✅ Installation completed successfully!
    echo.
    echo The Website Security Tool has been installed and shortcuts
    echo have been created on your desktop and in the start menu.
    echo.
    echo ⚠️  IMPORTANT: For full functionality, always run as Administrator
    echo.
    echo You can now:
    echo 1. Double-click the desktop shortcut
    echo 2. Find it in the Start Menu
    echo 3. Or run WebsiteSecurityTool.exe directly
    echo.
) else (
    echo Installation cancelled.
)
echo.
pause
