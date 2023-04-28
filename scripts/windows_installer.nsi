Name "Fluere Netflow Collector"
# name installer
OutFile "fluere-0.5.0-nightly-B2-installer.exe"

InstallDir "$PROGRAMFILES\fluere"

RequestExecutionLevel admin

Page InstFiles
Unicode True

Section
 
    UserInfo::GetAccountType
   
    # pop the result from the stack into $0
    Pop $0

    StrCmp $0 "Admin" +2
    MessageBox MB_OK "You must be an administrator to install this program."

    DetailPrint "User is admin"
    
    SetOutPath $INSTDIR
    DetailPrint "Created directory"
    
    File ../target\release\fluere.exe
    DetailPrint "Added fluere.exe"

    WriteRegStr HKLM SOFTWARE\Fluere "Install_Dir" "$INSTDIR"
    DetailPrint "Added registry string"

    EnVar::AddValue  "Path" "$PROGRAMFILES\fluere"
    Pop $0
    DetailPrint "Added to path"
    
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Fluere" "DisplayName" "Fluere"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Fluere" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Fluere" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Fluere" "NoRepair" 1
    DetailPrint "Added registry keys"

    WriteUninstaller "$INSTDIR\uninstall.exe"
    DetailPrint "Added uninstaller"
    
SectionEnd
 

Section "Uninstall"

    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Fluere"
    DeleteRegKey HKLM SOFTWARE\Fluere
    DetailPrint "Removed registry keys"

    Delete $INSTDIR\fluere.exe
    DetailPrint "Removed fluere.exe"
    Delete $INSTDIR\uninstall.exe
    DetailPrint "Removed uninstall.exe"
    
    EnVar::DeleteValue "Path" "$PROGRAMFILES\fluere"
    Pop $0
    DetailPrint "Removed from path"
    
    RMDir "$INSTDIR"
    DetailPrint "Removed from program files"

SectionEnd
