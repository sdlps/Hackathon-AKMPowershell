# KC2016 - Out-Of-Box Installation for PS Deployment
# This script will install vanila version of Knowledge Center 2016

###############################################################################################################################

# Our Case for customer environment:
#      - New Customer
#      - Oracle 11g Database
#      - On-Premise
#      - STS: ADFS
################################################################################################################################

param(
    #Database params
    $databaseServerName = "AKMDATABASE",
    $databaseType = "Oracle",
    $databaseVersion = "11.2",
    $databaseBackupFile = "C:\Temp\Demo.database.oracle.11.2.DMP",
    $osUserName = "UserName", 
    $osUserPassword = "Password",
    $osUserFullName = "User Name",
    $thirdpartyInstallerLocation = "I:\ThirdParyTools",
    $additionalInstallerPath = @("C:\Tools\ImageMagic.exe","C:\Tools\Batik.exe","C:\Tools\SVG.exe"),
    $sslCertificatePath = "C:\CertificatePath"
) 

Import-Module servermanager
$module = Get-Module servermanager
$module.exportedCmdlets

#Before we do anything, we check if the user is admin (or run as administrator)
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
        Break
   }
  

################################################################################################################################
#	1. Create Virtual machine
#   CommandLet source: https://azure.microsoft.com/en-us/documentation/articles/virtual-machines-windows-classic-create-powershell/

# Set your subscription and storage account
$subscr="2016Andriy"
$staccount="ashatrov@sdl.com"
Select-AzureSubscription -SubscriptionName $subscr –Current
Set-AzureSubscription -SubscriptionName $subscr -CurrentStorageAccountName $staccount

# Determine the ImageFamily
Get-AzureVMImage | select ImageFamily -Unique

#Build your command set
$vmname="KC2016AKM"
$vmsize="Medium"
$vm1=New-AzureVMConfig -Name $vmname -InstanceSize $vmsize -ImageName $image

######################################################
#	2. Create Database Oracle/SQL server
Create-Database -Type $databaseType -DatabaseServerName $databaseServerName -DatabaseVersion $databaseVersion

######################################################
#	3. Import DB dump
Import-Database -Name $databaseName -Type $databaseType -DatabaseServerName $databaseServerName -DatabaseBackupFile $databaseBackupFile

######################################################
#	4. Install Windows server pre-requisites and features

#region Install-Prerequisites
Write-Host "Add Feature .NET Framework"
#https://docs.sdl.com/LiveContent/content/en-US/SDL%20LiveContent%20full%20documentation-v143/GUID-47EC6977-C62C-493E-B6DA-F0A3D0003C9D
Add-WindowsFeature NET-Framework-45-Core

#https://docs.sdl.com/LiveContent/content/en-US/SDL%20LiveContent%20full%20documentation-v143/GUID-F9E7D252-9EA1-4D70-8FEC-29BC89F6A65B
Add-WindowsFeature NET-HTTP-Activation
Add-WindowsFeature NET-WCF-HTTP-Activation45 

#https://docs.sdl.com/LiveContent/content/en-US/SDL%20LiveContent%20full%20documentation-v143/GUID-F0F2DB60-4C4F-4962-9FC1-AE8D2F1929FE
Write-Host "Add Role Webserver"
Add-WindowsFeature Web-Server

Write-Host "Add Common HTTP features "
Add-WindowsFeature Web-Static-Content 
Add-WindowsFeature Web-Default-Doc
Add-WindowsFeature Web-Dir-Browsing
Add-WindowsFeature Web-Http-Errors 

Write-Host "Add Application Development IIS Features"
Add-WindowsFeature Web-Asp-Net45
Add-WindowsFeature Web-Net-Ext45
Add-WindowsFeature Web-ASP 
Add-WindowsFeature Web-ISAPI-Ext 
Add-WindowsFeature Web-ISAPI-Filter 

Write-Host "Add Compression"
Add-WindowsFeature Web-Stat-Compression
Add-WindowsFeature Web-Dyn-Compression 

Write-Host "Add Health and Diagnostics IIS Features"
Add-WindowsFeature Web-Http-Logging
Add-WindowsFeature Web-Request-Monitor

Write-host "Add Management Features"
Add-WindowsFeature Web-Mgmt-Console
#End of Add Role Webserver

#https://docs.sdl.com/LiveContent/content/en-US/SDL%20LiveContent%20full%20documentation-v143/GUID-B06F62DB-9D30-4C2E-8C89-C116BD8F0829
Write-host "Add Application Server Role"
Add-WindowsFeature Application-Server
Add-WindowsFeature AS-Dist-Transaction
Add-WindowsFeature AS-Incoming-Trans
Add-WindowsFeature AS-Outgoing-Trans
#End of Add Application Server Role


#https://docs.sdl.com/LiveContent/content/en-US/SDL%20LiveContent%20full%20documentation-v143/GUID-3EE5FE3E-3E35-452F-9314-DD4775B27CD5
Write-Host "Configuring IIS applicationHost.Config"

Import-Module WebAdministration

# Define the mimetypes for IIS that can be statically compressed
$staticcompression = @(
	@{mimeType='text/*'; enabled='True'},
	@{mimeType='message/*'; enabled='True'},
	@{mimeType='application/x-javascript'; enabled='True'},
	@{mimeType='application/atom+xml'; enabled='True'},
	@{mimeType='application/xaml+xml'; enabled='True'},
 @{mimeType='application/octet-stream'; enabled='True'},
	@{mimeType='*/*'; enabled='False'}
)
# Set the specified static mimetypes in the compression settings
# in applicationHost.config
$filter = 'system.webServer/httpCompression/statictypes'
Set-Webconfiguration -Filter $filter -Value $staticcompression

#Define the mimetypes for IIS that can be dynamically compressed
$dynamiccompression = @(
	@{mimeType='text/*'; enabled='True'},
	@{mimeType='message/*'; enabled='True'},
	@{mimeType='application/x-javascript'; enabled='True'},
	@{mimeType='application/soap+xml'; enabled='True'},
	@{mimeType='application/xml'; enabled='True'},
	@{mimeType='application/json'; enabled='True'},
 @{mimeType='application/octet-stream'; enabled='True'},
	@{mimeType='*/*'; enabled='False'}	
)
# Set the specified dynamic mimetypes in the compression settings 
# in applicationHost.config
$filter = 'system.webServer/httpCompression/dynamictypes'
Set-Webconfiguration -Filter $filter -Value $dynamiccompression
# Note that compression can be set per web.config file			

#Run in Command Prompt

cmd.exe /c %windir%\system32\inetsrv\appcmd unlock config /section:system.webServer/asp /commit:apphost
cmd.exe /c %windir%\system32\inetsrv\appcmd unlock config /section:system.webServer/serverRuntime /commit:apphost
cmd.exe /c %windir%\system32\inetsrv\appcmd unlock config /section:system.webServer/defaultDocument /commit:apphost
cmd.exe /c %windir%\system32\inetsrv\appcmd unlock config /section:system.webServer/staticContent /commit:apphost
cmd.exe /c %windir%\system32\inetsrv\appcmd unlock config /section:system.webServer/directoryBrowse /commit:apphost
cmd.exe /c %windir%\system32\inetsrv\appcmd unlock config /section:system.webServer/handlers /commit:apphost
cmd.exe /c %windir%\system32\inetsrv\appcmd unlock config /section:system.webServer/urlCompression /commit:apphost


Write-Host "Setting Transaction Timeout"
$comAdmin = New-Object -com ("COMAdmin.COMAdminCatalog.1")
$LocalColl = $comAdmin.Connect("localhost")
$LocalComputer = $LocalColl.GetCollection("LocalComputer",$LocalColl.Name)
$LocalComputer.Populate()
$LocalComputerItem = $LocalComputer.Item(0)
$CurrVal = $LocalComputerItem.Value("TransactionTimeout")
$LocalComputerItem.Value("TransactionTimeout") = 3600
$LocalComputer.SaveChanges()

Write-Host "Setting DTC Setting"
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC -Name AllowOnlySecureRpcCalls -Value 0 -Type DWord
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC -Name TurnOffRpcSecurity -Value 1 -Type DWord
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC\Security -Name NetworkDtcAccess -Value 1 -Type DWord
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC\Security -Name XaTransactions -Value 1 -Type DWord
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC\Security -Name NetworkDtcAccessTransactions -Value 1 -Type DWord
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC\Security -Name NetworkDtcAccessOutbound -Value 1 -Type DWord
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC\Security -Name NetworkDtcAccessInbound -Value 1 -Type DWord
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC\Security -Name LuTransactions -Value 1 -Type DWord
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC\Security -Name LuTransactions -Value 1 -Type DWord

#https://docs.sdl.com/LiveContent/content/en-US/SDL%20LiveContent%20full%20documentation-v143/GUID-70BAEF73-D2B4-488B-8F71-505DB8ACB244
Write-Host "Set the group policy so that Windows 2012R2 does not forcefully unload the registry."
$Key = "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\System"
If  ( -Not ( Test-Path "Registry::$Key")){New-Item -Path "Registry::$Key" -ItemType RegistryKey -Force}
Set-ItemProperty -path "Registry::$Key" -Name "DisableForceUnload" -Type "DWord" -Value "1"

#endregion Install-Prerequisites

######################################################
#	5. Create dedicated user
# CommandLet source: http://krypted.com/windows-server/creating-users-on-windows-server-2012-using-powershell/

New-ADUser -SamAccountName $osUserName -AccountPassword "$osUserPassword" `
-name $osUserFullName -enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false

######################################################
#	6. Install Third-Party tool:
#		a. JDK
#		b. AntennaHouse
#		c. JavaHelp
#		d. ImageMagic (case-to-case)
#		e. Any other specifically required by customer

Install-ThirdPartyTool -InstallerPath $thisrdpartyInstallerLocation -AdditinalTools $additionalInstallerPath

######################################################
#	6. Import SSL certificate and prepare HTTPS binding

Import-Certificate -FilePath $sslCertificatePath
Create-HTTPS-BINDING -HostURL "KC2016AKM"
$certificateThumbprint = Get-CertificateThumprint

######################################################
#	7. Prepare inputparameters.xml
Create-InputParameters -Inputs @(
OSUse=$osUserName;
OSPassword=$osUserPassword;
DatabaseName=$databaseName;
DatabaseType=$databaseType;
DatabaseServerName=$databaseServerName;
BaseURL="KC2016.domain.com";
apppath="";
webpath="";
datapath="";
infoshareauthorwebappname="";
infosharewswebappname="";
infosharestswebappname="";
ps_fo_processor="";
ps_htmlhelp_processor="";
ps_java_home="";
ps_javahelp_home="";
solrlucene_service_port="";
solrlucene_stop_port="";
servicecertificatethumbprint="";
issuerwstrustbindingtype=""
)

######################################################
#	8. Run Install Tool
&C:\Tools\__InstallTool\InstallTool.exe

######################################################
#	9. Upgrade Database for 11 to 12
Database-Upgrade

######################################################
#	10. Prepare SDL hack for ADFS on Hosted server
Access-ADFS-For-Support 

######################################################
#	11. Start Trisoft* services and change them "Automatic"
Start-Service -Name "Trisoft*"
Set-Service -Name "Trisoft*" -StartupType Automatic

######################################################
#	12. Test Installation
#		a. Publishing
#		b. Export
#		c. Log-on or Test connection

Test-Publish
Test-Export
Test-Logon
#