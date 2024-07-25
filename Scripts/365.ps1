<#

    .SYNOPSIS
    Connects to a Microsoft 365 tenant and gathers baseline data

    .DESCRIPTION
    Connects to various Microsoft Graph API endpoints, and uses some native Microsoft Online PowerShell commands, to gather data from a Microsoft 365 tenant.
    This data is then saved locally (in JSON format) to disk where other N-central services can query it, or report on the data.
    Authentication to to the tenant is achieved through our Partner access using delegated admin to obtain Access Tokens (Secure App Model).

    See the following for the authentication model: https://computerculture.itglue.com/323106/assets/18412-general-notes/records/17774424

    Values required are:
        - $M365TenantPrimaryDomain
            - This is the primary domain of the M365 tenant and is used to connect to the tenant.
            - It can be specified on the command line ($ManualPrimaryDomain), or is passed as a variable from N-central
        - $LocalDataSaveLocation
            - This is the output location of the generated JSON data file.
            - It defaults to C:\Monitoring if not specified (suitable for execution in Docker container for N-central probes)
            - It can be overridden on the command line ($DataSaveLocation) if running script outside of N-central

#>

# Had to switch away from named parameters as N-central does not support it.
# param ($ManualPrimaryDomain, $DataSaveLocation, $RequestedBy)
$ManualPrimaryDomain = $args[0]
$DataSaveLocation = $args[1]
$RequestedBy = $args[2]

""
""
$Now = Get-Date
"$($Now.ToShortDateString()) $($Now.ToLongTimeString())"

# Check for domain provided via command line
if ($null -eq $ManualPrimaryDomain)
{
    "No domain provided via command line. Assuming variable provided via N-central."
}
else
{
    "Domain provided via command line: $ManualPrimaryDomain"
    $M365TenantPrimaryDomain = $ManualPrimaryDomain 
}

# Location where tenant monitoring JSON data will be stored
$LocalDataSaveLocation = "C:\Monitoring"
if ($null -ne $DataSaveLocation)
{
    $LocalDataSaveLocation = $DataSaveLocation
}

"Results will be saved in $LocalDataSaveLocation"

# Global Variables

# Number of days to look back for sign-in data
$SignInReportingPeriodInDays = 30

# Number of days without signin until user is considered inactive
$InactiveUserDaysThreshold = 90

# Calcualte the start date based on number of days above
$ReportingPeriodStart = $Now.AddDays(-$SignInReportingPeriodInDays)
$ReportingPeriodStartDateString = $ReportingPeriodStart.Year.ToString() + "-" + $ReportingPeriodStart.Month.ToString() + "-" + $ReportingPeriodStart.Day.ToString()

$ConsoleOutputSeparator = "---------------------------------------------------------"

# Microsoft Graph API Endpoints
$GraphURIOrganization = "https://graph.microsoft.com/v1.0/organization"
$GraphURIAdminReportSettings = "https://graph.microsoft.com/beta/admin/reportSettings"
$GraphURISubscribedSkus = "https://graph.microsoft.com/v1.0/subscribedSkus"
$GraphURIDomains = "https://graph.microsoft.com/v1.0/domains"
$GraphURIUsers = "https://graph.microsoft.com/v1.0/users?`$select=accountEnabled,userType,displayName,userPrincipalName,proxyAddresses,usageLocation"
$GraphURIUsersAADPremium = "https://graph.microsoft.com/beta/users?`$select=accountEnabled,userType,displayName,userPrincipalName,signInActivity,proxyAddresses,usageLocation"
$GraphURIGroups = "https://graph.microsoft.com/v1.0/groups?`$select=id,groupTypes,securityEnabled,mailEnabled,displayName,userPrincipalName,mail,proxyAddresses"
$GraphURIGroupMembers = "https://graph.microsoft.com/v1.0/groups/{id}/members"
$GraphURIUserRegistration = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails"
$GraphURISecurityDefaults = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
$GraphURIConditionalAccessPolicies = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
$GraphURIManagedDevices = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
$GraphURISecureScore = "https://graph.microsoft.com/v1.0/security/securescores?`$top=1"
$GraphURISecureScoreHistory = "https://graph.microsoft.com/v1.0/security/securescores"
$GraphURISignInReports = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $ReportingPeriodStartDateString"
$GraphURISignInLastNonInteractive = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=signInEventTypes/any(t: t eq 'nonInteractiveUser') and createdDateTime ge $ReportingPeriodStartDateString and userPrincipalName eq '<userPrincipalName>'&top=1"
$GraphURIMailboxUsage = "https://graph.microsoft.com/v1.0/reports/getMailboxUsageDetail(period='D7')"
$GraphURIEmailActivity = "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D30')"
$GraphURIOneDriveUsage = "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period='D7')"
$GraphURISharePointUsage = "https://graph.microsoft.com/v1.0/reports/getSharePointSiteUsageDetail(period='D7')"
# $GraphURISharePointSite = "https://graph.microsoft.com/beta/sites/<siteid>"
$GraphURISecurityAlerts = "https://api.securitycenter.microsoft.com/api/alerts"
$GraphURIApplications = "https://graph.microsoft.com/v1.0/applications"
$GraphURIServicePrincipals = "https://graph.microsoft.com/beta/servicePrincipals?filter=appId eq '<resourceAppId>'"
$SecurityURIMachines = "https://api.securitycenter.microsoft.com/api/machines"
$SecurityURIVulnerabilities = "https://api.securitycenter.microsoft.com/api/Vulnerabilities?`$filter=cvssV3 gt 7.5"

# URL to download CSV that maps Microsoft's product codes to user friendly display names
# Manually created and saved from this table: https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
# This file should be updated periodically to update names as Microsoft changes them
$M365ProductCodeMappingFileUri = "https://raw.githubusercontent.com/computer-culture/public-content/master/Downloads/N-central/M365ProductCodeMapping.csv"

# Initialise Authentication variables 
$global:AzureAdAppId                       = $null
$global:AzureAdAppSecret                   = $null
$global:AzureAdAppRefreshToken      = $null
$global:ExchangeRefreshToken        = $null
$TenantPrimaryDomain                = $null
$AzureAdGraphToken                  = $null
$MsGraphToken                       = $null
$global:GraphApiHeaders             = $null
# $global:SecurityCenterApiHeaders    = $null

# Set up data objects used to store information about the M365 tenant. 
# This data will be serialized to JSON on disk

$global:M365Tenant = [PSCustomObject]@{
    RequestedBy = $null
    TenantID = $null
    CompanyName = $null
    Address = $null
    AzureAdPremiumEnabled = $null
    EndpointManagementEnabled = $null
    OnPremisesSyncEnabled = $null
    LastOnPremisesSyncTime = $null
    GlobalAdmins = $null
    SecureScoreValue = $null
    SecureScoreMax = $null
    SecurityDefaultsEnabled = $null
    ConditionalAccessPolicies = New-Object System.Collections.ArrayList
    Licenses = New-Object System.Collections.ArrayList
    Domains = New-Object System.Collections.ArrayList
    Users = New-Object System.Collections.ArrayList
    Groups = New-Object System.Collections.ArrayList
    Devices = New-Object System.Collections.ArrayList
    SignIns = New-Object System.Collections.ArrayList
    SharePointSites = New-Object System.Collections.ArrayList
    Applications = New-Object System.Collections.ArrayList
    SecureScores = New-Object System.Collections.ArrayList
    Vulnerabilities = New-Object System.Collections.ArrayList
}

$M365License = [PSCustomObject]@{
    Enabled = $null
    ProductCode = $null
    ProductDescription = $null
    TotalCount = $null
    UsedCount = $null
}

$M365Domain = [PSCustomObject]@{
    Name = $null
    Default = $null
    EmailEnabled = $null
    MXRecord = $null
    SPFRecord = $null
    DKIMConfigured = $null
    DMARCConfigured = $null
}

$M365User = [PSCustomObject]@{
    Enabled = $null
    UserType = $null
    DisplayName = $null
    UPN = $null
    ProxyAddresses = $null
    LastSignInDateTime = $null
    LastNonInteractiveSignInDateTime = $null
    MFARegistered = $null  
    AuthenticationMethods = $null  
    MFAManuallyEnforced = $null
    MailboxItems = $null
    MailboxStorageUsed = $null
    MailboxQuota = $null
    OneDriveFiles = $null
    OneDriveQuota = $null
    OneDriveStorageUsed = $null
    UsageLocation = $null
    EmailsSent = $null
    EmailsReceived = $null
    EmailsRead = $null
}

$M365Group = [PSCustomObject]@{
    DisplayName = $null
    EmailAddress = $null
    MailEnabled = $null
    SecurityEnabled = $null
    IsM365Group = $null
    ProxyAddresses = $null
    Members = $null
}

$M365Device = [PSCustomObject]@{
    Name = $null
    UPN = $null
    UserDisplayName = $null
    ComplianceState = $null
    OwnershipType = $null
    LastSyncDateTime = $null
    OperatingSystem = $null
    OSVersion = $null
    Manufacturer = $null
    Model = $null
    SerialNumber = $null
}

$M365SignIn = [PSCustomObject]@{
    DateTime = $null
    UPN = $null
    UserDisplayName = $null
    AppDisplayName = $null
    IPAddress = $null
    ClientApp = $null
    ResourceAccessed = $null
    StatusCode = $null
    StatusFailureReason = $null
    StatusAdditionalDetails = $null
    Country = $null
}

$M365SharePointSite = [PSCustomObject]@{
    ID = $null
    Site = $null
    FileCount = $null
    StorageUsed = $null
    StorageAllocated = $null
}

$M365ConditionalAccessPolicy = [PSCustomObject]@{
    'Policy Name' = $null
    'State' = $null
    'Targets MFA' = $null
}

$M365Application = [PSCustomObject]@{
    Name = $null
    DateCreated = $null
    Permissions = New-Object System.Collections.ArrayList
}

$M365ApplicationPermission = [PSCustomObject]@{
    Name = $null
    Value = $null
}

$M365SecureScore = [PSCustomObject]@{
    Date = $null
    MaxScore = $null
    CurrentScore = $null
}

$MDEVulnerability = [PSCustomObject]@{
    Id = $null
    Description = $null
    Severity = $null
    CvssScore = $null
    ExposedMachines = $null
    PublishedOn = $null
    UpdatedOn = $null
    PublicExploit = $null
}

if ($null -ne $RequestedBy)
{
    $global:M365Tenant.RequestedBy = $RequestedBy
}

function Start-Script
{
    <#
        .SYNOPSIS
        This function is the entry point for the script. A call to this function is at the end of the script to allow all functions to be preloaded
    #>

    Initialize-Environment
    Get-M365Tenant
    # Set-TenantConfiguration
    Get-SecureScoreHistory
    Get-Licenses
    Get-Domains    
    Get-Users
    
    Get-ConditionalAccessPolicies    
    Get-SharePointUsage
    Get-MailboxUsage
    Get-EmailActivity
    Get-OneDriveUsage

    Get-Devices
    Get-Applications
    
    Get-Groups
    # Get-Vulnerabilities    

    if ($global:M365Tenant.AzureAdPremiumEnabled)
    {
        Get-SignIns
    }

    # If running on a Docker probe, use a standard file name, otherwise make it unique for the tenant
    if ($null -eq $ManualPrimaryDomain)
    {
        $global:M365Tenant | ConvertTo-Json -Depth 10 | Out-File "$LocalDataSaveLocation\M365TenantData.json"
    }
    else
    {
        $global:M365Tenant | ConvertTo-Json -Depth 10 | Out-File "$LocalDataSaveLocation\$ManualPrimaryDomain.json"
    }
    

    $ConsoleOutputSeparator
    $Now = Get-Date
    "$($Now.ToShortDateString()) $($Now.ToLongTimeString())"
}

function Get-M365Tenant
{
    "Getting tenant info..."
    $QueryResult = Query-MSGraphAPI($GraphURIOrganization)
    $Tenant = $QueryResult.value[0]
    
    $global:M365Tenant.TenantID = $Tenant.id
    $global:M365Tenant.CompanyName = $Tenant.DisplayName
    $global:M365Tenant.Address = "$($Tenant.street), $($Tenant.city), $($Tenant.countryLetterCode), $($Tenant.postalCode)"
    $global:M365Tenant.OnPremisesSyncEnabled = if ($Tenant.onPremisesSyncEnabled) {$true} else {$false}

    if ($global:M365Tenant.OnPremisesSyncEnabled)
    {
        $global:M365Tenant.LastOnPremisesSyncTime = $Tenant.onPremisesLastSyncDateTime.ToLocalTime()
    }  
    
    "Getting admin report settings..."
    $QueryResult = Query-MSGraphAPI($GraphURIAdminReportSettings)

    if ($QueryResult.displayConcealedNames)
    {
        "Report names are being concealed, turning this off..."
        $QueryBody = @{
            displayConcealedNames = $false
         } | ConvertTo-Json

        Set-MsGraphSetting -QueryUri $GraphURIAdminReportSettings -Body $QueryBody
    }

    $SecureScoreQueryResult = $null
    $RetryCount = 0

    while ($null -eq $SecureScoreQueryResult.value -and $RetryCount -lt 5)
    {
        if ($RetryCount -gt 0)
        {
            "Pausing for retry..."
            Start-Sleep -Seconds 10
        }
        "Getting Secure Score data..."
        $SecureScoreQueryResult = Query-MSGraphAPI($GraphURISecureScore)
        $RetryCount++
    }

    $SecureScoreResult = $SecureScoreQueryResult.value[0]

    "Checking if Secure Score lists 'AADPEnabled'..."
    $global:M365Tenant.AzureAdPremiumEnabled = $false
    if ($SecureScoreResult.enabledServices.contains("AADPEnabled"))
    {
        "Yes it does, Azure AD Premium Enabled."
        $global:M365Tenant.AzureAdPremiumEnabled = $true
    }

    "Checking for any assigned plans that include 'AADPremiumService'..."
    $AADPremiumPlans = $Tenant.assignedPlans | Where-Object {$_.service -eq "AADPremiumService" -and $_.capabilityStatus -eq "Enabled"}
    if ($AADPremiumPlans.Count -gt 0 -or $AADPremiumPlans.service -eq "AADPremiumService")
    {
        "Found one or more, Azure AD Premium Enabled."
        $global:M365Tenant.AzureAdPremiumEnabled = $true
    }

    # Get secure score
    $global:M365Tenant.SecureScoreValue = $SecureScoreResult.currentScore
    $global:M365Tenant.SecureScoreMax = $SecureScoreResult.maxScore

    # Get total number of global admins
    $GlobalAdminResult = $SecureScoreResult.controlScores | Where-Object {$_.controlName -eq "OneAdmin"}
    $global:M365Tenant.GlobalAdmins = $GlobalAdminResult.count

}

function Get-SecureScoreHistory
{
    $SecureScoreQueryResult = $null
    $RetryCount = 0

    while ($null -eq $SecureScoreQueryResult.value -and $RetryCount -lt 5)
    {
        if ($RetryCount -gt 0)
        {
            "Pausing for retry..."
            Start-Sleep -Seconds 10
        }
        "Getting Secure Score history..."
        $SecureScoreQueryResult = Query-MSGraphAPI($GraphURISecureScoreHistory)
        $RetryCount++
    }
    
    foreach ($SecureScoreResult in $SecureScoreQueryResult.value)
    {
        $SecureScore = $M365SecureScore.psobject.Copy()
        $SecureScore.Date = $SecureScoreResult.createdDateTime
        $SecureScore.MaxScore = $SecureScoreResult.maxScore
        $SecureScore.CurrentScore = $SecureScoreResult.currentScore

        $global:M365Tenant.SecureScores.Add($SecureScore) | Out-Null
    }
}

function Get-Groups
{
    "Getting groups..."
    $QueryResult = Query-MSGraphAPI($GraphURIGroups)
    $GroupsResult = $QueryResult.value

    $PageCount = 1
    while ($QueryResult.'@odata.nextLink')
    {
        $PageCount++
        "Getting Page $PageCount..."
        $QueryResult = Query-MSGraphAPI($QueryResult.'@odata.nextLink')
        $GroupsResult += $QueryResult.value
        
    }

    foreach ($GroupResult in $GroupsResult)
    {
        $Group = $M365Group.psobject.copy()
        $Group.DisplayName = $GroupResult.displayName
        $Group.MailEnabled = if ($GroupResult.mailEnabled) {$true} else {$false}
        if ($Group.MailEnabled)
        {
            $Group.EmailAddress = $GroupResult.mail
        }
        $Group.SecurityEnabled = if ($GroupResult.securityEnabled) {$true} else {$false}
        $Group.IsM365Group = if ($GroupResult.groupTypes.Contains("Unified")) {$true} else {$false}
        $Group.ProxyAddresses = $GroupResult.proxyAddresses | Where-Object {$_.ToLower().Contains("smtp:")}

        "Getting members for group $($Group.DisplayName)"
        $QueryURI = $GraphURIGroupMembers.Replace("{id}", $GroupResult.id)
        $GroupQueryResult = Query-MSGraphAPI($QueryURI)
        $GroupMembers = New-Object System.Collections.ArrayList
        foreach ($GroupMember in $GroupQueryResult.value)
        {
            $GroupMembers.Add($GroupMember.mail) | Out-Null
        }
        $Group.Members = $GroupMembers

        $global:M365Tenant.Groups.Add($Group) | Out-Null
    }
}

# function Get-Vulnerabilities
# {
#     "Getting vulnerabilities..."

#     $QueryResult = Query-MSSecurityCenterAPI($SecurityURIVulnerabilities)

#     $Vulnerabilities = $QueryResult.value

#     $PageCount = 1
#     while ($QueryResult.'@odata.nextLink')
#     {
#         $PageCount++
#         "Getting Page $PageCount..."
#         $QueryResult = Query-MSSecurityCenterAPI($QueryResult.'@odata.nextLink')
#         $Vulnerabilities += $QueryResult.value
#     }

#     $ExposedVulnerabilities = $Vulnerabilities | Where-Object {$_.exposedMachines -gt 0}

#     foreach ($ExposedVulnerability in $ExposedVulnerabilities)
#     {
#         $Vulnerability = $MDEVulnerability.psobject.Copy()
#         $Vulnerability.Id = $ExposedVulnerability.id
#         $Vulnerability.Description = $ExposedVulnerability.description
#         $Vulnerability.Severity = $ExposedVulnerability.severity
#         $Vulnerability.CvssScore = $ExposedVulnerability.cvssV3
#         $Vulnerability.ExposedMachines = $ExposedVulnerability.exposedMachines
#         $Vulnerability.PublishedOn = $ExposedVulnerability.publishedOn
#         $Vulnerability.UpdatedOn = $ExposedVulnerability.updatedOn
#         $Vulnerability.PublicExploit = $ExposedVulnerability.publicExploit
#         $global:M365Tenant.Vulnerabilities.Add($Vulnerability) | Out-Null
#     }
# }

function Get-Licenses
{
    # Down the file we use to map Microsoft product codes to user firendly product display names
    "Downloading M365 product mapping file..."
    $M365ProductCodeMappingFile = Invoke-RestMethod $M365ProductCodeMappingFileUri
    $M365ProductCodeMapping = $M365ProductCodeMappingFile | ConvertFrom-Csv

    "Getting license info and translating with mapping file..."
    $QueryResult = Query-MSGraphAPI($GraphURISubscribedSkus)
    $SubscribedSkus = $QueryResult.value
    
    foreach ($SubscribedSku in $SubscribedSkus)
    {
        $M365ProductName = ($M365ProductCodeMapping | Where-Object {$_."String ID" -eq $SubscribedSku.skuPartNumber} | Select-Object "Product name")."Product name"

        $License = $M365License.psobject.Copy()
        $License.Enabled = if ($SubscribedSku.capabilityStatus -eq "Enabled") {$true} else {$false}
        $License.ProductCode = $SubscribedSku.skuPartNumber
        $License.ProductDescription = $M365ProductName
        $License.TotalCount = $SubscribedSku.prepaidUnits.enabled
        $License.UsedCount = $SubscribedSku.consumedUnits

        $global:M365Tenant.Licenses.Add($License) | Out-Null        
    }
}

function Get-Domains
{
    "Getting Domains..."

    $QueryResult = Query-MSGraphAPI($GraphURIDomains)

    foreach ($DomainResult in $QueryResult.value)
    {
        $Domain = $M365Domain.psobject.Copy()
        $Domain.Name = $DomainResult.id
        $Domain.Default = if ($DomainResult.isDefault) {$true} else {$false}
        $Domain.EmailEnabled = if ($DomainResult.supportedServices.Contains("Email")) {$true} else {$false}

        if ($Domain.EmailEnabled)
        {
            # "Checking MX record for $($Domain.Name)..."
            # $MXRecord = Resolve-DnsName $Domain.Name -Server 1.1.1.1 -Type MX

            "Checking SPF record for $($Domain.Name)..."
            $RootTXTRecords = Resolve-DnsName $Domain.Name -Server 1.1.1.1 -Type TXT -ErrorAction SilentlyContinue

            foreach ($TXTRecord in $RootTXTRecords)
            {
                if ($TXTRecord.Text -match "v=spf1")
                {
                    $Domain.SPFRecord = $TXTRecord.Text
                }
            }

            "Check for DKIM Selectors..."
            $Selector1 = Resolve-DnsName selector1._domainkey.$($Domain.Name) -Server 1.1.1.1 -Type CNAME -ErrorAction SilentlyContinue
            $Selector2 = Resolve-DnsName selector2._domainkey.$($Domain.Name) -Server 1.1.1.1 -Type CNAME -ErrorAction SilentlyContinue

            if ($null -eq $Selector1 -or $null -eq $Selector2)
            {
                $Domain.DKIMConfigured = $false
            }
            else
            {
                $Domain.DKIMConfigured = $true    
            }

            "Check for DMARC Record..."
            $Domain.DMARCConfigured = $false
            $DmarcRecord = Resolve-DnsName "_dmarc.$($Domain.Name)" -Server 1.1.1.1 -Type TXT -ErrorAction SilentlyContinue

            if ($null -ne $DmarcRecord)
            {
                if ($DmarcRecord.Text -match "v=DMARC1")
                {
                    $Domain.DMARCConfigured = $true
                }
            }
        }        

        $global:M365Tenant.Domains.Add($Domain) | Out-Null    
    }
}

function Get-Users
{
    "Getting Users..."
    
    $UserRegistrations = $null

    if ($global:M365Tenant.AzureAdPremiumEnabled)
    {
        # Registrations represent the details of the usage of self-service password reset and multi-factor authentication (MFA) for all registered users.
        # Details include user information, status of registration, and the authentication method used.
        # If the customer has Azure AD Premium we will supplement user data with this info

        "Querying Graph API for User Registrations (Azure AD Premium Enabled)..."
        $QueryResult = Query-MSGraphAPI($GraphURIUserRegistration)
        $UserRegistrations = $QueryResult.value

        $PageCount = 1
        while ($QueryResult.'@odata.nextLink')
        {
            $PageCount++
            "Getting Page $PageCount..."
            $QueryResult = Query-MSGraphAPI($QueryResult.'@odata.nextLink')
            $UserRegistrations += $QueryResult.value
        }
    }       

    "Querying Azure AD for users..."
    # This is required to determine if users have MFA enforced
    # DEPRECATED WITH GDAP AUGUST 2023
    # $TenantADUsers = Get-MsolUser -All -TenantId $global:M365Tenant.TenantID

    # Primary query for users in the tenant
    "Querying Graph API for users..."

    $GraphURI = $GraphURIUsers # Does not include signin activity

    if ($global:M365Tenant.AzureAdPremiumEnabled)
    {
        $GraphURI = $GraphURIUsersAADPremium # Includes sign in activity such as last login time
    }

    $QueryResult = Query-MSGraphAPI($GraphURI)
    $TenantUsers = $QueryResult.value

    $PageCount = 1
    while ($QueryResult.'@odata.nextLink')
    {
        $PageCount++
        "Getting Page $PageCount..."
        $QueryResult = Query-MSGraphAPI($QueryResult.'@odata.nextLink')
        $TenantUsers += $QueryResult.value
    }
    
    "Compiling user results..."
    foreach ($UserResult in $TenantUsers)
    {
        $UserResult.userPrincipalName
        $User = $M365User.psobject.Copy()
        $User.Enabled = $UserResult.accountEnabled
        $User.UserType = $UserResult.userType
        $User.DisplayName = $UserResult.displayName
        $User.UPN = $UserResult.userPrincipalName
        $User.UsageLocation = $UserResult.usageLocation
        $User.ProxyAddresses = $UserResult.proxyAddresses | Where-Object {$_.ToLower().Contains("smtp:")}
        $User.LastSignInDateTime = if ($UserResult.signInActivity) {$UserResult.signInActivity.lastSignInDateTime}

        $DaysSinceLastUserInteractiveSignin = 999999

        if ($null -ne $User.LastSignInDateTime)
        {
            $Now = Get-Date
            $LastSignIn = [DateTime]$User.LastSignInDateTime
            $DaysSinceLastUserInteractiveSignin = ($Now - $LastSignIn).TotalDays
        }

        if (($null -eq $User.LastSignInDateTime -or $DaysSinceLastUserInteractiveSignin -gt $InactiveUserDaysThreshold) -and $User.UserType -ne "Guest")
        {
            # No recent interactive sign-ins recorded, so lets check non-interactive sign-ins
            "`tNo recent interactive sign-ins, getting non-interactive sign-ins..."
            $QueryURI = $GraphURISignInLastNonInteractive.Replace("<userPrincipalName>", $User.UPN)
            $QueryResult = Query-MSGraphAPI($QueryURI)
            if ($null -ne $QueryResult)
            {
                $User.LastNonInteractiveSignInDateTime = $QueryResult.value[0].createdDateTime
            }
        }

        # Check data from user registrations query
        $UserRegistrationDetails = $UserRegistrations | Where-Object {$_.userPrincipalName -eq $User.UPN}
        $User.MFARegistered = if ($UserRegistrationDetails.isMfaRegistered) {$true} elseif ($UserRegistrationDetails.isMfaRegistered -eq $false) {$false} else {$null}
        $User.AuthenticationMethods = $UserRegistrationDetails.authMethods

        # Check data from Get-MsolUser command
        # DEPRECATED WITH GDAP AUGUST 2023
        # $AzureADUser = $TenantADUsers | Where-Object {$_.UserPrincipalName -eq $User.UPN}
        # $User.MFAManuallyEnforced = if ($AzureADUser.StrongAuthenticationRequirements.State -eq "Enforced") {$true} else {$false}

        $global:M365Tenant.Users.Add($User) | Out-Null
    }
}

function Get-SignIns
{
    "Getting sign ins..."

    $QueryResult = Query-MSGraphAPI($GraphURISignInReports)

    $SignIns = $QueryResult.value

    $PageCount = 1
    while ($QueryResult.'@odata.nextLink')
    {
        $PageCount++
        "Getting Page $PageCount..."
        $QueryResult = Query-MSGraphAPI($QueryResult.'@odata.nextLink')
        $SignIns += $QueryResult.value
    }

    "Processing sign ins..."
    foreach ($SignInResult in $SignIns)
    {
        $SignIn = $M365SignIn.psobject.Copy()
        $SignIn.DateTime = $SignInResult.createdDateTime
        $SignIn.UPN = $SignInResult.userPrincipalName
        $SignIn.UserDisplayName = $SignInResult.userDisplayName
        $SignIn.AppDisplayName = $SignInResult.appDisplayName
        $SignIn.IPAddress = $SignInResult.ipAddress
        $SignIn.ClientApp = $SignInResult.clientAppUsed
        $SignIn.ResourceAccessed = $SignInResult.resourceDisplayName
        $Signin.StatusCode = $SignInResult.status.errorCode
        $Signin.StatusFailureReason = $SignInResult.status.failureReason
        $Signin.StatusAdditionalDetails = $SignInResult.status.additionalDetails
        $Signin.Country = if ($SignInResult.location.countryOrRegion) {$SignInResult.location.countryOrRegion} else {$null}

        $global:M365Tenant.SignIns.Add($SignIn) | Out-Null
    }
}

function Get-Devices
{
    "Getting devices..."
    $QueryResult = Query-MSGraphAPI($GraphURIManagedDevices)

    if ($QueryResult.value.count -gt 0)
    {
        $global:M365Tenant.EndpointManagementEnabled = $true
    }
    else
    {
        $global:M365Tenant.EndpointManagementEnabled = $false
    }
    
    foreach ($DeviceResult in $QueryResult.value)
    {
        $Device = $M365Device.psobject.Copy()
        $Device.Name = $DeviceResult.deviceName
        $Device.UPN = $DeviceResult.userPrincipalName
        $Device.UserDisplayName = $DeviceResult.userDisplayName
        $Device.ComplianceState = $DeviceResult.complianceState
        $Device.OwnershipType = $DeviceResult.managedDeviceOwnerType
        $Device.LastSyncDateTime = $DeviceResult.lastSyncDateTime
        $Device.OperatingSystem = $DeviceResult.operatingSystem
        $Device.OSVersion = $DeviceResult.osVersion
        $Device.Manufacturer = $DeviceResult.manufacturer
        $Device.Model = $DeviceResult.model
        $Device.SerialNumber = $DeviceResult.serialNumber

        $global:M365Tenant.Devices.Add($Device) | Out-Null
    }
}

function Get-MailboxUsage
{
    "Getting mailbox usage..."
    $MailboxResults = Get-GraphReport($GraphURIMailboxUsage)

    foreach ($MailboxResult in $MailboxResults)
    {
        $User = $global:M365Tenant.Users | Where-Object {$_.UPN -eq $MailboxResult.'User Principal Name'}
        if ($null -ne $User)
        {
            $User.MailboxItems = $MailboxResult.'Item Count'
            $User.MailboxStorageUsed = $MailboxResult.'Storage Used (Byte)'
            $User.MailboxQuota = $MailboxResult.'Prohibit Send/Receive Quota (Byte)'
        }        
    }
}

function Get-EmailActivity
{
    "Getting email activity..."
    $EmailResults = Get-GraphReport($GraphURIEmailActivity)

    foreach ($EmailResult in $EmailResults)
    {
        $User = $global:M365Tenant.Users | Where-Object {$_.UPN -eq $EmailResult.'User Principal Name'}
        if ($null -ne $User)
        {
            $User.EmailsSent = $EmailResult.'Send Count'
            $User.EmailsReceived = $EmailResult.'Receive Count'
            $User.EmailsRead = $EmailResult.'Read Count'
        }        
    }
}

function Get-OneDriveUsage
{
    "Getting OneDrive usage..."
    $OneDriveResults = Get-GraphReport($GraphURIOneDriveUsage)
    
    foreach ($OneDriveResult in $OneDriveResults)
    {
        $User = $global:M365Tenant.Users | Where-Object {$_.UPN -eq $OneDriveResult.'Owner Principal Name'}
        if ($null -ne $User)
        {
            $User.OneDriveFiles = $OneDriveResult.'File Count'
            $User.OneDriveStorageUsed = $OneDriveResult.'Storage Used (Byte)'
            $User.OneDriveQuota = $OneDriveResult.'Storage Allocated (Byte)'
        }        
    }
}

function Get-SharePointUsage
{
    "Getting SharePoint usage..."

    $SharePointResults = Get-GraphReport($GraphURISharePointUsage)

    foreach ($SharePointResult in $SharePointResults)
    {
        $SharePointSite = $M365SharePointSite.psobject.copy()

        # $QueryUri = $GraphURISharePointSite.Replace("<siteid>", $SharePointResult.'Site Id')
        # $SharePointGraphResult = Query-MSGraphAPI -QueryURI $QueryUri
        
        #$SharePointSite.Site = $SharePointResult.'Site URL'
        # $SharePointSite.Site = ($ResultList | Where-Object {$_.siteId -eq "$SharePointResult.'Site Id'"}).siteUrl
        $SharePointSite.ID = $SharePointResult.'Site Id'
        $SharePointSite.FileCount = $SharePointResult.'File Count'
        $SharePointSite.StorageUsed = $SharePointResult.'Storage Used (Byte)'
        $SharePointSite.StorageAllocated = $SharePointResult.'Storage Allocated (Byte)'

        $global:M365Tenant.SharePointSites.Add($SharePointSite) | Out-Null
    }
}

function Get-ConditionalAccessPolicies
{
    "Getting Conditional Access Policies..."
    $QueryResult = Query-MSGraphAPI($GraphURIConditionalAccessPolicies)

    foreach ($CAPolicyResult in $QueryResult.value)
    {
        $CAPolicy = $M365ConditionalAccessPolicy.psobject.Copy()
        $CAPolicy.'Policy Name' = $CAPolicyResult.displayName
        $CAPolicy.'State' = $CAPolicyResult.state
        $CAPolicy.'Targets MFA' = $false

        if ($null -ne $CAPolicyResult.grantControls)
        {
            if ($CAPolicyResult.grantControls.builtInControls.Contains("mfa"))
            {
                $CAPolicy.'Targets MFA' = $true
            }
        }

        $global:M365Tenant.ConditionalAccessPolicies.Add($CAPolicy) | Out-Null
    }

    "Checking if Security Defaults is enabled..."
    $QueryResult = Query-MSGraphAPI($GraphURISecurityDefaults)

    if ($QueryResult.isEnabled)
    {
        $global:M365Tenant.SecurityDefaultsEnabled = $true
    }
    else
    {
        $global:M365Tenant.SecurityDefaultsEnabled = $false
    }

}

function Get-Applications
{
    "Getting Applications..."
    $QueryResult = Query-MSGraphAPI("$GraphURIApplications")
    
    foreach ($Application in $QueryResult.value)
    {
        $Application.displayName
        foreach ($RequiredResourceAccess in $Application.requiredResourceAccess)
        {
            $ResourceAppId = $RequiredResourceAccess.resourceAppId
            # https://graph.microsoft.com/beta/servicePrincipals?filter=appId eq '00000003-0000-0000-c000-000000000000'
            $QueryURI = $GraphURIServicePrincipals.Replace("<resourceAppId>", $ResourceAppId)
            $QueryResult = Query-MSGraphAPI($QueryURI)
            $ServicePrincipal = $QueryResult.value[0]
            $AppDisplayName = $ServicePrincipal.appDisplayName
            "`t$AppDisplayName"
            foreach ($ResourceAccess in $RequiredResourceAccess.resourceAccess)
            {
                $Permission = $ServicePrincipal.publishedPermissionScopes | Where-Object {$_.id -eq $ResourceAccess.id}
                if ($null -eq $Permission)
                {
                    $Permission = $ServicePrincipal.appRoles | Where-Object {$_.id -eq $ResourceAccess.id}
                }
                "`t`t$(if ($Permission.adminConsentDisplayName) {$Permission.adminConsentDisplayName} else {$Permission.displayName}) ($($Permission.value))"
            }
        }
    }
}

function Get-GraphReport($QueryURI)
{
    # Downloads CSV using HTTP 302 Redirect
    $QueryResult = (Invoke-RestMethod -Uri $QueryURI -Headers $global:GraphApiHeaders -Method Get -ContentType "application/json")
    $ReportData = $QueryResult.Substring(3) | ConvertFrom-Csv
    return $ReportData
}

function Set-MsGraphSetting($QueryUri, $Body)
{
    do 
    {
        try
        {
            Write-Host "Patch Query: $QueryURI"
            $WebResponse = Invoke-WebRequest -Uri $QueryURI -Headers $global:GraphApiHeaders -Method Patch -Body $Body -ContentType "application/json" -UseBasicParsing

            $APIResponseCode = $WebResponse.StatusCode
            Write-Host "MS Graph API Response Code: $APIResponseCode"

            if ($WebResponse.StatusCode -eq 200)
            {
                $WebResponseContent = $WebResponse.content | ConvertFrom-Json
                return $WebResponseContent
            }
            else
            {
                return $null    
            }
        }
        catch 
        {

            $APIResponseCode = [int]$_.Exception.Response.StatusCode
            Write-Host "MS Graph API Response Code: $APIResponseCode"

            if ($_.Exception.Response.StatusDescription -eq "Forbidden")
            {
                return "Forbidden"
            }
            else
            {
                if ($APIResponseCode -eq 429)
                {
                    # Request has been throttled: https://learn.microsoft.com/en-us/graph/throttling
                    $RetryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
                    $RetryAfter = $RetryAfter + 2 # Add a bit of a buffer

                    Write-Host "Graph API request has been throttled, waiting for $RetryAfter seconds..."
                    Start-Sleep $RetryAfter
                }
                else 
                {
                    return $null
                }                    
            }
        }
    } while ($APIResponseCode -eq 429)
}

function Query-MSGraphAPI($QueryURI)
{

    # Attempt to call the Graph API, and move on if successful.
    # If a 429 response is received, it means the API call has been throttled, and the response will include a Retry-After value in seconds.
    # In that circumstance, we'll sleep for the required time by Microsoft, and run the query again until it succeeds.

    $APIResponseCode = 0

    do
    {        
        try
        {
            Write-Host "Query: $QueryURI"
            $WebResponse = Invoke-WebRequest -Uri $QueryURI -Headers $global:GraphApiHeaders -Method Get -ContentType "application/json" -UseBasicParsing

            $APIResponseCode = $WebResponse.StatusCode
            Write-Host "MS Graph API Response Code: $APIResponseCode"

            if ($WebResponse.StatusCode -eq 200)
            {
                $WebResponseContent = $WebResponse.content | ConvertFrom-Json
                return $WebResponseContent
            }
            else
            {
                return $null    
            }
        }
        catch 
        {

            $APIResponseCode = [int]$_.Exception.Response.StatusCode
            Write-Host "MS Graph API Response Code: $APIResponseCode"

            if ($_.Exception.Response.StatusDescription -eq "Forbidden")
            {
                return "Forbidden"
            }
            else
            {
                if ($APIResponseCode -eq 429)
                {
                    # Request has been throttled: https://learn.microsoft.com/en-us/graph/throttling
                    $RetryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
                    $RetryAfter = $RetryAfter + 2 # Add a bit of a buffer

                    Write-Host "Graph API request has been throttled, waiting for $RetryAfter seconds..."
                    Start-Sleep $RetryAfter
                }
                else 
                {
                    return $null
                }                    
            }
        }

    } while ($APIResponseCode -eq 429)   
}

# function Query-MSSecurityCenterAPI($QueryURI)
# {
#     # $QueryResult = Invoke-RestMethod -Uri $QueryURI -Headers $global:GraphApiHeaders -Method Get -ContentType "application/json" -ErrorAction SilentlyContinue
#     try
#     {
#         $WebResponse = Invoke-WebRequest -Uri $QueryURI -Headers $global:SecurityCenterApiHeaders -Method Get -ContentType "application/json" -UseBasicParsing
#         if ($WebResponse.StatusCode -eq 200)
#         {
#             $WebResponseContent = $WebResponse.content | ConvertFrom-Json
#             return $WebResponseContent
#         }
#         else
#         {
#             return $null    
#         }
#     }
#     catch {
#         if ($_.Exception.Response.StatusDescription -eq "Forbidden")
#         {
#             return "Forbidden"
#         }
#         else
#         {
#             return $null    
#         }
#     }   
# }

function Get-RequiredModule($ModuleName)
{
    "Loading module $ModuleName"
    if ( ! ( Get-Module -Name $ModuleName ) ) { # if module not loaded
        if ( Get-Module -ListAvailable -Name $ModuleName ) { # if module is available, just not loaded
            Import-Module -Name $ModuleName
        } else {
            Install-Module -Name $ModuleName -Scope AllUsers -AllowClobber -Force
            Import-Module -Name $ModuleName
        }
    }
}

function Test-InsideDockerContainer {
    $DockerSvc = Get-Service -Name cexecsvc -ErrorAction SilentlyContinue
    if($null -eq $DockerSvc)
    {
      return $false
    }
    else
    {
      return $true
    }
  }

function Set-TenantConfiguration
{
    # MFA access not working well with this one, disabled for now
    # https://github.com/computer-culture/m365-monitoring/issues/17
    
    # This uses an old MS API to set the M365 tenant configuration
    # We need to turn off anonymous reports for these scripts to work and produce a useful report
    # See https://www.cyberdrain.com/automating-with-powershell-disabling-anonymous-reports-for-office365/ and
    # also see https://techcommunity.microsoft.com/t5/microsoft-365-blog/privacy-changes-to-microsoft-365-usage-analytics/ba-p/2694137

    "Setting tenant configuration to disable anonymous reports..."
    $LoginUri = "https://login.microsoftonline.com/$($global:M365Tenant.TenantID)/oauth2/token"
    $loginBody = "resource=https://admin.microsoft.com&grant_type=refresh_token&refresh_token=$($global:ExchangeRefreshToken)"
    $ExchangeToken = Invoke-RestMethod $LoginUri -Body $loginBody -ContentType "application/x-www-form-urlencoded" -Method "POST" -ErrorAction SilentlyContinue
    $ConfigResult = Invoke-RestMethod -ContentType "application/json;charset=UTF-8" -Uri 'https://admin.microsoft.com/admin/api/reports/config/SetTenantConfiguration' -body '{"PrivacyEnabled":false,"PowerBiEnabled":true}' -method POST -Headers @{
        Authorization            = "Bearer $($ExchangeToken.access_token)";
        "x-ms-client-request-id" = [guid]::NewGuid().ToString();
        "x-ms-client-session-id" = [guid]::NewGuid().ToString()
        'x-ms-correlation-id'    = [guid]::NewGuid()
        'X-Requested-With'       = 'XMLHttpRequest'
    }
}

function Initialize-Environment
{
    $ConsoleOutputSeparator

    # Get authentication details for APIs we will be accessing

    if ([Environment]::UserInteractive -eq $false)
    {
        if (Test-InsideDockerContainer)
        {
            # Run from N-central, so pass in required variables
            $global:AzureAdAppId               = $M365PartnerAppID
            $global:AzureAdAppSecret           = $M365PartnerAppSecret
            # N-central variables have a length limit of 1024 characters, so refresh token is split in two
            $global:AzureAdAppRefreshToken     = $M365PartnerAppRefreshToken + $M365PartnerAppRefreshTokenExtended
            $global:ExchangeRefreshToken= $M365PartnerAppExchangeRefreshToken + $M365PartnerAppExchangeRefreshTokenExtended
            $TenantPrimaryDomain        = $M365TenantPrimaryDomain
        }
        else
        {
            # Run as a script, so domain name passed in as parameter
            $global:AzureAdAppId               = [System.Environment]::GetEnvironmentVariable("CCLPARTNERAPPAPPID", "Machine") 
            $global:AzureAdAppSecret           = [System.Environment]::GetEnvironmentVariable("CCLPARTNERAPPPASSWORD", "Machine")
            $global:AzureAdAppRefreshToken     = [System.Environment]::GetEnvironmentVariable("CCLPARTNERAPPREFRESHTOKEN", "Machine")
            $global:ExchangeRefreshToken= [System.Environment]::GetEnvironmentVariable("CCLPARTNERExchangeRefreshToken", "Machine")
            $TenantPrimaryDomain        = $M365TenantPrimaryDomain
        }        
    }
    else 
    {
        # Run interactively for debugging, so lets provide test variables
        $global:AzureAdAppId               = [System.Environment]::GetEnvironmentVariable("CCLPARTNERAPPAPPID", "Machine") 
        $global:AzureAdAppSecret           = [System.Environment]::GetEnvironmentVariable("CCLPARTNERAPPPASSWORD", "Machine")
        $global:AzureAdAppRefreshToken     = [System.Environment]::GetEnvironmentVariable("CCLPARTNERAPPREFRESHTOKEN", "Machine")
        $global:ExchangeRefreshToken= [System.Environment]::GetEnvironmentVariable("CCLPARTNERExchangeRefreshToken", "Machine")
        $TenantPrimaryDomain        = $M365TenantPrimaryDomain
    }

    # Create local storage folder if it doesn't already exist
    if (!(Test-Path $LocalDataSaveLocation))
    {
        "Creating directory $LocalDataSaveLocation"
        New-Item -Path $LocalDataSaveLocation -ItemType Directory | Out-Null
    }

    "Using Refresh Token ending in $($global:AzureAdAppRefreshToken.Substring($global:AzureAdAppRefreshToken.length - 6))"

    # # Load required modules
    # Get-RequiredModule -ModuleName MSOnline
    # Get-RequiredModule -ModuleName PartnerCenter

    # # Load credentials to authorise with Microsoft 365
    # $AzureAppCredential = New-Object System.Management.Automation.PSCredential($global:AzureAdAppId, ($global:AzureAdAppSecret | ConvertTo-SecureString -Force -AsPlainText))
    
    # "Getting Azure AD Graph Token..."
    # $AzureAdGraphToken = New-PartnerAccessToken -ApplicationId $global:AzureAdAppId -Credential $AzureAppCredential -RefreshToken $global:AzureAdAppRefreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal 
    
    # "Getting MS Graph Token..."
    # $MsGraphToken = New-PartnerAccessToken -ApplicationId $global:AzureAdAppId -Credential $AzureAppCredential -RefreshToken $global:AzureAdAppRefreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal

    # "Connecting to our Azure AD tenant..."
    # Connect-MsolService -AdGraphAccessToken $AzureAdGraphToken.AccessToken -MsGraphAccessToken $MsGraphToken.AccessToken

    # "Getting access tokens for tenant with primary domain: $TenantPrimaryDomain"
    # if ($TenantPrimaryDomain -eq "computerculture.onmicrosoft.com")
    # {
    #     # Use existing Graph token for use in our own tenant
    #     $global:GraphApiHeaders = @{ "Authorization" = "Bearer $($MsGraphToken.AccessToken)" }

    #     # Get our own tenant ID for Security API
    #     $TenantID = (Get-MSOLCompanyInformation).objectid.guid
    # }
    # else
    # {
    #     # Get customer tenant from our partner contracts
    #     # $CustomerTentant = Get-MsolPartnerContract -DomainName $TenantPrimaryDomain
    #     # if ($CustomerTentant.Count -ne 1)
    #     # {
    #     #     "Unable to find tenant with primary domain: $TenantPrimaryDomain"
    #     #     exit
    #     # }

    #     # Get access token for customer's tenant
    #     "Getting access token for Graph API..."
    #     $CustomerToken = Get-GraphAccessToken $TenantPrimaryDomain
    #     $global:GraphApiHeaders = @{ "Authorization" = "Bearer $($CustomerToken.access_token)" }
    #     # $CustomerToken = New-PartnerAccessToken -ApplicationId $AzureAdAppId -Credential $AzureAppCredential -RefreshToken $AzureAdAppRefreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenantid $($TenantPrimaryDomain) -ErrorAction Stop
        

    #     # Get customer tenant ID for Security API
    #     # $TenantId = $CustomerTentant.Tenantid
    # }

    # "Getting access token for Security Center..."
    # $appId = $AzureAdAppId
    # $appSecret = $AzureAdAppSecret

    # $resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
    # $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    # $authBody = [Ordered] @{
    #     resource = "$resourceAppIdUri"
    #     client_id = "$appId"
    #     client_secret = "$appSecret"
    #     grant_type = 'client_credentials'
    # }
    # $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    # $global:SecurityCenterApiHeaders = @{ "Authorization" = "Bearer $($authResponse.access_token)" }

    # "Security Headers: $($global:SecurityCenterApiHeaders)"

    "Getting access token for Graph API..."
    $CustomerToken = Get-GraphAccessToken $TenantPrimaryDomain
    $global:GraphApiHeaders = @{ "Authorization" = "Bearer $($CustomerToken.access_token)" }

    "M365 tenant authorization complete, ready to query MS Graph API"
    $ConsoleOutputSeparator
}

function Get-GraphAccessToken($TenantId)
{
    $global:AzureAdAppRefreshToken

    # Scope for requesting an access token
    $AccessTokenScope = "https://graph.microsoft.com/.default"

    # Endpoint to request access (refresh) token
    $TokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $TokenRequestBody = @{
        client_id = $global:AzureAdAppId
        client_secret = $global:AzureAdAppSecret
        scope = $AccessTokenScope
        refresh_token = $global:AzureAdAppRefreshToken
        grant_type = "refresh_token"
    }

    $Token = Invoke-RestMethod -Method Post -Uri $TokenEndpoint -UseBasicParsing -Body $TokenRequestBody
    
    return $Token    
}

# Launch script now that we have traversed over all the functions
Start-Script

$Now = Get-Date
# Pass summary back to N-central
$DataCollectionSummary = "Data collection successful $($Now.ToShortDateString()) $($Now.ToLongTimeString())"
$DataCollectionDateTime = $Now
