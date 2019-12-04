param (
    [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="DeepSecurity Manager API Key")][string]$apikey,
    [Parameter(Mandatory=$true, HelpMessage="CSV Location; C:\ds-tools\assignGroupsToRole.csv")][string]$csvlocation
)

<#
Example CSV format

roleName,GroupName
Audit Group,Database Servers

Example execution
.\assignGroupsToRole.ps1 -manager dsm.example.com:443 -apikey <Api key> -csvlocation "C:\ds-tools\assignGroupsToRole.csv"

#>

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Initial API endpoint variables
$roleSearchURL = "https://$manager/api/roles/search"
$computerGroupSearchURL = "https://$manager/api/computergroups/search"
# Import CSV
$RoleData = Import-CSV $csvlocation

# Headers to use for all rest queries
$headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
}

########### Search for role by name ###########
function roleSearchFunction {
    Param (
        [String] $roleName
    )
    [hashtable]$roleSearchResultsReturn = @{}

    $roleSearch = @{
        maxItems = "1"
        searchCriteria = @(
            @{
                stringTest = 'equal'
                fieldName = 'name'
                stringValue = $roleName
            }
        )
    }
    $roleSearchJson = $roleSearch | ConvertTo-Json

    $roleSearchResults = Invoke-WebRequest -Uri $roleSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $roleSearchJson | ConvertFrom-Json

    $roleSearchResultsReturn.roleID = $roleSearchResults.roles.ID
    $roleSearchResultsReturn.GroupIDs = $roleSearchResults.roles.computerGroupIDs
    return $roleSearchResultsReturn
}

########### Search for group by name ###########
function computerGroupSearchFunction {
    Param (
        [String] $groupName
    )
    $computerGroupSearch = @{
        maxItems = "1"
        searchCriteria = @(
            @{
                stringTest = 'equal'
                fieldName = 'name'
                stringValue = $groupName
            }
        )
    }
    $computerGroupSearchJson = $computerGroupSearch | ConvertTo-Json

    $computerGroupSearchResults = Invoke-WebRequest -Uri $computerGroupSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $computerGroupSearchJson | ConvertFrom-Json
    $groupID = $computerGroupSearchResults.ComputerGroups.ID
    return $groupID
}

########### Modify role by roleID ###########
function roleModifyFunction {
    Param (
        [array] $existingRoleGroupIDs,
        [String] $groupIDResults,
        [String] $roleID
    )

    $roleModifyhURL = "https://$manager/api/roles/$roleID"

    $roleModify = @{
        allComputers = 'false'
        computerGroupIDs = @(
        )
    }
    $roleGroupIDArray = @($roleModify.computerGroupIDs)

    # Add existing groups ids from the role to json
    foreach ($computerGroupIDs in $existingRoleGroupIDs) {
        $roleGroupIDArray += $computerGroupIDs
    }

    # Add group ids from group search to json
    $groupIDResults
    foreach ($groupID in $groupIDResults ){
        $roleGroupIDArray += $groupID
    }
    $roleModify.computerGroupIDs = $roleGroupIDArray
    $roleModifyJson = $roleModify | ConvertTo-Json

    $roleModifyResults = Invoke-WebRequest -Uri $roleModifyhURL -Method Post -ContentType "application/json" -Headers $headers -Body $roleModifyJson | ConvertFrom-Json
}

foreach ($i in $roleData) {
    # Search for role by name
    $existingRoleResults = roleSearchFunction $i.roleName

    # Search for group by name
    $groupIDResults =  computerGroupSearchFunction $i.groupName

    # If statement to check to see if the group is already assigned to the role.
    if ($existingRoleResults.GroupIDs -contains $groupIDResults) {
        write-host -NoNewline "Computer group "; Write-Host -NoNewline -f Magenta $i.groupName ; Write-Host -NoNewline " Already assigned to "; Write-Host -f Magenta $i.roleName
    }
    else {
        # Modify role by roleID
        $roleModifyVar = roleModifyFunction $existingRoleResults.GroupIDs $groupIDResults $existingRoleResults.roleID
        write-host -NoNewline "Computer group "; Write-Host -NoNewline -f Green $i.groupName ; Write-Host -NoNewline " assigned to "; Write-Host -f Green $i.roleName
    }

    
}
