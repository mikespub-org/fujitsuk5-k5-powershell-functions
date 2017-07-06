# Import K5 json definitions function
. $PSScriptRoot/k5json.ps1

# Only TLS 1.2 allowed, Powershell needs to be forced as it won't negotiate!
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Function Get-K5Token
{
    <#

    .SYNOPSIS
    Retrieves a token from the K5 identity service (keystone) to provide authentication for subsequent calls to K5 API endpoints

    .DESCRIPTION
    The Get-K5Token function retrieves a token from the K5 identity service scoped as requested using supplied credentials. The token
    should be saved in a variable and used to authenticate subsequent calls to K5 API endpoints. If called without parameters the region
    will default to uk-1 and contract, username, password, and project will be retrieved from k5env.csv which must exist in the same
    location as the script containing this function and be formatted as follows (OpenSSLPath only required if you intend to use the
    Get-K5WindowsPassword function to decrypt the k5user password assigned during the build process, thumbprint only required if your
    user is configured for two factor auth):

    "name","value"
    "k5user","username"
    "k5pword","password"
    "k5project","projectname"
    "proxyURL","http://your.proxy.name"
    "k5_uk_contract","uk_contract"
    "k5_de_contract","de_contract"
    "k5_fi_contract","fi_contract"
    "OpenSSLPath","C:\your\path\to\openssl.exe"
    "thumbprint","ClientCertThumbprint"

    The object returned by the Get-K5Token function has a number of properties:
    
    domainid    The id of the domain (contract) to which the token is scoped
    endpoints   A hashtable containing all the applicable API endpoints for the token's scope 
    expiry      A timestamp indicating when the token will expire
    projectid   The id of the project to which the token is scoped
    projects    An object containing details of all projects to which the user has access
    token       A hashtable containing the returned authentication token
    userid      The id of the user to whom the token has been issued

    .PARAMETER region
    The region to scope to, defaults to uk-1

    .PARAMETER contract
    The contract to scope to, defaults to the contract specified in k5env.csv for the region to which you are scoping.

    .PARAMETER user
    Your K5 username for the specified contract, defaults to the username stored in k5env.csv

    .PARAMETER password
    The password for the specified K5 username, defaults to the password stored in k5env.csv

    .PARAMETER projectname
    The project within the specified contract to which you wish to scope, defaults to the project specified in k5env.csv

    .PARAMETER global
    Switch parameter to specify the token should be globally scoped

    .PARAMETER unscoped
    Switch parameter to specify the token should not be scoped to a project

    .PARAMETER useProxy
    Switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used

    .EXAMPLE

    # Retrieve a token using the defaults stored in k5env.csv and store in $token for future use

PS C:\>$token = Get-K5Token

    .EXAMPLE

    # Retrieve a token supplying all required authentication information and store in $token for future use, use the proxy when making the call

PS C:\>$token = Get-K5Token -region de-1 -contract mycontract -user myuser -password mypassword -projectname myproject -useProxy

    .EXAMPLE

    # Show the returned token's expiry

PS C:\>$token.expiry

05 April 2017 16:20:23


    #>
    [cmdletbinding(DefaultParameterSetName=’Scoped’)]
    param
    (
        # Region parameter - default to uk-1
        [Parameter()][ValidateSet('de-1','fi-1','uk-1','es-1','jp-east-1')][string]$region = "uk-1",
        # Contract parameter - default to appropriate free tier contract for the specified region
        [string]$contract = $(
                                switch ($region)
                                {
                                    "uk-1" {$((Get-K5Vars)["k5_uk_contract"])}
                                    "fi-1" {$((Get-K5Vars)["k5_fi_contract"])}
                                    "de-1" {$((Get-K5Vars)["k5_de_contract"])}
                                    "es-1" {$((Get-K5Vars)["k5_es_contract"])}
                                }
                            ),
        # User parameter - default to required user
        [string]$user = $((Get-K5Vars)["k5user"]),
        # Password parameter - default to required user's password
        [string]$password = $((Get-K5Vars)["k5pword"]),
        # Project name parameter - default to required project
        [Parameter(ParameterSetName="Scoped")][string]$projectname = $((Get-K5Vars)["k5project"]),
        # Global token scope parameter - default to false
        [Parameter(ParameterSetName="Global")][switch]$global = $false,
        # Unscoped token parameter - default to false
        [Parameter(ParameterSetName="Unscoped")][switch]$unscoped = $false,
        # Use proxy switch parameter
        [switch]$useProxy
    )

    # URL for the specified region's identity service, future calls will use the endpoint returned when retrieving the token
    $regional_identity_url = "https://identity.$region.cloud.global.fujitsu.com/v3/auth/tokens"
    # Global identity service URL
    $global_identity_url = "https://auth-api.jp-east-1.paas.cloud.global.fujitsu.com/API/paas/auth/token"
    # Default header for REST API calls, accept JSON returns
    $headers = @{"Accept" = "application/json"}
    # Define the token object for the function return
    $token = "" | select "token","region","projectid","userid","domainid","expiry","endpoints","projects"
    $token.region = $region

    # Check if we need to return a globally scoped token
    if ($global)
    {
        try
        {
            # Retrieve the JSON for a global token request
            $json = get-k5json token_global
            # Make the API call to request a token from the global identity endpoint
            $detail = Invoke-WebRequest2 -Uri "$global_identity_url" -Method POST -headers $headers -Body $json -ContentType "application/json" -UseProxy $useProxy
            # Extract the payload from the API return and convert from JSON to a PS object
            $return = $detail.Content | ConvertFrom-json
            # Set the token property stored in the headers of the API return
            $token.token = @{"Token" = $detail.headers["X-Access-Token"]}
            # Set the token expiry time
            $token.expiry = [DateTime]([xml.xmlconvert]::ToDateTime($return.token.expires_at)).DateTime
        }
        catch
        {
            # If something went wrong, display an error and exit
            Display-Error -error "Global token retrieval failed..." -errorObj $_
        }
        # Exit and return the token object
        return $token
    }
    
    # Retrieve unscoped token   
    try
    {
        # Retrieve the JSON for an unscoped token request
        $json = get-k5json token_unscoped
        # Make the API call to request a token from the regional identity endpoint
        $detail = Invoke-WebRequest2 -Uri "$regional_identity_url" -Method POST -headers $headers -Body $json -ContentType "application/json" -UseProxy $useProxy
        # Extract the payload from the API return and convert from JSON to a PS object
        $return = $detail.Content | ConvertFrom-json
    }
    catch
    {
        # If something went wrong, display an error and exit
        Display-Error -error "Unscoped token retrieval failed..." -errorObj $_
    }
    # Set the token property stored in the headers of the API return
    $token.token = @{"X-Auth-Token" = $detail.headers["X-Subject-Token"]}
    # Set the domain id property
    $token.domainid = $return.token.project.domain.id
    # Set the user id property
    $token.userid = $return.token.user.id
    # Set the project id property
    $token.projectid = $return.token.project.id
    # Retrieve the endpoints from the API return and set the endpoints property accordingly
    $token.endpoints = Process-Endpoints $return.token.catalog.endpoints
    # Set the token expiry property
    $token.expiry = [DateTime]([xml.xmlconvert]::ToDateTime($return.token.expires_at)).DateTime
    # Add the token to the headers object for authenticating the following API calls 
    $headers += $token.token
    # Enumerate the projects available to this user
    try
    {
        # Make the API call to retrieve the list of projects accessible to this user from the identity endpoint
        $detail = Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/users/$($token.userid)/projects" -Method GET -headers $headers -ContentType "application/json" -UseProxy $useProxy
        # Extract the payload from the API return and convert from JSON to a PS object
        $return = $detail.Content | ConvertFrom-Json
    }
    catch
    {
        # If something went wrong, display an error and exit
        Display-Error -error "Project enumeration failed..." -errorObj $_
    }
    # Set the projects property using the projects returned from the API call        
    $token.projects = $return.projects
    # Do we require a scoped token?
    if (-not $unscoped)
    {
        # Scoped token required, find the project id of the project we need to scope to
        $token.projectid = ($return.projects | where name -eq $projectname).id
        # If we can't find a project id for the specified project name display an error and exit
        if ( -not $token.projectid) { Display-Error -error "Project $projectname not found."}
        # Reset the headers
        $headers = @{"Accept" = "application/json"}
        try
        {
            # Set the projectid propert expected in the JSON skeleton
            $projectid = $token.projectid
            # Retrieve the JSON for an scoped token request
            $json = get-k5json token_scoped
            # Make the API call to request a token from the identity endpoint
            $detail = Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/auth/tokens" -Method POST -headers $headers -Body $json -ContentType "application/json" -UseProxy $useProxy
            # Extract the payload from the API return and convert from JSON to a PS object
            $return = $detail.Content | ConvertFrom-json
        }
        catch
        {
            # If something went wrong, display an error and exit
            Display-Error -error "Scoped token retrieval failed..." -errorObj $_
        }
        # Scoped token, retrieve the endpoints from the API return and set the endpoints property accordingly
        $token.endpoints = Process-Endpoints $return.token.catalog.endpoints
        # Set the token property
        $token.token = @{"X-Auth-Token" = $detail.headers["X-Subject-Token"]}
        # Set the token expiry property
        $token.expiry = [DateTime]([xml.xmlconvert]::ToDateTime($return.token.expires_at)).DateTime
    }
    # Return the token object
    return $token
}

Function Process-Endpoints
{
    param
    (
        [array]$endpointlist
    )
    $endpoints = @{}
    foreach ($endpoint in $endpointlist)
    {
        $endpoints.Add($endpoint.name,$endpoint.url)
    }
    return $endpoints
}

Function Get-K5Vars
{
    $k5vars = @{} 
    $vars = Import-Csv $PSScriptRoot\k5env.csv
    foreach ($var in $vars)
    {
        $k5vars.Add($var.name,$var.value)
    }
    return $k5vars
}

Function Display-Error
{
    param
    (
        [string]$error,
        [pscustomobject]$errorObj
    )
    Write-Host "Error: $error" -ForegroundColor Red
    if ($errorObj)
    {
        Write-Host "Exception: $($errorObj.Exception.Message)" -ForegroundColor Red
        Write-Host "$($errorObj.InvocationInfo.PositionMessage)" -ForegroundColor Red
    }
    break
}

# Mirror Invoke-WebRequest function to allow use (or not) of proxy and certificates within the K5 functions without hardcoding
Function Invoke-WebRequest2
{
    param
    (
        [string]$Uri,
        [string]$Method,
        [hashtable]$Headers,
        [string]$Body,
        [string]$ContentType,
        [pscustomobject]$token,
        [bool]$UseProxy=$false
    )
    # If a token was passed in check it's expiry and inform user if it's expired
    if (($token) -and ($token.expiry -le [datetime]::Now)) {Display-Error "Token has expired, please obtain another..."}
    # Retrieve certificate thumbprint if it's been set
    $thumbprint = $((Get-K5Vars)["thumbprint"])
    # Base comand
    $cmd = 'Invoke-WebRequest -Uri $Uri -Method $Method -headers $Headers -ContentType $ContentType '
    # Add body if required
    if ($Body) {$cmd = $cmd + '-Body $Body '}
    # Add proxy if required
    if ($UseProxy) {$cmd = $cmd + '-Proxy $((Get-K5Vars)["proxyURL"]) -ProxyUseDefaultCredentials '}
    # Add certificate thumbprint if required
    if ($thumbprint) {$cmd = $cmd + '-CertificateThumbprint $thumbprint '}
    try
    {
        $return = Invoke-Expression $cmd
    }
    catch
    {
        # Check to see if proxy auth failed and user forgot to specify using a proxy...
        if (($_.Exception.Message -match "\(407\) Proxy") -and (-not $useProxy))
        # We need to try the proxy
        {
            $cmd = $cmd + '-Proxy $((Get-K5Vars)["proxyURL"]) -ProxyUseDefaultCredentials '
            $return = Invoke-Expression $cmd
        } else {
            # Something else went wrong, throw the erro back to the caling function
            throw $_
        }
    }
    # Return the web request return
    return $return
}

Function Get-K5UserGroups
{
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [switch]$useProxy
    )
    if (-not $token){break}
    try
    {
        $headers = @{"Accept" = "application/json"}
        $headers += $token.token
        $detail = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["identityv3"])/users/?domain_id=$($token.domainid)" -Method GET -headers $headers -ContentType "application/json" -UseProxy $useProxy
        $users = ($detail.Content | ConvertFrom-Json).users
        $usergroups = @()
        foreach ($user in $users)
        {
            $detail = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["identityv3"])/users/$($user.id)/groups" -Method GET -headers $headers -ContentType "application/json" -UseProxy $useProxy
            $return = $detail.Content | ConvertFrom-Json
            foreach ($group in $return.groups)
            {
                $usergroup = "" | select "Username","Group","Description","id"
                $usergroup.Username = $user.name
                $usergroup.Group = $group.name
                $usergroup.Description = $group.description
                $usergroup.id = $group.id
                $usergroups += $usergroup
            }
        }
    }
    catch
    {
        Display-Error -error "Get-K5UserGroups failed..." -errorObj $_
    }
    return $usergroups
}

Function Get-K5Resources
{
    <#

    .SYNOPSIS
    Retrieves a list of K5 resources of a given type

    .DESCRIPTION
    The Get-K5Resources function retrieves a list of resources of a given type, optionally for a specific resource name.
    The list is either comprised of names and ids, or if required, a detailed list of all attributes.

    .PARAMETER token
    Required, a token object returned by the Get-K5Token function

    .PARAMETER type
    Required, the type of resource required, if not specified the error message will detail the acceptable types

    .PARAMETER name
    Optional, the name of the resource required, eg the server name if type is servers

    .PARAMETER detailed
    Optional, switch to request detailed list

    .PARAMETER useProxy
    Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

    .EXAMPLE 
    
# Get a simple list of names and ids of all servers, use proxy when making the call
    
PS C:\>Get-K5Resources -token $token -type servers -UseProxy

name                      id                                  
----                      --                                  
WinTest                   ecff651a-0e4d-4685-8dcc-f1064384f717
meta_test                 486ca902-8ff8-3979-a1c6-db38b7862d3e
ACT_Project_a_Server2_AZ1 843f0b1b-df88-417a-b822-2a689fd9432a
ACT_Project_a_Server1_AZ1 21dd980d-a50a-44cf-b4fc-270a579dc788
ACT_Project_a_Server2_AZ2 90756aa3-5373-4901-b4ea-70ce358f97dd
ACT_Project_a_Server1_AZ2 20f7c1de-5d40-bd67-d173-b813148ca5b4

    .EXAMPLE 
# Get a detailed list of attributes for server named WinTest
    
PS C:\>PSGet-K5Resources -token $token -type servers -name WinTest -detailed


status                               : ACTIVE
updated                              : 2017-04-05T09:27:26Z
hostId                               : f60457d820d0dd319f19a1c2d2a234552a7356d7597756b1ed02e3fb
OS-EXT-SRV-ATTR:host                 : gb1a01-pgy023-00
addresses                            : @{ACT_Project_a_Net_AZ1=System.Object[]}
links                                : {@{href=http://10.19.0.201/v2/3d7a4ca55d2f4ff8b0fd7175d4bdde9f/servers/ecff651a-0e4d-4685-8dcc-f1064384f717; rel=self}, 
                                       @{href=http://10.19.0.201/3d7a4ca55d2f4ff8b0fd7175d4bdde9f/servers/ecff651a-0e4d-4685-8dcc-f1064384f717; rel=bookmark}}
key_name                             : ACT_KP_AZ1
image                                : @{id=6ef614db-1145-42a0-8ec2-bc4d526aa4be; links=System.Object[]}
OS-EXT-STS:task_state                : 
OS-EXT-STS:vm_state                  : active
OS-EXT-SRV-ATTR:instance_name        : instance-00014b43
OS-SRV-USG:launched_at               : 2017-04-05T09:27:25.000000
OS-EXT-SRV-ATTR:hypervisor_hostname  : gb1a01-pgy023-00
flavor                               : @{id=1102; links=System.Object[]}
id                                   : ecf2d41a-0f1d-4a45-8fcc-f1045384f717
security_groups                      : {@{name=default}}
OS-SRV-USG:terminated_at             : 
OS-EXT-AZ:availability_zone          : uk-1a
user_id                              : 9a64f6341e6414d7839f0620422cbdaa
name                                 : WinTest
created                              : 2017-04-05T09:02:11Z
tenant_id                            : 5d7a4cd55e3f6f40b84d717ad4f4de97
OS-DCF:diskConfig                    : MANUAL
os-extended-volumes:volumes_attached : {@{id=05a3d439-5800-46c4-8ade-550b547af25c}}
accessIPv4                           : 
accessIPv6                           : 
progress                             : 0
OS-EXT-STS:power_state               : 1
config_drive                         : 
metadata                             : @{admin_pass=}

    #>

    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$type = $(Display-Error -error "Please specify a resource type using the -type parameter"),
        [string]$name,
        [switch]$detailed,
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $type)) {break}
    $type_nw    = "routers","networks","subnets","ports","security-groups","security-group-rules","floatingips","network_connectors","network_connector_endpoints"
    $type_fw    = "firewalls","firewall_rules","firewall_policies"
    $type_vpn   = "ipsecpolicies","ipsec-site-connections","vpnservices","ikepolicies"
    $type_comp  = "servers","images","flavors","os-keypairs"
    $type_block = "volumes","types","snapshots"
    $type_obj   = "containers"
    $type_user  = "users","groups"
    $type_role = "roles"
    $type_stack = "stacks"
    $type_db = "instances"
    $type_limit = "limits"
    $validtypes = ((Get-Variable -name type_*).Value | sort) -join ", " 
    switch ($type)
    {
       {$_ -in $type_nw}    {$endpoint = $token.endpoints["networking"] + "/v2.0/" + $type}
       {$_ -in $type_fw}    {$endpoint = $token.endpoints["networking"] + "/v2.0/fw/" + $type}
       {$_ -in $type_vpn}   {$endpoint = $token.endpoints["networking"] + "/v2.0/vpn/" + $type}
       {$_ -in $type_comp}  {$endpoint = $token.endpoints["compute"] +"/" + $type}
       {$_ -in $type_limit} {$endpoint = $token.endpoints["compute"] +"/" + $type}
       {$_ -in $type_block} {$endpoint = $token.endpoints["blockstoragev2"] +"/" + $type}
       {$_ -in $type_obj}   {$endpoint = $token.endpoints["objectstorage"] + "/?format=json"}
       {$_ -in $type_user}  {$endpoint = $token.endpoints["identityv3"] + "/" + $type + "/?domain_id=" + $token.domainid}
       {$_ -in $type_role}  {$endpoint = $token.endpoints["identityv3"] + "/roles"}
       {$_ -in $type_stack} {$endpoint = $token.endpoints["orchestration"] +"/stacks"}
       {$_ -in $type_db}    {$endpoint = $token.endpoints["database"] +"/instances"}
       default              {Display-Error -error "Unknown type `'$type`' - acceptable values are $validtypes"}
    }
    if (-not $endpoint){break}
    try
    {
        if ($type -in $type_limit)
        {
            $return = @()
            $detail = (Invoke-WebRequest2 -token $token -Uri "${endpoint}?availability_zone=$($token.region)a" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy | ConvertFrom-Json).limits.absolute
            $detail | Add-Member -MemberType NoteProperty -Name "AZ" -Value "$($token.region)a"
            $return += $detail
            $detail = (Invoke-WebRequest2 -token $token -Uri "${endpoint}?availability_zone=$($token.region)b" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy | ConvertFrom-Json).limits.absolute
            $detail | Add-Member -MemberType NoteProperty -Name "AZ" -Value "$($token.region)b"
            $return += $detail
            return $return
            break
        }
        $detail = (Invoke-WebRequest2 -token $token -Uri "$endpoint" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy).content | ConvertFrom-Json
        if ($detail)
        {
            if ($type -in $type_obj)
            {
                if ($name) {$detail = $detail  | where name -eq $name}
                if (-not $detail) { Display-Error -error "Resource named: $name of type: $type not found"}
                if ($detailed)
                {
                    $return = @()
                    foreach ($container in $detail)
                    {
                        $detail2 = Invoke-WebRequest2 -token $token -Uri "$($endpoint.replace('/?format=json',''))/$($container.name)?format=json" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy | ConvertFrom-Json
                        foreach ($object in $detail2)
                        {
                            $object | Add-Member -MemberType NoteProperty -Name "Container" -Value $container.name
                            $return += $object
                        }
                        
                    }
                    
                } else {
                    $return = $detail
                }
                return $return
            } else {
                while (($detail | gm -MemberType NoteProperty).count -in 1..2)
                {
                    $detail = $detail.$(($detail | gm | where name -ne "links")[-1].Name)
                }
                if ($detail.stack_name -ne $null){$detail | Add-Member -MemberType AliasProperty -Name name -Value stack_name}
                if ($name)
                {
                    $detail = $detail  | where name -eq $name
                    if (-not $detail) { Display-Error -error "Resource named '$name' of type '$type' not found"}
                }
                if ($detailed)
                {
                    if ((($detail.links -ne $null) -or ($detail.id -eq $null)) -and ( $type -ne $user))
                    {
                        $return = @()
                        if ($detail.links -ne $null){$ids = $detail.id} else {$ids = $detail.name}
                        foreach ($id in $ids)
                        {
                            $return += (Invoke-WebRequest2 -token $token -Uri "$endpoint/$id" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy).content | ConvertFrom-Json
                        }
                        $return = $return.$(($return | gm)[-1].Name)
                    } else {
                        $return = $detail
                    }
                } else {
                    $return = $detail | select name,id
                }
            }
        }
    }
    catch
    {
        Display-Error -error "Get-K5Resources failed..." -errorObj $_
    }
    foreach ($object in $return)
    {
        $object | Add-Member -MemberType NoteProperty -Name "self" -Value "$endpoint/$($object.id)"
    }
    return $return
}


Function Get-K5RoleToGroupAssignments
{
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$groupid = $(Display-Error -error "Please specify a group id using the -groupid parameter"),
        [string]$projectid = $($token.projectid),
        [switch]$UseProxy
    )
    $detail = (Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/projects/$projectid/groups/$groupid/roles" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy).Content | ConvertFrom-Json
    return $detail.roles
}

Function Modify-K5RoleToGroupAssignments
{
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$roleid = $(Display-Error -error "Please specify a role id using the -roleid parameter"),
        [string]$groupid = $(Display-Error -error "Please specify a group id using the -groupid parameter"),
        [string]$projectid = $($token.projectid),
        [Parameter()][ValidateSet('Add','Delete')][string]$operation = "Add",
        [switch]$UseProxy
    )
    switch ($operation)
    {
        Add    {$detail = (Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/projects/$projectid/groups/$groupid/roles/$roleid" -Method PUT -headers $token.token -ContentType "application/json" -UseProxy $useProxy).Content | ConvertFrom-Json}
        Delete {$detail = (Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/projects/$projectid/groups/$groupid/roles/$roleid" -Method DELETE -headers $token.token -ContentType "application/json" -UseProxy $useProxy).Content | ConvertFrom-Json}
    }
    if ($useProxy)
    {
        Get-K5RoleToGroupAssignments -token $token -groupid $groupid -projectid $projectid -UseProxy
    } else {
        Get-K5RoleToGroupAssignments -token $token -groupid $groupid -projectid $projectid
    }
}


Function Get-K5VNCConsole
{
    <#

    .SYNOPSIS
    Retrieves time limited URL to access the console of a given server

    .DESCRIPTION
    The Get-K5VNCConsole function retrieves a time limited URL which can then be used to access the console of a given server
    via your browser.

    .PARAMETER token
    Required, a token object returned by the Get-K5Token function

    .PARAMETER servername
    Required, the name of the server to establish a console session on

    .PARAMETER useProxy
    Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

    .EXAMPLE 
    
# Retrieve a URL to use for console access to the server named WinTest using proxy when making the call
    
PS C:\>Get-K5VNCConsole -token $token -servername WinTest -UseProxy

https://console-a.uk-1.cloud.global.fujitsu.com/vnc_auto.html?token=f8049b3a-8fd0-4afe-9427-8f4ab765aa29

    #>    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$servername = $(Display-Error -error "Please specify a server name using the -servername parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $servername)) {break}
    try
    {
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $serverid = (($return.Content | ConvertFrom-Json).servers | where name -eq $servername).id
        if (-not $serverid)
        {
            Display-Error -error "Get-K5VNCConsole - Server $servername not found."
        }
        $json = Get-K5JSON vnc_console
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers/$serverid/action" -Method POST -headers $token.token -Body $json -ContentType "application/json" -UseProxy $useProxy
        $url = ($return.content | ConvertFrom-Json).console.url
    }
    catch
    {
        Display-Error -error "Get-K5VNCConsole failed..." -errorObj $_
    }
    return $url
}

Function Get-K5TTYConsole
{
    <#

    .SYNOPSIS
    Retrieves serial console output of a given server

    .DESCRIPTION
    The Get-K5TTYConsole function retrieves the output of the serial console of a given server, by default it will return the last 50 lines
    but more (or less) can be retrieved by use of the -lines parameter

    .PARAMETER token
    Required, a token object returned by the Get-K5Token function

    .PARAMETER servername
    Required, the name of the server from which to return the console output

    .PARAMETER lines
    Optional, the number of lines of console output to return

    .PARAMETER useProxy
    Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

    .EXAMPLE 
    
# Get the last 5 lines of console output from server named WinTest using proxy when making the call
    
PS C:\>Get-K5TTYConsole -token $token -servername WinTest -UseProxy -lines 5

2017-04-05 09:32:03.999 1408 DEBUG cloudbaseinit.metadata.services.baseopenstackservice [-] user_data metadata not present get_client_auth_certs C:\Program Files (x86)\Cloudbase Solutions\Cloudbase-Init\Py
thon27\lib\site-packages\cloudbaseinit\metadata\services\baseopenstackservice.py:144
2017-04-05 09:32:03.999 1408 INFO cloudbaseinit.plugins.windows.winrmcertificateauth [-] WinRM certificate authentication cannot be configured as a certificate has not been provided in the metadata
2017-04-05 09:32:03.999 1408 INFO cloudbaseinit.init [-] Executing plugin 'LocalScriptsPlugin'
2017-04-05 09:32:07.013 1408 DEBUG cloudbaseinit.osutils.windows [-] Stopping service cloudbase-init stop_service C:\Program Files (x86)\Cloudbase Solutions\Cloudbase-Init\Python27\lib\site-packages\cloudb
aseinit\osutils\windows.py:719
    .EXAMPLE 
    
# Get the last 1000 lines of console output from server named meta_test, and from that select the first 10 lines
    
PS C:\>Get-K5TTYConsole -token $token -servername meta_test -lines 1000 | select -First 10

[    0.000000] Initializing cgroup subsys cpuset
[    0.000000] Initializing cgroup subsys cpu
[    0.000000] Initializing cgroup subsys cpuacct
[    0.000000] Linux version 3.13.0-61-generic (buildd@lgw01-50) (gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) ) #100-Ubuntu SMP Wed Jul 29 11:21:34 UTC 2015 (Ubuntu 3.13.0-61.100-generic 3.13.11-ckt22)
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-3.13.0-61-generic root=LABEL=cloudimg-rootfs ro console=tty1 console=ttyS0
[    0.000000] KERNEL supported cpus:
[    0.000000]   Intel GenuineIntel
[    0.000000]   AMD AuthenticAMD
[    0.000000]   Centaur CentaurHauls
[    0.000000] Disabled fast string operations

#>
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$servername = $(Display-Error -error "Please specify a server name using the -servername parameter"),
        [int]$lines = 50,
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $servername)) {break}
    try
    {
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $serverid = (($return.Content | ConvertFrom-Json).servers | where name -eq $servername).id
        if (-not $serverid)
        {
            Display-Error -error "Get-K5TTYConsole - Server $servername not found."
        }
        $json = Get-K5JSON tty_console
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers/$serverid/action" -Method POST -headers $token.token -Body $json -ContentType "application/json" -UseProxy $useProxy
        $output = ($return.content | ConvertFrom-Json).output -split "`n"
    }
    catch
    {
        Display-Error -error "Get-K5TTYConsole failed..." -errorObj $_
    }
    return $output
}

Function Get-K5WindowsPassword
{
    <#

    .SYNOPSIS
    Decrypt the automatically generated admin password for a given Windows server

    .DESCRIPTION
    The Get-K5WindowsPassword function decrypts the buid time auto generated  k5user administrative user's password using the
    private key associated with the server when it was built

    .PARAMETER token
    Required, a token object returned by the Get-K5Token function

    .PARAMETER key
    Required, path to the file containg the private key

    .PARAMETER useProxy
    Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

    .EXAMPLE 
    
# Get the decrypted k5user password from server named WinTest using proxy when making the call
    
PS C:\>Get-K5WindowsPassword -token $token -servername WinTest -key C:\Path\To\My\PrivateKey.pem -UseProxy

X672WKSztcYDtL9Tb6Raf

#>
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$servername = $(Display-Error -error "Please specify a server name using the -servername parameter"),
        [string]$key = $(Display-Error -error "Please specify the path to a private key file using the -key parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $servername) -or (-not $key)) {break}
    try
    {
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $serverid = (($return.Content | ConvertFrom-Json).servers | where name -eq $servername).id
        if (-not $serverid)
        {
            Display-Error -error "Server $servername not found."
        }
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers/$serverid/os-server-password" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $password = ($return.Content | ConvertFrom-Json).password
        $password | & cmd /c "$((Get-K5Vars)["OpenSSLPath"]) base64 -d -A | $((Get-K5Vars)["OpenSSLPath"]) rsautl -decrypt -inkey $key"
    }
    catch
    {
        Display-Error -error "Get-K5WindowsPassword failed..." -errorObj $_
    }
}

