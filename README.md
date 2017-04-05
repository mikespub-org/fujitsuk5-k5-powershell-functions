# k5-powershell-functions

```
NAME
    Get-K5Token
    
SYNOPSIS
    Retrieves a token from the K5 identity service (keystone) to provide authentication for subsequent calls to K5 API endpoints
    
    
SYNTAX
    Get-K5Token [-region <String>] [-contract <String>] [-user <String>] [-password <String>] [-projectname <String>] [-useProxy] [<CommonParameters>]
    
    Get-K5Token [-region <String>] [-contract <String>] [-user <String>] [-password <String>] [-global] [-useProxy] [<CommonParameters>]
    
    Get-K5Token [-region <String>] [-contract <String>] [-user <String>] [-password <String>] [-unscoped] [-useProxy] [<CommonParameters>]
    
    
DESCRIPTION
    The Get-K5Token function retrieves a token from the K5 identity service scoped as requested using supplied credentials. The token
    should be saved in a variable and used to authenticate subsequent calls to K5 API endpoints. If called without parameters the region
    will default to uk-1 and contract, username, password, and project will be retrieved from k5env.csv which must exist in the same
    location as the script containing this function and be formatted as follows (OpenSSLPath only required if you intend to use the
    Get-K5WindowsPassword function to decrypt the k5user password assigned during the build process):
    
    "name","value"
    "k5user","username"
    "k5pword","password"
    "k5project","projectname"
    "proxyURL","http://your.proxy.name"
    "k5_uk_contract","uk_contract"
    "k5_de_contract","de_contract"
    "k5_fi_contract","fi_contract"
    "OpenSSLPath","C:\your\path\to\openssl.exe"
    
    The object returned by the Get-K5Token function has a number of properties:
    
    domainid    The id of the domain (contract) to which the token is scoped
    endpoints   A hashtable containing all the applicable API endpoints for the token's scope 
    expiry      A timestamp indicating when the token will expire
    projectid   The id of the project to which the token is scoped
    projects    An object containing details of all projects to which the user has access
    token       A hashtable containing the returned authentication token
    userid      The id of the user to whom the token has been issued
    

PARAMETERS
    -region <String>
        The region to scope to, defaults to uk-1
        
    -contract <String>
        The contract to scope to, defaults to the contract specified in k5env.csv for the region to which you are scoping.
        
    -user <String>
        Your K5 username for the specified contract, defaults to the username stored in k5env.csv
        
    -password <String>
        The password for the specified K5 username, defaults to the password stored in k5env.csv
        
    -projectname <String>
        The project within the specified contract to which you wish to scope, defaults to the project specified in k5env.csv
        
    -global [<SwitchParameter>]
        Switch parameter to specify the token should be globally scoped
        
    -unscoped [<SwitchParameter>]
        Switch parameter to specify the token should not be scoped to a project
        
    -useProxy [<SwitchParameter>]
        Switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used
        
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\># Retrieve a token using the defaults stored in k5env.csv and store in $token for future use
    
    PS C:\>$token = Get-K5Token
    
    
    
    
    -------------------------- EXAMPLE 2 --------------------------
    
    PS C:\># Retrieve a token supplying al required authentication information and store in $token for future use, use the proxy when making the call
    
    PS C:\>$token = Get-K5Token -region de-1 -contract mycontract -user myuser -password mypassword -projectname myproject -useProxy
    
    
    
    
    -------------------------- EXAMPLE 3 --------------------------
    
    PS C:\># Show the returned token's expiry
    
    PS C:\>$token.expiry
    
    05 April 2017 16:20:23
    
    
    
NAME
    Get-K5Resources
    
SYNOPSIS
    Retrieves a list of K5 resources of a given type
    
    
SYNTAX
    Get-K5Resources [[-token] <PSObject>] [[-type] <String>] [[-name] <String>] [-detailed] [-UseProxy] [<CommonParameters>]
    
    
DESCRIPTION
    The Get-K5Resources function retrieves a list of resources of a given type, optionally for a specific resource name.
    The list is either comprised of names and ids, or if required, a detailed list of all attributes.
    

PARAMETERS
    -token <PSObject>
        Required, a token object returned by the Get-K5Token function
        
    -type <String>
        Required, the type of resource required, if not specified the error message will detail the acceptable types
        
    -name <String>
        Optional, the name of the resource required, eg the server name if type is servers
        
    -detailed [<SwitchParameter>]
        Optional, switch to request detailed list
        
    -UseProxy [<SwitchParameter>]
        Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used
        
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\># Get a simple list of names and ids of all servers, use proxy when making the call
    
    PS C:\>Get-K5Resources -token $token -type servers -UseProxy
    
    name                      id                                  
    ----                      --                                  
    WinTest                   ecff651a-0e4d-4685-8dcc-f1064384f717
    meta_test                 486ca902-8ff8-3979-a1c6-db38b7862d3e
    ACT_Project_a_Server2_AZ1 843f0b1b-df88-417a-b822-2a689fd9432a
    ACT_Project_a_Server1_AZ1 21dd980d-a50a-44cf-b4fc-270a579dc788
    ACT_Project_a_Server2_AZ2 90756aa3-5373-4901-b4ea-70ce358f97dd
    ACT_Project_a_Server1_AZ2 20f7c1de-5d40-bd67-d173-b813148ca5b4
    
    
    
    
    -------------------------- EXAMPLE 2 --------------------------
    
    PS C:\># Get a detailed list of attributes for server named WinTest
    
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
    
    
NAME
    Get-K5VNCConsole
    
SYNOPSIS
    Retrieves time limited URL to access the console of a given server
    
    
SYNTAX
    Get-K5VNCConsole [[-token] <PSObject>] [[-servername] <String>] [-UseProxy] [<CommonParameters>]
    
    
DESCRIPTION
    The Get-K5VNCConsole function retrieves a time limited URL which can then be used to access the console of a given server
    via your browser.
    

PARAMETERS
    -token <PSObject>
        Required, a token object returned by the Get-K5Token function
        
    -servername <String>
        Required, the name of the server to establish a console session on
        
    -UseProxy [<SwitchParameter>]
        Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used
        
   
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\># Retrieve a URL to use for console access to the server named WinTest using proxy when making the call
    
    PS C:\>Get-K5VNCConsole -token $token -servername WinTest -UseProxy
    
    https://console-a.uk-1.cloud.global.fujitsu.com/vnc_auto.html?token=f8049b3a-8fd0-4afe-9427-8f4ab765aa29
    

    
NAME
    Get-K5TTYConsole
    
SYNOPSIS
    Retrieves serial console output of a given server
    
    
SYNTAX
    Get-K5TTYConsole [[-token] <PSObject>] [[-servername] <String>] [[-lines] <Int32>] [-UseProxy] [<CommonParameters>]
    
    
DESCRIPTION
    The Get-K5TTYConsole function retrieves the output of the serial console of a given server, by default it will return the last 50 lines
    but more (or less) can be retrieved by use of the -lines parameter
    

PARAMETERS
    -token <PSObject>
        Required, a token object returned by the Get-K5Token function
        
    -servername <String>
        Required, the name of the server from which to return the console output
        
    -lines <Int32>
        Optional, the number of lines of console output to return
        
    -UseProxy [<SwitchParameter>]
        Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used
    
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\># Get the last 5 lines of console output from server named WinTest using proxy when making the call
    
    PS C:\>Get-K5TTYConsole -token $token -servername WinTest -UseProxy -lines 5
    
    2017-04-05 09:32:03.999 1408 DEBUG cloudbaseinit.metadata.services.baseopenstackservice [-] user_data metadata not present get_client_auth_certs C:\Program Files (x86)\Cloudbase 
    Solutions\Cloudbase-Init\Py
    thon27\lib\site-packages\cloudbaseinit\metadata\services\baseopenstackservice.py:144
    2017-04-05 09:32:03.999 1408 INFO cloudbaseinit.plugins.windows.winrmcertificateauth [-] WinRM certificate authentication cannot be configured as a certificate has not been provided in the metadata
    2017-04-05 09:32:03.999 1408 INFO cloudbaseinit.init [-] Executing plugin 'LocalScriptsPlugin'
    2017-04-05 09:32:07.013 1408 DEBUG cloudbaseinit.osutils.windows [-] Stopping service cloudbase-init stop_service C:\Program Files (x86)\Cloudbase 
    Solutions\Cloudbase-Init\Python27\lib\site-packages\cloudb
    aseinit\osutils\windows.py:719
    
    
    
    
    -------------------------- EXAMPLE 2 --------------------------
    
    PS C:\># Get the last 1000 lines of console output from server named meta_test, and from that select the first 10 lines
    
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
    

    
NAME
    Get-K5WindowsPassword
    
SYNOPSIS
    Decrypt the automatically generated admin password for a given Windows server
    
    
SYNTAX
    Get-K5WindowsPassword [[-token] <PSObject>] [[-servername] <String>] [[-key] <String>] [-UseProxy] [<CommonParameters>]
    
    
DESCRIPTION
    The Get-K5WindowsPassword function decrypts the buid time auto generated  k5user administrative user's password using the
    private key associated with the server when it was built
    

PARAMETERS
    -token <PSObject>
        Required, a token object returned by the Get-K5Token function
        
    -servername <String>
        
    -key <String>
        Required, path to the file containg the private key
        
    -UseProxy [<SwitchParameter>]
        Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used
        
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\># Get the decrypted k5user password from server named WinTest using proxy when making the call
    
    PS C:\>Get-K5WindowsPassword -token $token -servername WinTest -key C:\Path\To\My\PrivateKey.pem -UseProxy
    
    X672WKSztcYDtL9Tb6Raf
  
