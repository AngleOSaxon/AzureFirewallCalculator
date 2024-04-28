$azInstalled = Get-InstalledModule Az;
$networkInstalled = Get-InstalledModule Az.Network;

if (-Not($azInstalled) -or -Not($networkInstalled)) {
    Write-Error "Required modules Az and Az.Network are not installed.  Install them and try again.";
    exit(1);
}

Import-Module Az;
Import-Module Az.Network;

$subscriptionName = $null; #replace with subscription name; eg mycompany-dev
$firewallName = $null; #replace with firewall name

if (-Not($subscriptionName) -or -Not($firewallname)) {
    Write-Error "Please edit this script to add your subscription name and firewall name";
    exit(1);
}

Connect-AzAccount;

Set-AzContext -Subscription $subscriptionName;

$firewall = Get-AzFirewall -Name $firewallName;
if (-Not($firewall)) {
    Write-Error = "Unable to get firewall.  Check name, subscription, and authentication status."
    exit(1);
}

function Get-SubscriptionIdFromResourceId($resourceId) {
    return $resourceId.Split("/")[2];
}

$ipGroupSubscriptions = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]';
foreach ($ruleCollection in $firewall.NetworkRuleCollections) {
    foreach ($rule in $ruleCollection.Rules) {
        foreach ($ipGroup in ($rule.SourceIpGroups + $rule.DestinationIpGroups)) {
            $ipGroupSubscriptions.Add((Get-SubscriptionIdFromResourceId -resourceId $ipGroup).ToLower());
        }
    }
}
foreach ($ruleCollection in $firewall.ApplicationRuleCollections) {
    foreach ($rule in $ruleCollection.Rules) {
        foreach ($ipGroup in ($rule.SourceIpGroups)) {
            $ipGroupSubscriptions.Add((Get-SubscriptionIdFromResourceId -resourceId $ipGroup).ToLower());
        }
    }
}

$ipGroups = @();
foreach ($subscription in $ipGroupSubscriptions) {
    Set-AzContext -Subscription $subscription;

    $ipGroups += (Get-AzIpGroup);
}

$firewall | ConvertTo-Json -Depth 10 > firewall.json;
$ipGroups | ConvertTo-Json -Depth 10 > ipGroups.json;