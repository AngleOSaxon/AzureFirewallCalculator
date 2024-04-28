$azInstalled = Get-InstalledModule Az;
$networkInstalled = Get-InstalledModule Az.Network;

if (-Not($azInstalled) -or -Not($networkInstalled)) {
    Write-Error "Required modules Az and Az.Network are not installed.  Install them and try again.";
    exit(1);
}

Import-Module Az;
Import-Module Az.Network;

$subscriptionName = ''; #replace with subscription name; eg mycompany-dev
$firewallName = ''; #repace with firewall name

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

$policy = Get-AzFirewallPolicy -ResourceId $firewall.FirewallPolicy.Id;

$ruleCollectionGroups = @();

if ($policy) {
    $ruleCollectionNames = $policy.RuleCollectionGroups | ForEach-Object { $_.Id.Split('/')[-1] };

    $ruleCollectionGroups = $ruleCollectionNames | ForEach-Object { Get-AzFirewallPolicyRuleCollectionGroup -Name $_  -AzureFirewallPolicy $policy };
}

$ipGroupSubscriptions = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]';
foreach ($policyRuleCollectionGroup in $ruleCollectionGroups) {
    foreach ($ruleCollection in $policyRuleCollectionGroup.Properties.RuleCollection) {
        foreach ($rule in $ruleCollection.Rules) {
            foreach ($ipGroup in $rule.SourceIpGroups) {
                $ipGroupSubscriptions.Add((Get-SubscriptionIdFromResourceId -ResourceId $ipGroup).ToLower());
            }
            foreach ($ipGroup in $rule.DestinationIpGroups) {
                $ipGroupSubscriptions.Add((Get-SubscriptionIdFromResourceId -ResourceId $ipGroup).ToLower());
            }
        }
    }
}
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

if ($policy) {
    ConvertTo-Json -InputObject @($policy) -Depth 10 > policy.json;
}
if ($ruleCollectionGroups) {
    ConvertTo-Json -InputObject $ruleCollectionGroups -Depth 10 > ruleCollectionGroups.json;
}
$firewall | ConvertTo-Json -Depth 10 > firewall.json;
ConvertTo-Json -InputObject $ipGroups -Depth 10 > ipGroups.json;