# AzureFirewallCalculator

A simple tool to check what rules will be hit in an Azure Firewall.

## What is it

A cross-platform desktop app that will load an Azure Firewall instance, allow you to enter network request information, and list the rules 
that will be hit and why they will be hit.  I built it because my day job has a large and complex set of rules and I wanted a way to figure
out what rules would be applied and why without needing to actually generate traffic.

Only supports Classic Rules currently, with preliminary support for Firewall Policies.

## How do I use it?

Load a firewall's configuration one of two ways:
  - Direct request from Azure Resource Manager APIs
    - Requires permission to use your Azure credentials
    - You must have Reader permissions for all the relevant resources (firewalls, IP Groups)
  - Import firewall from Powershell exports
    - Use Powershell to get instances of the resources, write them out as JSON, and then import the files
    - Sample Powershell script included in the app
   
## Features

- Attempts to resolve names in FQDN-based rules
  - Uses system DNS on the executing computer for the resolution, so internal names may or may not be resolved properly depending on DNS configuration
- Attempts to resolve names for Application requests and process them as Network requests as well
  - If multiple addresses are resolved for an FQDN name, all are processed as network requests
- Includes IPs from referenced IP Groups in rules
- Includes IPs from referenced [service tags](https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview#available-service-tags) in rules
- Wildcard processing for [FQDN prefix wildcards](https://learn.microsoft.com/en-us/azure/firewall/firewall-faq#how-do-wildcards-work-in-target-urls-and-target-fqdns-in-application-rules) in application rules
  - Does not support wildcards in TargetUrl
- Resolves names in Source and Destination fields
- Wildcard searches (using `*`) in Source and Destination
- Static DNS configuration
- Displays overlap between rules

### Missing features

- Does not support any rule-matching related to TargetUrl in HTTP requests
- Ignores the rule collection group level and associated priority
- Does not support loading individual policies
- Does not recursively load child policies; only the immediate decendants of a firewall policy
- Does not support [FQDN Tags](https://learn.microsoft.com/en-us/azure/firewall/fqdn-tags)
