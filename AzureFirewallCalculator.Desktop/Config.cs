using System;
using System.Collections.Generic;

namespace AzureFirewallCalculator.Desktop;

public class Config
{
    public string CacheFileName { get; set; } = "EntraCache";

    public string CacheFileDirectory { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    public string KeychainServiceName { get; set; } = "AntiwizardAzureTools";

    public string KeychainAccountName { get; set; } = "AzureFirewallCalculator";

    public string LinuxKeyRingSchema = "net.antiwizard.azuretools.tokencache";

    public string LinuxKeyRingCollection = "default";

    public string LinuxKeyRingLabel = "MSAL token cache for Azure tools.";

    public KeyValuePair<string, string> LinuxKeyRingAttr1 = new("Version", "1");

    public KeyValuePair<string, string> LinuxKeyRingAttr2 = new("ProductGroup", "MyApps");
}