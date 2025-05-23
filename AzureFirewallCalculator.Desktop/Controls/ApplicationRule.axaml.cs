using System;
using System.Collections;
using Avalonia;
using Avalonia.Controls;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Desktop.Controls;

public partial class ApplicationRule : UserControl
{
    public static readonly StyledProperty<string> RuleNameProperty = 
        AvaloniaProperty.Register<ApplicationRule, string>(nameof(RuleName));

    public static readonly StyledProperty<RuleIpRange[]> SourceIpsProperty = 
        AvaloniaProperty.Register<ApplicationRule, RuleIpRange[]>(nameof(SourceIps), Array.Empty<RuleIpRange>());

    public static readonly StyledProperty<string[]> DestinationFqdnsProperty = 
        AvaloniaProperty.Register<ApplicationRule, string[]>(nameof(DestinationFqdns), Array.Empty<string>());

    public static readonly StyledProperty<string[]> PrefixWildcardsProperty =
        AvaloniaProperty.Register<ApplicationRule, string[]>(nameof(PrefixWildcards), Array.Empty<string>());

    public static readonly StyledProperty<bool> AllowAllDestinationsProperty =
        AvaloniaProperty.Register<ApplicationRule, bool>(nameof(AllowAllDestinations), false);

    public static readonly StyledProperty<string[]> DestinationTagsProperty = 
        AvaloniaProperty.Register<ApplicationRule, string[]>(nameof(DestinationTags), Array.Empty<string>());

    public static readonly StyledProperty<ApplicationProtocolPort[]> ProtocolsProperty =
        AvaloniaProperty.Register<ApplicationRule, ApplicationProtocolPort[]>(nameof(Protocols), Array.Empty<ApplicationProtocolPort>());

    public string RuleName
    {
        get => GetValue(RuleNameProperty);
        set => SetValue(RuleNameProperty, value);
    }

    public RuleIpRange[] SourceIps
    {
        get => GetValue(SourceIpsProperty);
        set => SetValue(SourceIpsProperty, value);
    }

    public string[] DestinationFqdns
    {
        get => GetValue(DestinationFqdnsProperty);
        set => SetValue(DestinationFqdnsProperty, value);
    }

    public string[] PrefixWildcards
    {
        get => GetValue(PrefixWildcardsProperty);
        set => SetValue(PrefixWildcardsProperty, value);
    }

    public bool AllowAllDestinations
    {
        get => GetValue(AllowAllDestinationsProperty);
        set => SetValue(AllowAllDestinationsProperty, value);
    }

    public string[] DestinationTags
    {
        get => GetValue(DestinationTagsProperty);
        set => SetValue(DestinationTagsProperty, value);
    }

    public ApplicationProtocolPort[] Protocols
    {
        get => GetValue(ProtocolsProperty);
        set => SetValue(ProtocolsProperty, value);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        // Sometimes the target components are null when inside a ScrollView
        if (change.Property == RuleNameProperty && RuleNameTextBlock != null)
        {
            this.RuleNameTextBlock.Text = (string)(change.NewValue ?? string.Empty);
        }
        else if (change.Property == SourceIpsProperty && SourceIpDisplay != null)
        {
            this.SourceIpDisplay.Ips = (RuleIpRange[])(change.NewValue ?? Array.Empty<RuleIpRange>());
        }
        else if (change.Property == DestinationFqdnsProperty && DestinationFqdnsList != null)
        {
            this.DestinationFqdnsList.ItemsSource = (string[])(change.NewValue ?? Array.Empty<string>());
        }
        else if (change.Property == ProtocolsProperty && ApplicationProtocolsDisplay != null)
        {
            this.ApplicationProtocolsDisplay.Content = (ApplicationProtocolPort[])(change.NewValue ?? Array.Empty<ApplicationProtocolPort>());
        }
    }
}
