using System;
using System.Reactive;
using System.Reactive.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using AzureFirewallCalculator.Core;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.Controls;

public partial class NetworkRule : UserControl
{
    public NetworkRule()
    {
        InitializeComponent();
        RuleDestinationPortsRepeater.DataContext = DestinationPortMatches;
    }

    public static readonly StyledProperty<string> RuleNameProperty = AvaloniaProperty.Register<NetworkRule, string>(nameof(RuleName), string.Empty);

    public string RuleName
    {
        get => GetValue(RuleNameProperty);
        set => SetValue(RuleNameProperty, value);
    }

    public static readonly StyledProperty<RuleIpRange[]> SourceIpsProperty = AvaloniaProperty.Register<NetworkRule, RuleIpRange[]>(nameof(SourceIps), []);

    public RuleIpRange[] SourceIps
    {
        get => GetValue(SourceIpsProperty);
        set => SetValue(SourceIpsProperty, value);
    }

    public static readonly StyledProperty<RuleIpRange[]> SourceIpMatchesProperty = AvaloniaProperty.Register<NetworkRule, RuleIpRange[]>(nameof(SourceIpMatches), []);

    public RuleIpRange[] SourceIpMatches
    {
        get => GetValue(SourceIpMatchesProperty);
        set => SetValue(SourceIpMatchesProperty, value);
    }

    public static readonly StyledProperty<RuleIpRange[]> DestinationIpsProperty = AvaloniaProperty.Register<NetworkRule, RuleIpRange[]>(nameof(DestinationIps), []);

    public RuleIpRange[] DestinationIps
    {
        get => GetValue(DestinationIpsProperty);
        set => SetValue(DestinationIpsProperty, value);
    }

    public static readonly StyledProperty<RuleIpRange[]> DestinationIpMatchesProperty = AvaloniaProperty.Register<NetworkRule, RuleIpRange[]>(nameof(DestinationIpMatches), []);

    public RuleIpRange[] DestinationIpMatches
    {
        get => GetValue(DestinationIpMatchesProperty);
        set => SetValue(DestinationIpMatchesProperty, value);
    }

    public static readonly StyledProperty<NetworkProtocols> NetworkProtocolsProperty = AvaloniaProperty.Register<NetworkRule, NetworkProtocols>(nameof(NetworkProtocols), Core.NetworkProtocols.None);

    public NetworkProtocols NetworkProtocols
    {
        get => GetValue(NetworkProtocolsProperty);
        set => SetValue(NetworkProtocolsProperty, value);
    }

    public static readonly StyledProperty<NetworkProtocols> NetworkProtocolMatchesProperty = AvaloniaProperty.Register<NetworkRule, NetworkProtocols>(nameof(NetworkProtocolMatches), Core.NetworkProtocols.None);

    public NetworkProtocols NetworkProtocolMatches
    {
        get => GetValue(NetworkProtocolMatchesProperty);
        set => SetValue(NetworkProtocolMatchesProperty, value);
    }

    public static readonly StyledProperty<RulePortRange[]> DestinationPortsProperty = AvaloniaProperty.Register<NetworkRule, RulePortRange[]>(nameof(DestinationPorts), []);

    public RulePortRange[] DestinationPorts
    {
        get => GetValue(DestinationPortsProperty);
        set => SetValue(DestinationPortsProperty, value);
    }

    public static readonly StyledProperty<RulePortRange[]> DestinationPortMatchesProperty = AvaloniaProperty.Register<NetworkRule, RulePortRange[]>(nameof(DestinationPortMatches), []);

    public RulePortRange[] DestinationPortMatches
    {
        get => GetValue(DestinationPortMatchesProperty);
        set => SetValue(DestinationPortMatchesProperty, value);
    }

    public static readonly StyledProperty<bool> BoldExactMatchOnlyProperty = AvaloniaProperty.Register<NetworkRule, bool>(nameof(BoldExactMatchOnly), true);

    public bool BoldExactMatchOnly
    {
        get => GetValue(BoldExactMatchOnlyProperty);
        set => SetValue(BoldExactMatchOnlyProperty, value);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        if (change.Property == RuleNameProperty && RuleNameTextBlock != null)
        {
            this.RuleNameTextBlock.Text = (string)(change.NewValue ?? string.Empty);
        }
        else if (change.Property == BoldExactMatchOnlyProperty && SourceIpDisplay != null && DestinationIpDisplay != null)
        {
            this.SourceIpDisplay.ExactMatchOnly = (bool)(change.NewValue ?? false);
            this.DestinationIpDisplay.ExactMatchOnly = (bool)(change.NewValue ?? false);
        }
        else if (change.Property == SourceIpsProperty && SourceIpDisplay != null)
        {
            this.SourceIpDisplay.Ips = (RuleIpRange[])(change.NewValue ?? Array.Empty<RuleIpRange>());
        }
        else if (change.Property == SourceIpMatchesProperty && SourceIpDisplay != null)
        {
            this.SourceIpDisplay.Matches = (RuleIpRange[])(change.NewValue ?? Array.Empty<RuleIpRange>());
        }
        else if (change.Property == DestinationIpsProperty && DestinationIpDisplay != null)
        {
            this.DestinationIpDisplay.Ips = (RuleIpRange[])(change.NewValue ?? Array.Empty<RuleIpRange>());
        }
        else if (change.Property == DestinationIpMatchesProperty && DestinationIpDisplay != null)
        {
            this.DestinationIpDisplay.Matches = (RuleIpRange[])(change.NewValue ?? Array.Empty<RuleIpRange>());
        }
        else if (change.Property == NetworkProtocolsProperty && NetworkProtocolsDisplay != null)
        {
            this.NetworkProtocolsDisplay.Content = ((NetworkProtocols)(change.NewValue ?? NetworkProtocols.None), NetworkProtocolMatches);
        }
        else if (change.Property == NetworkProtocolMatchesProperty && NetworkProtocolsDisplay != null)
        {
            this.NetworkProtocolsDisplay.Content = (NetworkProtocols, (NetworkProtocols)(change.NewValue ?? NetworkProtocols.None));
        }
        else if (change.Property == DestinationPortsProperty && RuleDestinationPortsRepeater != null)
        {
            this.RuleDestinationPortsRepeater.ItemsSource = (RulePortRange[])(change.NewValue ?? Array.Empty<RulePortRange>());
        }
        else if (change.Property == DestinationPortMatchesProperty && RuleDestinationPortsRepeater != null)
        {
            RuleDestinationPortsRepeater.DataContext = change.NewValue;
        }
    }
}