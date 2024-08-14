using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Media;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Desktop.Controls;

public partial class IpRangeDisplay : UserControl
{
    public IpRangeDisplay() : base()
    {
        InitializeComponent();
    }

    public RuleIpRange Range { get; set; }
    public bool IsGap { get; set; }
    public static readonly StyledProperty<Pen> PenProperty = AvaloniaProperty.Register<Pen, Pen>(nameof(Pen), new Pen(new SolidColorBrush(Color.FromRgb(r: 0, g: 0, b: 0))));
    public Pen Pen
    {
        get => GetValue(PenProperty);
        set => SetValue(PenProperty, value);
    }

    protected override void OnInitialized()
    {
        base.OnInitialized();
        RangeBody.Fill = Pen.Brush;
    }
}