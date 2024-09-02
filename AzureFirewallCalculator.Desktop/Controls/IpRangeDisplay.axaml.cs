using System;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.VisualTree;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Desktop.Controls;

public partial class IpRangeDisplay : UserControl
{
    public IpRangeDisplay() : base()
    {
        InitializeComponent();
    }

    public static readonly StyledProperty<RuleIpRange> RangeProperty = AvaloniaProperty.Register<IpRangeDisplay, RuleIpRange>(nameof(Range), new());
    public RuleIpRange Range
    {
        get => GetValue(RangeProperty);
        set => SetValue(RangeProperty, value);
    }
    public static readonly StyledProperty<bool> IsGapProperty = AvaloniaProperty.Register<IpRangeDisplay, bool>(nameof(IsGap), defaultValue: false);
    public bool IsGap
    {
        get => GetValue(IsGapProperty);
        set => SetValue(IsGapProperty, value);
    }
    public static readonly StyledProperty<Pen> PenProperty = AvaloniaProperty.Register<IpRangeDisplay, Pen>(nameof(Pen), new Pen(new SolidColorBrush(Color.FromRgb(r: 0, g: 0, b: 0))));
    public Pen Pen
    {
        get => GetValue(PenProperty);
        set => SetValue(PenProperty, value);
    }

    public static readonly StyledProperty<uint> EffectiveLowerBoundProperty = AvaloniaProperty.Register<IpRangeDisplay, uint>(nameof(EffectiveLowerBound), 0);
    public uint EffectiveLowerBound
    {
        get => GetValue(EffectiveLowerBoundProperty);
        set => SetValue(EffectiveLowerBoundProperty, value);
    }

    public static readonly StyledProperty<uint> EffectiveUpperBoundProperty = AvaloniaProperty.Register<IpRangeDisplay, uint>(nameof(EffectiveUpperBound), uint.MaxValue);
    public uint EffectiveUpperBound
    {
        get => GetValue(EffectiveUpperBoundProperty);
        set => SetValue(EffectiveUpperBoundProperty, value);
    }

    protected override void OnInitialized()
    {
        base.OnInitialized();
        
        IpShape.Fill = Pen.Brush;
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);

        if (e.Property == RangeProperty && e.NewValue is RuleIpRange range)
        {
            if (ToolTip.GetTip(IpBlock) is IpRangeToolTip ipBlockTooltip)
            {
                ipBlockTooltip.Range = range;
            }
            if (ToolTip.GetTip(SingleIp) is IpRangeToolTip singleIpTooltip)
            {
                singleIpTooltip.Range = range;
            }
        }
        else if (e.Property == EffectiveLowerBoundProperty && e.NewValue is uint effectiveLowerBound)
        {
            IpBlock.IsVisible = effectiveLowerBound != EffectiveUpperBound;
            SingleIp.IsVisible = effectiveLowerBound == EffectiveUpperBound;
        }
        else if (e.Property == EffectiveUpperBoundProperty && e.NewValue is uint effectiveUpperBound)
        {
            IpBlock.IsVisible = EffectiveLowerBound != effectiveUpperBound;
            SingleIp.IsVisible = EffectiveLowerBound == effectiveUpperBound;
        }
        else if (e.Property == PenProperty && e.NewValue is Pen pen)
        {
            IpShape.Fill = pen.Brush;
        }
    }

    private Shape IpShape => EffectiveLowerBound == EffectiveUpperBound ? SingleIp : IpBlock;

    // I want the range to appear selected once focused
    // Including showing the tooltip
    // I want the tooltip to allow clicking on it without deselecting the range
    // I want clicking outside the range to close everything and deselect it
    // These are all a halfassed attempt to make that work, but it produced a lot
    // of janky behaviors that I don't want to debug right now
    protected override void OnPointerExited(PointerEventArgs e)
    {
        base.OnPointerExited(e);

        // if (RangeBody.IsFocused)
        // {
        //     ToolTip.SetIsOpen(RangeBody, true);
        // }
    }

    protected override void OnGotFocus(GotFocusEventArgs e)
    {
        base.OnGotFocus(e);
        //RangeBody.Classes.Add("Selected");
    }

    protected override void OnLostFocus(RoutedEventArgs e)
    {
        base.OnLostFocus(e);

        // Test if the new focused element is part of the tooltip
        // var tooltip = ToolTip.GetTip(RangeBody);
        // var topLevel = TopLevel.GetTopLevel(this);
        // var focused = topLevel?.FocusManager?.GetFocusedElement() as Control;
        // Visual? ancestor = focused;
        // while (ancestor != null && ancestor != tooltip)
        // {
        //     ancestor = ancestor?.GetVisualParent();
        // }

        // ToolTip.SetIsOpen(RangeBody, ancestor == tooltip);
        // if (ancestor != tooltip)
        // {
        //     RangeBody.Classes.Remove("Selected");
        // }
    }
}