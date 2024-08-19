using System;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
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
        RangeText.Text = Range.ToString();
    }

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