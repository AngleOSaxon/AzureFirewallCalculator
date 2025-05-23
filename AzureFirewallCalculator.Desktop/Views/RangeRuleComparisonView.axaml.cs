using System;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Markup.Xaml;
using Avalonia.ReactiveUI;
using AzureFirewallCalculator.Desktop.ViewModels;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.Views;

public partial class RangeRuleComparisonView : ReactiveUserControl<RangeRuleComparisonViewModel>, IViewFor<RangeRuleComparisonViewModel>, IViewFor
{
    public RangeRuleComparisonView()
    {
        this.WhenActivated(disposables => 
        {
            var selectionTab = this.GetControl<TabStrip>(nameof(DisplaySelectionTab));
            if (selectionTab?.SelectedItem is TabItem tabItem)
            {
                ViewModel!.SelectedDisplay = tabItem?.Name;
            }
        });
        AvaloniaXamlLoader.Load(this);
    }

    public async void FirewallRuleSearch(object sender, KeyEventArgs args)
    {
        if (args.Key != Key.Enter || args.Source is ComboBox)
        {
            return;
        }
        await this.ViewModel!.CompareRanges();
    }

    public void TabStripItem_Clicked(object sender, PointerReleasedEventArgs e)
    {
        var selectionTab = this.GetControl<TabStrip>(nameof(DisplaySelectionTab));
        if (sender is TabItem tabItem)
        {
            ViewModel!.SelectedDisplay = tabItem.Name!;
        }
        else
        {
            throw new Exception($"Unexpected click event from object of type '{sender.GetType()}', '{sender}'");
        }
    }
}