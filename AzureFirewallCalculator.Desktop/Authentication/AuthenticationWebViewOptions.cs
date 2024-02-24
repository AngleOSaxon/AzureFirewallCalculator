using Microsoft.Identity.Client;

namespace AzureFirewallCalculator.Desktop.Authentication;

public static class AuthenticationWebViewOptions
{
    public readonly static SystemWebViewOptions Options = new()
    {
        HtmlMessageSuccess = @"<html style='font-family: sans-serif;'>
                                <head><title>Authentication Complete</title></head>
                                <body style='text-align: center;'>
                                    <header>
                                        <h1>Azure Firewall Calculator</h1>
                                    </header>
                                    <main style='border: 1px solid lightgrey; margin: auto; width: 600px; padding-bottom: 15px;'>
                                        <h2 style='color: limegreen;'>Authentication complete</h2>
                                        <div>You can return to the application. Feel free to close this browser tab.</div>
                                    </main>

                                </body>
                            </html>",

        HtmlMessageError = @"<html style='font-family: sans-serif;'>
                            <head><title>Authentication Failed</title></head>
                            <body style='text-align: center;'>
                                <header>
                                    <h1>Azure Firewall Calculator</h1>
                                </header>
                                <main style='border: 1px solid lightgrey; margin: auto; width: 600px; padding-bottom: 15px;'>
                                    <h2 style='color: salmon;'>Authentication failed</h2>
                                    <div><b>Error details:</b> error {0} error_description: {1}</div>
                                    <br>
                                    <div>You can return to the application. Feel free to close this browser tab.</div>
                                </main>

                            </body>
                        </html>"
    };
}