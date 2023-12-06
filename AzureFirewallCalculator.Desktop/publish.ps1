#!/usr/bin/env pwsh
param (
    [string]$version
)

$directory = $PSScriptRoot;
$prevDirectory = (Get-Location).Path;

$version = "0.$version";

try {
    Set-Location $directory;
    dotnet publish -c Release --self-contained -r win-x64 -p:PublishSingleFile=true
    dotnet publish -c Release --self-contained -r linux-x64 -p:PublishSingleFile=true
    dotnet publish -c Release --self-contained -r osx-x64 -p:PublishSingleFile=true

    $builtFilePath = "bin/Release/net8.0/{0}/publish/*";
    $compressedFilePath = "bin/Release/net8.0/{0}/AzureFirewallCalculator.Desktop.{0}.v$version.zip";

    $win64Spec = "win-x64";
    $linux64Spec = "linux-x64";
    $macx64Spec = "osx-x64";
    Compress-Archive -Path ($builtFilePath -f $win64Spec) -DestinationPath ($compressedFilePath -f $win64Spec)
    Compress-Archive -Path ($builtFilePath -f $linux64Spec) -DestinationPath ($compressedFilePath -f $linux64Spec)
    Compress-Archive -Path ($builtFilePath -f $macx64Spec) -DestinationPath ($compressedFilePath -f $macx64Spec)

    New-Item "output" -ItemType Directory;
    
    Move-Item -Path ($compressedFilePath -f $win64Spec) -Destination "output";
    Move-Item -Path ($compressedFilePath -f $linux64Spec) -Destination "output";
    Move-Item -Path ($compressedFilePath -f $macx64Spec) -Destination "output";
}
finally {
    Set-Location $prevDirectory;
}

