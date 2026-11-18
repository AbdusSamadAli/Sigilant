param(
    [int]$Hours = 24,
    [string]$OutFile = ".\real_logs\windows_events.jsonl",
    [int]$MaxEvents = 20000
)

$ids = @{
    'Security' = @(1102, 4624, 4625, 4648, 4672, 4688, 4698, 4720, 4726, 4728, 4732, 4740, 4756)
    'Microsoft-Windows-Sysmon/Operational' = @(1, 3, 10, 11, 13, 22)
}
$start = (Get-Date).AddHours(-$Hours)
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile) | Out-Null
$writer = [System.IO.StreamWriter]::new((Resolve-Path -LiteralPath (Split-Path $OutFile)).Path + "\" + (Split-Path $OutFile -Leaf), $false, [System.Text.UTF8Encoding]::new($false))
$count = 0

foreach ($log in $ids.Keys) {
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $ids[$log]; StartTime = $start } -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        Write-Warning "Skipping ${log}: $($_.Exception.Message)"
        continue
    }
    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = [ordered]@{}
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) { $data[$d.Name] = [string]$d.'#text' }
        }
        $record = [ordered]@{
            TimeCreated = $e.TimeCreated.ToUniversalTime().ToString("o")
            Channel     = $e.LogName
            EventID     = $e.Id
            Computer    = $e.MachineName
            EventData   = $data
        }
        $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 4))
        $count++
    }
}
$writer.Close()
Write-Host "Exported $count events to $OutFile"
