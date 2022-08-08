<#
.SYNOPSIS

Check for evidence of sandbox by looking for static honey files, checking if total c disk space is less than 50GB,
the abscence of "_WAIT" connections (abscence of network connection activity), physical mem used by all processes from ps under 2GB,
total physical memory under 4GB. 
Checks were discovered from probing VirusTotal sandboxes.


.DESCRIPTION

Determine if running in sandbox by checking environmental factors.

#>
Function Check-Sandbox() {
    #TODO
    Function Check-Filter() {
    
    }
    # using dict because more stealthy than hashset
    # keys dont matter, so in real usage, replace with some benign text
    # add your own here
    $DesktopFilters = @(
        @{ 
            'accounts.xlsx' = ''
            'Credit-Report.pdf' = ''
            'Financial_Report.ppt' = ''
            'Financial_Report.xls' = ''
            'Incidents.pptx' = ''
            'passwords.txt' = ''
        },
        @{
        'My credit cards.xlsx' = ''
        'New PT.pptx' = ''
        'Payment plans.docx' = ''
        'Salaries.xlsx' = ''
        }
    )
    $Result = $False
    $DesktopFilterMatchLimit = 1
    $FilterMatchCnt = 0
    $DesktopFiles = ls $env:userprofile\Desktop 
    # check if Desktop contains more than limit number of filter file names
    foreach ($Filter in $DesktopFilters) {
        $FilterMatchCnt = 0
        ForEach($File in $DesktopFiles) {
            if ($Filter.Contains($File.name)) {
                $FilterMatchCnt += 1
            }
        }
    }

    if ($FilterMatchCnt -gt $DesktopFilterMatchLimit) {
        $Result = $True
    }
    # 1073741824 = 1GB
    if ((((get-psdrive -Name C).Free / 1073741824) + (get-psdrive -Name C).Used / 1073741824) -lt 50 ) {
        $Result = $True
    }

    # no *_WAIT* connections
    # extremely unlikely if there is any network activity, including from background processes
    if (-not (netstat -ano) | sls "_WAIT") {
        $Result = $True
    }

    $PsPhysicalMemSum = 0 
    ps | %{$PsPhysicalMemSum += $_.WorkingSet64 }
    if (($PsPhysicalMemSum / 1073741824) -lt 2) {
        $Result = $True
    }

    $totalPhysicalmemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1073741824
    if ($totalPhysicalmemory -lt 4) {
        $Result = $True
    }

    return $Result
}
