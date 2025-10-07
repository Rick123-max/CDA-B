<img width="1000" height="2000" alt="image" src="https://github.com/user-attachments/assets/652d5e7c-ffef-48f2-b6cc-6152fe671341" />

- Endlocal: Returns environmental variables to their original values after a localization

<img width="600" height="1000" alt="image" src="https://github.com/user-attachments/assets/46e59443-30fe-4ed7-b23e-dfd67be6473e" />

- bash:
  - `set PATH=%PATH%C:\NewFolder;` : sets a temporary variable
  - `setx PATH "%PATH%C:\NewFolder;"` : sets a permanent variable

<img width="1950" height="984" alt="image" src="https://github.com/user-attachments/assets/baddc391-3947-46f0-85e6-60d1d7d2d29c" />

<img width="1000" height="1200" alt="image" src="https://github.com/user-attachments/assets/1b5a2b5c-ee73-42e0-bda7-32b751cbd371" />

- Get-Service -name "" " finds a service in powershell
- Find a service in CMD: sc query ""


- **FIND**:  searches for files in a directory hierarchy from a specified starting point, or multiple starting points, in the directory tree

- **GREP and EGREP**: searches the named input file for lines containing a match to the given pattern.
  - Options:
    - -E, --extended-regexp — Interpret the pattern as an extended regular expression
    - -i, --ignore-case — Ignore case distinction in both the PATTERN and the input files
    - -v, --invert-match — Invert the sense of matching (select the non-matching lines)
    - -r, --recursive — Read all files under each directory, recursively
    - -C NUM, --context=NUM — Print NUM lines of both input and output context

- **CAT**:  concatenates files and prints on the standard output

- **CUT**:  removes sections from each line of a file. When no FILE or when FILE is -, read from standard input
    - cut OPTION... [FILE]...
    - -b, --bytes=LIST — Select only these bytes
    - -c, --characters=LIST — Select only these characters
    - -d, --delimiter=DELIM — Use DELIM instead of TAB for field delimiter
    - -f, --fields=LIST — Select only these fields; also print any line that contains no delimiter character, unless -s option is specified
    - -s, --only-delimited — Only print lines that contain delimiters--output-delimiter=STRING — Use STRING as the output delimiter; the default is to use the input delimiter
    - -z, --zero-terminated — Line delimiter is NULL, not newline
  - As a reminder, /etc/passwd has a format of:
    - username:password:user ID:group ID:user name or comment:home directory: command interpreter or shell
  - `cut -d ":" -f1,7 /etc/passwd`: parses out only the username and shell from /etc/passwd

- **TR**: translates or delete characters from standard input; writing to standard output
  - Common options:
    - tr [OPTION]... SET1 [SET2]
    - -d, --delete — Delete characters in SET1, do not translate
    - -s, --squeeze-repeats — Replace each sequence of a repeated character in the last specified SET with a single occurrence of that character (squeeze a bunch of spaces into a single space)
    - [:alnum:] — All letters and digits
    - [:alpha:] — All letters
    - [:blank:] — All horizontal whitespace
    - [:digit:] — All digits
    - [:lower:] — All lower case letters
    - [:print:] — All printable characters including spaces
    - [:punct:] — All punctuation characters
    - [:space:] — All horizontal and vertical whitespace
    - [:upper:] — All upper case letters

- **SORT**: sorts lines of text files to standard output, or from standard input if no files are specified
  - Common options:
    - sort [OPTION]...[FILE]...
    - -b, --ignore-leading-blanks — Ignore leading blanks
    - -d, --dictionary-order — Consider only blanks and alphanumeric characters
    - -f, --ignore-case — Fold lower case to upper case characters
    - -g, --general-numeric-sort — Compare according to general numerical value
    - -i, --ignore-nonprinting — Consider only printable characters
    - -r, --reverse — Reverse the result of comparisons
    - -o, --output=FILE — Write result to FILE instead of standard output
    - -u, --unique — Output only the first of an equal run
   
- **DIFF**: compares files line by line to identify differences
  - Common options:
    - diff [OPTION]... FILES
    - -q, --brief — Report only when files differ
    - -c, -C NUM, --context[=NUM] — Output NUM (default 3) lines of copied context
    - -u, -U NUM, --unified[=NUM] — Output NUM (default 3) lines of unified context
    - -y, --side-by-side — Output in two columns--suppress-common-lines — Do not output common lines
    - -r, --recursive — Recursively compare any subdirectories found
    - -i, --ignore-case — Ignore case differences in file contents
    - -E, --ignore-tab-expansion — Ignore changes due to tab expansion
    - -Z, --ignore-trailing-space — Ignore white space at line end
    - -b, --ignore-space-change — Ignore changes in the amount of white space
    - -w, --ignore-all-space — Ignore all white space
    - -B, --ignore-blank-lines — Ignore changes whose lines are all blank
   
- **SLEEP**: delays for a specified amount of time.

- **WATCH**:  runs a command repeatedly, displaying its output and errors, which allows you to watch the programs output change over time
  - Common options:
    - watch [options] command
    - -d, --differences — Highlight the differences between successive updates
    - -n, --interval seconds — Specify update interval in seconds
   
- **KILL**: Sends a signal to a process or processes.
  - kill [options] <pid> [...]
  - -l, --list [signal] — List signal names
  - -s, --signal <signal> — Specify the signal to be sent
  - -9, -SIGKILL, -KILL — Alternate ways to send signal SIGKILL
  <img width="963" height="689" alt="image" src="https://github.com/user-attachments/assets/0b6c9e65-57f2-428b-8de9-b6d987d40471" />

- **LSOF**:  lists standard output file information about files opened by processes

- **TIMEOUT**: runs a command with a time limit and kills it if stil running after a set duration.

- **SED**: stream editor performs basic text transformations on an input stream

- **AWK AND GAWK**: used for pattern scanning and processing of files and standard input.
- awk is similar to sed in that it performs operations as part of a script that is a separate file or input on the command line.
  - ```awk '{print}' /etc/passwd```
  - ```awk '/bash/ {print}' /etc/passwd```
  - ```awk 'BEGIN { FS=":" }; {print $1,$7}' /etc/passwd```
  - ```awk 'BEGIN { FS=":" }; /bash/ {print $1,$4,$7}' /etc/passwd```
  - ```cat /etc/passwd | awk 'BEGIN { FS=":" }; /bash/ {print $1,$4,$7}'```
  - ```awk '{ FS=":" }; NR==3, NR==6 {print NR,$1,$NF}' /etc/passwd```
- awk has a large quantity of built-in variables, a few common ones are listed below:
  - $NF — Last field
  - $NR — Line number
  - $0 — All fields in the line

### WMIC
- `wmic /node:"172.16.5.2" /user:"administrator" rdtoggle list`: query RDP status on a device
- `wmic /node:"172.16.5.2" /user:"cda\trainee" /password:"Th1s is 0perational Cyber Training!" process get /all /format:list`:
- `wmic /node:"172.16.5.2" /user:"administrator" rdtoggle where AllowTSConnections="0" call SetAllowTSConnections "1"`: turns on the RDP on a remote system
- `wmic /node:"174.16.1.6" /user:"cda\trainee" os list brief`: shows OS info for a remote system
- `wmic /node:"174.16.1.6" /user:"cda\trainee" os get BuildNumber,SerialNumber,LastBootUpTime`: Retrieve OS info including last boot up time
- `wmic /node:"174.16.1.3" /user:"cda\trainee" os list brief /format:list`: Give info about a system
- `wmic /node:"172.16.5.2" /user:"cda\trainee" /password:"Th1s is 0perational Cyber Training!" process call create "notepad.exe"`: runs a process on a remote system
- `wmic /note:"172.16.5.2" where "ProcessID=2488" call terminate`: remotely kills a process
- `wmic /output:os_info.txt os list brief`: outputs wmic to a file
- `wmic /output:os_info.htm os list brief /format:hform`: outputs in HTML format
- `wmic product get caption,identifyingnumber,installdate,version`: pulls specific information using WMIC
- ```wmic process where processid=2564 call terminate```
- ```wmic nicconfig where index=0 call flushdns```
- ```wmic service list brief```
- ```wmic service where name="TermService" list /format:list```: **Queries status of TermService service, which deals with RDP**
- ```wmic service where name="TermService" call ChangeStartMode "Disabled"``` **Disables RDP**
- `**ntevent where "eventtype<3 and LogFile='system' and timegenerated>'20210101**'" get eventcode,eventidentifier,recordnumber,sourcename,timegenerated,type`: Used to retrieve WIN EVENT LOGS.
- `wmic ntevent where "RecordNumber=4394 and LogFile='system'" list /format:list`: pulls a specific log
- `wmic group list brief`: pulls configured Windows local groups

<img width="1930" height="1406" alt="image" src="https://github.com/user-attachments/assets/845be887-d85a-4927-b229-c30290c778a2" />

### POWERSHELL
- `Import-Module .\Example.ps1 -Force`: impots a module into current enviroment
- `$person = New-Object Person`: create a variable
- `$person.GenerateGreeting()`: Invoke a Method
- `Get-ProcessesWithModules | Where Modules -contains "MSCOREE.DLL"`
- `Get-ProcessesWithModules | Where ProcessName -eq "Explorer"`
- `(Get-ProcessesWithModules | Where ProcessName -eq "Explorer").Modules | Sort`: Filters on loaded modules for specified process
- `Get-Childitem -Path C:\ -Include XmlLite.dll -File -Recurse -ErrorAction SilentlyContinue`: Find the path of all instances os XmlLite.dll
- `(Get-Process | Where ProcessName -eq "Explorer").Modules | Where Modulename -eq 'XmlLite.dll'`: Validates the version of the loaded module

### File Hashing
- `Get-FileHash .\Files\d1ejyvn0.ybv`: Get the hash of a file
- `Get-FileHash .\Files\d1ejyvn0.ybv -Algorithm SHA1`: Gets the file hash in a different algorithm
- ```
  ### This gives a list of files in a directory. ###
  $files = Get-ChildItem ".\Files"
  foreach($file in $files) {
    Write-Output $file
  }
  ```
  ```
  ### This gives a list of hashes for all files in a directory ###
  foreach($file in $files) {
    Get-FileHash $file.FullName
  }
  ```
- `Get-ChildItem '.\Files' | Get-FileHash`: one line to get the file hashes
- `Get-FileHash .\Files\*`: also gets file hashes of a directory

 ```
### This Explores Base64 Encoding ###
$contents = [System.IO.File]::ReadAllBytes('C:\Users\trainee\Documents\Samples\Demo.ps1')
[Convert]::ToBase64String($contents)
```
```
### convert Base64 to a file and execute ###
$base64 = [Convert]::ToBase64String($contents)
$raw = [Convert]::FromBase64String($base64)
[System.IO.File]::WriteAllBytes('C:\Users\trainee\Desktop\Demo.ps1', $raw)
.\Demo.ps1
###
```

### Interacting with the Alias Provider
- `Get-PSProvider`: lists all PS Providers
- `Get-ChildItem Alias:` Lists out all of the Aliases on the system
- `New-Item -Path Alias:list -Value "Get-ChildItem"`: creates a new alias
- `Rename-Item Alias:list enumerate`: Changes the name of an alias
- `Set-Item Alias:enumerate "Get-Item"`
- `Get-ChildItem Alias: | Where Definition -Eq "Get-Item"`: lists all aliases for a specifc CMDLET
  
### Interacting with the Environemnt PSProvider
- `(Get-Item Path).Value`: lists the entire path variable
- ```
  ### Add a path to the Path env variable ###
  $path = $Env:Path
  $path = $path + "C:\Users\trainee\Documents\Samples;"
  Set-Item Path $path
  ```

### Interacting with Registry PSProvider
- The Registry PSProvider (available via the HKEY_LOCAL_MACHINE [HKLM]: and HKEY_CURRENT_USER [HKCU]: drives) is used to interact with the registry on the system
  ```
  ### View Run entries using HKCU: and HKLM: drives ###
  Get-Item HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
  Get-Item HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
  ```
  ```
  ### User New-PSDrive to create new drive mapped to a folder ###
  New-PSDrive -Name "WCurrentVersion" -PSProvider "Registry" -Root "HKLM:\Software\Microsoft\Windows\CurrentVersion"
  ```
- `Get-Item 'User Shell Folders'`: returns user shell folder

### Interacting Remotely Using PowerShell
- Web Request: `Invoke-WebRequest -URI "http:...exe" -Outfile (file name)`
- `$credentials = Get-Credential`: stores credentials
- `Invoke-Command -Credential $credentials -ComputerName 'cda-dc' -ScriptBlock {Get-FileHash 'C:\Users\Administrator\Desktop\hashme.txt'}`: Get a file hash of a file with a known path on a remote system
- `[string[]] $computers = Get-Content 'Computers.txt'`: load a list of interactable computers
```
### Gathers info about all of the computers in the computers variable list
foreach($computer in $computers){
Invoke-Command -Credential $credentials -ComputerName $computer -FilePath C:\Users\trainee\Documents\Samples\GatherInfo.ps1
}
```

### Downloading from Remote Computers
- `$session = New-PSSession -ComputerName 'cda-dc' -Credential $credentials`: Opens a new PSSession
- `Copy-Item -FromSession $session 'C:\Users\Administrator\Desktop\hashme.txt' -Destination 'C:\Users\trainee\Desktop\hashme.txt'`: copies a file from the session
- ```
  ### Compare newly hashed file to hash of same file on remote machine
  PS C:\Users\trainee\Desktop> $local = Get-FileHash hashme.txt
PS C:\Users\trainee\Desktop> $remote = Invoke-Command -Credential $credentials -ComputerName 'cda-dc' -ScriptBlock {Get-FileHash 'C:\Users\Administrator\Desktop\hashme.txt'}
PS C:\Users\trainee\Desktop> $local.Hash -eq $remote.Hash
```

### Downloading files from Web Servers using PowerShell
- `Invoke-WebRequest -Uri "http://training.local/TestFile.zip" -OutFile TestFile.zip`:  downloads a file located at a website
- `(Get-FileHash TestFile.zip).Hash -eq "029C54D99DA58FE76CDA1C2FB365DE4FDC0173CB9A05A10B9DF417C0804D75CF"`: tests if the file hash matches a known good.
- ```
### Download payload from Website
PS C:\Users\trainee\Desktop> Invoke-WebRequest -Uri "http://training.local/payload.ps1" -OutFile payload.ps1
PS C:\Users\trainee\Desktop> .\payload.ps1
```
- `Start-BitsTransfer -Source "http://training.local/128.file" -Destination "C:\Files\128.file"`: download a large file
- `Start-BitsTransfer -Asynchronous -Source "http://training.local/512.file" -Destination "C:\Files\512.file"`: downloads in the background
- `Get-BitsTransfer`: shows status of download

### SSH STUFF
- `lsof -nP | grep LISTEN': list processes that have LISTEN sockets
- `lsof -nP | grep LISTEN | tr -s " "`: compresses the output to only have single spaces
- `lsof -nP | grep LISTEN | tr -s " " | cut -d " " -f 2`: cuts out the PID from the results
- `lsof -nP 2>/dev/null | grep LISTEN | tr -s " " | cut -d " " -f 2 | sort -u`: same results, but pushes the errors to /dev/null and gets rid of duplicates.


### NANO A SCRIPT
- nano <script>
- write script, CTRL X, Y, Enter
- chmod u+x <script>
- Run Script


### Using Powershell to View Loaded Libraries
- Query for explorere process: `Get-Process explorer`
- View loaded modules: `(Get-Process explorer).Modules`

  ```
  ### Find the processes for specified Module ###
  $processes = Get-Process
  foreach($process in $processes) {
  >> foreach($module in $process.Modules){
  >>  if ($module.ModuleName -eq 'advapi32.dll'){
  >>   $process
  >>  }
  >> }
  >>}
  ```

### Query Remote System using Powershell
- Store the credentials: `$credentials = Get-Credential`
- query current running processes on remote computer: `Invoke-Command -Credential $credentials -ComputerName 'cda-dc' -ScriptBlock {Get-Process}`
- Query for suspicious processes: `Invoke-Command -Credential $credentials -ComputerName 'cda-dc' -ScriptBlock {Get-Process powershell -module}`
- Query for which user ran a process: `Invoke-command -computername cda-acct-1 scriptblock {Get-process -name powershell -includeusername}`
- Query for powershell on a remote system: `Get-ciminstance -class win32_process -filter "name = 'powershell.exe'" - computername cda-acct-1 | format-list * `
- Coply collection locally: `$processes = Invoke-Command -Credential $credentials -ComputerName 'cda-dc' -ScriptBlock {Get-Process}`

  ```
  ### Filter processes for specific loaded modules ###
    foreach($process in $processes) {
  >> foreach($module in $process.Modules){
  >>  if ($module -like '*advapi32.dll*'){
  >>   $process
  >>  }
  >> }
  >>}
  ```
  
- Query to retrieve collection: `Invoke-Command -Credential $credentials -ComputerName 'cda-dc' -ScriptBlock {Get-Process explorer -Module}`

### Viewing Standard Windows API Functions

#### In CLI
- Loads all libraries loaded for explorer.exe process: `tasklist /fi "imagename eq explorer.exe" /m`
  - The /m switch displays all modules — meaning all loaded DLLs — associated with the selected processes.
  - The /fi switch is a filter. It uses the quoted string immediately following the switch as a query on the list of all processes returned by tasklist.
  - The imagename query selector indicates that results are filtered by the canonical name of the process.
  - The eq query operator filters results in which the selector’s value is equivalent to the trailing expression.
  - The [process] term is a regular expression, such as explorer or explore*.
- Load all libraries loaded for wmiprvse.exe process on remote computer: `tasklist /s 172.16.3.2 /u Administrator /fi "imagename eq wmiprvse.exe" /m`

#### In Powershell
- List all DLLs loaded by explorer.exe on local machine: `Get-Process “explorer” | Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue | Format-Table -Autosize`




  
