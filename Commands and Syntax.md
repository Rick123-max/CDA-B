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


- `wmic /node:"172.16.5.2" /user:"administrator" rdtoggle list`: query RDP status on a device
- `wmic /node:"172.16.5.2" /user:"administrator" rdtoggle where AllowTSConnections="0" call SetAllowTSConnections "1"`: turns on the RDP on a remote system
- `wmic /node:"174.16.1.6" /user:"cda\trainee" os list brief`: shows OS info for a remote system
- `wmic /node:"174.16.1.6" /user:"cda\trainee" os get BuildNumber,SerialNumber,LastBootUpTime`: Retrieve OS info including last boot up time
- `wmic /node:"174.16.1.3" /user:"cda\trainee" os list brief /format:list`: Give info about a system
- `wmic /node:"172.16.5.2" /user:"cda\trainee" /password:"Th1s is 0perational Cyber Training!" process call create "notepad.exe"`: runs a process on a remote system
- `wmic /note:"172.16.5.2" where "ProcessID=2488" call terminate`: remotely kills a process
- `wmic /output:os_info.txt os list brief`: outputs wmic to a file
- `wmic /output:os_info.htm os list brief /format:hform`: outputs in HTML format
- `wmic product get caption,identifyingnumber,installdate,version`: pulls specific information using WMIC
- `**ntevent where "eventtype<3 and LogFile='system' and timegenerated>'20210101**'" get eventcode,eventidentifier,recordnumber,sourcename,timegenerated,type`: Used to retrieve WIN EVENT LOGS.
- `wmic ntevent where "RecordNumber=4394 and LogFile='system'" list /format:list`: pulls a specific log
- `wmic group list brief`: pulls configured Windows local groups

<img width="1930" height="1406" alt="image" src="https://github.com/user-attachments/assets/845be887-d85a-4927-b229-c30290c778a2" />




 
