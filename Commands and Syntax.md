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





 
