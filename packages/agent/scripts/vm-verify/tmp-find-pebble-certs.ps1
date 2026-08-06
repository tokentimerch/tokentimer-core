Get-ChildItem -Path "C:\pebble\test\certs" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
Get-ChildItem -Path "C:\ProgramData\pebble" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
