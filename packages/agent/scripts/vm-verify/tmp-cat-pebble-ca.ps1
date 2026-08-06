$content = Get-Content "C:\pebble\test\certs\pebble.minica.pem" -Raw
Write-Output "---BEGIN---"
Write-Output $content
Write-Output "---END---"
