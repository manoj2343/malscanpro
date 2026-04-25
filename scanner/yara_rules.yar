rule SuspiciousPowerShell
{
    strings:
        $ps = "powershell -nop -w hidden"
    condition:
        $ps
}

rule PossibleKeylogger
{
    strings:
        $keylog = "GetAsyncKeyState"
    condition:
        $keylog
}

rule SuspiciousPDFScript
{
    strings:
        $a = "/JS"
        $b = "/JavaScript"
    condition:
        $a and $b
}

rule ImageStegoPattern
{
    strings:
        $s1 = "HiddenText"
    condition:
        $s1
}

rule Ransomware_Locky
{
    meta:
        description = "Detects Locky ransomware file content"
        author = "MalScanPro"
        malware_family = "Locky"
    strings:
        $s1 = "!!!-WARNING-!!!.txt"
        $s2 = "your files are encrypted"
        $s3 = "Locky"
    condition:
        any of ($s*)
}

rule Ransomware_WannaCry
{
    meta:
        description = "Detects WannaCry ransomware based on binary content"
        author = "MalScanPro"
        malware_family = "WannaCry"
    strings:
        $s1 = "WanaDecrypt0r"
        $s2 = "WANNACRY"
        $s3 = "Microsoft Security Response Center"
    condition:
        any of ($s*)
}

rule Ransomware_Ryuk
{
    meta:
        description = "Detects Ryuk ransomware patterns"
        author = "MalScanPro"
        malware_family = "Ryuk"
    strings:
        $s1 = "HERMES"
        $s2 = "RyukReadMe.html"
        $s3 = "Your files are encrypted by Ryuk"
    condition:
        any of ($s*)
}

rule RansomNote_Generic
{
    meta:
        description = "Detects generic ransom note text"
        author = "MalScanPro"
    strings:
        $a = "your files have been encrypted"
        $b = "decrypt your files"
        $c = "bitcoin address"
        $d = "email us"
    condition:
        2 of ($a, $b, $c, $d)
}

rule Ransomware_Executable_Pattern
{
    meta:
        description = "Detects suspicious executable behaviors typical in ransomware"
        author = "MalScanPro"
    strings:
        $code1 = "CryptEncrypt"
        $code2 = "FindFirstFile"
        $code3 = "CreateFile"
        $code4 = "DeleteFile"
        $code5 = ".encrypted"
    condition:
        3 of ($code*)
}

rule Suspicious_JavaScript_Obfuscation
{
    meta:
        description = "Detects common JavaScript obfuscation techniques"
        severity = "high"
    strings:
        $base64 = "atob(" nocase
        $eval = "eval(" nocase
        $escape = "unescape(" nocase
        $document_write = "document.write(" nocase
        $fromCharCode = "String.fromCharCode(" nocase
    condition:
        2 of ($*)
}

rule URL_Phishing_Detected
{
    meta:
        description = "Detects phishing-related keywords in HTML or script"
        severity = "medium"
    strings:
        $1 = "login" nocase
        $2 = "password" nocase
        $3 = "bank" nocase
        $4 = "paypal" nocase
        $5 = "account" nocase
        $6 = "update your information" nocase
    condition:
        3 of them
}

rule Suspicious_IFRAME_Usage
{
    meta:
        description = "Detects suspicious iframe usage for redirection"
        severity = "medium"
    strings:
        $iframe = "<iframe" nocase
        $src = "src=" nocase
        $hidden = "display:none" nocase
    condition:
        all of them
}

rule Powershell_Dropper
{
    meta:
        description = "Detects Powershell-based droppers from scripts"
        severity = "high"
    strings:
        $ps1 = "powershell -nop -w hidden" nocase
        $ie = "IEX(" nocase
    condition:
        all of them
}

rule Common_Malware_Hosts
{
    meta:
        description = "Matches known malware host domains"
        severity = "high"
    strings:
        $1 = "raw.githubusercontent.com"
        $2 = "pastebin.com"
        $3 = "bit.ly"
        $4 = "mega.nz"
        $5 = "dropbox.com"
    condition:
        any of them
}

rule EICAR_Test_File
{
    meta:
        description = "Detects EICAR test file"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
