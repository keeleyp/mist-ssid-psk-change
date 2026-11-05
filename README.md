# Mist SSID PSK Change (PowerShell)

Changes the PSK of one Juniper Mist WLAN: reads the WLAN, shows the SSID and current PSK,
prompts for a new PSK (twice), confirms, writes it and reads it back to verify.

## Use

1. Copy `mist_ssid_psk_change.ini.example` to `mist_ssid_psk_change.ini` and fill in
   `cloud`, `api_token`, `org_id`, `wlan_id` (and `site_id` only for a site-level WLAN).
2. Run:

```powershell
./Set-MistSsidPsk.ps1
./Set-MistSsidPsk.ps1 -IniPath .\Customer_A.ini

# Non-interactive: no prompts or confirmation, prints only the completion line (or an error)
./Set-MistSsidPsk.ps1 -NewPsk 'Summer2026!Guest'
```

Use single quotes around the PSK so PowerShell doesn't expand `$` or backticks.
A PSK given on the command line ends up in your shell history.

Works on PowerShell 7+ (Windows/macOS/Linux) and Windows PowerShell 5.1.
On Windows you may need `Set-ExecutionPolicy -Scope Process Bypass` first.

## Notes

- Only the `auth` object is sent, with just `psk` replaced, so WPA2/WPA3 pairwise and
  multi-PSK settings are kept.
- PSK rules: 8–63 printable ASCII characters, or exactly 64 hex digits.
- The token needs write access to the org (or site).
- Proxy / Zscaler: optional `[network]` section (`verify_ssl`, `proxy`,
  `proxy_use_default_credentials`). PowerShell trusts the OS certificate store, so a
  Zscaler root CA installed in Windows / Keychain just works.
- `*.ini` is gitignored except the `.example` — never commit a real token.
