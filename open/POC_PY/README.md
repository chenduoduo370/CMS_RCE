# CVE Payload Tool (packaged)

This repository contains a PyQt5-based GUI tool for building and sending CVE payloads.

How to run the packaged exe:

- Build: Use `build_exe.ps1` (PowerShell) in this folder to build a single-file exe with PyInstaller.
- Run: `.\dist\cve_poc.exe`

If the exe exits immediately, ensure the target system has the required VC runtimes. The build already bundles PyQt5 and Qt plugins.


