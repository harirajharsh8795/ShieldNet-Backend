# ShieldNet Desktop Preview

This is the first installable desktop release surface for Windows, Linux, and macOS.
It installs the existing FastAPI control plane and offline Streamlit dashboard into a
local virtual environment, then starts both services on loopback.

## Windows

Open PowerShell in the repository root and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\desktop\install.ps1
```

## Linux or macOS

From the repository root, run:

```bash
chmod +x desktop/install.sh
./desktop/install.sh
```

The dashboard opens at `http://127.0.0.1:8501`. The API documentation is at
`http://127.0.0.1:8000/docs`.

To create a portable source bundle after cloning or downloading this repository:

```powershell
.\desktop\build-package.ps1
```

The generated `dist/ShieldNet-Desktop-Preview.zip` contains the application,
models, installers, and documentation. It still requires Python 3.10 or newer
on the target machine.

This release is an offline dashboard and replay/analysis application. It does not
capture live packets, execute host-firewall commands, or claim active protection.
Npcap/libpcap capture and privileged OS firewall helpers are the next implementation
milestones.