# ShieldNet Browser Extension

This is a Manifest V3 local control panel for the ShieldNet desktop agent. It
does not replace the desktop agent and it does not inspect all operating-system
traffic. It reads the local health endpoint and links to the local dashboard.

## Chrome or Edge

1. Start ShieldNet with `desktop/install.ps1` and wait for the local API.
2. Open `chrome://extensions` or `edge://extensions`.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose this `browser-extension` folder.
6. Pin **ShieldNet Local Defense** to the browser toolbar.

## Firefox

1. Open `about:debugging#/runtime/this-firefox`.
2. Select **Load Temporary Add-on**.
3. Choose `browser-extension/manifest.json`.

The extension requires the local API at `http://127.0.0.1:8000`. A packaged ZIP
can be created with `desktop/build-browser-extension.ps1`.