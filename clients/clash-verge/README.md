# Nodectl Verge

Nodectl Verge adds support for the public enrollment file produced by nodectl. It uses the open-source Clash Verge Rev v2.5.10 application and its bundled Mihomo core.

## Using the public file

1. Install the Windows x64 adapter from the nodectl release and close any other application managing the system proxy.
2. In Nodectl Verge, open Profiles and drag in the administrator's `nodectl-*.yaml` file. Confirm the service displayed in the import dialog.
3. Select “启用代理并打开认证页” and sign in with your assigned account. The same profile refreshes automatically. Each device can import the same file.

## Building

Run `bash clients/clash-verge/prepare.sh <empty-directory>` to reconstruct the pinned upstream source with this adapter applied. The [Windows build workflow](../../.github/workflows/windows-adapter.yml) builds the installer and packages corresponding source under GPL-3.0.
