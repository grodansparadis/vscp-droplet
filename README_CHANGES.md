# Changes in vscp-droplet

Every change that goes into a release is listed here, newest release first.
Add each change under **Unreleased** when it is made. When a release is
tagged, rename **Unreleased** to the version and date, and start a new
**Unreleased** section above it.

## Unreleased

- No changes since the last release.

## A0.0.1 - 2023-02-23

- Fixed missed write to persistent storage when enable values where changed in web i/f (51cda98)
- Added OTA local firmware file upgrade on Alpha nodes (50c25f2)
- Client provisioning added (d89bd1e)
- Removed some junk (c89e08b)
- Rearranged code (a82aab3)
- Initial beta code (8b41c56)
- Added possibility to enable/disable services (3c4e761)
- vscp link server fully implemented (8aedd77)
- VSCP Link now sending frames (7b1b929)
- Fixed problems in droplet receive (41ee59f)
- Fixed VSCP link protocol server handler (occaitional glitches when workload was high) (ef25b31)
- Configuration in place (9b8ff35)
- MQTT config added (62ed8df)
- Config of log options added (82de73b)
- Moved logging files to main project (e7663a6)
- Web Config for module in place (8a4a755)
- Updated copyright year (dc01cb6)
- Fixed OTA (8f8847e)
- webinterface with system info and reset functionality (803adb5)
- Added mqtt client and json parsing (86eaf3e)
- Send/receive of encrypted and unencrypted data works (91908c2)
- Encrypted send added (8738cdc)
- New provisioning (705085c)
- Added OTA (880119b)
- Provisioning in place (BLE + SoftAP) (4504f64)
- Full speed receive/transmit test (237ab56)
- Added link protocol (6ba696f)
- Added tx/rx sample for espnow (c2011f2)
- Provisined alpha sending messages but not yet events (7429aad)
- Changed projectname (abfbb12)
- Fixed button on alpha example (03d02b1)
- security and node bind from button tested and validated (f6a30f6)
- Fixed relocation bugs (37d3913)
- Aded latest esp-now samples (fa9a64f)
- Sample code working with web browser (cde7225)
- Rearranged code (f8acdf6)
- Working initialization (e6dc535)
- Initial commit (e7ddce9)
