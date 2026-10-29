# Mobile and firmware

## 1. Android (APK)

Read order: manifest → permissions → entry points → code → resources → native.

```bash
unzip -l app.apk | head -40          # inventory
# with apktool (if available)
apktool d app.apk -o app-decoded -f
cat app-decoded/AndroidManifest.xml
# with jadx (if available)
jadx -d app-jadx app.apk
rg -n --no-heading "getDeviceId|IMEI|android_id|Build\.SERIAL|TelephonyManager|LocationManager"
```

Checklist of the questions that matter:

| Question | Where |
| --- | --- |
| Is it debuggable? | manifest `android:debuggable`, `application` flags |
| Does it export components? | `<activity android:exported="true">` + intent filters |
| Are permissions excessive? | `<uses-permission>` vs actual API usage |
| Is there cleartext traffic? | `android:usesCleartextTraffic`, network security config |
| Does it use exported providers/ContentProviders? | `<provider android:exported>` + permissions |
| Is the WebView dangerous? | `addJavascriptInterface` on untrusted origins, `setAllowFileAccess` |
| Are there dynamic receivers / native libs? | `<receiver>`, `lib/armeabi-v7a/*.so` |
| Is the signing key consistent? | compare the certificate across versions |

Rules:

- Manifest facts are `observed`. Whether an exported component is *reachable* is an inference
  until you actually send the intent.
- A permission is not a vulnerability; a permission plus an exported, unguarded path is.
- The `lib/` directory is a **second target**: each `.so` gets its own digest and ledger rows.
- Server-side behaviour is out of scope for the APK alone — mark it `unknown`.

## 2. iOS (IPA)

```bash
unzip -l app.ipa
codesign -d --entitlements :- Payload/App.app/App        # entitlements
otool -L Payload/App.app/App                              # linked dylibs
plutil -p Payload/App.app/Info.plist
```

- Entitlements are the security surface: `get-task-allow`, keychain groups, App Groups,
  `com.apple.developer.*`, background modes.
- A debug-signed or enterprise-signed build is a distribution finding.
- Mach-O inside the bundle is a native target → `native-binary-analysis.md`.

## 3. Unity IL2CPP

`global-metadata.dat` carries the type/method/string universe of the game.

| Layer | Data |
| --- | --- |
| Assembly images | `Assembly-CSharp.dll` etc. |
| Types, methods, fields | names + index ranges |
| String literals | the game's string table |
| Native code | `GameAssembly.so` / `UnityFramework` → needs native analysis |

Linking a method name to a native address requires the matching binary; without it, addresses
are `unknown`. Byte-pattern fallback matching is an **inference**.

Known metadata versions: 24, 27, 29, 31, 39. Other/unrecognised magic may mean encryption —
that is `unsupported`, not "decryptable".

## 4. Godot PCK / Unity data files

- PCK: pack inventory, header facts, per-member identity. Encrypted directories have **unknown**
  entry coverage; an empty filtered page cannot prove absence.
- A declared MD5 is not the same as an observed SHA-256. State which you have.

## 5. Flutter

- `libapp.so` + `isolate_snapshot_data`: hash the Dart snapshot and per-ABI library digests.
- Engine build provenance (engine version, build flags) is often embedded — treat it as
  self-reported metadata.
- Dart AOT code is native; use the native workflow for logic.

## 6. Firmware

```bash
binwalk file.bin                     # regions
binwalk -e --run-as=root file.bin    # extract (only in a disposable environment)
unblob file.bin --report-dir out/    # alternative
```

Workflow:

1. **Region inventory** — headers, filesystems, compressed blobs, bootloaders. Record region
   offsets and lengths.
2. **Extraction** — to a working dir, in the sandbox.
3. **Native handoff** — the extracted bootloader/kernel/firmware images go to the native
   workflow (formats may be raw; declare architecture and entry point explicitly).
4. **Filesystem inspection** — `/etc/passwd`, init scripts, SSH keys, web server configs, default
   credentials in shipped firmware are classic findings. Verify they are really shipped (not
   added by the filesystem tooling).

Firmware-specific notes:

- Many devices use signed firmware; the signature check is part of the boot chain — describe it as
  a control, and note where it can be bypassed **in your own lab device** (for research), not how
  to defeat it in the field.
- Vendor "hardening" claims (e.g. encrypted NVRAM) must be checked against the actual format.
- Extracted filesystems may contain developer leftovers (private keys, test endpoints) — high
  impact, report with the exact path and digest.

## 7. Mobile runtime notes

- Device analysis (adb) is for **your own device/emulator**; attach to a disposable emulator.
- A rooted/jailbroken device changes the observation; record the device state.
- Runtime hooks on ART/JVM can crash the app — a crash is not evidence of a vulnerability.
- Traffic from a real device can leak real accounts: use a test account with no data.

## 8. Coverage statements

For mobile/firmware work, state: tool versions, decode coverage (e.g. "3 of 7 DEX classes
inspected"), whether the native libraries were analysed, whether the server side was examined
(almost always `not examined`), and the device/emulator state.
