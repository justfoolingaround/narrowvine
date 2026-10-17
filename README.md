# narrowvine

A Python host layer for Google's Widevine CDM (`libwidevinecdm.so`,
that has been verified against **4.10.3050.0**), using Chromium's
`ContentDecryptionModule` interface version 10. The CDM engine is
Google's proprietary binary; the Rust crate (`narrowvine-core`)
implements `cdm::Host_10` and exposes it through a
PyO3 extension built by maturin.

I do not ship any keys associated with Widevine here. Think of this
as a very stripped down version of your Linux browser.

## Install / build

```sh
make                 # uv sync -> maturin compiles the Rust extension
make test            # build + uv run pytest -q
make typecheck       # mypy over the Python library
make proto           # regenerate the license protobuf bindings
```

`narrowvine` is a host layer only: it does not ship a Widevine binary. Point it
at your own `libwidevinecdm.so` by passing a path or setting
`WIDEVINE_CDM_PATH`; a `vendor/libwidevinecdm.so` in the repo and the working
directory are also searched.

You can find these easily using (I'm sure Google will not be happy if I
provided my own):
```sh
$ find ~ -name "libwidevinecdm.so"
```

## Usage

```python
import requests

from narrowvine.cdm import Cdm
from narrowvine.device import Device
from narrowvine.pssh import PSSH

pssh = PSSH(
    "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa"
    "7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA=="
)

device = Device.load()

with Cdm.from_device(device) as cdm:
    with cdm.open() as session:
        challenge = cdm.get_license_challenge(session, pssh)

        licence = requests.post(
            "https://cwip-shaka-proxy.appspot.com/no_auth", data=challenge
        )
        licence.raise_for_status()

        cdm.parse_license(session, licence.content)

        for key in cdm.get_keys(session):
            # The proprietary CDM never exposes key material: `key.key` is None.
            print(f"[{key.type.name}] {key.kid.hex()} status={key.status.name}")
```

`narrowvine` mirrors the pywidevine workflow (`Device`, `PSSH`, `Cdm.open`,
`get_license_challenge`, `parse_license`, `get_keys`, `close`) with context
managers on both `Cdm` and `Session`.

**Why no `.wvd` and no key bytes?** pywidevine is a pure-Python CDM: a `.wvd`
private key signs the request and unwraps the license, so it can print
`kid:key`. `libwidevinecdm.so` keeps its device certificate and private key
sealed inside the binary and decrypts the license internally; the host only ever
sees key **ids and statuses** via `OnSessionKeysChange`. `Key.key` is therefore
`None`; decryption happens through the CDM (`Cdm.decrypt`,
`Cdm.decrypt_and_decode_frame`, ...).


## Analyze any CDM

`scripts/analyze_cdm.py` inspects your own `libwidevinecdm.so`: file/ELF +
required exports, version, interface and init status, an offline license
challenge decoded into the client identity, audio/video decoder support, and
optionally a real license round-trip.

```sh
uv run python scripts/analyze_cdm.py /path/to/your/libwidevinecdm.so
uv run python scripts/analyze_cdm.py /path/to/your/libwidevinecdm.so --json
uv run python scripts/analyze_cdm.py --license-url https://.../no_auth
```

Example output:

```
file           /.../libwidevinecdm.so
version        4.10.3050.0
interface      10 (requested)
initialized    True
challenge      LICENSE_REQUEST (1743 bytes)
client         DRM_DEVICE_CERTIFICATE (1310 bytes)
  model_name             = ChromeCDM
  platform_name          = Linux
  widevine_cdm_version   = 4.10.3050.0
pssh key ids   eb676abbcb345e96bbcf616630f1a3da
decrypt        success (AES-CTR; this is the audio path)
audio decoder  initialization_error (not implemented by this CDM)
video decoder  success
```

`audio decoder  initialization_error` is expected for this build. Audio
**decryption** works through `Cdm.decrypt` (AES-CTR, codec-agnostic); what the
CDM lacks is an audio **decoder**. In Widevine 4.10.3050.0 both audio entry
points are hardcoded stubs:

```
InitializeAudioDecoder   -> mov eax, 3; ret   (kInitializationError)
DecryptAndDecodeSamples  -> mov eax, 5; ret   (kDecodeError)
```

So decrypt audio with `Cdm.decrypt` and decode it outside the CDM
(`scripts/play_drm.py` does this and feeds 48 kHz stereo AAC to ffmpeg). This is
a property of Google's binary, not of the host layer.

## Playback

```sh
uv run python scripts/play_drm.py --segments 5 --ffplay
# -> /tmp/narrowvine_play/decrypted.mp4 (640x360 H.264 + AAC, ~20s)
```

## Version and security level

From `scripts/inspect_license.py`:

- **CDM version** `4.10.3050.0`; `model_name=ChromeCDM`, `platform_name=Linux`.
- **Device identity**: provisioned `DRM_DEVICE_CERTIFICATE` (~1.3 KB root of trust).
- **License keys**: content key `level = 1` = `SW_SECURE_CRYPTO`.
- Host calls `Initialize(..., use_hw_secure_codecs = false)`.

**This is Widevine L3 (software).** L1/L2 require `HW_SECURE_*` backed by a
hardware TEE; a plain `libwidevinecdm.so` on a generic desktop cannot reach them.

## CDM interface 10 (verified)

Method slots: `Initialize`, `GetStatusForPolicy`, `SetServerCertificate`,
`CreateSessionAndGenerateRequest`, `LoadSession`, `UpdateSession`,
`CloseSession`, `RemoveSession`, `TimerExpired`, `Decrypt`,
`InitializeAudioDecoder`, `InitializeVideoDecoder`, `DeinitializeDecoder`,
`ResetDecoder`, `DecryptAndDecodeFrame`, `DecryptAndDecodeSamples`,
`OnPlatformChallengeResponse`, `OnQueryOutputProtectionStatus`, `OnStorageId`,
`Destroy` (plus two destructor slots).

`CreateCdmInstance` accepts interfaces 10 and 11 (two vtables, 11 at `this+8`);
this layer requests 10. Host is `cdm::Host_10`.

Known CDM quirks handled by the library:

- `Decrypt()` rejects `num_subsamples > 1` and occasionally trips on the leading
  AVCC length; `utils/cenc.py` flattens the cipher stream into one subsample.
- `InitializeAudioDecoder` / `DecryptAndDecodeSamples` are unsupported
  (`kInitializationError` / `kDecodeError`): decrypt audio and decode it outside
  the CDM.
- `ResetDecoder` after `DeinitializeDecoder` crashes inside the CDM; the wrapper
  guards it.

## Persistence, timers and policies

**Persistent state / `LoadSession`.** `Host::CreateFileIO` and
`Host::RequestStorageId` are implemented: the CDM's session/usage files are
written under a storage directory (`Cdm.from_device(device, storage_dir=...)`,
`$NARROWVINE_STORAGE`, or `~/.local/share/narrowvine`). Request a persistent
session and reload it later with the same storage directory:

```python
with Cdm.from_device(device, storage_dir="./wv-state") as cdm:
    with cdm.open(session_type=narrowvine.SESSION_PERSISTENT_LICENSE) as session:
        cdm.parse_license(session, request_license(cdm.get_license_challenge(session, pssh)))

# in another process/run
with Cdm.from_device(device, storage_dir="./wv-state") as cdm:
    with cdm.load_session(session_id) as session:
        print(cdm.get_keys(session))
```

**Linux cannot use persistent licenses.** Google's CDM requires VMP (CDM host
verification) for `kPersistentLicense`; Linux has no VMP, so the CDM returns
`NotSupportedError` (system code 45) *before* touching host storage. This is a
platform/CDM limit, not a host-layer one (chromiumembedded/cef#3404: "Persistent
licenses are not supported [on Linux], only streaming licenses"). The Axinom
test vector proves it: its JWT has `allow_persistence: true` and the server
returns `can_persist`, yet the CDM still refuses the persistent session.
Temporary/streaming sessions are unaffected, and the storage path is exercised
by the usage table on every session.

**Timers.** `SetTimer` is scheduled on a background thread, but the CDM is only
called on the thread that created it (as Chromium's host does), so due timers
are fired by `Cdm.service_timers()` — or `Cdm.wait(timeout)` for simple
scripts. Call `service_timers()` from your event loop during playback.

**Server certificates and policy.** `Cdm.set_server_certificate(cert)` stores a
service certificate used to encrypt license requests, and
`Cdm.get_status_for_policy(min_hdcp_version)` returns the `KeyStatus` for a
hypothetical key under that HDCP policy.

`narrowvine.fetch_service_certificate(la_url, headers=None)` asks a license
server for its certificate (a `SignedMessage{SERVICE_CERTIFICATE_REQUEST}`) and
returns the `SignedDrmCertificate`. `set_server_certificate` accepts either that
or the whole `SignedMessage` response. Google's public CWIP test proxy serves
one:

```python
from narrowvine import Device, Cdm, fetch_service_certificate, request_license

PROXY = "https://cwip-shaka-proxy.appspot.com/no_auth"
cert = fetch_service_certificate(PROXY)          # SignedDrmCertificate

cdm = Cdm.from_device(Device.load())
cdm.set_server_certificate(cert)                 # accepts once per CDM instance
# a second set_server_certificate() is rejected (InvalidStateError)
```

The proxy's certificate is a `SERVICE` certificate for `staging.google.com`.
Setting it does not by itself make this CDM switch the license request to
`encrypted_client_id` for the test vectors tried here; the host-side binding is
what matters and is verified by the test suite.

## Limitations

- Persistent-license `LoadSession` is not usable on Linux: Google's CDM requires
  VMP for `kPersistentLicense` and rejects it (system code 45) before using host
  storage. The host side (FileIO + storage ID) is implemented and would work on
  a platform/CDM that permits persistence.
- CDM audio *decoding* is not implemented by this binary (video decoding is);
  decrypt audio with `Cdm.decrypt` and decode it outside the CDM.
- `SetServerCertificate` accepts a real service certificate but no service
  certificate is bundled; the current test servers do not require one.
- Linux x86-64, CDM interface 10. All CDM calls must stay on the creating thread.
