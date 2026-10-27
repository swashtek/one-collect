# EventSource in-band manifest test assets

These assets test `TdhDecoder` decoding of .NET `EventSource` providers that use
the default manifest mode. In this mode, the provider sends its manifest in-band
as chunked ETW events and doesn't register it with the OS.

| File | Purpose |
|---|---|
| `one_collect_test_eventsource.xml` | Real `EventSource.GenerateManifest` output for the fixture `TestSource` (provider `OneCollect-Test-InbandManifest`, GUID `{369e340b-d54c-5d95-1211-b7a318f16882}`). Unit tests and the emulated integration test use it. |
| `EsFixture/` | Small .NET console app that defines `TestSource`. It can regenerate the manifest or emit live events. You don't need it to build or run CI tests. |

## Fixture events

| Id | Name | Payload |
|---|---|---|
| 1 | `AllScalars` | every integer width, `float`, `double`, `bool` (4-byte `BOOL`), `char` |
| 2 | `Strings` | two null-terminated UTF-16 strings and an `int` |
| 3 | `Misc` | `Guid`, `DateTime` (FILETIME), `IntPtr`, enum (`map=`) |
| 4 | `Blob` | `int`, `byte[]` (u32 length + bytes), `int` |
| 5 | `Ping` | no parameters (no `template` attribute) |
| 6 / 7 | `RequestStart` / `RequestStop` | `int`; these events share task `Request` |
| 8 | `Versioned` | `int`, event version 2 |

In `emit` mode, the fixture also calls `EventSource.Write("MixedTl", ...)`. This
emits a self-describing (TraceLogging) event from the same provider, which covers
the mixed-mode case.

## Regenerating the manifest

```powershell
cd one_collect\test_assets\eventsource\EsFixture
dotnet run -c Release -- manifest ..\one_collect_test_eventsource.xml
```

## Running the live .NET test (optional)

`tdh_decodes_live_dotnet_eventsource` in `tests/etw_tdh_integration.rs` drives a
real EventSource process. The test is skipped unless `ONE_COLLECT_ES_FIXTURE`
points to the fixture executable. It must run from an elevated shell.

```powershell
cd one_collect\test_assets\eventsource\EsFixture
dotnet build -c Release -o $env:TEMP\EsFixture
$env:ONE_COLLECT_ES_FIXTURE = "$env:TEMP\EsFixture\EsFixture.exe"
cd ..\..\..
cargo test --test etw_tdh_integration tdh_decodes_live_dotnet_eventsource -- --ignored --nocapture --test-threads=1
```

The always-available `tdh_decodes_eventsource_inband_manifest` test emulates the
same protocol through `EventRegister`/`EventWrite`, so it doesn't need .NET.
