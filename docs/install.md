# Installation

```sh
pip install flowreassemble
```

flowreassemble needs Python 3.10 or later. Wheels exist for these platforms:

| Platform | Wheel | libpcap |
| --- | --- | --- |
| Linux x86_64 and aarch64, glibc 2.28 or later | `manylinux_2_28` | Included in the wheel |
| macOS 11 or later, Apple silicon and Intel | `universal2` | The one that ships with macOS |

On Linux, the wheel contains its own copy of libpcap, so you don't need to
install one. There are no Windows wheels yet.

## Build from source

On other platforms, pip builds from the source distribution. The build needs:

- a Rust toolchain (Rust 1.85 or later), for example from <https://rustup.rs>
- a C compiler, for the vendored libhtp
- the libpcap and zlib development files (on Debian and Ubuntu:
  `apt install libpcap-dev zlib1g-dev`)

## Capture privileges

Reading pcap files needs no privileges. Live capture does: root or the
`CAP_NET_RAW` capability on Linux, and read access to the `/dev/bpf*` devices
on macOS. See [Live capture](sources.md#live-capture).
