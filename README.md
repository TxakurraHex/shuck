# shuck

A hand-rolled packet dissector for the terminal. Reads `.pcap` and `.pcapng`
files offline, decodes the link/network/transport/application headers
byte-by-byte, and lets you walk the protocol tree with your bytes lit up
in a hex pane.

It is a small Wireshark, written from scratch as a way to internalize
network wire formats. It is not, and will not become, a Wireshark
replacement.

## Status

Early. Phase 1 of the planned roadmap. Today shuck can:

- Open `.pcap` (classic, both endiannesses, both microsecond and nanosecond
  timestamp variants) and `.pcapng` files
- Dissect Ethernet II, including a single 802.1Q VLAN tag
- Render a three-pane TUI: frame list, layer tree, hex view
- Highlight the bytes corresponding to any selected field, in real time,
  in both the hex column and the ASCII gutter

Anything beyond Ethernet is shown as an undissected payload. That is the
honest state of the project.

## Roadmap

| Phase | Scope                                                | State   |
|-------|------------------------------------------------------|---------|
| 0     | TUI scaffolding, pcap/pcapng readers, frame list     | done    |
| 1     | Ethernet II, VLAN, hex highlighting, tree navigation | done    |
| 2     | IPv4, ARP                                            | next    |
| 3     | TCP, UDP                                             | planned |
| 4     | DNS                                                  | planned |
| —     | IPv6, ICMP, HTTP/1.1, TLS ClientHello (SNI)          | stretch |

Live capture, BPF-style display filters, decryption, and reassembly are
explicit non-goals for the foreseeable future.

## Quick start

```bash
git clone https://github.com/TxakurraHex/shuck
cd shuck

# A small all-DNS sample to get going.
mkdir -p samples
curl -L -o samples/dns.cap \
  https://wiki.wireshark.org/uploads/27261cb09c4327c4dabd2c4477ee5bd1/dns.cap

cargo run --release -- samples/dns.cap
```

### Keys

| Key          | Action                            |
|--------------|-----------------------------------|
| `j` / `↓`    | Next item in the focused pane     |
| `k` / `↑`    | Previous item in the focused pane |
| `g` / `Home` | First frame                       |
| `G` / `End`  | Last frame                        |
| `Tab`        | Switch focus (frame list ↔ tree)  |
| `q` / `Esc`  | Quit                              |

When focus is on the frame list, navigation moves between frames. When
focus is on the layer tree, navigation moves between fields, and the hex
pane highlights the selected field's bytes.

## Layout

```
shuck/
├── Cargo.toml
├── samples/ # gitignored, drop pcap files here
└── src/
├── main.rs # entry, arg parsing, app loop
├── app.rs # App state, input handling
├── pcap.rs # .pcap / .pcapng → Vec<Frame>
├── model.rs # Frame, Layer, Field types
├── dissect/
│ ├── mod.rs # dispatch + DissectError + helpers
│ └── ethernet.rs # Phase 1
│ # ipv4.rs / arp.rs / tcp.rs / udp.rs / dns.rs land in later phases
└── ui/
├── mod.rs # draw() top-level
├── frame_list.rs
├── tree.rs
└── hex.rs
```

## Design notes

### Hand-rolled dissectors

The whole point of this project is the parsing. Every protocol is decoded
by shuck's own code rather than via a library like `etherparse`. That makes
the project slower to build but better as a way to learn how the bytes are
laid out.

### Absolute byte offsets

Every `Field` carries the absolute byte offset and length of its bytes
within the original frame, not an offset relative to its enclosing
protocol. This is what makes hex-pane highlighting trivial: the UI does
not need to know anything about layering.

A dissector for an inner protocol receives a `base_offset` parameter from
its caller. When IPv4 (eventually) calls into TCP, it will pass
`base + ihl_bytes`, and TCP's fields will land at correct frame-relative
offsets without any extra bookkeeping.

### Offline only

shuck reads pcap files from disk. It does not capture from interfaces.
Live capture brings privilege requirements, BPF filter compilation, and
ring-buffer mechanics that are interesting on their own and not part of
what this project is for.

### Errors are layers

If a frame cannot be dissected, shuck renders a synthetic "Undissected"
layer in the tree carrying the parser's error message. A single bad
frame never takes down the capture view.

## Tested against

- `dns.cap` from the Wireshark wiki sample captures
  ([wiki.wireshark.org/SampleCaptures](https://wiki.wireshark.org/SampleCaptures))
- pcapng files written by recent versions of Wireshark and tcpdump

## Why "shuck"?

Shucking is the act of stripping back an outer husk to get at what's
inside. A packet is a similar object: layer wrapped around layer wrapped
around payload. The tool does exactly that, one nested header at a time.

## License

MIT License

## Acknowledgements

- The Wireshark project, both for the sample captures and for being the
  reference against which shuck's output gets sanity-checked.
- Tobias Bieniek and the [`pcap-file`](https://crates.io/crates/pcap-file)
  maintainers for a clean, pure-Rust pcap and pcapng reader.
- The [`ratatui`](https://ratatui.rs) and [`crossterm`](https://crates.io/crates/crossterm)
  authors for making terminal UIs in Rust pleasant.
