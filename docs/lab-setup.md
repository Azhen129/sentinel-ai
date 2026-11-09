# Authorized local lab setup

See the [Ubuntu lab instructions in the README](../README.md#authorized-ubuntu-lab-ingestion) for application commands. Neither Zeek nor tshark is required for synthetic replay or importing an existing Zeek log.

For **Ubuntu 24.04**, Zeek's [official installation guide](https://docs.zeek.org/en/current/install.html) documents this package setup. For other Ubuntu releases, select that release's repository in the official guide:

```sh
sudo apt-get update
sudo apt-get install -y curl gnupg python3-venv
echo 'deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt-get update
sudo apt-get install zeek-8.0
export PATH="/opt/zeek/bin:$PATH"
zeek --version
# Optional existing-PCAP adapter:
sudo apt-get install tshark
tshark --version
```

If the tshark package asks whether non-root users should capture packets, choose **No**; this application only reads offline files. Ubuntu 24.04's default Python 3.12 is supported by the pinned dependencies; use `python3 -m venv .venv` there. These Linux installation steps are documented from the upstream guide and were not executed on this Windows machine.

Use a dedicated SQLite file (`SENTINEL_DB_PATH=data/lab.db`), set `SENTINEL_LAB_MODE=true`, and set a long random `SENTINEL_API_KEY` before starting the backend. All lab imports require that key in `X-Sentinel-Key`. The System page accepts it in memory only for log imports. No browser storage persists the key. Offline PCAP import also needs `SENTINEL_PCAP_ENABLED=true` and tshark on PATH.

Only expose the lab API on loopback unless you add authentication and TLS at a reverse proxy. Reading telemetry and editing incidents are not user-authenticated in this local prototype. CORS is not an authentication mechanism. Keep a separate database for a public synthetic demo; the backend refuses demo startup if the selected database contains any lab connections or incidents.

Read only authorized, already collected files. An unprivileged account needs read permission on those files and write permission on the SQLite directory. The application never opens an interface for capture, scans a host, blocks a connection or changes firewall rules. Offline Zeek log generation uses `zeek -r` on an existing file and does not require live-capture privileges.

PCAP support is a limited optional adapter: at most 20 MB and 50,000 packets, TCP/UDP only, frame byte counts rather than payload bytes, inferred reset states and coarse bidirectional five-tuple grouping. Separate sessions sharing a tuple may merge. Use Zeek connection logs when accurate session telemetry matters. End-to-end tshark/Zeek execution was not verified in the Windows build environment; parser and flow-aggregation tests were run.
