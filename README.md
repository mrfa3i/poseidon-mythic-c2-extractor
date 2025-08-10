# Poseidon Mythic C2 Communication Extractor

Automated script to extract and decrypt Mythic C2 communications from PCAP files just for the [HTTP C2 profile](https://github.com/MythicAgents/poseidon/blob/master/Payload_Type/poseidon/poseidon/agent_code/pkg/profiles/http.go)



Targets the Poseidon agent (Golang) for Linux and macOS.

## Features

- Parses Mythic Poseidon C2 HTTP communications from PCAP/PCAPNG files  
- Decrypts AES-CBC encrypted payloads using a provided base64 AES key  
- Saves interactive shell commands, executed commands with output, and file chunks  
- Optionally dumps file chunks to a `dump/` directory  
- Matches commands sent by Mythic with their outputs  

## Installation

1. Install dependencies:

```bash
pip install -r requirements.txt
```
2. Make sure you have tshark installed on your system, as pyshark depends on it.

- On Debian/Ubuntu:

```bash
sudo apt-get install tshark
```

- On macOS (with Homebrew):

```bash
brew install wireshark
```

## Usage

```py
python poseidon_http_c2_extractor.py -f <pcap_file> -k <base64_aes_key> [--dump]
```

## Arguments

- ``-f``, ``--file`` : Path to the PCAP or PCAPNG file to analyze (required)

- ``-k``, ``--key`` : Base64-encoded AES key used to decrypt payloads (required)

- ``--dump`` : Optional flag to save extracted file chunks under the dump/ directory

## Output Files
- ``interactive_shell_session.txt`` : Contains decoded interactive shell session commands and outputs

- ``executed_commands.txt`` : Logs executed commands with timestamps and their outputs

- ``dump/streamN.dat`` : File chunks saved from Mythic C2 download tasks (if ``--dump`` specified)

## References

- [Poseidon Agent Repo](https://github.com/MythicAgents/poseidon)
