#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Project: Poseidon Mythic C2 Communication Extractor
# Description: Automated script to extract Mythic C2 communications
#              from PCAP files using HTTP profile. Targets Poseidon agent
#              (Golang) for Linux and macOS.
# Agent Repo: https://github.com/MythicAgents/poseidon
# Organization: Mythic Agents (community & SpecterOps)
# Author: mrfa3i
# Year: 2025
# -----------------------------------------------------------------------------
import argparse
import pyshark
import base64
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime

# Store commands from responses until matched with user_output in requests
task_map = {}

def decrypt_data(enc, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(enc), AES.block_size)
    return decrypted_data

def c2_informations(uuid, iv, key):
    print(f"UUID: {uuid}")
    print(f'KEY: {key.hex()}')
    print(f"IV: {iv.hex()}")
    print()

def decrypt_payload(b64_payload, key):
    hex_str = b64_payload.replace(":", "").replace("\n", "").strip()
    try:
        raw_bytes = bytes.fromhex(hex_str)
    except ValueError:
        raw_bytes = base64.b64decode(b64_payload)

    decoded_data = base64.b64decode(raw_bytes)

    iv = decoded_data[36:36+AES.block_size]
    enc = decoded_data[36+AES.block_size:-32]  # exclude HMAC

    c2_informations(uuid=decoded_data[:36], iv=iv, key=key)

    decrypted_data = decrypt_data(enc, key, iv)
    return decrypted_data

def extract_b64_payload(packet):
    if hasattr(packet.http, "file_data"):
        return packet.http.file_data.strip()
    if hasattr(packet, "data") and hasattr(packet.data, "data"):
        hex_str = packet.data.data.replace(":", "").strip()
        try:
            raw_bytes = bytes.fromhex(hex_str)
            return raw_bytes.decode("utf-8", errors="ignore")
        except Exception:
            return None
    return None

def process_decrypted_data(stream_id, decrypted_bytes, dump, is_request):
    try:
        text_data = decrypted_bytes.decode("utf-8", errors="ignore")
        print(text_data)

        try:
            data_json = json.loads(text_data)
        except json.JSONDecodeError:
            return

        # Store command + parameters from RESPONSE
        if not is_request and "tasks" in data_json:
            for task in data_json["tasks"]:
                if "id" in task and "command" in task:
                    ts = task.get("timestamp")
                    ts_str = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                    cmd_full = task["command"]
                    if task.get("parameters"):
                        cmd_full = f"{cmd_full} {task['parameters']}".strip()
                    task_map[task["id"]] = {
                        "timestamp": ts_str,
                        "command": cmd_full
                    }

        # Match and save output from REQUEST
        if is_request and "responses" in data_json:
            for resp in data_json["responses"]:
                if "task_id" in resp and "user_output" in resp:
                    task_id = resp["task_id"]
                    if task_id in task_map:
                        ts = task_map[task_id]["timestamp"]
                        cmd = task_map[task_id]["command"]
                        output = resp["user_output"]

                        try:
                            parsed_out = json.loads(output)
                            output_str = json.dumps(parsed_out, indent=4)
                        except Exception:
                            output_str = output

                        with open("executed_commands.txt", "a", encoding="utf-8") as f:
                            f.write(f"{ts} {cmd}\n{output_str}\n\n")

                        print(f"[+] Saved executed command '{cmd}' with output to executed_commands.txt")
                        del task_map[task_id]

        # Dump file chunks into dump/ directory if --dump flag used
        if dump and "responses" in data_json:
            dump_dir = "dump"
            if not os.path.exists(dump_dir):
                os.makedirs(dump_dir)
            for resp in data_json["responses"]:
                if "download" in resp and "chunk_data" in resp["download"]:
                    chunk_b64 = resp["download"]["chunk_data"]
                    if chunk_b64:
                        chunk_bytes = base64.b64decode(chunk_b64)
                        filename = os.path.join(dump_dir, f"stream{stream_id}.dat")
                        with open(filename, "ab") as f:
                            f.write(chunk_bytes)
                        print(f"[+] Saved chunk to {filename}")

        # Save interactive_shell_session shell commands
        if is_request and "interactive" in data_json:
            for item in data_json["interactive"]:
                if "data" in item and item["data"]:
                    try:
                        decoded_cmd = base64.b64decode(item["data"]).decode("utf-8", errors="ignore")
                        with open("interactive_shell_session.txt", "a", encoding="utf-8") as f:
                            f.write(decoded_cmd + "\n")
                        print(f"[+] Saved interactive_shell_session shell command to interactive_shell_session.txt")
                    except Exception as e:
                        print(f"[!] Failed to decode interactive_shell_session data: {e}")

    except Exception as e:
        print(f"[!] Error processing decrypted data: {e}")

def extract_data_fields(pcap_file, key_b64, dump):
    key = base64.b64decode(key_b64)
    capture = pyshark.FileCapture(pcap_file, display_filter="http")

    streams = {}

    for packet in capture:
        try:
            stream_id = packet.tcp.stream
        except AttributeError:
            continue

        if stream_id not in streams:
            streams[stream_id] = {}

        if hasattr(packet.http, "request_method") and packet.http.request_method == "POST":
            b64_payload = extract_b64_payload(packet)
            if b64_payload:
                streams[stream_id]['request'] = b64_payload

        elif hasattr(packet.http, "response_code"):
            b64_payload = extract_b64_payload(packet)
            if b64_payload:
                streams[stream_id]['response'] = b64_payload

        if 'request' in streams[stream_id] and 'response' in streams[stream_id]:
            print(f"\n=== TCP Stream {stream_id} ===")
            try:
                decrypted_resp = decrypt_payload(streams[stream_id]['response'], key)
                print("\n[Response Decrypted]:")
                process_decrypted_data(stream_id, decrypted_resp, dump, is_request=False)
            except Exception as e:
                print(f"[!] Failed to decrypt response stream {stream_id}: {e}")

            try:
                decrypted_req = decrypt_payload(streams[stream_id]['request'], key)
                print("\n[Request Decrypted]:")
                process_decrypted_data(stream_id, decrypted_req, dump, is_request=True)
            except Exception as e:
                print(f"[!] Failed to decrypt request stream {stream_id}: {e}")

            print("="*80)
            del streams[stream_id]

    capture.close()

def main():
    parser = argparse.ArgumentParser(
        description="Extract and decrypt Poseidon Mythic C2 payloads from a PCAP file",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example usage:
  python poseidon_http_c2_extractor.py -f <pcap_file> -k BASE64_KEY --dump
""")
    parser.add_argument("-f", "--file", required=True, help="Path to the PCAP/PCAPNG file")
    parser.add_argument("-k", "--key", required=True, help="Base64-encoded AES key")
    parser.add_argument("--dump", action="store_true", help="Dump chunk_data to dump/ directory")
    args = parser.parse_args()

    extract_data_fields(args.file, args.key, args.dump)

if __name__ == "__main__":
    main()