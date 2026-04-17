#!/usr/bin/env python3
"""
smblist - SMB share enumerator and file browser

Usage:
  smblist.py <creds> [shares.txt]              - enumerate shares file
  smblist.py <creds> -nxc <nxc_output>         - parse existing nxc output
  smblist.py -nxc <nxc_output>                 - just parse nxc into share list
  smblist.py <creds> -host <host|hosts.txt>    - run nxc then enumerate
  smblist.py <creds> -get <//host/share/file>  - download a specific file
  smblist.py <creds> -gui [paths.txt]          - launch web gui
  smblist.py <creds> [shares.txt] -o out.txt   - output to file and terminal

creds format: domain/user%pass
"""

import sys, os, re, subprocess, threading, webbrowser, json, time
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def parse_creds(c):
    domain = c.split('/')[0] if '/' in c else ''
    userpass = c.split('/')[-1]
    user = userpass.split('%')[0]
    passwd = userpass.split('%')[1] if '%' in userpass else ''
    return domain, user, passwd


def parse_smb_path(path):
    """Split //host/share/dir/file into (share, dir, filename)."""
    parts = path.split('/', 4)
    share = '/'.join(parts[:4]) if len(parts) >= 4 else path
    filepath = '/' + parts[4] if len(parts) > 4 else '/'
    return share, os.path.dirname(filepath), os.path.basename(filepath)


def run_cmd(cmd, use_proxy=False, timeout=None):
    if use_proxy:
        cmd = ['proxychains', '-q'] + cmd
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              env={**os.environ, 'PROXYCHAINS_QUIET_MODE': '1'},
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='timed out')


def parse_nxc(source, is_file=True):
    lines = open(source).readlines() if is_file else source.splitlines(keepends=True)
    hostmap = {}
    for line in lines:
        nm = re.search(r'\(name:([^)]+)\)', line)
        dm = re.search(r'\(domain:([^)]+)\)', line)
        im = re.search(r'SMB\s+([\d.]+)', line)
        if im and nm and dm:
            hostmap[im.group(1)] = (nm.group(1).strip() + '.' + dm.group(1).strip()).upper()
    results = []
    for line in lines:
        if 'READ' not in line:
            continue
        im = re.search(r'SMB\s+([\d.]+)', line)
        m = re.search(r'SMB\s+[\d.]+\s+\d+\s+\S+\s+(.+?)\s+READ', line)
        if not im or not m:
            continue
        share = m.group(1).strip()
        if share == 'IPC$':
            continue
        host = hostmap.get(im.group(1), im.group(1))
        results.append('//' + host + '/' + share)
    return results


def resolve_host(host, dns_server):
    """Resolve hostname to IP via a specific DNS server using dig."""
    try:
        result = subprocess.run(
            ['dig', '+short', f'@{dns_server}', host],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in reversed(result.stdout.strip().splitlines()):
                line = line.strip()
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                    return line
    except Exception:
        pass
    return host


def smbclient_ls(share, creds, proxy=False, dns_server=''):
    share_cmd = share
    if dns_server:
        parts = share.split('/', 3)
        if len(parts) >= 3:
            ip = resolve_host(parts[2], dns_server)
            if ip != parts[2]:
                share_cmd = f'//{ip}/{parts[3]}' if len(parts) > 3 else f'//{ip}/'
    result = run_cmd(['smbclient', share_cmd, '-U', creds, '-c', 'recurse;ls'], proxy)
    paths = []
    seen = set()
    current_path = ''
    for line in result.stdout.splitlines():
        if line.startswith('\\'):
            current_path = line.strip()
        elif line.strip():
            m = re.match(r'^  (.+?)\s{2,}(\w+)\s', line)
            if not m:
                continue
            name = m.group(1).strip()
            ftype = m.group(2)
            if name in ('.', '..') or 'blocks' in line or ftype.startswith('D'):
                continue
            full = share + current_path.replace('\\', '/') + '/' + name
            if full not in seen:
                seen.add(full)
                paths.append(full)
    return paths


def run_smblist(shares, creds, outfile=None, proxy=False):
    fh = open(outfile, 'a') if outfile else None
    try:
        for share in shares:
            share = share.strip()
            if not share:
                continue
            for p in smbclient_ls(share, creds, proxy):
                print(p)
                if fh:
                    fh.write(p + '\n')
    finally:
        if fh:
            fh.close()


def download_file(fullpath, creds, proxy=False):
    share, d, fname = parse_smb_path(fullpath)
    print(f'[*] Downloading: {fname}')
    print(f'[*] From: {share}{d}')
    run_cmd(['smbclient', share, '-U', creds, '-c', f'cd "{d}"; get "{fname}"'], proxy)
    if os.path.exists(fname):
        print(f'[+] Saved: {os.getcwd()}/{fname}')
    else:
        print(f'[-] Failed: {fname}')


def run_host(target, creds, user, passwd, domain, proxy=False):
    safe = target.replace('/', '_')
    outfile = f'smblist_{safe}'
    print(f'[*] Running nxc against {target}', file=sys.stderr)
    result = run_cmd(
        ['netexec', 'smb', target, '-u', user, '-p', passwd, '-d', domain, '--shares'],
        proxy
    )
    shares = parse_nxc(result.stdout, is_file=False)
    if not shares:
        print(f'[-] No readable shares found for {target}', file=sys.stderr)
        return
    print(f'[*] Saving to {outfile}', file=sys.stderr)
    open(outfile, 'w').close()
    run_smblist(shares, creds, outfile=outfile, proxy=proxy)
    print(f'[+] Done: {outfile}', file=sys.stderr)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

HTML = """<!DOCTYPE html>
<html><head><meta charset=UTF-8><title>smblist</title>
<style>
:root{
  --bg0:#010409;--bg1:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#2d333b;
  --bd:#30363d;--bd-s:#21262d;
  --tx:#e6edf3;--tx-m:#b1bac4;--tx-s:#9ca3af;--tx-d:#768390;
  --ac:#2f81f7;--ac-m:rgba(47,129,247,.15);--ac-bg:#1a3a6b;--ac-tx:#79b8ff;
  --green:#3fb950;--green-bg:#1a4a2a;
  --yellow:#e3b341;--red:#f85149;--red-bg:#4a1212;
  --ui:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  --mono:'JetBrains Mono','Cascadia Code','Fira Code','Consolas',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--ui);background:var(--bg1);color:var(--tx);height:100vh;display:flex;flex-direction:column;overflow:hidden;font-size:13px}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--bd);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--tx-d)}
/* === toolbar === */
#top{padding:0 14px;border-bottom:1px solid var(--bd-s);display:flex;gap:5px;align-items:center;background:var(--bg2);flex-shrink:0;height:46px;overflow:hidden}
#brand{display:flex;align-items:center;gap:8px;margin-right:6px;flex-shrink:0}
#brand-mark{width:24px;height:24px;border-radius:6px;background:var(--ac);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;color:#fff;letter-spacing:-.05em;flex-shrink:0}
#brand-name{font-size:13px;font-weight:700;color:var(--tx);letter-spacing:-.02em}
.t-sep{width:1px;background:var(--bd-s);height:22px;margin:0 3px;flex-shrink:0}
.t-lbl{font-size:11px;color:var(--tx-d);white-space:nowrap;flex-shrink:0;font-weight:500}
.t-grp{display:flex;align-items:center;gap:4px;flex-shrink:0}
.tbi{background:var(--bg1);border:1px solid var(--bd);color:var(--tx);padding:5px 9px;font-family:var(--ui);font-size:12px;border-radius:6px;outline:none;transition:border-color .15s,box-shadow .15s}
.tbi:focus{border-color:var(--ac);box-shadow:0 0 0 3px var(--ac-m)}
.tbi::placeholder{color:var(--tx-d)}
#manualpath{width:180px}
#hostinput{width:150px}
.btn{background:var(--bg3);border:1px solid var(--bd);color:var(--tx-m);padding:5px 12px;cursor:pointer;font-family:var(--ui);font-size:12px;border-radius:6px;transition:all .15s;white-space:nowrap;flex-shrink:0;font-weight:500}
.btn:hover{background:var(--bg4);border-color:var(--tx-d);color:var(--tx)}
.btn.active{background:var(--ac-bg);border-color:var(--ac);color:var(--ac-tx)}
.btn-accent{background:var(--ac-bg);border-color:var(--ac);color:var(--ac-tx)}
.btn-accent:hover{background:var(--ac);color:#fff}
.btn-file{cursor:pointer}
.cb-lbl{font-size:12px;color:var(--tx-m);display:flex;align-items:center;gap:5px;cursor:pointer;white-space:nowrap;flex-shrink:0;font-weight:500}
.cb-lbl input[type=checkbox]{accent-color:var(--ac);cursor:pointer;width:13px;height:13px}

/* === jobs strip === */
#jobspanel{padding:5px 14px;border-bottom:1px solid var(--bd-s);background:var(--bg0);flex-shrink:0;display:none;flex-wrap:wrap;gap:6px;align-items:center}
.jlbl{font-size:11px;color:var(--tx-d);font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.job{font-size:11px;padding:2px 10px;border-radius:20px;border:1px solid var(--bd-s);background:var(--bg2);display:inline-flex;align-items:center;gap:6px}
.jhost{color:var(--ac-tx);font-weight:600}
.jstat{color:var(--tx-d)}
.jstat.active{color:var(--yellow)}
.jstat.done{color:var(--green)}
.jstat.error{color:var(--red)}
.jcount{color:var(--green);font-size:10px}
.jnote{color:var(--red);font-size:10px}
.jcur{color:var(--tx-d);font-size:10px;font-family:var(--mono);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.spinner{display:inline-block;width:9px;height:9px;border:1.5px solid var(--bd);border-top-color:var(--ac);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

#main{display:flex;flex:1;overflow:hidden;min-height:0}

/* === host tree === */
#hosttree{width:230px;border-right:1px solid var(--bd-s);display:flex;flex-direction:column;flex-shrink:0;background:var(--bg2);min-width:120px}
#treeheader{padding:10px 12px 8px;border-bottom:1px solid var(--bd-s);flex-shrink:0;display:flex;align-items:center;justify-content:space-between}
#treeheader span{font-size:10px;font-weight:700;color:var(--tx-d);letter-spacing:.1em;text-transform:uppercase}
#treeheader button{background:none;border:1px solid var(--bd);color:var(--tx-d);padding:3px 9px;cursor:pointer;font-family:var(--ui);font-size:11px;border-radius:5px;font-weight:500;transition:all .15s}
#treeheader button:hover{border-color:var(--ac);color:var(--ac-tx)}
#treebody{flex:1;overflow-y:auto;padding:4px 0}
.tall{padding:6px 12px;cursor:pointer;font-size:12px;color:var(--tx-d);display:flex;align-items:center;gap:6px;margin:2px 6px;border-radius:6px;font-weight:500;transition:background .1s,color .1s}
.tall:hover{background:var(--bg3);color:var(--tx-m)}
.tall.sel{background:var(--ac-bg);color:var(--ac-tx)}
.tallcount{font-size:11px;color:var(--tx-d);margin-left:auto;font-weight:400;font-family:var(--mono)}
.tall.sel .tallcount{color:var(--ac-tx);opacity:.7}
.tgroup{margin:2px 0}
.tghead{padding:5px 8px 5px 12px;display:flex;align-items:center;gap:5px;cursor:pointer;font-size:12px;color:var(--tx-s);user-select:none;border-radius:6px;margin:1px 6px;transition:background .1s;font-weight:500}
.tghead:hover{background:var(--bg3);color:var(--tx-m)}
.tghead.sel .tgname{color:var(--ac-tx)}
.tghead.dragover{background:rgba(47,129,247,.08);outline:1px dashed rgba(47,129,247,.4);outline-offset:-1px}
.tgcaret{font-size:9px;color:var(--tx-d);width:12px;flex-shrink:0;display:inline-block;transition:transform .15s}
.tgcaret.open{transform:rotate(90deg)}
.tgname{flex:1;overflow:hidden;text-overflow:ellipsis;color:var(--tx-m);font-size:12px}
.tgcount{font-size:10px;color:var(--tx-d);flex-shrink:0;background:var(--bg3);border-radius:10px;padding:1px 6px;border:1px solid var(--bd-s);font-family:var(--mono)}
.tgdots{color:var(--bd);padding:1px 5px;border-radius:4px;flex-shrink:0;font-size:14px;line-height:1;opacity:0;cursor:pointer;transition:opacity .1s}
.tghead:hover .tgdots{opacity:1}
.tgdots:hover{color:var(--tx-m);background:var(--bg4);opacity:1}
.tghosts{padding-left:8px}
.thost{padding:4px 8px 4px 10px;display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px;border-radius:6px;margin:1px 6px;user-select:none;transition:background .1s}
.thost:hover{background:var(--bg3)}
.thost.sel{background:var(--ac-bg)}
.thost.pick{background:rgba(47,129,247,.18);outline:1px solid rgba(47,129,247,.4);outline-offset:-1px}
#treesel{padding:6px 10px;border-bottom:1px solid var(--bd-s);background:var(--bg3);display:none;align-items:center;gap:6px;flex-shrink:0;flex-wrap:wrap}
#treesel span{font-size:11px;color:var(--tx-m);white-space:nowrap}
#treesel select{background:var(--bg1);border:1px solid var(--bd);color:var(--tx);padding:3px 6px;font-size:11px;border-radius:5px;outline:none;cursor:pointer}
#treesel select:focus{border-color:var(--ac)}
.thost.dragging{opacity:.25}
.thdrag{color:var(--bd);font-size:11px;flex-shrink:0;cursor:grab;line-height:1;opacity:0;transition:opacity .1s}
.thost:hover .thdrag{opacity:1}
.thdrag:hover{color:var(--tx-d)}
.thostname{flex:1;color:var(--tx-s);overflow:hidden;text-overflow:ellipsis;font-size:11px;font-family:var(--mono);letter-spacing:-.02em}
.thost.sel .thostname{color:var(--ac-tx)}
.thostcount{font-size:10px;color:var(--tx-d);flex-shrink:0;min-width:24px;text-align:right;font-family:var(--mono)}
.thost.sel .thostcount{color:var(--ac-tx);opacity:.6}
.tugzone{margin:8px 6px 2px;border-radius:6px}
.tugzone.dragover{background:rgba(47,129,247,.05);outline:1px dashed rgba(47,129,247,.3);outline-offset:-1px}
.tuglbl{padding:4px 10px;font-size:10px;color:var(--tx-d);font-weight:700;letter-spacing:.08em;text-transform:uppercase;display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--bd-s);margin-top:2px}

/* === panel dividers === */
#htdiv{width:4px;background:var(--bd-s);cursor:col-resize;flex-shrink:0;transition:background .15s}
#htdiv:hover,#htdiv.drag{background:var(--ac)}
#divider{width:4px;background:var(--bd-s);cursor:col-resize;flex-shrink:0;transition:background .15s}
#divider:hover{background:var(--ac)}

/* === path list === */
#left{width:36%;border-right:1px solid var(--bd-s);display:flex;flex-direction:column;min-height:0;min-width:100px;background:var(--bg1)}
#leftbar{padding:10px 10px 8px;border-bottom:1px solid var(--bd-s);background:var(--bg2);flex-shrink:0;display:flex;flex-direction:column;gap:8px}
.lbl{font-size:10px;font-weight:700;color:var(--tx-d);letter-spacing:.08em;text-transform:uppercase;margin-bottom:3px}
#filterpath{background:var(--bg1);border:1px solid var(--bd);color:var(--tx);padding:5px 9px;font-family:var(--ui);font-size:12px;border-radius:6px;outline:none;width:100%;transition:border-color .15s,box-shadow .15s}
#filterpath:focus{border-color:var(--ac);box-shadow:0 0 0 3px var(--ac-m)}
#filterpath::placeholder{color:var(--tx-d)}
#extbar{display:flex;flex-wrap:wrap;gap:3px;min-height:4px}
.eb{font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer;background:var(--bg3);border:1px solid var(--bd-s);color:var(--tx-d);font-weight:600;transition:all .12s;font-family:var(--mono)}
.eb:hover{background:var(--bg4);color:var(--tx-m);border-color:var(--bd)}
.eb.on{background:var(--ac-bg);border-color:var(--ac);color:var(--ac-tx)}
#pathList{flex:1;overflow-y:auto;position:relative;background:var(--bg1)}
.path{padding:3px 14px;cursor:pointer;font-size:11px;color:var(--tx-s);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;position:absolute;left:0;right:0;font-family:var(--mono);letter-spacing:-.02em;transition:color .08s}
.path:hover{background:var(--bg2);color:var(--tx)}
.path.active{background:var(--ac-bg);color:var(--ac-tx)}

/* === file viewer === */
#right{flex:1;background:var(--bg0);display:flex;flex-direction:column;min-height:0;overflow:hidden;min-width:120px}
#rightbar{padding:7px 12px 6px;border-bottom:1px solid var(--bd-s);background:var(--bg2);flex-shrink:0;display:flex;gap:6px;align-items:center}
#rightbar span{font-size:10px;font-weight:700;color:var(--tx-d);letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}
#filtercontent{flex:1;background:var(--bg1);border:1px solid var(--bd);color:var(--tx);padding:5px 9px;font-family:var(--ui);font-size:12px;border-radius:6px;outline:none;transition:border-color .15s,box-shadow .15s}
#filtercontent:focus{border-color:var(--ac);box-shadow:0 0 0 3px var(--ac-m)}
#filtercontent::placeholder{color:var(--tx-d)}
#header{font-size:11px;color:var(--ac-tx);padding:7px 16px;word-break:break-all;border-bottom:1px solid var(--bd-s);background:var(--bg1);flex-shrink:0;font-family:var(--mono);letter-spacing:-.02em;opacity:.85}
#contentarea{flex:1;overflow-y:auto;padding:16px;min-height:0}
#content{font-size:12px;white-space:pre-wrap;word-break:break-all;color:var(--tx-m);line-height:1.7;margin:0;font-family:var(--mono);letter-spacing:-.01em}
#bottom{padding:10px 14px;border-top:1px solid var(--bd-s);flex-shrink:0;display:none}
.dl-btn{background:var(--green-bg);border:1px solid rgba(63,185,80,.3);color:var(--green);padding:6px 16px;cursor:pointer;font-family:var(--ui);font-size:12px;border-radius:6px;font-weight:500;transition:all .15s}
.dl-btn:hover{background:rgba(63,185,80,.2);border-color:var(--green)}

/* === status bar === */
#status{padding:4px 16px;font-size:11px;color:var(--tx-d);background:var(--bg2);border-top:1px solid var(--bd-s);flex-shrink:0;font-weight:500}
#leftfoot{padding:6px 10px;border-top:1px solid var(--bd-s);background:var(--bg2);flex-shrink:0}

/* === misc === */
.hl{background:rgba(227,179,65,.2);color:var(--yellow);border-radius:2px}
.ok{color:var(--green)}.err{color:var(--red)}

/* === context menu === */
.cmenu{position:fixed;background:var(--bg3);border:1px solid var(--bd);border-radius:8px;padding:4px 0;z-index:9999;min-width:150px;box-shadow:0 8px 30px rgba(0,0,0,.6),0 2px 8px rgba(0,0,0,.4)}
.cmitem{padding:6px 14px;font-size:12px;color:var(--tx-m);cursor:pointer;white-space:nowrap;transition:background .1s,color .1s;font-weight:500}
.cmitem:hover{background:var(--bg4);color:var(--tx)}
.cmitem.sub{color:var(--tx-d);cursor:default;font-size:10px;padding:5px 14px 2px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
.cmitem.danger{color:#a55}
.cmitem.danger:hover{background:var(--red-bg);color:var(--red)}
.cmsep{height:1px;background:var(--bd-s);margin:3px 0}
/* === modal === */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:10000;display:flex;align-items:center;justify-content:center}
.modal{background:var(--bg2);border:1px solid var(--bd);border-radius:10px;padding:20px;width:420px;max-width:90vw;box-shadow:0 16px 48px rgba(0,0,0,.7);display:flex;flex-direction:column;gap:12px}
.modal-title{font-size:13px;font-weight:700;color:var(--tx);letter-spacing:-.01em}
.modal-sub{font-size:11px;color:var(--tx-d)}
.modal textarea{background:var(--bg1);border:1px solid var(--bd);color:var(--tx);padding:8px 10px;font-family:var(--mono);font-size:11px;border-radius:6px;outline:none;resize:vertical;min-height:160px;line-height:1.6;transition:border-color .15s,box-shadow .15s}
.modal textarea:focus{border-color:var(--ac);box-shadow:0 0 0 3px var(--ac-m)}
.modal textarea::placeholder{color:var(--tx-d)}
.modal-foot{display:flex;gap:8px;justify-content:flex-end}
</style></head>
<body>
<div id=hostmodal style="display:none" class=modal-overlay onclick="if(event.target===this)closeHostModal()">
  <div class=modal>
    <div class=modal-title>Scan multiple hosts</div>
    <div class=modal-sub>One host / FQDN / CIDR per line</div>
    <textarea id=hostlist placeholder="host1.domain.com&#10;host2.domain.com&#10;192.168.1.0/24"></textarea>
    <div class=modal-foot>
      <button class=btn onclick=closeHostModal()>cancel</button>
      <button class="btn btn-accent" onclick=submitHostList()>Get Shares</button>
    </div>
  </div>
</div>
<div id=top>
  <div id=brand>
    <div id=brand-mark>sm</div>
    <span id=brand-name>smblist</span>
  </div>
  <div class=t-sep></div>
  <div class=t-grp>
    <span class=t-lbl>From File:</span>
    <label class="btn btn-file">browse<input type=file id=fileInput accept=.txt onchange=loadFile(this) style="display:none"></label>
    <span class=t-lbl>Path:</span>
    <input type=text class=tbi id=manualpath placeholder="or enter file path">
    <button class=btn onclick=loadManual()>Get Path</button>
  </div>
  <div class=t-sep></div>
  <div class=t-grp>
    <span class=t-lbl>Domain:</span>
    <input type=text class=tbi id=hostinput placeholder="FQDN" onkeydown="if(event.key==='Enter')addHost()">
    <button class="btn btn-accent" onclick=addHost()>Get Shares</button>
    <button class=btn onclick=openHostModal() title="Scan a list of hosts">paste list</button>
  </div>
  <div class=t-sep></div>
  <div class=t-grp>
    <span class=t-lbl>DNS:</span>
    <input type=text class=tbi id=dnsinput placeholder="DC IP" style="width:110px" oninput=updateDns()>
  </div>
  <div class=t-sep></div>
  <label class=cb-lbl><input type=checkbox id=useProxy checked> proxychains</label>
  <button class=btn id=fnbtn onclick=toggleFN()>full path</button>
  <button class=btn id=unbtn onclick=toggleUN()>unique names</button>
  <button class=btn onclick=clearRight()>clear</button>
</div>
<div id=jobspanel></div>
<div id=main>
  <div id=hosttree>
    <div id=treeheader>
      <span>hosts</span>
      <button onclick=addGroup()>+ group</button>
    </div>
    <div id=treesel>
      <span id=treeselcount></span>
      <select id=treeseldest></select>
      <button class=btn style="padding:3px 10px;font-size:11px" onclick=addSelectedToGroup()>add to group</button>
      <button class=btn style="padding:3px 8px;font-size:11px" onclick=clearSel()>✕ clear</button>
    </div>
    <div id=treebody></div>
  </div>
  <div id=htdiv></div>
  <div id=left>
    <div id=leftbar>
      <div>
        <div class=lbl>filter paths</div>
        <input type=text id=filterpath placeholder="keyword, keyword  (comma = OR)" oninput=scheduleFilter()>
      </div>
      <div>
        <div class=lbl>file types</div>
        <div id=extbar></div>
      </div>
    </div>
    <div id=pathList></div>
    <div id=leftfoot><button class=dl-btn style="width:100%;font-size:11px;padding:5px" onclick=downloadAll()>download all</button></div>
  </div>
  <div id=divider></div>
  <div id=right>
    <div id=rightbar>
      <span>search content</span>
      <input type=text id=filtercontent placeholder="keyword, keyword  (comma = OR)" oninput=scheduleHL()>
    </div>
    <div id=header>select a file to preview</div>
    <div id=contentarea><pre id=content style="color:var(--tx-d)">select a path from the list to view its contents</pre></div>
    <div id=bottom><button class=dl-btn onclick=dl()>download file</button></div>
  </div>
</div>
<div id=status>0 paths</div>
<script>
const ROW_H=20;
let all=[],cur=null,ft=null,hlt=null,lastContent='',filtered=[],displayed=[],exts=new Set(),fnOnly=false,uniqueNames=false;
let pollTimer=null;
let activeCtrl=null,activeTid=null;
const previewCache=new Map();
const CACHE_MAX=30;
function cachePut(path,data){if(previewCache.size>=CACHE_MAX)previewCache.delete(previewCache.keys().next().value);previewCache.set(path,data);}
function showPreview(d){
  const c=document.getElementById('content');
  if(d.ok){
    lastContent=d.content;c.innerHTML=hl(d.content);hitcount(d.content);
    if(d.truncated){
      const w=document.createElement('div');w.id='trunc-warn';
      w.style.cssText='color:var(--yellow);font-size:11px;margin-bottom:10px;font-family:var(--ui)';
      w.textContent='[preview truncated at 512 KB — use download to get the full file]';
      document.getElementById('contentarea').prepend(w);
    }
  } else {c.textContent=d.msg;}
  document.getElementById('bottom').style.display='block';
}

// tree state — groups store hostnames, not job ids
let groups=[];        // [{id,name,hostnames:[],collapsed:bool}]
let selectedHosts=new Set(),lastSelHost=null;
let activeFilter=null; // null | {type:'host',hostname} | {type:'group',groupId}
let allPaths=[];
let allJobs={};
let dragState=null;   // {hostname, sourceGroupId}  (null = ungrouped)

function saveGroups(){try{localStorage.setItem('smblist_g',JSON.stringify(groups));}catch(e){}}
function loadGroups(){try{groups=JSON.parse(localStorage.getItem('smblist_g')||'[]');}catch(e){groups=[];}}

// extract unique hostnames from paths in sorted order
function hostsFromPaths(paths){
  const s=new Set();
  paths.forEach(p=>{const m=p.match(/^\/\/([^/]+)/);if(m)s.add(m[1]);});
  return [...s].sort();
}

function ungroupedHosts(hosts){
  const inGroup=new Set(groups.flatMap(g=>g.hostnames));
  return hosts.filter(h=>!inGroup.has(h));
}

// ── init ──
loadGroups();
function loadPaths(){fetch('/paths').then(r=>r.json()).then(d=>{allPaths=d;all=d;exts.clear();go();renderTree();});}
loadPaths();
fetch('/jobs').then(r=>r.json()).then(d=>{
  allJobs=d;renderJobs(d);
  if(Object.values(d).some(j=>j.status!=='done'&&j.status!=='error'))startPolling();
});

// ── file loading ──
function loadFile(inp){
  const f=inp.files[0];if(!f)return;
  const r=new FileReader();
  r.onload=ev=>{
    allPaths=ev.target.result.split('\\n').map(l=>l.trim()).filter(Boolean);
    activeFilter=null;all=allPaths;exts.clear();go();renderTree();
  };
  r.readAsText(f);
}
function loadManual(){
  const p=document.getElementById('manualpath').value.trim();if(!p)return;
  fetch('/loadfile?path='+encodeURIComponent(p)).then(r=>r.json()).then(d=>{
    if(d.ok){allPaths=d.paths;activeFilter=null;all=allPaths;exts.clear();go();renderTree();}
    else document.getElementById('status').innerHTML='<span class=err>[-] '+d.msg+'</span>';
  });
}

// ── host scanning ──
function dnsVal(){return document.getElementById('dnsinput').value.trim();}
function updateDns(){fetch('/setdns?dns='+encodeURIComponent(dnsVal()));}
function addHost(){
  const h=document.getElementById('hostinput').value.trim();if(!h)return;
  fetch('/addhost?host='+encodeURIComponent(h)+'&proxy='+proxy()+'&dns='+encodeURIComponent(dnsVal()))
    .then(r=>r.json()).then(d=>{
      if(d.ok){document.getElementById('hostinput').value='';startPolling();poll();}
      else if(d.skip)document.getElementById('status').innerHTML='<span class=err>[!] '+esc(d.msg)+'</span>';
      else document.getElementById('status').innerHTML='<span class=err>[-] '+esc(d.msg)+'</span>';
    });
}
function openHostModal(){
  document.getElementById('hostmodal').style.display='flex';
  document.getElementById('hostlist').focus();
}
function closeHostModal(){
  document.getElementById('hostmodal').style.display='none';
  document.getElementById('hostlist').value='';
}
function submitHostList(){
  const hosts=document.getElementById('hostlist').value
    .split(/[\\n,]+/).map(h=>h.trim()).filter(Boolean);
  if(!hosts.length)return;
  closeHostModal();
  document.getElementById('status').textContent='[*] queuing '+hosts.length+' host(s)...';
  let queued=0,skipped=0,pollingStarted=false;
  function next(i){
    if(i>=hosts.length){
      const parts=[];
      if(queued>0)parts.push(queued+' queued');
      if(skipped>0)parts.push(skipped+' already scanned');
      if(parts.length)document.getElementById('status').textContent='[*] '+parts.join(', ');
      return;
    }
    fetch('/addhost?host='+encodeURIComponent(hosts[i])+'&proxy='+proxy()+'&dns='+encodeURIComponent(dnsVal()))
      .then(r=>r.json()).then(d=>{
        if(d.ok){
          queued++;
          if(!pollingStarted){pollingStarted=true;startPolling();poll();}
        } else if(d.skip){skipped++;}
        next(i+1);
      });
  }
  next(0);
}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeHostModal();});

// ── polling ──
function startPolling(){if(pollTimer)return;pollTimer=setInterval(poll,2000);}
function stopPolling(){if(pollTimer){clearInterval(pollTimer);pollTimer=null;}}
function poll(){
  Promise.all([
    fetch('/paths').then(r=>r.json()),
    fetch('/jobs').then(r=>r.json())
  ]).then(([newPaths,jobdata])=>{
    allJobs=jobdata;allPaths=newPaths;
    renderJobs(jobdata);renderTree();
    if(activeFilter){applyFilter();}
    else{all=newPaths;go();}
    const anyActive=Object.values(jobdata).some(j=>j.status!=='done'&&j.status!=='error');
    if(!anyActive&&Object.keys(jobdata).length>0){stopPolling();all=allPaths;go();renderTree();}
  });
}

// ── jobs panel ──
let _lastJobNotes={};
function renderJobs(jobdata){
  const panel=document.getElementById('jobspanel');
  const active=Object.values(jobdata).filter(j=>j.status!=='done'&&j.status!=='error');
  // surface notes from newly-finished jobs in the status bar
  Object.values(jobdata).forEach(j=>{
    if((j.status==='done'||j.status==='error')&&j.note&&!_lastJobNotes[j.host]){
      _lastJobNotes[j.host]=j.note;
      const cls=j.status==='error'?'err':'err';
      document.getElementById('status').innerHTML=
        `<span class=${cls}>[!] ${esc(j.host)}: ${esc(j.note)}</span>`;
    }
  });
  if(!active.length){panel.style.display='none';return;}
  panel.style.display='flex';
  panel.innerHTML='<span class=jlbl>scanning:</span>'+active.map(j=>{
    const spin='<span class=spinner></span>';
    const count=j.found>0?`<span class=jcount>${j.found} paths</span>`:'';
    const cur=j.current?`<span class=jcur title="${esc(j.current)}">${esc(j.current.split('/').pop()||j.current)}</span>`:'';
    return `<span class=job>${spin}<span class=jhost>${esc(j.host)}</span><span class="jstat active">${esc(j.status)}</span>${count}${cur}</span>`;
  }).join('');
}

// ── tree rendering ──
function renderTree(){
  const hosts=hostsFromPaths(allPaths);
  const ug=ungroupedHosts(hosts);
  const body=document.getElementById('treebody');
  body.innerHTML='';

  // all
  const allEl=document.createElement('div');
  allEl.className='tall'+(activeFilter===null?' sel':'');
  allEl.innerHTML='all <span class=tallcount>('+allPaths.length+')</span>';
  allEl.onclick=()=>setFilter(null);
  body.appendChild(allEl);

  // named groups
  groups.forEach(g=>body.appendChild(makeGroupEl(g)));

  // ungrouped drop zone + host list
  if(hosts.length>0){
    body.appendChild(makeUngroupedEl(ug));
  }
}

function makeGroupEl(group){
  const wrap=document.createElement('div');
  wrap.className='tgroup';

  const isSel=activeFilter&&activeFilter.type==='group'&&activeFilter.groupId===group.id;
  const head=document.createElement('div');
  head.className='tghead'+(isSel?' sel':'');

  // drop target
  head.addEventListener('dragover',e=>{e.preventDefault();head.classList.add('dragover');});
  head.addEventListener('dragleave',()=>head.classList.remove('dragover'));
  head.addEventListener('drop',e=>{e.preventDefault();head.classList.remove('dragover');dropOnGroup(group.id);});

  const caret=document.createElement('span');
  caret.className='tgcaret'+(group.collapsed?'':' open');
  caret.textContent='▶';

  const nm=document.createElement('span');
  nm.className='tgname';nm.textContent=group.name;

  const cnt=document.createElement('span');
  cnt.className='tgcount';cnt.textContent='('+group.hostnames.length+')';

  const dots=document.createElement('span');
  dots.className='tgdots';dots.textContent='⋮';
  dots.onclick=e=>{e.stopPropagation();showGroupMenu(e,group.id);};

  head.appendChild(caret);head.appendChild(nm);head.appendChild(cnt);head.appendChild(dots);

  const bodyEl=document.createElement('div');
  bodyEl.className='tghosts';
  bodyEl.style.display=group.collapsed?'none':'block';

  head.onclick=e=>{
    if(e.target===dots||e.target.classList.contains('tgdots'))return;
    group.collapsed=!group.collapsed;
    caret.className='tgcaret'+(group.collapsed?'':' open');
    bodyEl.style.display=group.collapsed?'none':'block';
    saveGroups();
    if(!group.collapsed)setFilter({type:'group',groupId:group.id});
  };

  group.hostnames.forEach(h=>{
    const pathCount=allPaths.filter(p=>p.startsWith('//'+h+'/')).length;
    bodyEl.appendChild(makeHostEl(h,pathCount,group.id));
  });

  wrap.appendChild(head);wrap.appendChild(bodyEl);
  return wrap;
}

function makeUngroupedEl(hosts){
  const wrap=document.createElement('div');
  wrap.className='tugzone';

  // label row — also a drop target for moving hosts back to ungrouped
  const lbl=document.createElement('div');
  lbl.className='tuglbl';
  lbl.innerHTML='<span>ungrouped</span><span style="color:#1e3e1e">'+hosts.length+'</span>';
  lbl.addEventListener('dragover',e=>{e.preventDefault();wrap.classList.add('dragover');});
  lbl.addEventListener('dragleave',()=>wrap.classList.remove('dragover'));
  lbl.addEventListener('drop',e=>{e.preventDefault();wrap.classList.remove('dragover');dropOnGroup(null);});
  wrap.appendChild(lbl);

  hosts.forEach(h=>{
    const pathCount=allPaths.filter(p=>p.startsWith('//'+h+'/')).length;
    wrap.appendChild(makeHostEl(h,pathCount,null));
  });
  return wrap;
}

function clearSel(){selectedHosts.clear();lastSelHost=null;updateSelBar();renderTree();}
function updateSelBar(){
  const bar=document.getElementById('treesel');
  if(selectedHosts.size===0){bar.style.display='none';return;}
  bar.style.display='flex';
  document.getElementById('treeselcount').textContent=selectedHosts.size+' host'+(selectedHosts.size>1?'s':'')+' selected';
  const sel=document.getElementById('treeseldest');
  sel.innerHTML=groups.map(g=>`<option value="${g.id}">${esc(g.name)}</option>`).join('')
    +'<option value="__new__">+ new group</option>';
}
function addSelectedToGroup(){
  const sel=document.getElementById('treeseldest');
  let gid=sel.value;
  if(gid==='__new__'){
    const name=prompt('Group name:');
    if(!name||!name.trim())return;
    gid='g'+Date.now();
    groups.push({id:gid,name:name.trim().toUpperCase(),hostnames:[],collapsed:false});
  }
  const g=groups.find(x=>x.id===gid);
  if(!g)return;
  selectedHosts.forEach(h=>{
    groups.forEach(gr=>{gr.hostnames=gr.hostnames.filter(x=>x!==h);});
    if(!g.hostnames.includes(h))g.hostnames.push(h);
  });
  saveGroups();clearSel();
}

function makeHostEl(hostname,pathCount,sourceGroupId){
  const isSel=activeFilter&&activeFilter.type==='host'&&activeFilter.hostname===hostname;
  const isPick=selectedHosts.has(hostname);
  const div=document.createElement('div');
  div.className='thost'+(isSel?' sel':'')+(isPick?' pick':'');
  div.draggable=true;

  div.addEventListener('dragstart',e=>{
    dragState={hostname,sourceGroupId};
    e.dataTransfer.effectAllowed='move';
    e.dataTransfer.setData('text/plain',hostname);
    setTimeout(()=>div.classList.add('dragging'),0);
  });
  div.addEventListener('dragend',()=>{div.classList.remove('dragging');});
  div.onclick=e=>{
    if(e.shiftKey){
      const allH=hostsFromPaths(allPaths);
      const curIdx=allH.indexOf(hostname);
      const lastIdx=lastSelHost?allH.indexOf(lastSelHost):curIdx;
      const lo=Math.min(curIdx,lastIdx),hi=Math.max(curIdx,lastIdx);
      for(let i=lo;i<=hi;i++)selectedHosts.add(allH[i]);
      lastSelHost=hostname;
      updateSelBar();renderTree();
    } else {
      if(selectedHosts.size>0){clearSel();return;}
      setFilter({type:'host',hostname});
    }
  };

  const drag=document.createElement('span');
  drag.className='thdrag';drag.textContent='⠿';

  const nm=document.createElement('span');
  nm.className='thostname';nm.title=hostname;nm.textContent=hostname;

  const cnt=document.createElement('span');
  cnt.className='thostcount';cnt.textContent=pathCount||'';

  div.appendChild(drag);div.appendChild(nm);div.appendChild(cnt);
  return div;
}

// ── drag / drop ──
function dropOnGroup(targetGroupId){
  if(!dragState)return;
  const{hostname,sourceGroupId}=dragState;
  dragState=null;
  if(sourceGroupId===targetGroupId)return;

  // remove from source group
  if(sourceGroupId!==null){
    const src=groups.find(g=>g.id===sourceGroupId);
    if(src)src.hostnames=src.hostnames.filter(h=>h!==hostname);
  }
  // add to target group
  if(targetGroupId!==null){
    const tgt=groups.find(g=>g.id===targetGroupId);
    if(tgt&&!tgt.hostnames.includes(hostname))tgt.hostnames.push(hostname);
  }
  saveGroups();renderTree();
  if(activeFilter)applyFilter();
}

// ── filter ──
function setFilter(f){
  activeFilter=f;exts.clear();renderTree();applyFilter();
}

function applyFilter(){
  if(!activeFilter){all=allPaths;go();return;}
  if(activeFilter.type==='host'){
    all=allPaths.filter(p=>p.startsWith('//'+activeFilter.hostname+'/'));
  } else if(activeFilter.type==='group'){
    const g=groups.find(x=>x.id===activeFilter.groupId);
    if(!g){activeFilter=null;all=allPaths;go();return;}
    all=allPaths.filter(p=>g.hostnames.some(h=>p.startsWith('//'+h+'/')));
  }
  go();
}

// ── group management ──
function addGroup(){
  const name=prompt('Group name:');
  if(!name||!name.trim())return;
  groups.push({id:'g'+Date.now(),name:name.trim().toUpperCase(),hostnames:[],collapsed:false});
  saveGroups();renderTree();
}
function renameGroup(id){
  const g=groups.find(x=>x.id===id);if(!g)return;
  const name=prompt('Rename:',g.name);
  if(!name||!name.trim())return;
  g.name=name.trim().toUpperCase();saveGroups();renderTree();
}
function deleteGroup(id){
  groups=groups.filter(x=>x.id!==id);
  if(activeFilter&&activeFilter.type==='group'&&activeFilter.groupId===id){
    activeFilter=null;all=allPaths;go();
  }
  saveGroups();renderTree();
}

// ── context menu ──
function closeMenu(){const m=document.getElementById('_cm');if(m)m.remove();}
document.addEventListener('click',closeMenu);

function posMenu(menu,e){
  document.body.appendChild(menu);
  const r=menu.getBoundingClientRect();
  let x=e.clientX,y=e.clientY;
  if(x+r.width>window.innerWidth)x=e.clientX-r.width;
  if(y+r.height>window.innerHeight)y=e.clientY-r.height;
  menu.style.left=x+'px';menu.style.top=y+'px';
}
function mkItem(text,cls,cb){
  const d=document.createElement('div');
  d.className='cmitem'+(cls?' '+cls:'');d.textContent=text;
  if(cb)d.onclick=()=>{closeMenu();cb();};return d;
}
function mkSep(){const d=document.createElement('div');d.className='cmsep';return d;}

function showGroupMenu(e,groupId){
  closeMenu();
  const menu=document.createElement('div');
  menu.className='cmenu';menu.id='_cm';
  menu.appendChild(mkItem('rename','',()=>renameGroup(groupId)));
  menu.appendChild(mkSep());
  menu.appendChild(mkItem('delete group','danger',()=>deleteGroup(groupId)));
  e.stopPropagation();posMenu(menu,e);
}

// ── resizable panels ──
(()=>{
  const dv=document.getElementById('htdiv'),ht=document.getElementById('hosttree');
  let drag=false,sx=0,sw=0;
  dv.addEventListener('mousedown',e=>{drag=true;sx=e.clientX;sw=ht.offsetWidth;dv.classList.add('drag');document.body.style.cssText='cursor:col-resize;user-select:none';});
  document.addEventListener('mousemove',e=>{if(!drag)return;ht.style.width=Math.max(100,Math.min(sw+e.clientX-sx,400))+'px';});
  document.addEventListener('mouseup',()=>{drag=false;dv.classList.remove('drag');document.body.style.cssText='';});
})();
(()=>{
  const dv=document.getElementById('divider'),lf=document.getElementById('left');
  let drag=false,sx=0,sw=0;
  dv.addEventListener('mousedown',e=>{drag=true;sx=e.clientX;sw=lf.offsetWidth;document.body.style.cssText='cursor:col-resize;user-select:none';});
  document.addEventListener('mousemove',e=>{if(!drag)return;lf.style.width=Math.max(100,Math.min(sw+e.clientX-sx,window.innerWidth-200))+'px';lf.style.flex='none';});
  document.addEventListener('mouseup',()=>{drag=false;document.body.style.cssText='';});
})();

// ── path list ──
function getExt(p){const m=p.match(/\\.([a-zA-Z0-9]+)$/);return m?m[1].toLowerCase():null;}
function go(){
  const val=document.getElementById('filterpath').value.trim();
  let tf=all;
  if(val){const terms=val.toLowerCase().split(',').map(t=>t.trim()).filter(Boolean);tf=all.filter(p=>terms.some(t=>p.toLowerCase().includes(t)));}
  rebuildExts(tf);
  filtered=exts.size>0?tf.filter(p=>{const e=getExt(p);return e&&exts.has(e);}):tf;
  render(filtered);
}
function rebuildExts(paths){
  const counts={};
  paths.forEach(p=>{const e=getExt(p);if(e)counts[e]=(counts[e]||0)+1;});
  const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  const bar=document.getElementById('extbar');bar.innerHTML='';
  sorted.forEach(([ext,cnt])=>{
    const b=document.createElement('span');
    b.className='eb'+(exts.has(ext)?' on':'');
    b.textContent='.'+ext;b.title=cnt+' files';
    b.onclick=()=>{if(exts.has(ext))exts.delete(ext);else exts.add(ext);b.classList.toggle('on',exts.has(ext));go();};
    bar.appendChild(b);
  });
}
function scheduleFilter(){clearTimeout(ft);exts.clear();ft=setTimeout(go,150);}
function scheduleHL(){clearTimeout(hlt);hlt=setTimeout(()=>{if(lastContent){document.getElementById('content').innerHTML=hl(lastContent);hitcount(lastContent);}},150);}
function toggleFN(){
  fnOnly=!fnOnly;
  const b=document.getElementById('fnbtn');
  b.textContent=fnOnly?'filename only':'full path';
  b.classList.toggle('active',fnOnly);render(filtered);
}
function toggleUN(){
  uniqueNames=!uniqueNames;
  document.getElementById('unbtn').classList.toggle('active',uniqueNames);
  render(filtered);
}
function render(paths){
  if(uniqueNames){
    const seen=new Set();
    displayed=paths.filter(p=>{const n=(p.split('/').pop()||p).toLowerCase();return seen.has(n)?false:(seen.add(n),true);});
  } else {
    displayed=paths;
  }
  const suffix=(uniqueNames?' \u2192 '+displayed.length+' unique':'')+(activeFilter?' \u25b6 filtered':'');
  document.getElementById('status').textContent=paths.length+' / '+all.length+' paths'+suffix;
  const list=document.getElementById('pathList');list.innerHTML='';
  if(!displayed.length)return;
  const spacer=document.createElement('div');
  spacer.style.height=(displayed.length*ROW_H)+'px';spacer.style.position='relative';
  list.appendChild(spacer);
  let lastStart=-1;
  function paint(){
    const scrollTop=list.scrollTop;
    const visible=Math.ceil(list.clientHeight/ROW_H);
    const start=Math.max(0,Math.floor(scrollTop/ROW_H)-5);
    const end=Math.min(displayed.length,start+visible+10);
    if(start===lastStart)return;lastStart=start;
    spacer.querySelectorAll('.path').forEach(e=>e.remove());
    for(let i=start;i<end;i++){
      const p=displayed[i];
      const d=document.createElement('div');
      d.className='path';d.title=p;
      d.textContent=fnOnly?(p.split('/').pop()||p):p;
      d.style.top=(i*ROW_H)+'px';d.dataset.idx=i;
      d.addEventListener('click',function(){sel(this,displayed[+this.dataset.idx]);});
      spacer.appendChild(d);
    }
  }
  list.onscroll=paint;paint();requestAnimationFrame(()=>{lastStart=-1;paint();});
}
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function escRe(s){return s.replace(/[.*+?^${}()|[\\]\\\\]/g,'\\\\$&');}
function hl(text){
  const val=document.getElementById('filtercontent').value.trim();
  let r=esc(text);if(!val)return r;
  val.split(',').map(t=>t.trim()).filter(Boolean).forEach(t=>{
    r=r.replace(new RegExp(escRe(esc(t)),'gi'),m=>'<span class=hl>'+m+'</span>');
  });
  return r;
}
function hitcount(text){
  const val=document.getElementById('filtercontent').value.trim();
  const rb=document.getElementById('rightbar');
  const old=rb.querySelector('.hc');if(old)old.remove();
  if(!val)return;
  let total=0;
  val.split(',').map(t=>t.trim()).filter(Boolean).forEach(t=>{
    const m=esc(text).match(new RegExp(escRe(esc(t)),'gi'));if(m)total+=m.length;
  });
  if(total>0){
    const s=document.createElement('span');s.className='hc';
    s.style.cssText='font-size:10px;color:#ff8;margin-left:4px;white-space:nowrap';
    s.textContent=total+' match'+(total===1?'':'es');rb.appendChild(s);
  }
}
function proxy(){return document.getElementById('useProxy').checked?1:0;}
function sel(el,path){
  // abort any in-flight request
  if(activeCtrl){clearTimeout(activeTid);activeCtrl.abort();activeCtrl=null;activeTid=null;}
  document.querySelectorAll('.path').forEach(e=>e.classList.remove('active'));
  el.classList.add('active');cur=path;
  document.getElementById('header').textContent=path;
  document.getElementById('bottom').style.display='none';
  const oldWarn=document.getElementById('trunc-warn');if(oldWarn)oldWarn.remove();
  lastContent='';
  // serve from cache if available
  if(previewCache.has(path)){showPreview(previewCache.get(path));return;}
  document.getElementById('content').textContent='loading...';
  activeCtrl=new AbortController();
  activeTid=setTimeout(()=>{if(activeCtrl)activeCtrl.abort();},35000);
  fetch('/cat?path='+encodeURIComponent(path)+'&proxy='+proxy(),{signal:activeCtrl.signal})
    .then(r=>r.json()).then(d=>{
      clearTimeout(activeTid);activeCtrl=null;activeTid=null;
      if(d.ok)cachePut(path,d);
      showPreview(d);
    }).catch(e=>{
      clearTimeout(activeTid);activeCtrl=null;activeTid=null;
      const c=document.getElementById('content');
      c.textContent=e.name==='AbortError'?'timed out reading file — use download to get it':'error reading file';
      document.getElementById('bottom').style.display='block';
    });
}
function dl(){
  if(!cur)return;
  document.getElementById('status').textContent='[*] downloading: '+cur;
  fetch('/download?path='+encodeURIComponent(cur)+'&proxy='+proxy())
    .then(r=>r.json()).then(d=>{
      document.getElementById('status').innerHTML=d.ok?'<span class=ok>[+] saved: '+d.msg+'</span>':'<span class=err>[-] failed: '+d.msg+'</span>';
    });
}
function downloadAll(){
  if(!displayed.length){document.getElementById('status').textContent='nothing to download';return;}
  const n=displayed.length;
  document.getElementById('status').textContent='[*] queuing '+n+' file(s) for download...';
  fetch('/downloadall',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({paths:displayed,proxy:proxy()===1})
  }).then(r=>r.json()).then(d=>{
    const s=document.getElementById('status');
    if(d.ok){
      const hosts=[...new Set(displayed.map(p=>{const m=p.match(/^\/\/([^/]+)/);return m?m[1]:null;}).filter(Boolean))];
      s.innerHTML='<span class=ok>[+] downloading '+d.count+' file(s) \u2192 smblist/'+esc(hosts.join(', smblist/'))+'/</span>';
    }
    else s.innerHTML='<span class=err>[-] '+esc(d.msg)+'</span>';
  });
}
function clearRight(){
  cur=null;lastContent='';
  document.getElementById('header').textContent='select a path';
  document.getElementById('content').textContent='click a path to view its contents';
  document.getElementById('bottom').style.display='none';
  const old=document.getElementById('rightbar').querySelector('.hc');if(old)old.remove();
}
</script></body></html>"""


def start_gui(creds, pathsfile=''):
    domain, user, passwd = parse_creds(creds)

    live_paths = []
    paths_lock = threading.Lock()
    jobs = {}
    dns_server = ['']   # mutable so handlers can update it
    jobs_lock = threading.Lock()
    job_counter = [0]

    if pathsfile and os.path.exists(pathsfile):
        with open(pathsfile) as f:
            live_paths = [l.strip() for l in f if l.strip()]
    else:
        # auto-load any smblist_* files in cwd
        seen = set()
        for fname in sorted(os.listdir('.')):
            if fname.startswith('smblist_') and os.path.isfile(fname):
                try:
                    with open(fname) as f:
                        for line in f:
                            p = line.strip()
                            if p and p not in seen:
                                seen.add(p)
                                live_paths.append(p)
                    print(f'[*] auto-loaded: {fname} ({len(live_paths)} paths total)', file=sys.stderr)
                except Exception:
                    pass

    def bg_run_host(job_id, host, use_proxy, dns=''):
        def setstatus(s):
            with jobs_lock:
                jobs[job_id]['status'] = s
        try:
            setstatus('running nxc')
            nxc_cmd = ['netexec', 'smb', host, '-u', user, '-p', passwd, '-d', domain, '--shares']
            if dns:
                nxc_cmd += ['--dns-server', dns]
            result = run_cmd(nxc_cmd, use_proxy)
            shares = parse_nxc(result.stdout, is_file=False)
            if not shares:
                # extract a useful error note from nxc output
                note = 'no readable shares'
                combined = (result.stderr + result.stdout).lower()
                if 'connection' in combined and ('refused' in combined or 'timed out' in combined or 'reset' in combined):
                    note = 'connection failed'
                elif 'name or service not known' in combined or 'resolve' in combined or 'dns' in combined:
                    note = 'DNS resolution failed — set DNS server'
                elif result.returncode != 0 and result.stderr.strip():
                    note = result.stderr.strip().splitlines()[-1][:60]
                with jobs_lock:
                    jobs[job_id]['status'] = 'done'
                    jobs[job_id]['note'] = note
                return

            safe = re.sub(r'[/\\:]', '_', host)
            outfile = f'smblist_{safe}'
            open(outfile, 'w').close()

            setstatus(f'enumerating {len(shares)} share(s)')
            with open(outfile, 'a') as fh:
                for share in shares:
                    new_paths = smbclient_ls(share, creds, use_proxy, dns_server=dns)
                    if new_paths:
                        with paths_lock:
                            live_paths.extend(new_paths)
                        with jobs_lock:
                            jobs[job_id]['found'] += len(new_paths)
                            jobs[job_id]['current'] = new_paths[-1]
                        fh.write('\n'.join(new_paths) + '\n')
                        fh.flush()

            setstatus('done')
        except Exception as e:
            with jobs_lock:
                jobs[job_id]['status'] = 'error'
                jobs[job_id]['note'] = str(e)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def send_json(self, data):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-cache, no-store')
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())

        def do_GET(self):
            p = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(p.query)
            use_proxy = qs.get('proxy', ['0'])[0] == '1'

            if p.path == '/':
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Cache-Control', 'no-cache, no-store')
                self.end_headers()
                self.wfile.write(HTML.encode())

            elif p.path == '/paths':
                with paths_lock:
                    snapshot = list(dict.fromkeys(live_paths))
                self.send_json(snapshot)

            elif p.path == '/jobs':
                with jobs_lock:
                    snapshot = dict(jobs)
                self.send_json(snapshot)

            elif p.path == '/setdns':
                dns_server[0] = qs.get('dns', [''])[0].strip()
                self.send_json({'ok': True})

            elif p.path == '/addhost':
                host = qs.get('host', [''])[0].strip()
                dns = qs.get('dns', [''])[0].strip() or dns_server[0]
                if dns:
                    dns_server[0] = dns
                if not host:
                    self.send_json({'ok': False, 'msg': 'no host provided'})
                    return
                # only block if a job is currently active (queued/running)
                with jobs_lock:
                    active_job = any(
                        j['host'].lower() == host.lower() and
                        j['status'] not in ('done', 'error')
                        for j in jobs.values()
                    )
                if active_job:
                    self.send_json({'ok': False, 'msg': f'{host} is already being scanned', 'skip': True})
                    return
                with jobs_lock:
                    job_counter[0] += 1
                    job_id = str(job_counter[0])
                    jobs[job_id] = {'host': host, 'status': 'queued', 'found': 0, 'note': '', 'current': ''}
                threading.Thread(
                    target=bg_run_host, args=(job_id, host, use_proxy, dns), daemon=True
                ).start()
                self.send_json({'ok': True, 'id': job_id})

            elif p.path == '/loadfile':
                path = qs.get('path', [''])[0]
                try:
                    with open(path) as f:
                        loaded = [l.strip() for l in f if l.strip()]
                    self.send_json({'ok': True, 'paths': loaded})
                except Exception as e:
                    self.send_json({'ok': False, 'msg': str(e)})

            elif p.path == '/cat':
                path = qs.get('path', [''])[0]
                share, d, fname = parse_smb_path(path)
                filepath = d.rstrip('/') + '/' + fname if fname else d
                tmppath = f'/tmp/smblist_preview_{threading.get_ident()}'
                result = run_cmd(
                    ['smbclient', share, '-U', creds, '-c',
                     f'get "{filepath}" {tmppath}'],
                    use_proxy, timeout=30
                )
                try:
                    CAP = 512 * 1024
                    with open(tmppath, 'rb') as f:
                        raw = f.read(CAP + 1)
                    os.remove(tmppath)
                    truncated = len(raw) > CAP
                    content = raw[:CAP].decode('utf-8', errors='replace')
                    self.send_json({'ok': True, 'content': content, 'truncated': truncated})
                except:
                    try: os.remove(tmppath)
                    except: pass
                    self.send_json({'ok': False,
                                    'msg': result.stderr.strip() or 'could not read file'})

            elif p.path == '/download':
                path = qs.get('path', [''])[0]
                share, d, fname = parse_smb_path(path)
                result = run_cmd(
                    ['smbclient', share, '-U', creds, '-c', f'cd "{d}"; get "{fname}"'],
                    use_proxy
                )
                if os.path.exists(fname):
                    self.send_json({'ok': True, 'msg': fname})
                else:
                    self.send_json({'ok': False, 'msg': result.stderr.strip()})

            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            p = urllib.parse.urlparse(self.path)
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length) or b'{}')

            if p.path == '/downloadall':
                paths = body.get('paths', [])
                use_proxy = bool(body.get('proxy', False))
                if not paths:
                    self.send_json({'ok': False, 'msg': 'no paths'})
                    return

                def do_dl_all():
                    for path in paths:
                        try:
                            share, d, fname = parse_smb_path(path)
                            if not fname:
                                continue
                            filepath = d.rstrip('/') + '/' + fname
                            host = path.split('/')[2] if len(path.split('/')) > 2 else 'unknown'
                            local_dir = os.path.join('smblist', host)
                            os.makedirs(local_dir, exist_ok=True)
                            local_path = os.path.join(local_dir, fname)
                            run_cmd(['smbclient', share, '-U', creds, '-c',
                                     f'get "{filepath}" {local_path}'], use_proxy)
                        except Exception:
                            pass

                threading.Thread(target=do_dl_all, daemon=True).start()
                self.send_json({'ok': True, 'count': len(paths)})
            else:
                self.send_response(404)
                self.end_headers()

    port = 18888
    print(f'[*] smblist gui at http://127.0.0.1:{port}')
    print('[*] ctrl+c to stop')
    threading.Timer(1, lambda: webbrowser.open(f'http://127.0.0.1:{port}')).start()
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def usage():
    print(__doc__)
    sys.exit(1)


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        usage()

    if sys.argv[1] == '-nxc':
        if len(sys.argv) < 3:
            usage()
        for s in parse_nxc(sys.argv[2]):
            print(s)
        return

    creds = sys.argv[1]
    args = sys.argv[2:]
    domain, user, passwd = parse_creds(creds)

    outfile = None
    if '-o' in args:
        idx = args.index('-o')
        outfile = args[idx + 1]
        args = [a for i, a in enumerate(args) if i != idx and i != idx + 1]
        open(outfile, 'w').close()

    if not args:
        shares = [l.strip() for l in sys.stdin if l.strip()]
        run_smblist(shares, creds, outfile=outfile)

    elif args[0] == '-gui':
        pathsfile = args[1] if len(args) > 1 else ''
        start_gui(creds, pathsfile)

    elif args[0] == '-get':
        download_file(args[1], creds)

    elif args[0] == '-nxc':
        for s in parse_nxc(args[1]):
            print(s)

    elif args[0] == '-host':
        target = args[1]
        if os.path.isfile(target):
            with open(target) as f:
                for host in f:
                    host = host.strip()
                    if host:
                        run_host(host, creds, user, passwd, domain)
        else:
            run_host(target, creds, user, passwd, domain)

    else:
        sharesfile = args[0]
        with open(sharesfile) as f:
            shares = [l.strip() for l in f if l.strip()]
        run_smblist(shares, creds, outfile=outfile)


if __name__ == '__main__':
    main()
