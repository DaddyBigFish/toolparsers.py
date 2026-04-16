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
 
import sys, os, re, subprocess, threading, webbrowser, json
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
 
# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
 
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
 
 
def smbclient_ls(share, creds, proxy=False):
    cmd = ['smbclient', share, '-U', creds, '-c', 'recurse;ls']
    if proxy:
        cmd = ['proxychains', '-q'] + cmd
    result = subprocess.run(cmd, capture_output=True, text=True,
                            env={**os.environ, 'PROXYCHAINS_QUIET_MODE': '1'})
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
    for share in shares:
        share = share.strip()
        if not share:
            continue
        paths = smbclient_ls(share, creds, proxy)
        for p in paths:
            print(p)
            if outfile:
                with open(outfile, 'a') as f:
                    f.write(p + '\n')
 
 
def download_file(fullpath, creds, proxy=False):
    parts = fullpath.split('/', 4)
    share = '/'.join(parts[:4]) if len(parts) >= 4 else fullpath
    filepath = '/' + parts[4] if len(parts) > 4 else '/'
    d = os.path.dirname(filepath)
    fname = os.path.basename(filepath)
    print(f'[*] Downloading: {fname}')
    print(f'[*] From: {share}{d}')
    cmd = ['smbclient', share, '-U', creds, '-c', f'cd "{d}"; get "{fname}"']
    if proxy:
        cmd = ['proxychains', '-q'] + cmd
    subprocess.run(cmd, capture_output=True,
                   env={**os.environ, 'PROXYCHAINS_QUIET_MODE': '1'})
    if os.path.exists(fname):
        print(f'[+] Saved: {os.getcwd()}/{fname}')
    else:
        print(f'[-] Failed: {fname}')
 
 
def run_host(target, creds, user, passwd, domain, proxy=False):
    safe = target.replace('/', '_')
    outfile = f'smblist_{safe}'
    print(f'[*] Running nxc against {target}', file=sys.stderr)
    cmd = ['netexec', 'smb', target, '-u', user, '-p', passwd, '-d', domain, '--shares']
    if proxy:
        cmd = ['proxychains', '-q'] + cmd
    result = subprocess.run(cmd, capture_output=True, text=True,
                            env={**os.environ, 'PROXYCHAINS_QUIET_MODE': '1'})
    shares = parse_nxc(result.stdout, is_file=False)
    if not shares:
        print(f'[-] No readable shares found for {target}', file=sys.stderr)
        return
    print(f'[*] Saving to {outfile}', file=sys.stderr)
    if os.path.exists(outfile):
        open(outfile, 'w').close()
    run_smblist(shares, creds, outfile=outfile, proxy=proxy)
    print(f'[+] Done: {outfile}', file=sys.stderr)
 
 
# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
 
HTML = """<!DOCTYPE html>
<html><head><meta charset=UTF-8><title>smblist</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#0d0d0d;color:#c8c8c8;height:100vh;display:flex;flex-direction:column;overflow:hidden}
#top{padding:8px 14px;border-bottom:1px solid #222;display:flex;gap:8px;align-items:center;background:#111;flex-shrink:0;flex-wrap:wrap}
#top input[type=text]{background:#1a1a1a;border:1px solid #333;color:#c8c8c8;padding:5px 8px;font-family:monospace;font-size:12px;border-radius:4px}
#top button{background:#1a1a1a;border:1px solid #444;color:#8f8;padding:5px 10px;cursor:pointer;font-family:monospace;font-size:12px;border-radius:4px}
#top button:hover{background:#222}
#top button.active{background:#1a3a1a;border-color:#3a5a3a}
#top label{font-size:12px;color:#8f8;display:flex;align-items:center;gap:4px;cursor:pointer;white-space:nowrap}
#manualpath{width:200px}
#main{display:flex;flex:1;overflow:hidden;min-height:0}
#left{width:40%;border-right:1px solid #222;display:flex;flex-direction:column;min-height:0;min-width:100px}
#leftbar{padding:6px;border-bottom:1px solid #1a1a1a;background:#0d0d0d;flex-shrink:0;display:flex;flex-direction:column;gap:4px}
#leftbar input{background:#1a1a1a;border:1px solid #333;color:#c8c8c8;padding:4px 7px;font-family:monospace;font-size:11px;border-radius:4px;width:100%}
.lbl{font-size:10px;color:#555}
#extbar{display:flex;flex-wrap:wrap;gap:2px}
.eb{font-size:11px;padding:2px 6px;border-radius:3px;cursor:pointer;background:#1a1a1a;border:1px solid #2a2a2a;color:#888}
.eb:hover{color:#fff;border-color:#555}
.eb.on{background:#1a3a1a;border-color:#3a5a3a;color:#8f8}
#pathList{flex:1;overflow-y:auto;padding:4px;position:relative}
#divider{width:6px;background:#1a1a1a;cursor:col-resize;flex-shrink:0;border-left:1px solid #222;border-right:1px solid #222;display:flex;align-items:center;justify-content:center}
#divider:hover{background:#2a2a2a}
#divider::after{content:'';display:block;width:2px;height:30px;background:#444;border-radius:1px}
#right{flex:1;background:#0a0a0a;display:flex;flex-direction:column;min-height:0;overflow:hidden;min-width:100px}
#rightbar{padding:6px 8px 4px;border-bottom:1px solid #1a1a1a;background:#0d0d0d;flex-shrink:0;display:flex;gap:4px;align-items:center}
#rightbar input{flex:1;background:#1a1a1a;border:1px solid #333;color:#c8c8c8;padding:4px 7px;font-family:monospace;font-size:11px;border-radius:4px}
#rightbar span{font-size:10px;color:#555;white-space:nowrap}
#header{font-size:11px;color:#8f8;padding:6px 12px;word-break:break-all;border-bottom:1px solid #1a1a1a;background:#0d0d0d;flex-shrink:0}
#contentarea{flex:1;overflow-y:auto;padding:12px;min-height:0}
#content{font-size:12px;white-space:pre-wrap;word-break:break-all;color:#aaa;line-height:1.6;margin:0}
#bottom{padding:8px 12px;border-top:1px solid #1a1a1a;flex-shrink:0;display:none}
#status{padding:3px 14px;font-size:11px;color:#555;background:#111;border-top:1px solid #1a1a1a;flex-shrink:0}
.path{padding:2px 8px;cursor:pointer;border-radius:3px;font-size:11px;color:#aaa;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;position:absolute;left:0;right:0}
.path:hover{background:#1a1a1a;color:#fff}
.path.active{background:#1a3a1a;color:#8f8}
.hl{background:#3a3a00;color:#ff8}
.ok{color:#8f8}.err{color:#f88}
.dl-btn{background:#1a2a1a;border:1px solid #3a5a3a;color:#8f8;padding:5px 12px;cursor:pointer;font-family:monospace;font-size:12px;border-radius:4px}
.dl-btn:hover{background:#223a22}
</style></head>
<body>
<div id=top>
  <span style="font-size:11px;color:#555">load file:</span>
  <input type=file id=fileInput accept=.txt onchange=loadFile(this)>
  <span style="font-size:11px;color:#555">or disk path:</span>
  <input type=text id=manualpath placeholder="/home/user/paths.txt">
  <button onclick=loadManual()>load</button>
  <label><input type=checkbox id=useProxy checked> proxychains</label>
  <button id=fnbtn onclick=toggleFN()>full path</button>
  <button onclick=clearRight()>clear</button>
</div>
<div id=main>
  <div id=left>
    <div id=leftbar>
      <span class=lbl>filter paths:</span>
      <input type=text id=filterpath placeholder="keyword,keyword... (comma=OR)" oninput=scheduleFilter()>
      <span class=lbl>extensions:</span>
      <div id=extbar></div>
    </div>
    <div id=pathList></div>
  </div>
  <div id=divider></div>
  <div id=right>
    <div id=rightbar>
      <span>search in file:</span>
      <input type=text id=filtercontent placeholder="keyword,keyword... (comma=OR)" oninput=scheduleHL()>
    </div>
    <div id=header>select a path</div>
    <div id=contentarea><pre id=content>click a path to view its contents</pre></div>
    <div id=bottom><button class=dl-btn onclick=dl()>[+] download file</button></div>
  </div>
</div>
<div id=status>0 paths</div>
<script>
const ROW_H=20;
let all=[],cur=null,ft=null,hlt=null,lastContent='',filtered=[],exts=new Set(),fnOnly=false;
 
fetch('/paths').then(r=>r.json()).then(d=>{all=d;exts.clear();go();});
 
function loadFile(inp){
  const f=inp.files[0];if(!f)return;
  const r=new FileReader();
  r.onload=ev=>{all=ev.target.result.split('\\n').map(l=>l.trim()).filter(Boolean);exts.clear();go();};
  r.readAsText(f);
}
 
function loadManual(){
  const p=document.getElementById('manualpath').value.trim();if(!p)return;
  fetch('/loadfile?path='+encodeURIComponent(p)).then(r=>r.json()).then(d=>{
    if(d.ok){all=d.paths;exts.clear();go();}
    else document.getElementById('status').innerHTML='<span class=err>[-] '+d.msg+'</span>';
  });
}
 
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
  const bar=document.getElementById('extbar');
  bar.innerHTML='';
  sorted.forEach(([ext,cnt])=>{
    const b=document.createElement('span');
    b.className='eb'+(exts.has(ext)?' on':'');
    b.textContent='.'+ext;
    b.title=cnt+' files';
    b.onclick=()=>{if(exts.has(ext))exts.delete(ext);else exts.add(ext);b.classList.toggle('on',exts.has(ext));go();};
    bar.appendChild(b);
  });
}
 
function scheduleFilter(){clearTimeout(ft);ft=setTimeout(go,150);}
function scheduleHL(){clearTimeout(hlt);hlt=setTimeout(()=>{if(lastContent){document.getElementById('content').innerHTML=hl(lastContent);hitcount(lastContent);}},150);}
 
function toggleFN(){
  fnOnly=!fnOnly;
  const b=document.getElementById('fnbtn');
  b.textContent=fnOnly?'filename only':'full path';
  b.classList.toggle('active',fnOnly);
  render(filtered);
}
 
function render(paths){
  document.getElementById('status').textContent=paths.length+' / '+all.length+' paths';
  const list=document.getElementById('pathList');
  list.innerHTML='';
  if(!paths.length)return;
  const spacer=document.createElement('div');
  spacer.style.height=(paths.length*ROW_H)+'px';
  spacer.style.position='relative';
  list.appendChild(spacer);
  let lastStart=-1;
  function paint(){
    const scrollTop=list.scrollTop;
    const visible=Math.ceil(list.clientHeight/ROW_H);
    const start=Math.max(0,Math.floor(scrollTop/ROW_H)-5);
    const end=Math.min(paths.length,start+visible+10);
    if(start===lastStart)return;
    lastStart=start;
    spacer.querySelectorAll('.path').forEach(e=>e.remove());
    for(let i=start;i<end;i++){
      const p=paths[i];
      const d=document.createElement('div');
      d.className='path';
      d.title=p;
      d.textContent=fnOnly?(p.split('/').pop()||p):p;
      d.style.top=(i*ROW_H)+'px';
      d.dataset.idx=i;
      d.addEventListener('click',function(){sel(this,filtered[+this.dataset.idx]);});
      spacer.appendChild(d);
    }
  }
  list.onscroll=paint;
  paint();
}
 
(()=>{
  const dv=document.getElementById('divider'),lf=document.getElementById('left');
  let drag=false,sx=0,sw=0;
  dv.addEventListener('mousedown',e=>{drag=true;sx=e.clientX;sw=lf.offsetWidth;document.body.style.cssText='cursor:col-resize;user-select:none';});
  document.addEventListener('mousemove',e=>{if(!drag)return;lf.style.width=Math.max(100,Math.min(sw+e.clientX-sx,window.innerWidth-100))+'px';lf.style.flex='none';});
  document.addEventListener('mouseup',()=>{drag=false;document.body.style.cssText='';});
})();
 
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
    const m=esc(text).match(new RegExp(escRe(esc(t)),'gi'));
    if(m)total+=m.length;
  });
  if(total>0){
    const s=document.createElement('span');
    s.className='hc';s.style.cssText='font-size:10px;color:#ff8;margin-left:4px;white-space:nowrap';
    s.textContent=total+' match'+(total===1?'':'es');
    rb.appendChild(s);
  }
}
 
function proxy(){return document.getElementById('useProxy').checked?1:0;}
 
function sel(el,path){
  document.querySelectorAll('.path').forEach(e=>e.classList.remove('active'));
  el.classList.add('active');cur=path;
  document.getElementById('header').textContent=path;
  document.getElementById('content').textContent='loading...';
  document.getElementById('bottom').style.display='none';
  lastContent='';
  fetch('/cat?path='+encodeURIComponent(path)+'&proxy='+proxy())
    .then(r=>r.json()).then(d=>{
      const c=document.getElementById('content');
      if(d.ok){lastContent=d.content;c.innerHTML=hl(d.content);hitcount(d.content);}
      else c.textContent=d.msg;
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
 
function clearRight(){
  cur=null;lastContent='';
  document.getElementById('header').textContent='select a path';
  document.getElementById('content').textContent='click a path to view its contents';
  document.getElementById('bottom').style.display='none';
  const old=document.getElementById('rightbar').querySelector('.hc');if(old)old.remove();
}
</script></body></html>"""
 
 
def run_cmd(cmd, use_proxy):
    if use_proxy:
        cmd = ['proxychains', '-q'] + cmd
    return subprocess.run(cmd, capture_output=True, text=True,
                          env={**os.environ, 'PROXYCHAINS_QUIET_MODE': '1'})
 
 
def start_gui(creds, pathsfile=''):
    paths = []
    if pathsfile and os.path.exists(pathsfile):
        with open(pathsfile) as f:
            paths = [l.strip() for l in f if l.strip()]
 
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            p = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(p.query)
            use_proxy = qs.get('proxy', ['0'])[0] == '1'
 
            if p.path == '/':
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(HTML.encode())
 
            elif p.path == '/paths':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(paths).encode())
 
            elif p.path == '/loadfile':
                path = qs.get('path', [''])[0]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                try:
                    with open(path) as f:
                        loaded = [l.strip() for l in f if l.strip()]
                    self.wfile.write(json.dumps({'ok': True, 'paths': loaded}).encode())
                except Exception as e:
                    self.wfile.write(json.dumps({'ok': False, 'msg': str(e)}).encode())
 
            elif p.path == '/cat':
                path = qs.get('path', [''])[0]
                parts = path.split('/', 4)
                share = '/'.join(parts[:4]) if len(parts) >= 4 else path
                filepath = '/' + parts[4] if len(parts) > 4 else '/'
                result = run_cmd(
                    ['smbclient', share, '-U', creds, '-c', f'get "{filepath}" /tmp/smblist_preview'],
                    use_proxy
                )
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                try:
                    with open('/tmp/smblist_preview', 'rb') as f:
                        content = f.read().decode('utf-8', errors='replace')
                    os.remove('/tmp/smblist_preview')
                    self.wfile.write(json.dumps({'ok': True, 'content': content}).encode())
                except:
                    self.wfile.write(json.dumps({'ok': False, 'msg': result.stderr.strip() or 'could not read file'}).encode())
 
            elif p.path == '/download':
                path = qs.get('path', [''])[0]
                parts = path.split('/', 4)
                share = '/'.join(parts[:4]) if len(parts) >= 4 else path
                filepath = '/' + parts[4] if len(parts) > 4 else '/'
                d = os.path.dirname(filepath)
                fname = os.path.basename(filepath)
                result = run_cmd(
                    ['smbclient', share, '-U', creds, '-c', f'cd "{d}"; get "{fname}"'],
                    use_proxy
                )
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                if os.path.exists(fname):
                    self.wfile.write(json.dumps({'ok': True, 'msg': fname}).encode())
                else:
                    self.wfile.write(json.dumps({'ok': False, 'msg': result.stderr.strip()}).encode())
 
            else:
                self.send_response(404)
                self.end_headers()
 
    port = 18888
    print(f'[*] smblist gui at http://127.0.0.1:{port}')
    print('[*] ctrl+c to stop')
    threading.Timer(1, lambda: webbrowser.open(f'http://127.0.0.1:{port}')).start()
    HTTPServer(('127.0.0.1', port), Handler).serve_forever()
 
 
# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
 
def usage():
    print(__doc__)
    sys.exit(1)
 
if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
    usage()
 
creds = sys.argv[1]
args = sys.argv[2:]
 
# parse creds
def parse_creds(c):
    domain = c.split('/')[0] if '/' in c else ''
    userpass = c.split('/')[-1]
    user = userpass.split('%')[0]
    passwd = userpass.split('%')[1] if '%' in userpass else ''
    return domain, user, passwd
 
domain, user, passwd = parse_creds(creds)
 
# parse -o flag
outfile = None
if '-o' in args:
    idx = args.index('-o')
    outfile = args[idx + 1]
    args = [a for i, a in enumerate(args) if i != idx and i != idx + 1]
    open(outfile, 'w').close()
 
if not args:
    # stdin mode
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
 
elif args[0] == '-nxc' and creds == '-nxc':
    # called as: smblist.py -nxc file
    for s in parse_nxc(args[0]):
        print(s)
 
else:
    # shares file
    sharesfile = args[0]
    with open(sharesfile) as f:
        shares = [l.strip() for l in f if l.strip()]
    run_smblist(shares, creds, outfile=outfile)
