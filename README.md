<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IoT Hunter v2.0 — MR CYBER PULSE</title>
<meta name="description" content="Defensive IoT security toolkit: discovery, fingerprinting, default-credential checks, live anomaly detection, insecure-protocol detection, remediation planning and local PDF/JSON reporting.">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' fill='black'/><text y='72' x='50' font-size='64' text-anchor='middle' fill='white' font-family='monospace'>IH</text></svg>">

<style>
/* ============ RESET ============ */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root{
  --bg:#000;
  --panel:#0a0a0a;
  --panel-2:#101010;
  --fg:#ffffff;
  --muted:#9d9d9d;
  --dim:#6a6a6a;
  --line:#232323;
  --line-2:#3d3d3d;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --sans:Inter,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --radius:2px;
  --maxw:1120px;
}

html{scroll-behavior:smooth}

body{
  background:var(--bg);
  color:var(--fg);
  font-family:var(--sans);
  font-size:16px;
  line-height:1.7;
  -webkit-font-smoothing:antialiased;
  text-rendering:optimizeLegibility;
  overflow-x:hidden;
}

/* ============ GRID BACKGROUND ============ */
body::before{
  content:"";
  position:fixed;
  inset:0;
  z-index:-2;
  background-image:
    linear-gradient(rgba(255,255,255,.05) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px);
  background-size:54px 54px;
}
body::after{
  content:"";
  position:fixed;
  inset:0;
  z-index:-1;
  pointer-events:none;
  background:
    radial-gradient(ellipse 70% 50% at 50% -10%,rgba(255,255,255,.10),transparent 70%),
    radial-gradient(ellipse 90% 70% at 50% 110%,rgba(255,255,255,.05),transparent 70%);
}

/* ============ LAYOUT ============ */
.wrap{
  width:100%;
  max-width:var(--maxw);
  margin-inline:auto;
  padding-inline:24px;
}

section{
  padding:88px 0;
  border-top:1px solid var(--line);
  scroll-margin-top:80px;
}
section:first-of-type{border-top:none}

/* ============ HEADER ============ */
header{
  position:sticky;
  top:0;
  z-index:50;
  background:rgba(0,0,0,.78);
  backdrop-filter:blur(14px);
  -webkit-backdrop-filter:blur(14px);
  border-bottom:1px solid var(--line);
}

.nav{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:20px;
  height:62px;
}

.brand{
  display:flex;
  align-items:center;
  gap:10px;
  font-family:var(--mono);
  font-size:.82rem;
  letter-spacing:.14em;
  text-transform:uppercase;
  color:var(--fg);
  text-decoration:none;
  white-space:nowrap;
}
.brand .dot{
  width:8px;height:8px;
  background:#fff;
  border-radius:50%;
  animation:pulse 2.4s ease-in-out infinite;
}
@keyframes pulse{
  0%,100%{opacity:1;transform:scale(1)}
  50%{opacity:.25;transform:scale(.75)}
}

.nav-links{
  display:flex;
  align-items:center;
  gap:4px;
  list-style:none;
}
.nav-links a{
  display:block;
  padding:7px 11px;
  font-family:var(--mono);
  font-size:.74rem;
  letter-spacing:.08em;
  text-transform:uppercase;
  color:var(--muted);
  text-decoration:none;
  border-radius:var(--radius);
  transition:color .18s ease,background .18s ease;
}
.nav-links a:hover,
.nav-links a.active{
  color:#000;
  background:#fff;
}

.nav-toggle{
  display:none;
  background:none;
  border:1px solid var(--line-2);
  color:#fff;
  font-family:var(--mono);
  font-size:.72rem;
  letter-spacing:.1em;
  padding:7px 12px;
  cursor:pointer;
  border-radius:var(--radius);
}
.nav-toggle:hover{background:#fff;color:#000;border-color:#fff}

/* ============ HERO ============ */
.hero{
  padding:96px 0 88px;
  border-top:none;
}

.badge{
  display:inline-flex;
  align-items:center;
  gap:8px;
  border:1px solid var(--line-2);
  padding:5px 12px;
  font-family:var(--mono);
  font-size:.7rem;
  letter-spacing:.16em;
  text-transform:uppercase;
  color:var(--muted);
  border-radius:100px;
  margin-bottom:28px;
}
.badge::before{
  content:"";
  width:6px;height:6px;
  background:#fff;
  border-radius:50%;
}

h1{
  font-family:var(--mono);
  font-size:clamp(2.6rem,9vw,6rem);
  line-height:.95;
  letter-spacing:-.03em;
  font-weight:700;
  margin-bottom:22px;
}
h1 .outline{
  color:transparent;
  -webkit-text-stroke:1.5px #fff;
  text-stroke:1.5px #fff;
}

.tagline{
  font-family:var(--mono);
  font-size:clamp(.85rem,2.4vw,1.05rem);
  color:var(--fg);
  letter-spacing:.02em;
  margin-bottom:14px;
}
.tagline span{color:var(--dim)}

.hero-sub{
  max-width:62ch;
  color:var(--muted);
  font-size:1.02rem;
  margin-bottom:34px;
}

.hero-meta{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  margin-bottom:38px;
}
.chip{
  font-family:var(--mono);
  font-size:.7rem;
  letter-spacing:.1em;
  text-transform:uppercase;
  color:var(--muted);
  border:1px solid var(--line);
  padding:5px 10px;
  border-radius:100px;
}

.actions{
  display:flex;
  flex-wrap:wrap;
  gap:12px;
}

.btn{
  display:inline-flex;
  align-items:center;
  gap:9px;
  font-family:var(--mono);
  font-size:.78rem;
  letter-spacing:.1em;
  text-transform:uppercase;
  text-decoration:none;
  padding:13px 22px;
  border:1px solid #fff;
  border-radius:var(--radius);
  background:#fff;
  color:#000;
  cursor:pointer;
  transition:transform .16s ease,background .18s ease,color .18s ease;
}
.btn:hover{transform:translateY(-2px);background:#000;color:#fff}
.btn-ghost{
  background:transparent;
  color:#fff;
  border-color:var(--line-2);
}
.btn-ghost:hover{background:#fff;color:#000;border-color:#fff}

/* ============ TERMINAL ============ */
.terminal{
  margin-top:56px;
  border:1px solid var(--line-2);
  background:#050505;
  border-radius:var(--radius);
  overflow:hidden;
  box-shadow:0 24px 60px -30px rgba(255,255,255,.14);
}
.term-bar{
  display:flex;
  align-items:center;
  gap:8px;
  padding:10px 14px;
  border-bottom:1px solid var(--line);
  background:var(--panel-2);
}
.term-bar i{
  width:9px;height:9px;
  border-radius:50%;
  border:1px solid var(--line-2);
  background:#1a1a1a;
}
.term-bar span{
  margin-left:auto;
  font-family:var(--mono);
  font-size:.68rem;
  letter-spacing:.12em;
  text-transform:uppercase;
  color:var(--dim);
}
.term-body{
  padding:20px;
  font-family:var(--mono);
  font-size:.8rem;
  line-height:1.9;
  color:var(--muted);
  overflow-x:auto;
  white-space:pre;
}
.term-body .c{color:#fff}
.term-body .d{color:var(--dim)}
.term-body .b{color:#fff;font-weight:700}

/* ============ SECTION HEADINGS ============ */
.sec-head{
  display:flex;
  align-items:baseline;
  gap:16px;
  margin-bottom:34px;
  flex-wrap:wrap;
}
.sec-num{
  font-family:var(--mono);
  font-size:.72rem;
  letter-spacing:.18em;
  color:var(--dim);
  border:1px solid var(--line);
  padding:3px 8px;
  border-radius:var(--radius);
}
h2{
  font-family:var(--mono);
  font-size:clamp(1.5rem,4vw,2.15rem);
  letter-spacing:-.02em;
  font-weight:700;
  line-height:1.15;
}
.sec-desc{
  color:var(--muted);
  max-width:70ch;
  margin-bottom:30px;
}

h3{
  font-family:var(--mono);
  font-size:1rem;
  letter-spacing:.02em;
  font-weight:700;
  margin-bottom:10px;
}
p{color:var(--muted)}
p + p{margin-top:14px}
strong{color:#fff;font-weight:600}
a{color:#fff}

/* ============ GRIDS / CARDS ============ */
.grid{
  display:grid;
  gap:16px;
}
.grid-2{grid-template-columns:repeat(2,minmax(0,1fr))}
.grid-3{grid-template-columns:repeat(3,minmax(0,1fr))}
.grid-4{grid-template-columns:repeat(4,minmax(0,1fr))}

.card{
  border:1px solid var(--line);
  background:var(--panel);
  padding:24px;
  border-radius:var(--radius);
  transition:border-color .2s ease,background .2s ease,transform .2s ease;
}
.card:hover{
  border-color:var(--line-2);
  background:var(--panel-2);
  transform:translateY(-3px);
}
.card .k{
  font-family:var(--mono);
  font-size:.68rem;
  letter-spacing:.16em;
  text-transform:uppercase;
  color:var(--dim);
  display:block;
  margin-bottom:12px;
}
.card p{font-size:.92rem;color:var(--muted)}
.card code{
  font-family:var(--mono);
  font-size:.78rem;
  color:#fff;
  background:#161616;
  border:1px solid var(--line);
  padding:1px 6px;
  border-radius:var(--radius);
}

/* ============ LISTS ============ */
.list{list-style:none;display:grid;gap:12px}
.list li{
  position:relative;
  padding-left:26px;
  color:var(--muted);
  font-size:.95rem;
}
.list li::before{
  content:"—";
  position:absolute;
  left:0;
  color:var(--dim);
  font-family:var(--mono);
}
.list li strong{color:#fff}

.menu-list{
  list-style:none;
  counter-reset:m;
  display:grid;
  gap:1px;
  background:var(--line);
  border:1px solid var(--line);
  border-radius:var(--radius);
  overflow:hidden;
}
.menu-list li{
  counter-increment:m;
  display:flex;
  align-items:flex-start;
  gap:16px;
  padding:16px 20px;
  background:var(--panel);
  transition:background .18s ease;
}
.menu-list li:hover{background:var(--panel-2)}
.menu-list li::before{
  content:counter(m);
  font-family:var(--mono);
  font-size:.75rem;
  color:#000;
  background:#fff;
  min-width:22px;
  height:22px;
  display:grid;
  place-items:center;
  border-radius:var(--radius);
  flex-shrink:0;
  margin-top:4px;
  font-weight:700;
}
.menu-list .t{color:#fff;font-weight:600}
.menu-list .d{color:var(--muted);font-size:.9rem}

/* ============ CODE BLOCKS ============ */
.code{
  position:relative;
  border:1px solid var(--line);
  border-left:2px solid #fff;
  background:#070707;
  border-radius:var(--radius);
  padding:18px 20px;
  overflow-x:auto;
  margin:18px 0;
}
.code pre{
  font-family:var(--mono);
  font-size:.82rem;
  line-height:1.85;
  color:var(--muted);
  white-space:pre;
}
.code pre .c{color:#fff}

.copy{
  position:absolute;
  top:8px;
  right:8px;
  font-family:var(--mono);
  font-size:.62rem;
  letter-spacing:.12em;
  text-transform:uppercase;
  background:transparent;
  border:1px solid var(--line-2);
  color:var(--dim);
  padding:4px 9px;
  border-radius:var(--radius);
  cursor:pointer;
  transition:all .18s ease;
}
.copy:hover{background:#fff;color:#000;border-color:#fff}

/* ============ CALLOUT ============ */
.callout{
  border:1px solid var(--line-2);
  border-left:2px solid #fff;
  background:var(--panel);
  padding:24px 26px;
  border-radius:var(--radius);
}
.callout .label{
  font-family:var(--mono);
  font-size:.68rem;
  letter-spacing:.18em;
  text-transform:uppercase;
  color:#fff;
  display:block;
  margin-bottom:10px;
}
.callout p{font-size:.95rem}

/* ============ TABLE ============ */
.tbl-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--radius)}
table{
  width:100%;
  border-collapse:collapse;
  font-size:.9rem;
  min-width:520px;
}
th,td{
  text-align:left;
  padding:14px 18px;
  border-bottom:1px solid var(--line);
  vertical-align:top;
}
th{
  font-family:var(--mono);
  font-size:.68rem;
  letter-spacing:.14em;
  text-transform:uppercase;
  color:var(--dim);
  background:var(--panel-2);
  font-weight:600;
}
td{color:var(--muted)}
td:first-child{
  color:#fff;
  font-family:var(--mono);
  font-size:.8rem;
  white-space:nowrap;
}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:var(--panel)}

/* ============ AUTHOR ============ */
.author{
  display:grid;
  grid-template-columns:1.1fr .9fr;
  gap:32px;
  align-items:start;
}
.quote{
  font-family:var(--mono);
  font-size:clamp(1.05rem,3vw,1.5rem);
  line-height:1.5;
  color:#fff;
  letter-spacing:-.01em;
  margin:20px 0 8px;
}
.links{list-style:none;display:grid;gap:1px;background:var(--line);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden}
.links a,.links .row{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:14px;
  padding:14px 18px;
  background:var(--panel);
  text-decoration:none;
  color:var(--muted);
  font-size:.88rem;
  transition:background .18s ease,color .18s ease;
}
.links a:hover{background:#fff;color:#000}
.links a:hover .lk{color:#000}
.links .lk{
  font-family:var(--mono);
  font-size:.66rem;
  letter-spacing:.14em;
  text-transform:uppercase;
  color:var(--dim);
  flex-shrink:0;
}

/* ============ FOOTER ============ */
footer{
  border-top:1px solid var(--line);
  padding:44px 0 60px;
}
.foot{
  display:flex;
  flex-wrap:wrap;
  align-items:center;
  justify-content:space-between;
  gap:18px;
}
.foot p{font-size:.82rem;color:var(--dim);font-family:var(--mono)}
.foot .built{
  font-family:var(--mono);
  font-size:.78rem;
  letter-spacing:.06em;
  color:var(--muted);
}
.foot .built b{color:#fff}

/* ============ REVEAL ============ */
.reveal{
  opacity:0;
  transform:translateY(18px);
  transition:opacity .55s ease,transform .55s ease;
}
.reveal.in{opacity:1;transform:none}

/* ============ RESPONSIVE ============ */
@media (max-width:900px){
  .grid-3,.grid-4{grid-template-columns:repeat(2,minmax(0,1fr))}
  .author{grid-template-columns:1fr}
}

@media (max-width:720px){
  .nav-links{
    position:absolute;
    top:62px;
    left:0;
    right:0;
    flex-direction:column;
    align-items:stretch;
    gap:0;
    background:#000;
    border-bottom:1px solid var(--line);
    padding:8px;
    display:none;
  }
  .nav-links.open{display:flex}
  .nav-links a{padding:12px 14px;font-size:.78rem}
  .nav-toggle{display:block}

  section{padding:64px 0}
  .hero{padding:64px 0}
  .grid-2,.grid-3,.grid-4{grid-template-columns:1fr}
  .term-body{font-size:.72rem;padding:16px}
  .actions .btn{width:100%;justify-content:center}
}

@media (prefers-reduced-motion:reduce){
  *{animation:none!important;transition:none!important}
  .reveal{opacity:1;transform:none}
  html{scroll-behavior:auto}
}
</style>
</head>

<body>

<!-- ================= HEADER ================= -->
<header>
  <div class="wrap nav">
    <a class="brand" href="#top">
      <span class="dot"></span>
      IoT&nbsp;Hunter <span style="color:var(--dim)">v2.0</span>
    </a>

    <button class="nav-toggle" id="navToggle" aria-expanded="false" aria-controls="navLinks">MENU</button>

    <ul class="nav-links" id="navLinks">
      <li><a href="#overview">Overview</a></li>
      <li><a href="#legal">Legal</a></li>
      <li><a href="#install">Install</a></li>
      <li><a href="#usage">Usage</a></li>
      <li><a href="#modules">Modules</a></li>
      <li><a href="#author">Author</a></li>
      <li><a href="#license">License</a></li>
    </ul>
  </div>
</header>

<main id="top">

<!-- ================= HERO ================= -->
<section class="hero">
  <div class="wrap">
    <span class="badge">Defensive IoT Security Toolkit</span>

    <h1>IoT HUNTER<br><span class="outline">v2.0</span></h1>

    <p class="tagline">"Complex ko Simple. Simple ko Powerful." <span>— MR CYBER PULSE</span></p>

    <p class="hero-sub">
      Discovery, fingerprinting, default-credential checks, live anomaly detection,
      insecure-protocol detection, remediation planning, and local PDF/JSON reporting.
      <strong>Real network capture only</strong> — no demo data, no external APIs.
    </p>

    <div class="hero-meta">
      <span class="chip">Scapy ARP Scan</span>
      <span class="chip">Banner Grabbing</span>
      <span class="chip">Beaconing / Scan / Exfil</span>
      <span class="chip">Telnet · FTP · HTTP · MQTT</span>
      <span class="chip">Watermarked PDF</span>
      <span class="chip">GPL-3.0</span>
    </div>

    <div class="actions">
      <a class="btn" href="https://github.com/mrcyberharsh/iot-hunter" target="_blank" rel="noopener">View on GitHub ↗</a>
      <a class="btn btn-ghost" href="#usage">Read the Usage</a>
    </div>

    <!-- Terminal mockup -->
    <div class="terminal reveal">
      <div class="term-bar">
        <i></i><i></i><i></i>
        <span>iothunter — bash</span>
      </div>
      <div class="term-body"><span class="d">$</span> <span class="c">python iothunter.py</span>

<span class="d">  ██╗ ██████╗ ████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗</span>
<span class="d">  ██║██╔═══██╗╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗</span>
<span class="d">  ██║██║   ██║   ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝</span>
<span class="d">  ██║██║   ██║   ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗</span>
<span class="d">  ██║╚██████╔╝   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║</span>
<span class="d">  ╚═╝ ╚═════╝    ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝</span>
<span class="d">                                          v2.0  ·  by MR CYBER PULSE</span>

<span class="b">[!]</span> Authorized use only. Type <span class="c">YES</span> to continue: <span class="c">YES</span>

  <span class="c">[1]</span> Full Scan          <span class="d">discovery → fingerprint → credentials → protocol → anomaly → report</span>
  <span class="c">[2]</span> Discovery Only     <span class="d">ARP scan + port scan + OUI vendor lookup</span>
  <span class="c">[3]</span> Protocol Scan Only <span class="d">30s live capture for insecure protocols</span>
  <span class="c">[4]</span> Anomaly Monitor    <span class="d">real-time traffic monitoring</span>
  <span class="c">[5]</span> Exit

<span class="d">></span> <span class="c">_</span></div>
    </div>
  </div>
</section>

<!-- ================= OVERVIEW ================= -->
<section id="overview">
  <div class="wrap">
    <div class="sec-head">
      <span class="sec-num">01</span>
      <h2>What it does</h2>
    </div>

    <p class="sec-desc">
      A defensive toolkit for your own network. Everything runs locally — findings come from
      real traffic and real scans, never from simulated data.
    </p>

    <div class="grid grid-3">
      <div class="card reveal">
        <span class="k">Step 01</span>
        <h3>Discover</h3>
        <p>ARP sweep with Scapy, port scanning, and OUI vendor lookup to map what's actually on the wire.</p>
      </div>
      <div class="card reveal">
        <span class="k">Step 02</span>
        <h3>Fingerprint</h3>
        <p>Banner grabbing and device-type classification to identify IoT hardware and services.</p>
      </div>
      <div class="card reveal">
        <span class="k">Step 03</span>
        <h3>Check Credentials</h3>
        <p>Rate-limited default-credential testing against your local wordlist. Nothing leaves the machine.</p>
      </div>
      <div class="card reveal">
        <span class="k">Step 04</span>
        <h3>Detect Protocols</h3>
        <p>Flags Telnet, FTP, HTTP and unencrypted MQTT — including plaintext credentials in transit.</p>
      </div>
      <div class="card reveal">
        <span class="k">Step 05</span>
        <h3>Monitor Anomalies</h3>
        <p>Live packet capture with rolling-window statistics for beaconing, scanning, and exfiltration patterns.</p>
      </div>
      <div class="card reveal">
        <span class="k">Step 06</span>
        <h3>Remediate &amp; Report</h3>
        <p>Prioritized fixes with commands, exported as a watermarked PDF and machine-readable JSON.</p>
      </div>
    </div>
  </div>
</section>

<!-- ================= LEGAL ================= -->
<section id="legal">
  <div class="wrap">
    <div class="sec-head">
      <span class="sec-num">02</span>
      <h2>Legal disclaimer</h2>
    </div>

    <div class="callout reveal">
      <span class="label">⚠ Read before running</span>
      <p>
        Only scan networks and devices <strong>you own</strong> or are <strong>explicitly authorized</strong> to test.
        Unauthorized scanning of networks is illegal in most jurisdictions.
        This tool requires explicit confirmation of authorization before every run.
      </p>
    </div>
  </div>
</section>

<!-- ================= INSTALL ================= -->
<section id="install">
  <div class="wrap">
    <div class="sec-head">
      <span class="sec-num">03</span>
      <h2>Requirements &amp; setup</h2>
    </div>

    <div class="code">
      <button class="copy" data-copy>Copy</button>
      <pre><span class="c">pip install -r requirements.txt</span></pre>
    </div>

    <div class="grid grid-3" style="margin-top:26px">
      <div class="card reveal">
        <span class="k">Linux</span>
        <h3>libpcap</h3>
        <p>Usually preinstalled. May need <code>sudo apt install libpcap-dev</code>. Run with <code>sudo</code> for raw sockets / ARP.</p>
      </div>
      <div class="card reveal">
        <span class="k">Windows</span>
        <h3>Npcap</h3>
        <p>Install Npcap from <code>npcap.com</code> with <strong>"WinPcap API-compatible mode"</strong> enabled. Run the terminal as Administrator.</p>
      </div>
      <div class="card reveal">
        <span class="k">macOS</span>
        <h3>libpcap via brew</h3>
        <p>Install with <code>brew install libpcap</code>, then run with <code>sudo</code>.</p>
      </div>
    </div>

    <div class="sec-head" style="margin-top:64px">
      <span class="sec-num">03.1</span>
      <h2>Configuration</h2>
    </div>

    <p class="sec-desc">Edit <code style="font-family:var(--mono);color:#fff">config.yaml</code>:</p>

    <ul class="list reveal">
      <li><strong>interface / subnet</strong> — leave as <code style="font-family:var(--mono)">auto</code> for auto-detection</li>
      <li><strong>wordlist_path</strong> — path to your local user:pass wordlist (starter list in <code style="font-family:var(--mono)">modules/data/default_creds.txt</code>)</li>
      <li><strong>thresholds</strong> — tune anomaly detection sensitivity</li>
      <li><strong>report_path</strong> — where PDF/JSON reports are saved</li>
    </ul>
  </div>
</section>

<!-- ================= USAGE ================= -->
<section id="usage">
  <div class="wrap">
    <div class="sec-head">
      <span class="sec-num">04</span>
      <h2>Usage</h2>
    </div>

    <div class="code">
      <button class="copy" data-copy>Copy</button>
      <pre><span class="c">python iothunter.py</span></pre>
    </div>

    <p class="sec-desc">
      You'll see the banner, then a disclaimer prompt requiring <strong>YES</strong> to proceed, then the menu:
    </p>

    <ol class="menu-list reveal">
      <li>
        <div>
          <div class="t">Full Scan</div>
          <div class="d">discovery → fingerprint → credentials → protocol → anomaly → report</div>
        </div>
      </li>
      <li>
        <div>
          <div class="t">Discovery Only</div>
          <div class="d">ARP scan + port scan + OUI vendor lookup</div>
        </div>
      </li>
      <li>
        <div>
          <div class="t">Protocol Scan Only</div>
          <div class="d">30s live capture for insecure protocols</div>
        </div>
      </li>
      <li>
        <div>
          <div class="t">Anomaly Monitor Only</div>
          <div class="d">real-time traffic monitoring</div>
        </div>
      </li>
      <li>
        <div>
          <div class="t">Exit</div>
          <div class="d">close the tool</div>
        </div>
      </li>
    </ol>

    <p style="margin-top:22px">
      Reports are saved locally under <code style="font-family:var(--mono);color:#fff">reports/</code> as timestamped
      PDF (watermarked) and JSON files. Logs are written to
      <code style="font-family:var(--mono);color:#fff">logs/iothunter.log</code>.
    </p>
  </div>
</section>

<!-- ================= MODULES ================= -->
<section id="modules">
  <div class="wrap">
    <div class="sec-head">
      <span class="sec-num">05</span>
      <h2>Module overview</h2>
    </div>

    <div class="tbl-wrap reveal">
      <table>
        <thead>
          <tr><th>Module</th><th>Responsibility</th></tr>
        </thead>
        <tbody>
          <tr><td>discovery.py</td><td>ARP scan (Scapy) + port scan + OUI vendor lookup</td></tr>
          <tr><td>fingerprint.py</td><td>Banner grabbing + device-type classification</td></tr>
          <tr><td>credentials.py</td><td>Local wordlist default-credential testing, rate-limited</td></tr>
          <tr><td>anomaly.py</td><td>Live packet capture, rolling-window stats for beaconing / scan / exfil</td></tr>
          <tr><td>protocol.py</td><td>Detects Telnet / FTP / HTTP / unencrypted MQTT + plaintext credentials</td></tr>
          <tr><td>remediation.py</td><td>Maps findings to prioritized fixes and commands</td></tr>
          <tr><td>reporting.py</td><td>Generates watermarked PDF + JSON reports locally</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<!-- ================= NOTES ================= -->
<section id="notes">
  <div class="wrap">
    <div class="sec-head">
      <span class="sec-num">06</span>
      <h2>Notes</h2>
    </div>

    <div class="grid grid-3">
      <div class="card reveal">
        <span class="k">Privileges</span>
        <h3>Elevated access</h3>
        <p>ARP scanning and packet capture require root / Administrator privileges.</p>
      </div>
      <div class="card reveal">
        <span class="k">Real data only</span>
        <h3>No simulations</h3>
        <p>No hardcoded IPs, no simulated data — all findings come from real traffic and scans on your own network.</p>
      </div>
      <div class="card reveal">
        <span class="k">Tested on</span>
        <h3>Cross-platform</h3>
        <p>Linux (Parrot OS, Kali), Windows 10/11, and macOS (Intel &amp; Apple Silicon).</p>
      </div>
    </div>
  </div>
</section>

<!-- ================= AUTHOR ================= -->
<section id="author">
  <div class="wrap">
    <div class="sec-head">
      <span class="sec-num">07</span>
      <h2>Author &amp; credits</h2>
    </div>

    <div class="author">
      <div class="reveal">
        <h3 style="font-size:1.35rem">Harsh Saini <span style="color:var(--dim);font-weight:400">(MR CYBER)</span></h3>
        <p>17-year-old GRC &amp; Defensive Cybersecurity Learner</p>

        <p class="quote">"Builders don't stop.<br>They rebuild."</p>

        <p style="margin-top:18px">
          <strong>Manager:</strong> Prachi Sharma
        </p>
      </div>

      <ul class="links reveal">
        <li><a href="https://mrcyberharsh.github.io" target="_blank" rel="noopener"><span>mrcyberharsh.github.io</span><span class="lk">Website</span></a></li>
        <li><a href="https://github.com/mrcyberharsh" target="_blank" rel="noopener"><span>github.com/mrcyberharsh</span><span class="lk">GitHub</span></a></li>
        <li><a href="https://linkedin.com/in/mrcyberharsh" target="_blank" rel="noopener"><span>linkedin.com/in/mrcyberharsh</span><span class="lk">LinkedIn</span></a></li>
        <li><a href="mailto:manager.prachi@zohomail.in"><span>manager.prachi@zohomail.in</span><span class="lk">Business</span></a></li>
      </ul>
    </div>
  </div>
</section>

<!-- ================= SUPPORT ================= -->
<section id="support">
  <div class="wrap">
    <div class="sec-head">
      <span class="sec-num">08</span>
      <h2>Support &amp; contribution</h2>
    </div>

    <p class="sec-desc">If you find this tool useful, please consider:</p>

    <div class="grid grid-4">
      <div class="card reveal"><span class="k">01</span><h3>Star</h3><p>Star the repo on GitHub.</p></div>
      <div class="card reveal"><span class="k">02</span><h3>Report</h3><p>Report bugs via GitHub Issues.</p></div>
      <div class="card reveal"><span class="k">03</span><h3>Contribute</h3><p>Contribute via Pull Requests.</p></div>
      <div class="card reveal"><span class="k">04</span><h3>Share</h3><p>Share with the security community.</p></div>
    </div>

    <div class="actions" style="margin-top:30px">
      <a class="btn" href="https://github.com/mrcyberharsh/iot-hunter" target="_blank" rel="noopener">Star the repo ↗</a>
      <a class="btn btn-ghost" href="https://github.com/mrcyberharsh/iot-hunter/issues" target="_blank" rel="noopener">Open an issue</a>
    </div>
  </div>
</section>

<!-- ================= LICENSE ================= -->
<section id="license">
  <div class="wrap">
    <div class="sec-head">
      <span class="sec-num">09</span>
      <h2>License</h2>
    </div>

    <div class="callout reveal">
      <span class="label">GNU General Public License v3.0</span>
      <p>
        This project is licensed under the <strong>GNU General Public License v3.0 (GPL-3.0)</strong>.
        See the <code style="font-family:var(--mono);color:#fff">LICENSE</code> file for details.
      </p>
    </div>
  </div>
</section>

</main>

<!-- ================= FOOTER ================= -->
<footer>
  <div class="wrap foot">
    <p class="built">Built with love by <b>MR CYBER</b></p>
    <p>Complex ko Simple. Simple ko Powerful.</p>
    <p>© <span id="year"></span> Harsh Saini · GPL-3.0</p>
  </div>
</footer>

<script>
/* ---------- Mobile nav ---------- */
const toggle = document.getElementById('navToggle');
const links  = document.getElementById('navLinks');

toggle.addEventListener('click', () => {
  const open = links.classList.toggle('open');
  toggle.setAttribute('aria-expanded', String(open));
  toggle.textContent = open ? 'CLOSE' : 'MENU';
});

links.addEventListener('click', e => {
  if (e.target.tagName === 'A') {
    links.classList.remove('open');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.textContent = 'MENU';
  }
});

/* ---------- Scroll spy ---------- */
const navAnchors = [...document.querySelectorAll('.nav-links a')];
const sections   = navAnchors
  .map(a => document.querySelector(a.getAttribute('href')))
  .filter(Boolean);

const spy = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (!entry.isIntersecting) return;
    navAnchors.forEach(a =>
      a.classList.toggle('active', a.getAttribute('href') === '#' + entry.target.id)
    );
  });
}, { rootMargin: '-45% 0px -50% 0px' });

sections.forEach(s => spy.observe(s));

/* ---------- Reveal on scroll ---------- */
const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

if (!reduce) {
  const revealer = new IntersectionObserver((entries, obs) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('in');
        obs.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });

  document.querySelectorAll('.reveal').forEach((el, i) => {
    el.style.transitionDelay = (i % 6) * 60 + 'ms';
    revealer.observe(el);
  });
} else {
  document.querySelectorAll('.reveal').forEach(el => el.classList.add('in'));
}

/* ---------- Copy buttons ---------- */
document.querySelectorAll('[data-copy]').forEach(btn => {
  btn.addEventListener('click', async () => {
    const text = btn.parentElement.querySelector('pre').innerText;
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = 'Copied';
    } catch {
      btn.textContent = 'Failed';
    }
    setTimeout(() => (btn.textContent = 'Copy'), 1400);
  });
});

/* ---------- Year ---------- */
document.getElementById('year').textContent = new Date().getFullYear();
</script>

</body>
</html>
