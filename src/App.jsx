import { useState } from "react";

const EH_SPF = "v=spf1 include:spf.exacthosting.com ~all";

function expectedMX(domain) {
  return [
    "mx." + domain + ".cust.a.hostedemail.com",
    "mx." + domain + ".cust.b.hostedemail.com",
  ];
}

const RESOLVERS = [
  { name: "Google",     url: "https://dns.google/resolve",           color: "#4285F4" },
  { name: "Cloudflare", url: "https://cloudflare-dns.com/dns-query", color: "#F48120" },
];

const DNSBLS = [
  { name: "Spamhaus ZEN",    zone: "zen.spamhaus.org",          delistUrl: "https://check.spamhaus.org/" },
  { name: "SpamCop",         zone: "bl.spamcop.net",            delistUrl: "https://www.spamcop.net/bl.shtml" },
  { name: "SORBS",           zone: "dnsbl.sorbs.net",           delistUrl: "http://www.sorbs.net/lookup.shtml" },
  { name: "Barracuda",       zone: "b.barracudacentral.org",    delistUrl: "https://www.barracudacentral.org/rbl/removal-request" },
  { name: "UCEProtect L1",   zone: "dnsbl-1.uceprotect.net",   delistUrl: "https://www.uceprotect.net/en/rblcheck.php" },
  { name: "MAPS BL",         zone: "bl.emailbasura.org",        delistUrl: "https://www.emailbasura.org/" },
  { name: "Spam Champuru",   zone: "dnsbl.spam-champuru.net",   delistUrl: "http://www.spam-champuru.net/" },
  { name: "MAPS Blackholes", zone: "blackholes.mail-abuse.org", delistUrl: "https://www.mail-abuse.com/cgi-bin/lookup" },
  { name: "MAPS Relays",     zone: "relays.mail-abuse.org",     delistUrl: "https://www.mail-abuse.com/cgi-bin/lookup" },
];

// ---------------------------------------------------------------------------
// DNS helpers
// ---------------------------------------------------------------------------
function reverseIP(ip) { return ip.split(".").reverse().join("."); }

async function checkDNSBL(ip, zone) {
  try {
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(reverseIP(ip) + "." + zone) + "&type=A";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    const answers = (data.Answer || []).filter(r => r.type === 1);
    return answers.length > 0 ? { listed: true, response: answers[0].data } : { listed: false };
  } catch(e) { return { listed: null }; }
}

async function checkAllDNSBLs(ip) {
  return Promise.all(DNSBLS.map(async bl => ({ name: bl.name, zone: bl.zone, delistUrl: bl.delistUrl, ...(await checkDNSBL(ip, bl.zone)) })));
}

async function checkPTR(ip) {
  try {
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(reverseIP(ip) + ".in-addr.arpa") + "&type=PTR";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    const answers = (data.Answer || []).filter(r => r.type === 12);
    return answers.length > 0 ? { found: true, hostname: answers[0].data.replace(/\.$/, "") } : { found: false, hostname: null };
  } catch(e) { return { found: null, hostname: null }; }
}

async function checkForwardConfirmed(hostname, ip) {
  try {
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(hostname) + "&type=A";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    return (data.Answer || []).filter(r => r.type === 1).some(r => r.data === ip);
  } catch(e) { return null; }
}

const DKIM_SELECTORS = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2", "everlytickey1", "everlytickey2", "smtp", "mxvault"];

async function checkDKIM(domain) {
  try {
    const results = await Promise.all(DKIM_SELECTORS.map(async sel => {
      const url = "https://dns.google/resolve?name=" + encodeURIComponent(sel + "._domainkey." + domain) + "&type=TXT";
      const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
      const data = await res.json();
      const rec = (data.Answer || []).filter(r => r.type === 16).find(r => r.data && r.data.includes("v=DKIM1"));
      return rec ? { found: true, selector: sel, value: rec.data.replace(/"/g, "").trim() } : null;
    }));
    return results.find(r => r !== null) || { found: false };
  } catch(e) { return { found: null }; }
}

async function fetchNS(domain) {
  try {
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(domain) + "&type=NS";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    return (data.Answer || []).filter(r => r.type === 2).map(r => r.data.replace(/\.$/, "").toLowerCase());
  } catch(e) { return []; }
}

async function fetchSOA(domain) {
  try {
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(domain) + "&type=SOA";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    const answers = (data.Answer || []).filter(r => r.type === 6);
    if (answers.length > 0) { const parts = answers[0].data.split(" "); return { serial: parts[2] || null, raw: answers[0].data }; }
    return null;
  } catch(e) { return null; }
}

async function queryAuthoritative(domain, type) {
  try {
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(domain) + "&type=" + type + "&cd=1";
    const res = await fetch(url, { headers: { Accept: "application/dns-json", "Cache-Control": "no-cache", "Pragma": "no-cache" } });
    const data = await res.json();
    const typeMap = { A: 1, AAAA: 28, MX: 15, TXT: 16, NS: 2, SOA: 6 };
    const typeNum = typeMap[type];
    return (data.Answer || []).filter(r => !typeNum || r.type === typeNum).map(r => ({ ttl: r.TTL, data: r.data ? r.data.replace(/"/g, "").trim() : "", type: r.type }));
  } catch(e) { return null; }
}

// Sender Score via DNS (Validity / senderscore.org)
async function checkSenderScore(ip) {
  try {
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(reverseIP(ip) + ".score.senderscore.com") + "&type=A";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    const answers = (data.Answer || []).filter(r => r.type === 1);
    if (answers.length > 0) {
      const octets = answers[0].data.split(".");
      return { found: true, score: parseInt(octets[octets.length - 1], 10) };
    }
    return { found: false, score: null };
  } catch(e) { return { found: null, score: null }; }
}

// BIMI record: default._bimi.<domain>
async function checkBIMI(domain) {
  try {
    const url = "https://dns.google/resolve?name=" + encodeURIComponent("default._bimi." + domain) + "&type=TXT";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    const rec = (data.Answer || []).filter(r => r.type === 16).find(r => r.data && r.data.includes("v=BIMI1"));
    if (rec) {
      const val = rec.data.replace(/"/g, "").trim();
      const logoMatch = val.match(/l=([^;]+)/);
      return { found: true, value: val, logoUrl: logoMatch ? logoMatch[1].trim() : null };
    }
    return { found: false };
  } catch(e) { return { found: null }; }
}

// Resolve MX hostnames to IPs for DNSBL check
async function resolveMXIPs(mxHosts) {
  const results = [];
  await Promise.all(mxHosts.slice(0, 4).map(async host => {
    try {
      const url = "https://dns.google/resolve?name=" + encodeURIComponent(host) + "&type=A";
      const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
      const data = await res.json();
      (data.Answer || []).filter(r => r.type === 1).forEach(a => results.push({ host, ip: a.data }));
    } catch(e) {}
  }));
  return results;
}

function countSPFLookups(spfVal) {
  if (!spfVal) return 0;
  return (spfVal.match(/\b(include:|a:|mx:|ptr:|exists:)/g) || []).length;
}

function senderScoreColor(score) {
  if (score >= 80) return "var(--green)";
  if (score >= 60) return "var(--amber)";
  return "var(--red)";
}
function senderScoreBand(score) {
  if (score >= 80) return { label: "Good", cls: "pass" };
  if (score >= 60) return { label: "Fair", cls: "warn" };
  return { label: "Poor", cls: "fail" };
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------
const STYLE = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@600;700;800&family=DM+Sans:wght@300;400;500&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #f4f6f9; --white: #ffffff; --border: #e2e7ef; --border2: #cdd5e0;
    --text: #0f1923; --text-mid: #4a5568; --text-dim: #8896a8;
    --green: #00875a; --green-bg: #e3fcef; --green-border: #abf5d1;
    --red: #de350b; --red-bg: #ffebe6; --red-border: #ffbdad;
    --amber: #974f0c; --amber-bg: #fffae6; --amber-border: #ffe380;
    --blue: #0052cc; --blue-bg: #e6f0ff; --blue-border: #b3d4ff;
    --ms: #0078d4; --ms-bg: #e8f3fb; --ms-border: #b3d9f5;
    --rep: #6b46c1; --rep-bg: #f5f3ff; --rep-border: #ddd6fe;
    --accent: #0052cc;
    --mono: 'DM Mono', monospace; --display: 'Syne', sans-serif; --sans: 'DM Sans', sans-serif;
  }
  body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; }
  .app { max-width: 1000px; margin: 0 auto; padding: 32px 20px 80px; }
  .header { margin-bottom: 28px; }
  .header-eyebrow { display: inline-flex; align-items: center; gap: 6px; background: var(--blue-bg); border: 1px solid var(--blue-border); border-radius: 4px; padding: 4px 10px; margin-bottom: 10px; font-size: 11px; font-weight: 500; color: var(--blue); letter-spacing: 0.08em; text-transform: uppercase; font-family: var(--mono); }
  .pulse { width: 6px; height: 6px; border-radius: 50%; background: var(--accent); animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.5;transform:scale(0.8)} }
  .header h1 { font-family: var(--display); font-size: 28px; font-weight: 800; color: var(--text); letter-spacing: -0.03em; }
  .header p { font-size: 13px; color: var(--text-mid); margin-top: 4px; }
  .search-wrap { background: var(--white); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.05); }
  .search-row { display: flex; gap: 10px; }
  .domain-input { flex: 1; background: var(--bg); border: 1.5px solid var(--border); border-radius: 6px; font-family: var(--mono); font-size: 14px; color: var(--text); padding: 10px 14px; outline: none; transition: border-color 0.15s; }
  .domain-input::placeholder { color: var(--text-dim); }
  .domain-input:focus { border-color: var(--accent); background: var(--white); }
  .btn-scan { background: var(--accent); color: #fff; border: none; border-radius: 6px; font-family: var(--display); font-size: 13px; font-weight: 700; padding: 10px 20px; cursor: pointer; transition: all 0.15s; white-space: nowrap; }
  .btn-scan:hover:not(:disabled) { background: #003d99; }
  .btn-scan:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-fresh { background: var(--white); color: var(--accent); border: 1.5px solid var(--blue-border); border-radius: 6px; font-family: var(--mono); font-size: 11px; font-weight: 600; padding: 10px 14px; cursor: pointer; transition: all 0.15s; white-space: nowrap; letter-spacing: 0.05em; }
  .btn-fresh:hover:not(:disabled) { background: var(--blue-bg); border-color: var(--accent); }
  .btn-fresh:disabled { opacity: 0.4; cursor: not-allowed; }
  .progress-wrap { margin-top: 12px; }
  .progress-track { height: 3px; background: var(--border); border-radius: 2px; overflow: hidden; }
  .progress-fill { height: 100%; background: var(--accent); border-radius: 2px; transition: width 0.4s ease; }
  .progress-label { font-size: 11px; color: var(--text-dim); font-family: var(--mono); margin-top: 5px; }
  .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 16px; }
  .summary-card { background: var(--white); border: 1px solid var(--border); border-radius: 8px; padding: 14px; display: flex; flex-direction: column; gap: 3px; }
  .summary-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.15em; color: var(--text-dim); font-family: var(--mono); }
  .summary-value { font-size: 22px; font-weight: 800; font-family: var(--display); line-height: 1; }
  .summary-sub { font-size: 11px; color: var(--text-dim); }
  .col-green { color: var(--green); } .col-red { color: var(--red); } .col-amber { color: var(--amber); } .col-blue { color: var(--blue); }
  .section { margin-bottom: 12px; }
  .section-header { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: var(--white); border: 1px solid var(--border); border-radius: 8px 8px 0 0; cursor: pointer; user-select: none; }
  .section-header.collapsed { border-radius: 8px; }
  .section-title-row { display: flex; align-items: center; gap: 8px; }
  .section-title { font-family: var(--display); font-size: 13px; font-weight: 700; color: var(--text); }
  .section-count { font-size: 11px; font-family: var(--mono); color: var(--text-dim); }
  .chevron { font-size: 11px; color: var(--text-dim); transition: transform 0.2s; }
  .chevron.open { transform: rotate(180deg); }
  .section-body { background: var(--white); border: 1px solid var(--border); border-top: none; border-radius: 0 0 8px 8px; overflow: hidden; }
  .flag { display: flex; gap: 12px; padding: 12px 14px; border-bottom: 1px solid var(--border); align-items: flex-start; }
  .flag:last-child { border-bottom: none; }
  .flag-icon { font-size: 13px; flex-shrink: 0; font-family: var(--mono); font-weight: 700; margin-top: 1px; }
  .flag-body { flex: 1; }
  .flag-title { font-size: 13px; font-weight: 500; color: var(--text); margin-bottom: 2px; }
  .flag-detail { font-size: 11px; color: var(--text-mid); line-height: 1.5; font-family: var(--mono); word-break: break-all; }
  .flag-fix { font-size: 11px; color: var(--text-mid); margin-top: 3px; line-height: 1.5; }
  .sev-tag { font-size: 9px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; padding: 2px 6px; border-radius: 3px; white-space: nowrap; margin-top: 4px; display: inline-block; font-family: var(--mono); }
  .sev-critical { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
  .sev-warning  { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .sev-info     { background: var(--blue-bg); color: var(--blue); border: 1px solid var(--blue-border); }
  .sev-ok       { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }
  .record-group { border-bottom: 1px solid var(--border); }
  .record-group:last-child { border-bottom: none; }
  .record-type-header { padding: 7px 14px; background: var(--bg); font-size: 10px; font-weight: 500; letter-spacing: 0.15em; text-transform: uppercase; color: var(--text-dim); font-family: var(--mono); border-bottom: 1px solid var(--border); }
  .record-row { display: grid; grid-template-columns: 70px 55px 1fr auto; gap: 10px; padding: 9px 14px; border-bottom: 1px solid var(--border); align-items: center; font-family: var(--mono); font-size: 11px; }
  .record-row:last-child { border-bottom: none; }
  .record-row:hover { background: var(--bg); }
  .rec-type { color: var(--accent); font-weight: 500; }
  .rec-ttl { color: var(--text-dim); }
  .rec-val { color: var(--text); word-break: break-all; }
  .rec-ttl-warn { color: var(--amber); }
  .badge { font-size: 9px; font-weight: 600; letter-spacing: 0.12em; padding: 2px 6px; border-radius: 3px; text-transform: uppercase; font-family: var(--mono); }
  .badge-ok   { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }
  .badge-err  { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
  .badge-warn { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .ttl-note { font-size: 11px; color: var(--text-dim); padding: 9px 14px; font-family: var(--mono); background: var(--bg); border-top: 1px solid var(--border); }
  .prop-grid { display: flex; flex-direction: column; }
  .prop-row { display: grid; grid-template-columns: 90px 1fr repeat(2, 90px); gap: 10px; padding: 9px 14px; border-bottom: 1px solid var(--border); align-items: center; font-size: 11px; }
  .prop-row.header-row { background: var(--bg); font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-dim); padding: 7px 14px; }
  .prop-row:last-child { border-bottom: none; }
  .prop-type { font-family: var(--mono); color: var(--accent); font-weight: 500; }
  .prop-val { font-family: var(--mono); color: var(--text); word-break: break-all; font-size: 10px; }
  .prop-cell { text-align: center; }
  .dot-ok   { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: var(--green); }
  .dot-fail { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: var(--red); }
  .empty-state { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 60px 24px; gap: 10px; text-align: center; }
  .empty-icon { font-size: 36px; opacity: 0.3; font-family: var(--mono); }
  .empty-title { font-family: var(--display); font-size: 15px; font-weight: 700; color: var(--text-mid); }
  .empty-sub { font-size: 12px; color: var(--text-dim); max-width: 340px; line-height: 1.6; }
  @keyframes fadeUp { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
  .fade-up { animation: fadeUp 0.3s ease forwards; }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }
  .ns-bar { display: flex; align-items: flex-start; gap: 10px; padding: 9px 14px; background: var(--blue-bg); border: 1px solid var(--blue-border); border-radius: 6px; margin-bottom: 14px; font-size: 11px; font-family: var(--mono); }
  .ns-bar-label { color: var(--blue); font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; flex-shrink: 0; }
  .ns-bar-hosts { color: var(--text-mid); flex: 1; line-height: 1.6; }
  .ns-bar-serial { color: var(--text-dim); font-size: 10px; flex-shrink: 0; }
  .auth-banner { display: flex; align-items: center; gap: 8px; padding: 8px 14px; background: var(--green-bg); border: 1px solid var(--green-border); border-radius: 6px; margin-bottom: 14px; font-size: 11px; font-family: var(--mono); color: var(--green); }
  .btn-blacklist { background: var(--white); color: var(--accent); border: 1px solid var(--blue-border); border-radius: 4px; font-family: var(--mono); font-size: 10px; font-weight: 600; letter-spacing: 0.08em; padding: 4px 10px; cursor: pointer; transition: all 0.15s; white-space: nowrap; text-transform: uppercase; }
  .btn-blacklist:hover:not(:disabled) { background: var(--blue-bg); border-color: var(--accent); }
  .btn-blacklist:disabled { opacity: 0.5; cursor: not-allowed; }
  .bl-panel { padding: 12px 14px; border-top: 1px solid var(--border); background: var(--bg); }
  .bl-title { font-size: 10px; font-weight: 600; letter-spacing: 0.15em; text-transform: uppercase; color: var(--text-dim); font-family: var(--mono); margin-bottom: 10px; }
  .bl-row { display: flex; align-items: center; justify-content: space-between; padding: 7px 0; border-bottom: 1px solid var(--border); font-size: 12px; gap: 12px; }
  .bl-row:last-child { border-bottom: none; }
  .bl-name { font-family: var(--mono); color: var(--text); flex: 1; }
  .bl-zone { font-family: var(--mono); font-size: 10px; color: var(--text-dim); flex: 2; }
  .bl-actions { display: flex; align-items: center; gap: 6px; flex-shrink: 0; }
  .bl-status-listed { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); font-size: 9px; font-weight: 700; letter-spacing: 0.1em; padding: 2px 7px; border-radius: 3px; text-transform: uppercase; font-family: var(--mono); white-space: nowrap; }
  .bl-status-clean  { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); font-size: 9px; font-weight: 700; letter-spacing: 0.1em; padding: 2px 7px; border-radius: 3px; text-transform: uppercase; font-family: var(--mono); white-space: nowrap; }
  .bl-status-error  { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); font-size: 9px; font-weight: 700; letter-spacing: 0.1em; padding: 2px 7px; border-radius: 3px; text-transform: uppercase; font-family: var(--mono); white-space: nowrap; }
  .btn-delist { display: inline-flex; align-items: center; gap: 3px; background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); border-radius: 3px; font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: 0.08em; padding: 2px 7px; cursor: pointer; text-decoration: none; text-transform: uppercase; white-space: nowrap; transition: all 0.15s; }
  .btn-delist:hover { background: var(--red); color: #fff; border-color: var(--red); }
  .bl-summary { font-size: 11px; margin-top: 10px; font-family: var(--mono); }
  .bl-summary.clean { color: var(--green); }
  .bl-summary.listed { color: var(--red); font-weight: 600; }
  .ms-panel { border-top: 1px solid var(--border); background: var(--white); }
  .ms-panel-header { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: var(--ms-bg); border-bottom: 1px solid var(--ms-border); }
  .ms-panel-title { display: flex; align-items: center; gap: 8px; font-family: var(--display); font-size: 12px; font-weight: 700; color: var(--ms); }
  .ms-logo { font-family: var(--mono); font-weight: 700; background: var(--ms); color: white; padding: 1px 5px; border-radius: 2px; font-size: 11px; letter-spacing: 0.05em; }
  .ms-actions { display: flex; gap: 6px; align-items: center; }
  .btn-ms { background: var(--white); color: var(--ms); border: 1px solid var(--ms-border); border-radius: 4px; font-family: var(--mono); font-size: 10px; font-weight: 600; letter-spacing: 0.08em; padding: 4px 10px; cursor: pointer; transition: all 0.15s; white-space: nowrap; text-transform: uppercase; text-decoration: none; display: inline-flex; align-items: center; gap: 4px; }
  .btn-ms:hover { background: var(--ms-bg); border-color: var(--ms); }
  .btn-ms:disabled { opacity: 0.5; cursor: not-allowed; }
  .ms-checks { padding: 10px 14px; background: var(--bg); }
  .ms-check-row { display: flex; align-items: flex-start; gap: 10px; padding: 8px 0; border-bottom: 1px solid var(--border); }
  .ms-check-row:last-child { border-bottom: none; }
  .ms-check-icon { font-family: var(--mono); font-size: 10px; font-weight: 700; flex-shrink: 0; min-width: 34px; margin-top: 1px; }
  .ms-check-icon.pass { color: var(--green); } .ms-check-icon.fail { color: var(--red); } .ms-check-icon.warn { color: var(--amber); } .ms-check-icon.info { color: var(--blue); }
  .ms-check-body { flex: 1; }
  .ms-check-title { font-size: 12px; font-weight: 500; color: var(--text); }
  .ms-check-detail { font-size: 10px; color: var(--text-mid); font-family: var(--mono); margin-top: 2px; word-break: break-all; }
  .ms-check-fix { font-size: 10px; color: var(--text-mid); margin-top: 2px; }
  .ms-check-sev { font-size: 9px; font-weight: 700; letter-spacing: 0.1em; padding: 2px 6px; border-radius: 3px; text-transform: uppercase; font-family: var(--mono); display: inline-block; margin-top: 3px; }
  .ms-check-sev.pass { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }
  .ms-check-sev.fail { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
  .ms-check-sev.warn { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .ms-check-sev.info { background: var(--blue-bg); color: var(--blue); border: 1px solid var(--blue-border); }
  .ms-jmrp { display: flex; align-items: flex-start; gap: 8px; margin: 10px 14px; padding: 9px 12px; background: var(--ms-bg); border: 1px solid var(--ms-border); border-radius: 6px; }
  .ms-jmrp-icon { font-size: 14px; flex-shrink: 0; }
  .ms-jmrp-body { flex: 1; }
  .ms-jmrp-title { font-size: 11px; font-weight: 600; color: var(--ms); font-family: var(--mono); letter-spacing: 0.05em; text-transform: uppercase; margin-bottom: 3px; }
  .ms-jmrp-text { font-size: 11px; color: var(--text-mid); line-height: 1.5; }
  .ms-jmrp-link { color: var(--ms); text-decoration: underline; font-family: var(--mono); font-size: 10px; }
  .ms-checking { font-size: 11px; color: var(--text-dim); font-family: var(--mono); padding: 12px 14px; }

  /* ── Sender Reputation Panel ── */
  .rep-panel { background: var(--white); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 12px; }
  .rep-header { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: var(--rep-bg); border-bottom: 1px solid var(--rep-border); flex-wrap: wrap; gap: 8px; }
  .rep-title { display: flex; align-items: center; gap: 8px; font-family: var(--display); font-size: 13px; font-weight: 700; color: var(--rep); }
  .rep-logo { font-family: var(--mono); font-weight: 700; background: var(--rep); color: white; padding: 1px 6px; border-radius: 2px; font-size: 11px; letter-spacing: 0.05em; }
  .rep-links { display: flex; gap: 6px; flex-wrap: wrap; }
  .btn-rep { background: var(--white); color: var(--rep); border: 1px solid var(--rep-border); border-radius: 4px; font-family: var(--mono); font-size: 10px; font-weight: 600; letter-spacing: 0.06em; padding: 4px 10px; cursor: pointer; transition: all 0.15s; white-space: nowrap; text-transform: uppercase; text-decoration: none; display: inline-flex; align-items: center; gap: 4px; }
  .btn-rep:hover { background: var(--rep-bg); border-color: var(--rep); }
  .btn-rep:disabled { opacity: 0.5; cursor: not-allowed; }
  .rep-checking { font-size: 11px; color: var(--text-dim); font-family: var(--mono); padding: 12px 14px; }
  .score-row { display: flex; align-items: center; gap: 14px; padding: 14px 14px 12px; border-bottom: 1px solid var(--border); }
  .score-meter-wrap { flex: 1; }
  .score-meter-label { font-size: 10px; font-family: var(--mono); color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 6px; }
  .score-meter-track { height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; }
  .score-meter-fill { height: 100%; border-radius: 4px; transition: width 0.6s ease; }
  .score-num { font-family: var(--display); font-size: 28px; font-weight: 800; line-height: 1; min-width: 52px; text-align: right; }
  .score-sub { font-size: 10px; color: var(--text-dim); font-family: var(--mono); margin-top: 2px; text-align: right; }
  .score-band { font-size: 9px; font-weight: 700; letter-spacing: 0.12em; padding: 2px 7px; border-radius: 3px; text-transform: uppercase; font-family: var(--mono); display: inline-block; margin-top: 5px; }
  .score-band.pass { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }
  .score-band.warn { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .score-band.fail { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
  .rep-check-row { display: flex; align-items: flex-start; gap: 10px; padding: 10px 14px; border-bottom: 1px solid var(--border); }
  .rep-check-row:last-child { border-bottom: none; }
  .rep-check-icon { font-family: var(--mono); font-size: 10px; font-weight: 700; flex-shrink: 0; min-width: 34px; margin-top: 1px; }
  .rep-check-icon.pass { color: var(--green); } .rep-check-icon.fail { color: var(--red); } .rep-check-icon.warn { color: var(--amber); } .rep-check-icon.info { color: var(--blue); }
  .rep-check-body { flex: 1; }
  .rep-check-title { font-size: 12px; font-weight: 500; color: var(--text); }
  .rep-check-detail { font-size: 10px; color: var(--text-mid); font-family: var(--mono); margin-top: 2px; word-break: break-all; line-height: 1.5; }
  .rep-check-fix { font-size: 10px; color: var(--text-mid); margin-top: 2px; line-height: 1.5; }
  .rep-check-sev { font-size: 9px; font-weight: 700; letter-spacing: 0.1em; padding: 2px 6px; border-radius: 3px; text-transform: uppercase; font-family: var(--mono); display: inline-block; margin-top: 3px; }
  .rep-check-sev.pass { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }
  .rep-check-sev.fail { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
  .rep-check-sev.warn { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .rep-check-sev.info { background: var(--blue-bg); color: var(--blue); border: 1px solid var(--blue-border); }
  .bimi-row { display: flex; align-items: center; gap: 12px; padding: 9px 14px; border-bottom: 1px solid var(--border); background: var(--bg); font-size: 11px; font-family: var(--mono); }
  .bimi-label { color: var(--text-dim); font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; flex-shrink: 0; }
  .bimi-url { color: var(--text-mid); flex: 1; word-break: break-all; }
  .mx-bl-wrap { padding: 10px 14px; border-bottom: 1px solid var(--border); background: var(--bg); }
  .mx-bl-label { font-size: 10px; font-family: var(--mono); color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 7px; }
  .mx-bl-table { border: 1px solid var(--border); border-radius: 4px; overflow: hidden; }
  .mx-bl-row { display: flex; gap: 10px; padding: 5px 10px; border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 10px; align-items: center; }
  .mx-bl-row:last-child { border-bottom: none; }
  .mx-bl-row:nth-child(odd) { background: var(--white); }
  .mx-bl-host { color: var(--text-mid); flex: 2; }
  .mx-bl-ip { color: var(--accent); flex: 1; }
  .mx-bl-result { flex-shrink: 0; }

  @media (max-width: 600px) {
    .summary { grid-template-columns: 1fr 1fr; }
    .prop-row { grid-template-columns: 70px 1fr repeat(2, 54px); font-size: 10px; }
    .bl-zone { display: none; }
    .ms-actions { flex-direction: column; align-items: flex-end; gap: 4px; }
    .score-row { flex-direction: column; align-items: flex-start; gap: 8px; }
    .score-num { text-align: left; }
  }
`;

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------
async function queryResolver(resolverUrl, domain, type) {
  try {
    const url = resolverUrl + "?name=" + encodeURIComponent(domain) + "&type=" + type;
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    const typeMap = { A: 1, AAAA: 28, MX: 15, TXT: 16 };
    const typeNum = typeMap[type];
    const answers = data.Answer || [];
    const filtered = typeNum ? answers.filter(r => r.type === typeNum) : answers;
    return filtered.map(r => ({ ttl: r.TTL, data: r.data ? r.data.replace(/"/g, "").trim() : "", type: r.type }));
  } catch(e) { return null; }
}

async function queryAll(domain, type) {
  return Promise.all(RESOLVERS.map(r => queryResolver(r.url, domain, type)));
}

function ttlToHuman(ttl) {
  if (ttl >= 86400) return Math.round(ttl / 86400) + "d";
  if (ttl >= 3600)  return Math.round(ttl / 3600) + "h";
  if (ttl >= 60)    return Math.round(ttl / 60) + "m";
  return ttl + "s";
}

function parseMXHost(raw) {
  if (!raw) return "";
  const parts = raw.split(" ");
  return (parts.length > 1 ? parts.slice(1).join(" ") : parts[0]).replace(/\.$/, "").trim().toLowerCase();
}

// ---------------------------------------------------------------------------
// Flag generation
// ---------------------------------------------------------------------------
function generateFlags(records, domain) {
  const flags = [];
  const { A, MX, spf, dmarc, dkim } = records;
  const ehMX = expectedMX(domain);

  // SPF
  if (!spf || spf.length === 0) {
    flags.push({ sev: "critical", icon: "FAIL", title: "No SPF record found", detail: "", fix: "Add TXT record: " + EH_SPF });
  } else if (spf.length > 1) {
    flags.push({ sev: "critical", icon: "FAIL", title: "Multiple SPF records detected", detail: spf.map(r => r.data).join(" | "), fix: "Merge into a single SPF record." });
  } else {
    const spfVal = spf[0] ? spf[0].data : "";
    if (spfVal.includes("+all")) {
      flags.push({ sev: "critical", icon: "FAIL", title: "SPF uses +all (too permissive)", detail: spfVal, fix: "Change +all to ~all or -all. +all allows any server to send as this domain." });
    } else if (spfVal.includes("-all")) {
      if (!spfVal.includes("spf.exacthosting.com")) {
        flags.push({ sev: "warning", icon: "WARN", title: "SPF hardfail (-all) but missing Exact Hosting include", detail: spfVal, fix: "Add include:spf.exacthosting.com before the -all mechanism." });
      } else {
        flags.push({ sev: "ok", icon: "PASS", title: "SPF uses hardfail (-all) — strict enforcement", detail: spfVal });
      }
    } else if (!spfVal.includes("spf.exacthosting.com")) {
      flags.push({ sev: "warning", icon: "WARN", title: "SPF does not include Exact Hosting", detail: spfVal, fix: "Expected: include:spf.exacthosting.com" });
    } else {
      flags.push({ sev: "ok", icon: "PASS", title: "SPF record looks correct (softfail ~all)", detail: spfVal });
    }
  }

  // DMARC
  if (!dmarc || dmarc.length === 0) {
    flags.push({ sev: "warning", icon: "WARN", title: "No DMARC record found", detail: "", fix: "Add a TXT record on _dmarc subdomain." });
  } else {
    const dmarcVal = dmarc[0] ? dmarc[0].data : "";
    if (dmarcVal.includes("p=none")) {
      flags.push({ sev: "info", icon: "INFO", title: "DMARC policy is none (monitoring only)", detail: dmarcVal, fix: "Consider upgrading to p=quarantine or p=reject." });
    } else {
      flags.push({ sev: "ok", icon: "PASS", title: "DMARC policy is enforced", detail: dmarcVal });
    }
    if (!dmarcVal.includes("rua=")) {
      flags.push({ sev: "info", icon: "INFO", title: "DMARC has no rua= reporting address", detail: "Without aggregate reports the domain is blind to spoofing attempts.", fix: "Add rua=mailto:dmarc@" + domain + " to the DMARC record." });
    }
  }

  // DKIM
  if (!dkim || dkim.found === null) {
    flags.push({ sev: "warning", icon: "WARN", title: "DKIM check inconclusive", detail: "Could not query DKIM selectors.", fix: null });
  } else if (!dkim.found) {
    flags.push({ sev: "warning", icon: "WARN", title: "No DKIM record found", detail: "Checked selectors: " + DKIM_SELECTORS.join(", "), fix: "Set up DKIM signing. Add the public key TXT record at <selector>._domainkey." + domain });
  } else {
    flags.push({ sev: "ok", icon: "PASS", title: "DKIM record found (selector: " + dkim.selector + ")", detail: dkim.value });
  }

  // MX
  if (!MX || MX.length === 0) {
    flags.push({ sev: "critical", icon: "FAIL", title: "No MX records found -- email will not deliver", detail: "", fix: "Add MX records: " + ehMX.join(" and ") });
  } else {
    const mxHosts = MX.map(r => parseMXHost(r.data));
    const ipMX = MX.filter(r => /^\d+\s+\d+\.\d+/.test(r.data));
    if (ipMX.length > 0) flags.push({ sev: "critical", icon: "FAIL", title: "MX record points to an IP address", detail: ipMX[0] ? ipMX[0].data : "", fix: "MX must point to a hostname, not an IP." });
    const hasA = mxHosts.some(h => h.includes(ehMX[0].toLowerCase()));
    const hasB = mxHosts.some(h => h.includes(ehMX[1].toLowerCase()));
    if (!hasA && !hasB) {
      flags.push({ sev: "critical", icon: "FAIL", title: "MX records do not match Hosted Email pattern", detail: mxHosts.join(", "), fix: "Expected: " + ehMX.join(" and ") });
    } else if (!hasA || !hasB) {
      const missing = !hasA ? ehMX[0] : ehMX[1];
      flags.push({ sev: "warning", icon: "WARN", title: "Only one cluster present -- missing " + (!hasA ? "Cluster A" : "Cluster B"), detail: mxHosts.join(", "), fix: "Add missing MX: " + missing });
    } else {
      flags.push({ sev: "ok", icon: "PASS", title: "MX records match both Hosted Email clusters", detail: mxHosts.join(", ") });
    }
  }

  // A record
  if (!A || A.length === 0) {
    flags.push({ sev: "warning", icon: "WARN", title: "No A record found", detail: "", fix: "Add an A record pointing to your server IP." });
  } else {
    const highTTL = A.find(r => r.ttl > 86400);
    if (highTTL) {
      flags.push({ sev: "info", icon: "INFO", title: "A record TTL is very high (" + ttlToHuman(highTTL.ttl) + ")", detail: "IP: " + highTTL.data, fix: "Lower TTL to 300-3600 before making IP changes." });
    } else {
      flags.push({ sev: "ok", icon: "PASS", title: "A record present", detail: A.map(r => r.data).join(", ") });
    }
  }

  return flags;
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------
function CollapsibleSection({ title, count, badge, children, defaultOpen }) {
  const [isOpen, setIsOpen] = useState(defaultOpen !== false);
  return (
    <div className="section">
      <div className={"section-header" + (isOpen ? "" : " collapsed")} onClick={() => setIsOpen(o => !o)}>
        <div className="section-title-row">
          <span className="section-title">{title}</span>
          {count !== undefined && <span className="section-count">{count} record{count !== 1 ? "s" : ""}</span>}
          {badge}
        </div>
        <span className={"chevron" + (isOpen ? " open" : "")}>v</span>
      </div>
      {isOpen && <div className="section-body">{children}</div>}
    </div>
  );
}

function FlagItem({ sev, icon, title, detail, fix }) {
  const cls = sev === "critical" ? "sev-critical" : sev === "warning" ? "sev-warning" : sev === "info" ? "sev-info" : "sev-ok";
  return (
    <div className="flag">
      <span className="flag-icon">{icon}</span>
      <div className="flag-body">
        <div className="flag-title">{title}</div>
        {detail && <div className="flag-detail">{detail}</div>}
        {fix && <div className="flag-fix">Fix: {fix}</div>}
        <span className={"sev-tag " + cls}>{sev === "ok" ? "pass" : sev}</span>
      </div>
    </div>
  );
}

function NSInfoBar({ ns, soa }) {
  if (!ns || ns.length === 0) return null;
  return (
    <div className="ns-bar">
      <span className="ns-bar-label">NS</span>
      <span className="ns-bar-hosts">{ns.join("  •  ")}</span>
      {soa && soa.serial && <span className="ns-bar-serial">SOA serial: {soa.serial}</span>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sender Reputation Panel
// ---------------------------------------------------------------------------
function SenderReputationPanel({ ip, domain, spfVal, dmarcVal, mxHosts }) {
  const [state, setState] = useState("idle");
  const [checks, setChecks] = useState([]);
  const [senderScore, setSenderScore] = useState(null);
  const [bimi, setBimi] = useState(null);
  const [mxBlResults, setMxBlResults] = useState([]);

  async function runChecks() {
    setState("checking");
    setChecks([]); setSenderScore(null); setBimi(null); setMxBlResults([]);
    const newChecks = [];

    // 1. Sender Score
    const ss = await checkSenderScore(ip);
    setSenderScore(ss);
    if (ss.found === true) {
      if (ss.score < 60) newChecks.push({ sev: "fail", title: "Sender Score is poor (" + ss.score + "/100)", detail: "A score below 60 indicates significant reputation problems that will cause spam filtering at many receivers.", fix: "Investigate blacklist listings, complaint rates and sending practices. Review at senderscore.org." });
      else if (ss.score < 80) newChecks.push({ sev: "warn", title: "Sender Score is fair (" + ss.score + "/100)", detail: "Scores between 60–79 may trigger spam filtering at stricter receivers.", fix: "Monitor complaint rates and ensure DMARC reporting is enabled to catch abuse early." });
      else newChecks.push({ sev: "pass", title: "Sender Score is good (" + ss.score + "/100)", detail: "Score of " + ss.score + " indicates a healthy sending reputation for " + ip + ".", fix: null });
    } else if (ss.found === false) {
      newChecks.push({ sev: "info", title: "No Sender Score data for this IP", detail: ip + " is not yet in the Sender Score database. Common for new or low-volume IPs.", fix: null });
    } else {
      newChecks.push({ sev: "info", title: "Sender Score lookup unavailable", detail: "Could not query score.senderscore.com DNS zone.", fix: null });
    }

    // 2. BIMI
    const bimiResult = await checkBIMI(domain);
    setBimi(bimiResult);
    if (bimiResult.found === true) {
      newChecks.push({ sev: "pass", title: "BIMI record found (default._bimi." + domain + ")", detail: bimiResult.value, fix: null });
    } else if (bimiResult.found === false) {
      newChecks.push({ sev: "info", title: "No BIMI record found", detail: "BIMI enables brand logo display in Gmail, Yahoo and Apple Mail. Requires an enforced DMARC policy (p=quarantine or p=reject).", fix: "Add TXT at default._bimi." + domain + ": v=BIMI1; l=https://yourdomain.com/logo.svg" });
    } else {
      newChecks.push({ sev: "info", title: "BIMI check inconclusive", detail: "Could not query BIMI record.", fix: null });
    }

    // 3. SPF hardfail / softfail
    if (spfVal) {
      if (spfVal.includes("-all")) {
        newChecks.push({ sev: "pass", title: "SPF uses hardfail (-all) — strong outbound reputation signal", detail: "Receiving servers will reject unauthorized senders outright. Strongest SPF posture.", fix: null });
      } else if (spfVal.includes("~all")) {
        newChecks.push({ sev: "info", title: "SPF uses softfail (~all)", detail: "Unauthorized mail is flagged but not rejected. Some filters treat softfail the same as hardfail, others are lenient.", fix: "Once all legitimate sending IPs are confirmed in SPF, upgrade to -all for stronger enforcement." });
      }
    }

    // 4. DMARC rua reporting
    if (dmarcVal) {
      const ruaMatch = dmarcVal.match(/rua=mailto:([^;,\s]+)/);
      if (ruaMatch) {
        newChecks.push({ sev: "pass", title: "DMARC aggregate reporting configured", detail: "Aggregate reports will be delivered to: " + ruaMatch[1], fix: null });
      } else {
        newChecks.push({ sev: "warn", title: "DMARC has no rua= aggregate reporting address", detail: "Without rua= you have no visibility into SPF/DKIM failures or spoofing attempts against this domain.", fix: "Add rua=mailto:dmarc@" + domain + " to the DMARC TXT record." });
      }
    }

    // 5. MX IP DNSBL check
    if (mxHosts && mxHosts.length > 0) {
      const mxIPs = await resolveMXIPs(mxHosts);
      if (mxIPs.length > 0) {
        const mxBL = await Promise.all(mxIPs.map(async ({ host, ip: mxip }) => ({ host, ip: mxip, ...(await checkDNSBL(mxip, "zen.spamhaus.org")) })));
        setMxBlResults(mxBL);
        const listed = mxBL.filter(r => r.listed === true);
        if (listed.length > 0) {
          newChecks.push({ sev: "fail", title: "MX server IP(s) listed on Spamhaus ZEN", detail: listed.map(r => r.ip + " (" + r.host + ")").join(", "), fix: "Inbound mail may be rejected by senders checking your MX IPs. Request delisting at check.spamhaus.org." });
        } else {
          newChecks.push({ sev: "pass", title: "MX server IPs are clean on Spamhaus ZEN", detail: mxBL.map(r => r.ip + " (" + r.host + ")").join(", "), fix: null });
        }
      } else {
        newChecks.push({ sev: "info", title: "Could not resolve MX server IPs for DNSBL check", detail: "MX hostnames did not return A records.", fix: null });
      }
    }

    setChecks(newChecks);
    setState("done");
  }

  const ic = c => c.sev === "pass" ? "pass" : c.sev === "fail" ? "fail" : c.sev === "warn" ? "warn" : "info";
  const il = c => c.sev === "pass" ? "PASS" : c.sev === "fail" ? "FAIL" : c.sev === "warn" ? "WARN" : "INFO";
  const ssColor = senderScore && senderScore.found ? senderScoreColor(senderScore.score) : "var(--text-dim)";
  const ssBand  = senderScore && senderScore.found ? senderScoreBand(senderScore.score) : null;

  return (
    <div className="rep-panel">
      <div className="rep-header">
        <div className="rep-title"><span className="rep-logo">REP</span> Sender Reputation</div>
        <div className="rep-links">
          <button className="btn-rep" onClick={runChecks} disabled={state === "checking"}>
            {state === "checking" ? "Checking..." : state === "done" ? "Re-run" : "Run Checks"}
          </button>
          <a className="btn-rep" href={"https://www.senderscore.org/lookup/?lookup=" + encodeURIComponent(ip)} target="_blank" rel="noopener noreferrer">Sender Score ↗</a>
          <a className="btn-rep" href={"https://postmaster.google.com/u/0/managedomains?d=" + encodeURIComponent(domain)} target="_blank" rel="noopener noreferrer">Google Postmaster ↗</a>
          <a className="btn-rep" href={"https://talosintelligence.com/reputation_center/lookup?search=" + encodeURIComponent(ip)} target="_blank" rel="noopener noreferrer">Talos ↗</a>
        </div>
      </div>

      {state === "checking" && <div className="rep-checking">Running sender reputation checks...</div>}

      {state === "done" && (
        <>
          {/* Sender Score meter */}
          {senderScore && senderScore.found === true && (
            <div className="score-row">
              <div className="score-meter-wrap">
                <div className="score-meter-label">Sender Score (Validity) — {ip}</div>
                <div className="score-meter-track">
                  <div className="score-meter-fill" style={{ width: senderScore.score + "%", background: ssColor }} />
                </div>
                {ssBand && <span className={"score-band " + ssBand.cls}>{ssBand.label}</span>}
              </div>
              <div>
                <div className="score-num" style={{ color: ssColor }}>{senderScore.score}</div>
                <div className="score-sub">out of 100</div>
              </div>
            </div>
          )}

          {/* BIMI logo URL */}
          {bimi && bimi.found && bimi.logoUrl && (
            <div className="bimi-row">
              <span className="bimi-label">BIMI Logo</span>
              <span className="bimi-url">{bimi.logoUrl}</span>
              <a href={bimi.logoUrl} target="_blank" rel="noopener noreferrer" style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--accent)", whiteSpace: "nowrap" }}>View ↗</a>
            </div>
          )}

          {/* MX IP DNSBL table */}
          {mxBlResults.length > 0 && (
            <div className="mx-bl-wrap">
              <div className="mx-bl-label">MX Server IPs — Spamhaus ZEN</div>
              <div className="mx-bl-table">
                {mxBlResults.map((r, i) => (
                  <div className="mx-bl-row" key={i}>
                    <span className="mx-bl-host">{r.host}</span>
                    <span className="mx-bl-ip">{r.ip}</span>
                    <span className="mx-bl-result">
                      {r.listed === true  && <span className="bl-status-listed">Listed</span>}
                      {r.listed === false && <span className="bl-status-clean">Clean</span>}
                      {r.listed === null  && <span className="bl-status-error">Error</span>}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Check rows */}
          {checks.map((c, i) => (
            <div className="rep-check-row" key={i}>
              <span className={"rep-check-icon " + ic(c)}>{il(c)}</span>
              <div className="rep-check-body">
                <div className="rep-check-title">{c.title}</div>
                {c.detail && <div className="rep-check-detail">{c.detail}</div>}
                {c.fix && <div className="rep-check-fix">Fix: {c.fix}</div>}
                <span className={"rep-check-sev " + ic(c)}>{c.sev}</span>
              </div>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Microsoft Panel
// ---------------------------------------------------------------------------
function MicrosoftPanel({ ip, domain, spfVal, dmarcVal }) {
  const [msState, setMsState] = useState("idle");
  const [msChecks, setMsChecks] = useState([]);

  async function runMsChecks() {
    setMsState("checking"); setMsChecks([]);
    const checks = [];
    const ptr = await checkPTR(ip);
    if (ptr.found === null) { checks.push({ sev: "warn", title: "rDNS check failed", detail: "Could not query PTR record.", fix: null }); }
    else if (!ptr.found) { checks.push({ sev: "fail", title: "No reverse DNS (PTR) record found", detail: ip + " has no PTR record.", fix: "Add a PTR record for this IP. Contact your hosting provider or datacenter." }); }
    else {
      const fcrdns = await checkForwardConfirmed(ptr.hostname, ip);
      if (fcrdns === null) checks.push({ sev: "warn", title: "PTR found but forward check failed", detail: "PTR: " + ptr.hostname, fix: null });
      else if (!fcrdns) checks.push({ sev: "fail", title: "FCrDNS failed — PTR does not resolve back to " + ip, detail: "PTR: " + ptr.hostname, fix: "Ensure " + ptr.hostname + " A record points to " + ip + ". Microsoft requires FCrDNS." });
      else checks.push({ sev: "pass", title: "rDNS is forward-confirmed (FCrDNS)", detail: ip + " → " + ptr.hostname + " → " + ip, fix: null });
    }
    const dkim = await checkDKIM(domain);
    if (dkim.found === null) checks.push({ sev: "warn", title: "DKIM check failed", detail: "Could not query DKIM selectors.", fix: null });
    else if (!dkim.found) checks.push({ sev: "fail", title: "No DKIM record found", detail: "Checked: " + DKIM_SELECTORS.join(", "), fix: "Set up DKIM signing for " + domain + ". Microsoft filters weight DKIM heavily." });
    else checks.push({ sev: "pass", title: "DKIM record found (selector: " + dkim.selector + ")", detail: dkim.selector + "._domainkey." + domain, fix: null });
    if (!dmarcVal) checks.push({ sev: "fail", title: "No DMARC record", detail: "Missing _dmarc." + domain, fix: "Add: v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain });
    else if (dmarcVal.includes("p=none")) checks.push({ sev: "warn", title: "DMARC policy is p=none", detail: dmarcVal, fix: "Upgrade to p=quarantine or p=reject for better Microsoft reputation." });
    else checks.push({ sev: "pass", title: "DMARC policy enforced (" + (dmarcVal.match(/p=\w+/)?.[0] || "set") + ")", detail: dmarcVal, fix: null });
    if (!spfVal) { checks.push({ sev: "fail", title: "No SPF record", detail: "SPF lookup count check skipped.", fix: null }); }
    else {
      const n = countSPFLookups(spfVal);
      if (n > 10) checks.push({ sev: "fail", title: "SPF exceeds 10 DNS lookup limit (" + n + " found)", detail: spfVal, fix: "Microsoft strictly enforces the 10-lookup limit. Flatten SPF or use a flattening service." });
      else if (n >= 8) checks.push({ sev: "warn", title: "SPF approaching lookup limit (" + n + "/10)", detail: spfVal, fix: (10 - n) + " lookup(s) remaining. Avoid adding more includes." });
      else checks.push({ sev: "pass", title: "SPF lookup count OK (" + n + "/10)", detail: spfVal, fix: null });
    }
    setMsChecks(checks); setMsState("done");
  }

  return (
    <div className="ms-panel">
      <div className="ms-panel-header">
        <div className="ms-panel-title"><span className="ms-logo">MS</span> Microsoft Deliverability</div>
        <div className="ms-actions">
          <button className="btn-ms" onClick={runMsChecks} disabled={msState === "checking"}>
            {msState === "checking" ? "Checking..." : msState === "done" ? "Re-run" : "Run MS Checks"}
          </button>
          <a className="btn-ms" href="https://sendersupport.olc.protection.outlook.com/snds/" target="_blank" rel="noopener noreferrer">SNDS Portal ↗</a>
        </div>
      </div>
      {msState === "checking" && <div className="ms-checking">Running Microsoft deliverability checks...</div>}
      {msState === "done" && (
        <>
          <div className="ms-checks">
            {msChecks.map((c, i) => (
              <div className="ms-check-row" key={i}>
                <span className={"ms-check-icon " + c.sev}>{c.sev === "pass" ? "PASS" : c.sev === "fail" ? "FAIL" : c.sev === "warn" ? "WARN" : "INFO"}</span>
                <div className="ms-check-body">
                  <div className="ms-check-title">{c.title}</div>
                  {c.detail && <div className="ms-check-detail">{c.detail}</div>}
                  {c.fix && <div className="ms-check-fix">Fix: {c.fix}</div>}
                  <span className={"ms-check-sev " + c.sev}>{c.sev}</span>
                </div>
              </div>
            ))}
          </div>
          <div className="ms-jmrp">
            <span className="ms-jmrp-icon">i</span>
            <div className="ms-jmrp-body">
              <div className="ms-jmrp-title">JMRP Enrollment</div>
              <div className="ms-jmrp-text">
                Check whether this IP is enrolled in Microsoft's Junk Mail Reporting Program.{" "}
                <a className="ms-jmrp-link" href="https://sendersupport.olc.protection.outlook.com/snds/JMRP.aspx" target="_blank" rel="noopener noreferrer">JMRP signup / status ↗</a>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Blacklist Checker
// ---------------------------------------------------------------------------
function BlacklistChecker({ ip, domain, spfVal, dmarcVal, mxHosts }) {
  const [blState, setBlState] = useState("idle");
  const [blResults, setBlResults] = useState([]);

  async function runCheck() {
    setBlState("checking"); setBlResults([]);
    setBlResults(await checkAllDNSBLs(ip));
    setBlState("done");
  }

  const listedCount = blResults.filter(r => r.listed === true).length;

  return (
    <div>
      <div style={{ padding: "10px 14px", borderTop: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 12, background: "var(--white)" }}>
        <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)" }}>IP: {ip}</span>
        <button className="btn-blacklist" onClick={runCheck} disabled={blState === "checking"}>
          {blState === "checking" ? "Checking..." : blState === "done" ? "Re-check Blacklists" : "Check Blacklists"}
        </button>
      </div>
      {blState === "done" && (
        <div className="bl-panel">
          <div className="bl-title">Blacklist Check Results for {ip}</div>
          {blResults.map((r, i) => (
            <div className="bl-row" key={i}>
              <span className="bl-name">{r.name}</span>
              <span className="bl-zone">{r.zone}</span>
              <div className="bl-actions">
                {r.listed === true  && <span className="bl-status-listed">Listed</span>}
                {r.listed === false && <span className="bl-status-clean">Clean</span>}
                {r.listed === null  && <span className="bl-status-error">Error</span>}
                {r.listed === true && r.delistUrl && <a className="btn-delist" href={r.delistUrl} target="_blank" rel="noopener noreferrer">Delist ↗</a>}
              </div>
            </div>
          ))}
          <div className={"bl-summary " + (listedCount > 0 ? "listed" : "clean")}>
            {listedCount > 0 ? listedCount + " of " + blResults.length + " blacklists returned a listing." : "Not listed on any of the " + blResults.length + " blacklists checked."}
          </div>
        </div>
      )}
      <MicrosoftPanel ip={ip} domain={domain} spfVal={spfVal} dmarcVal={dmarcVal} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Record Table
// ---------------------------------------------------------------------------
function RecordTable({ records, domain, spfVal, dmarcVal, mxHosts }) {
  const types = ["A", "AAAA", "MX", "TXT"];
  return (
    <div>
      {types.map(type => {
        const recs = records[type];
        if (!recs || recs.length === 0) return null;
        return (
          <div className="record-group" key={type}>
            <div className="record-type-header">{type} records</div>
            {recs.map((r, i) => (
              <div className="record-row" key={i}>
                <span className="rec-type">{type}</span>
                <span className={r.ttl > 3600 ? "rec-ttl rec-ttl-warn" : "rec-ttl"}>{ttlToHuman(r.ttl)}</span>
                <span className="rec-val">{r.data}</span>
                {r.ttl > 3600 ? <span className="badge badge-warn">High TTL</span> : <span />}
              </div>
            ))}
            {type === "A" && recs.map((r, i) => (
              <BlacklistChecker key={"bl-" + i} ip={r.data} domain={domain} spfVal={spfVal} dmarcVal={dmarcVal} mxHosts={mxHosts} />
            ))}
          </div>
        );
      })}
      {records.dkim && records.dkim.found && (
        <div className="record-group">
          <div className="record-type-header">DKIM records</div>
          <div className="record-row">
            <span className="rec-type">TXT</span>
            <span className="rec-ttl">--</span>
            <span className="rec-val">{records.dkim.selector}._domainkey → {records.dkim.value}</span>
            <span className="badge badge-ok">DKIM</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Propagation Grid
// ---------------------------------------------------------------------------
function PropagationGrid({ prop }) {
  const types = ["A", "MX", "SPF", "DMARC", "DKIM"];
  return (
    <div className="prop-grid">
      <div className="prop-row header-row">
        <span>Type</span><span>Value (Google)</span>
        {RESOLVERS.map(r => <span key={r.name} className="prop-cell" style={{ color: r.color }}>{r.name}</span>)}
      </div>
      {types.map(type => {
        const res = prop[type];
        if (!res) return null;
        if (type === "DKIM") {
          const dkim = prop.DKIM;
          return (
            <div className="prop-row" key={type}>
              <span className="prop-type">DKIM</span>
              <span className="prop-val">{dkim.found ? dkim.selector + "._domainkey (found)" : dkim.found === false ? "not found" : "error"}</span>
              {RESOLVERS.map((_, i) => (
                <span key={i} className="prop-cell">{dkim.found ? <span className="dot-ok" /> : <span className="dot-fail" />}</span>
              ))}
            </div>
          );
        }
        const googleRecs = res[0];
        let pv = googleRecs ? googleRecs.map(r => r.data).join(", ") : "--";
        if (pv.length > 55) pv = pv.substring(0, 55) + "...";
        return (
          <div className="prop-row" key={type}>
            <span className="prop-type">{type}</span>
            <span className="prop-val">{pv}</span>
            {res.map((recs, i) => (
              <span key={i} className="prop-cell">
                {recs === null ? <span className="dot-fail" title="Error" /> : recs.length === 0 ? <span className="dot-fail" title="Not found" /> : <span className="dot-ok" title="Found" />}
              </span>
            ))}
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
export default function App() {
  const [domain, setDomain] = useState("");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressLabel, setProgressLabel] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  async function runScan(d, forceFresh) {
    setScanning(true); setResult(null); setError("");
    try {
      setProgress(10); setProgressLabel("Fetching A records...");
      const [Ares, AAAAres] = await Promise.all([queryAll(d, "A"), queryAll(d, "AAAA")]);

      setProgress(25); setProgressLabel("Fetching MX records...");
      const MXres = await queryAll(d, "MX");

      setProgress(42); setProgressLabel("Fetching TXT / SPF...");
      const TXTres = await queryAll(d, "TXT");

      setProgress(56); setProgressLabel("Fetching DMARC...");
      const DMARCres = await queryAll("_dmarc." + d, "TXT");

      setProgress(68); setProgressLabel("Checking DKIM selectors...");
      const dkim = await checkDKIM(d);

      setProgress(80); setProgressLabel("Fetching NS + SOA...");
      const [ns, soa] = await Promise.all([fetchNS(d), fetchSOA(d)]);

      let authRecords = null;
      if (forceFresh) {
        setProgress(90); setProgressLabel("Querying authoritative (no-cache)...");
        const [authA, authMX, authTXT, authDMARC] = await Promise.all([
          queryAuthoritative(d, "A"), queryAuthoritative(d, "MX"),
          queryAuthoritative(d, "TXT"), queryAuthoritative("_dmarc." + d, "TXT"),
        ]);
        authRecords = { A: authA, MX: authMX, TXT: authTXT, DMARC: authDMARC };
      }

      setProgress(95); setProgressLabel("Analyzing...");

      const A     = (forceFresh && authRecords?.A)     ? authRecords.A     : (Ares[0]     || []);
      const AAAA  = AAAAres[0] || [];
      const MX    = (forceFresh && authRecords?.MX)    ? authRecords.MX    : (MXres[0]    || []);
      const TXT   = (forceFresh && authRecords?.TXT)   ? authRecords.TXT   : (TXTres[0]   || []);
      const spf   = TXT.filter(r => r.data && r.data.includes("v=spf1"));
      const dmarc = (forceFresh && authRecords?.DMARC) ? authRecords.DMARC : (DMARCres[0] || []);

      const records  = { A, AAAA, MX, TXT, spf, dmarc, dkim };
      const flags    = generateFlags(records, d);
      const mxHosts  = MX.map(r => parseMXHost(r.data)).filter(Boolean);
      const prop     = { A: Ares, MX: MXres, SPF: TXTres.map(recs => recs ? recs.filter(r => r.data && r.data.includes("v=spf1")) : []), DMARC: DMARCres, DKIM: dkim };
      const critical = flags.filter(f => f.sev === "critical").length;
      const warnings = flags.filter(f => f.sev === "warning").length;
      const total    = A.length + AAAA.length + MX.length + TXT.length + dmarc.length;
      const spfVal   = spf[0]   ? spf[0].data   : null;
      const dmarcVal = dmarc[0] ? dmarc[0].data : null;
      const aIP      = A[0]     ? A[0].data     : null;

      setProgress(100);
      setResult({ domain: d, records, flags, prop, critical, warnings, total, spfVal, dmarcVal, ns, soa, forceFresh, aIP, mxHosts });
    } catch(e) {
      setError("Scan failed: " + e.message);
    } finally {
      setScanning(false); setProgress(0); setProgressLabel("");
    }
  }

  async function handleScan() {
    const d = domain.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();
    if (!d) return;
    await runScan(d, false);
  }

  async function handleForceFresh() {
    const d = domain.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();
    if (!d) return;
    await runScan(d, true);
  }

  const overallStatus = result ? result.critical > 0 ? "badge-err" : result.warnings > 0 ? "badge-warn" : "badge-ok" : null;
  const overallLabel  = result ? result.critical > 0 ? "Issues Found" : result.warnings > 0 ? "Warnings" : "All Clear" : null;

  return (
    <>
      <style>{STYLE}</style>
      <div className="app">
        <div className="header">
          <div className="header-eyebrow"><span className="pulse" /> Exact Hosting - Internal Tool</div>
          <h1>DNS Debugger</h1>
          <p>Record lookup, misconfiguration detection and propagation status across multiple resolvers.</p>
        </div>

        <div className="search-wrap">
          <div className="search-row">
            <input className="domain-input" type="text" placeholder="Enter domain -- e.g. example.com"
              value={domain} onChange={e => setDomain(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter" && !scanning) handleScan(); }} />
            <button className="btn-fresh" onClick={handleForceFresh} disabled={!domain.trim() || scanning}
              title="Bypass resolver cache — use after making DNS changes in cPanel">Force Fresh</button>
            <button className="btn-scan" onClick={handleScan} disabled={!domain.trim() || scanning}>
              {scanning ? "Scanning..." : "Scan Domain"}
            </button>
          </div>
          {scanning && (
            <div className="progress-wrap">
              <div className="progress-track"><div className="progress-fill" style={{ width: progress + "%" }} /></div>
              <div className="progress-label">{progressLabel}</div>
            </div>
          )}
          {error && <div style={{ color: "var(--red)", fontSize: 12, marginTop: 8, fontFamily: "var(--mono)" }}>{error}</div>}
        </div>

        {result && (
          <div className="fade-up">
            <NSInfoBar ns={result.ns} soa={result.soa} />
            {result.forceFresh && (
              <div className="auth-banner">
                <span>✓</span>
                <span>Force Fresh mode — results fetched with cache bypass (cd=1). Most current upstream data available.</span>
              </div>
            )}

            <div className="summary">
              <div className="summary-card">
                <span className="summary-label">Domain</span>
                <span className="summary-value col-blue" style={{ fontSize: 15, paddingTop: 4 }}>{result.domain}</span>
                <span className="summary-sub">{result.forceFresh ? "force-fresh scan" : "scanned just now"}</span>
              </div>
              <div className="summary-card">
                <span className="summary-label">Critical</span>
                <span className={"summary-value " + (result.critical > 0 ? "col-red" : "col-green")}>{result.critical}</span>
                <span className="summary-sub">issues to fix</span>
              </div>
              <div className="summary-card">
                <span className="summary-label">Warnings</span>
                <span className={"summary-value " + (result.warnings > 0 ? "col-amber" : "col-green")}>{result.warnings}</span>
                <span className="summary-sub">worth reviewing</span>
              </div>
              <div className="summary-card">
                <span className="summary-label">Records</span>
                <span className="summary-value col-blue">{result.total}</span>
                <span className="summary-sub">total found</span>
              </div>
            </div>

            <CollapsibleSection title="Health Check" badge={<span className={"badge " + overallStatus}>{overallLabel}</span>} defaultOpen={true}>
              {result.flags.map((f, i) => <FlagItem key={i} {...f} />)}
            </CollapsibleSection>

            {result.aIP && (
              <SenderReputationPanel ip={result.aIP} domain={result.domain} spfVal={result.spfVal} dmarcVal={result.dmarcVal} mxHosts={result.mxHosts} />
            )}

            <CollapsibleSection title="All Records" count={result.total} defaultOpen={true}>
              <RecordTable records={result.records} domain={result.domain} spfVal={result.spfVal} dmarcVal={result.dmarcVal} mxHosts={result.mxHosts} />
            </CollapsibleSection>

            <CollapsibleSection title="Propagation Status" count={RESOLVERS.length} defaultOpen={true}>
              <PropagationGrid prop={result.prop} />
              <div className="ttl-note">
                Resolvers: {RESOLVERS.map(r => r.name).join(", ")}. Green = found, red = not found. DKIM checked via Google only.
                {result.soa && result.soa.serial && <span> | SOA serial: {result.soa.serial} — compare to cPanel to confirm changes are live.</span>}
              </div>
            </CollapsibleSection>
          </div>
        )}

        {!result && !scanning && (
          <div className="empty-state">
            <div className="empty-icon">[?]</div>
            <div className="empty-title">Enter a domain to begin</div>
            <div className="empty-sub">DNS records, health checks, sender reputation, BIMI, MX blacklist, Microsoft deliverability and propagation status. Use Force Fresh after DNS changes in cPanel.</div>
          </div>
        )}
      </div>
    </>
  );
}
