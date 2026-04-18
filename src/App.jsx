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
  { name: "OpenDNS",    url: "https://doh.opendns.com/dns-query",    color: "#4CAF50" },
];

const DNSBLS = [
  { name: "Spamhaus ZEN",       zone: "zen.spamhaus.org",              delistUrl: "https://check.spamhaus.org/" },
  { name: "SpamCop",            zone: "bl.spamcop.net",                delistUrl: "https://www.spamcop.net/bl.shtml" },
  { name: "SORBS",              zone: "dnsbl.sorbs.net",               delistUrl: "http://www.sorbs.net/lookup.shtml" },
  { name: "Barracuda",          zone: "b.barracudacentral.org",        delistUrl: "https://www.barracudacentral.org/rbl/removal-request" },
  { name: "UCEProtect L1",      zone: "dnsbl-1.uceprotect.net",       delistUrl: "https://www.uceprotect.net/en/rblcheck.php" },
  { name: "MAPS BL",            zone: "bl.emailbasura.org",            delistUrl: "https://www.emailbasura.org/" },
  { name: "Spam Champuru",      zone: "dnsbl.spam-champuru.net",       delistUrl: "http://www.spam-champuru.net/" },
  { name: "MAPS Blackholes",    zone: "blackholes.mail-abuse.org",     delistUrl: "https://www.mail-abuse.com/cgi-bin/lookup" },
  { name: "MAPS Relays",        zone: "relays.mail-abuse.org",         delistUrl: "https://www.mail-abuse.com/cgi-bin/lookup" },
];

function reverseIP(ip) {
  return ip.split(".").reverse().join(".");
}

async function checkDNSBL(ip, zone) {
  try {
    const reversed = reverseIP(ip);
    const query = reversed + "." + zone;
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(query) + "&type=A";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    const answers = (data.Answer || []).filter(r => r.type === 1);
    if (answers.length > 0) {
      return { listed: true, response: answers[0].data };
    }
    return { listed: false };
  } catch(e) {
    return { listed: null };
  }
}

async function checkAllDNSBLs(ip) {
  const results = await Promise.all(
    DNSBLS.map(async bl => {
      const result = await checkDNSBL(ip, bl.zone);
      return { name: bl.name, zone: bl.zone, delistUrl: bl.delistUrl, ...result };
    })
  );
  return results;
}

async function checkPTR(ip) {
  try {
    const reversed = reverseIP(ip);
    const query = reversed + ".in-addr.arpa";
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(query) + "&type=PTR";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    const answers = (data.Answer || []).filter(r => r.type === 12);
    if (answers.length > 0) {
      return { found: true, hostname: answers[0].data.replace(/\.$/, "") };
    }
    return { found: false, hostname: null };
  } catch(e) {
    return { found: null, hostname: null };
  }
}

async function checkForwardConfirmed(hostname, ip) {
  try {
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(hostname) + "&type=A";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    const answers = (data.Answer || []).filter(r => r.type === 1);
    return answers.some(r => r.data === ip);
  } catch(e) {
    return null;
  }
}

// Query all selectors in parallel instead of serially for speed
const DKIM_SELECTORS = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2", "everlytickey1", "everlytickey2", "smtp", "mxvault"];

async function checkDKIM(domain) {
  try {
    const results = await Promise.all(
      DKIM_SELECTORS.map(async sel => {
        const query = sel + "._domainkey." + domain;
        const url = "https://dns.google/resolve?name=" + encodeURIComponent(query) + "&type=TXT";
        const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
        const data = await res.json();
        const answers = (data.Answer || []).filter(r => r.type === 16);
        const dkimRec = answers.find(r => r.data && r.data.includes("v=DKIM1"));
        if (dkimRec) {
          return { found: true, selector: sel, value: dkimRec.data.replace(/"/g, "").trim() };
        }
        return null;
      })
    );
    const hit = results.find(r => r !== null);
    if (hit) return hit;
    return { found: false };
  } catch(e) {
    return { found: null };
  }
}

// Fetch NS records for a domain
async function fetchNS(domain) {
  try {
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(domain) + "&type=NS";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    const answers = (data.Answer || []).filter(r => r.type === 2);
    return answers.map(r => r.data.replace(/\.$/, "").toLowerCase());
  } catch(e) {
    return [];
  }
}

// Fetch SOA serial to detect authoritative state
async function fetchSOA(domain) {
  try {
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(domain) + "&type=SOA";
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();
    const answers = (data.Answer || []).filter(r => r.type === 6);
    if (answers.length > 0) {
      // SOA data: "ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 300"
      const parts = answers[0].data.split(" ");
      return { serial: parts[2] || null, ttl: answers[0].TTL || null, raw: answers[0].data };
    }
    return null;
  } catch(e) {
    return null;
  }
}

// Authoritative query: looks up the NS for the domain then queries via DoH using cd=1 (disable DNSSEC caching)
// cd=1 forces the resolver to not use its DNSSEC cache, giving fresher results
async function queryAuthoritative(domain, type) {
  try {
    // cd=1 disables cache-driven DNSSEC, gives fresher upstream answers
    const url = "https://dns.google/resolve?name=" + encodeURIComponent(domain) + "&type=" + type + "&cd=1";
    const res = await fetch(url, {
      headers: {
        Accept: "application/dns-json",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
      },
    });
    const data = await res.json();
    const typeMap = { A: 1, AAAA: 28, MX: 15, TXT: 16, NS: 2, SOA: 6 };
    const typeNum = typeMap[type];
    const answers = data.Answer || [];
    const filtered = typeNum ? answers.filter(r => r.type === typeNum) : answers;
    return filtered.map(r => ({ ttl: r.TTL, data: r.data ? r.data.replace(/"/g, "").trim() : "", type: r.type }));
  } catch(e) {
    return null;
  }
}

function countSPFLookups(spfVal) {
  if (!spfVal) return 0;
  const mechanisms = (spfVal.match(/\b(include:|a:|mx:|ptr:|exists:)/g) || []);
  return mechanisms.length;
}

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
    --accent: #0052cc;
    --mono: 'DM Mono', monospace;
    --display: 'Syne', sans-serif;
    --sans: 'DM Sans', sans-serif;
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
  .fresh-badge { display: inline-flex; align-items: center; gap: 5px; background: var(--green-bg); border: 1px solid var(--green-border); border-radius: 4px; padding: 3px 8px; font-size: 10px; font-family: var(--mono); color: var(--green); font-weight: 600; letter-spacing: 0.06em; }
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
  .prop-row { display: grid; grid-template-columns: 90px 1fr repeat(3, 70px); gap: 10px; padding: 9px 14px; border-bottom: 1px solid var(--border); align-items: center; font-size: 11px; }
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
  .empty-sub { font-size: 12px; color: var(--text-dim); max-width: 300px; line-height: 1.6; }
  @keyframes fadeUp { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
  .fade-up { animation: fadeUp 0.3s ease forwards; }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

  /* NS info bar */
  .ns-bar { display: flex; align-items: flex-start; gap: 10px; padding: 9px 14px; background: var(--blue-bg); border: 1px solid var(--blue-border); border-radius: 6px; margin-bottom: 14px; font-size: 11px; font-family: var(--mono); }
  .ns-bar-label { color: var(--blue); font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; flex-shrink: 0; }
  .ns-bar-hosts { color: var(--text-mid); flex: 1; line-height: 1.6; }
  .ns-bar-serial { color: var(--text-dim); font-size: 10px; flex-shrink: 0; }

  /* Authoritative fresh banner */
  .auth-banner { display: flex; align-items: center; gap: 8px; padding: 8px 14px; background: var(--green-bg); border: 1px solid var(--green-border); border-radius: 6px; margin-bottom: 14px; font-size: 11px; font-family: var(--mono); color: var(--green); }
  .auth-banner.warn { background: var(--amber-bg); border-color: var(--amber-border); color: var(--amber); }

  /* Blacklist styles */
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

  /* Microsoft panel styles */
  .ms-panel { border-top: 1px solid var(--border); background: var(--white); }
  .ms-panel-header { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: var(--ms-bg); border-bottom: 1px solid var(--ms-border); }
  .ms-panel-title { display: flex; align-items: center; gap: 8px; font-family: var(--display); font-size: 12px; font-weight: 700; color: var(--ms); }
  .ms-logo { font-size: 11px; font-family: var(--mono); font-weight: 700; color: var(--ms); background: var(--ms); color: white; padding: 1px 5px; border-radius: 2px; letter-spacing: 0.05em; }
  .ms-actions { display: flex; gap: 6px; align-items: center; }
  .btn-ms { background: var(--white); color: var(--ms); border: 1px solid var(--ms-border); border-radius: 4px; font-family: var(--mono); font-size: 10px; font-weight: 600; letter-spacing: 0.08em; padding: 4px 10px; cursor: pointer; transition: all 0.15s; white-space: nowrap; text-transform: uppercase; text-decoration: none; display: inline-flex; align-items: center; gap: 4px; }
  .btn-ms:hover { background: var(--ms-bg); border-color: var(--ms); }
  .btn-ms:disabled { opacity: 0.5; cursor: not-allowed; }
  .ms-checks { padding: 10px 14px; background: var(--bg); }
  .ms-check-row { display: flex; align-items: flex-start; gap: 10px; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 12px; }
  .ms-check-row:last-child { border-bottom: none; }
  .ms-check-icon { font-family: var(--mono); font-size: 10px; font-weight: 700; flex-shrink: 0; min-width: 34px; margin-top: 1px; }
  .ms-check-icon.pass { color: var(--green); }
  .ms-check-icon.fail { color: var(--red); }
  .ms-check-icon.warn { color: var(--amber); }
  .ms-check-icon.info { color: var(--blue); }
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

  @media (max-width: 600px) {
    .summary { grid-template-columns: 1fr 1fr; }
    .prop-row { grid-template-columns: 70px 1fr repeat(3, 44px); font-size: 10px; }
    .bl-zone { display: none; }
    .ms-actions { flex-direction: column; align-items: flex-end; gap: 4px; }
  }
`;

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
  } catch(e) {
    return null;
  }
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
  const host = parts.length > 1 ? parts.slice(1).join(" ") : parts[0];
  return host.replace(/\.$/, "").trim().toLowerCase();
}

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
      flags.push({ sev: "critical", icon: "FAIL", title: "SPF uses +all (too permissive)", detail: spfVal, fix: "Change +all to ~all or -all." });
    } else if (!spfVal.includes("spf.exacthosting.com")) {
      flags.push({ sev: "warning", icon: "WARN", title: "SPF does not include Exact Hosting", detail: spfVal, fix: "Expected: include:spf.exacthosting.com" });
    } else {
      flags.push({ sev: "ok", icon: "PASS", title: "SPF record looks correct", detail: spfVal });
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
    if (ipMX.length > 0) {
      flags.push({ sev: "critical", icon: "FAIL", title: "MX record points to an IP address", detail: ipMX[0] ? ipMX[0].data : "", fix: "MX must point to a hostname, not an IP." });
    }
    const hasClusterA = mxHosts.some(h => h.includes(ehMX[0].toLowerCase()));
    const hasClusterB = mxHosts.some(h => h.includes(ehMX[1].toLowerCase()));
    if (!hasClusterA && !hasClusterB) {
      flags.push({ sev: "critical", icon: "FAIL", title: "MX records do not match Hosted Email pattern", detail: mxHosts.join(", "), fix: "Expected: " + ehMX.join(" and ") });
    } else if (!hasClusterA || !hasClusterB) {
      const missing = !hasClusterA ? ehMX[0] : ehMX[1];
      const clusterName = !hasClusterA ? "Cluster A" : "Cluster B";
      flags.push({ sev: "warning", icon: "WARN", title: "Only one cluster present -- missing " + clusterName, detail: mxHosts.join(", "), fix: "Add missing MX: " + missing });
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
      {soa && soa.serial && (
        <span className="ns-bar-serial">SOA serial: {soa.serial}</span>
      )}
    </div>
  );
}

function MicrosoftPanel({ ip, domain, spfVal, dmarcVal }) {
  const [msState, setMsState] = useState("idle");
  const [msChecks, setMsChecks] = useState([]);

  async function runMsChecks() {
    setMsState("checking");
    setMsChecks([]);
    const checks = [];

    // 1. PTR / rDNS
    const ptr = await checkPTR(ip);
    if (ptr.found === null) {
      checks.push({ sev: "warn", title: "rDNS check failed", detail: "Could not query PTR record.", fix: null });
    } else if (!ptr.found) {
      checks.push({ sev: "fail", title: "No reverse DNS (PTR) record found", detail: ip + " has no PTR record.", fix: "Add a PTR record for this IP. Contact your hosting provider or datacenter." });
    } else {
      const fcrdns = await checkForwardConfirmed(ptr.hostname, ip);
      if (fcrdns === null) {
        checks.push({ sev: "warn", title: "PTR record found but forward check failed", detail: "PTR: " + ptr.hostname, fix: null });
      } else if (!fcrdns) {
        checks.push({ sev: "fail", title: "rDNS exists but forward-confirmed check failed", detail: "PTR hostname " + ptr.hostname + " does not resolve back to " + ip, fix: "Ensure the A record for " + ptr.hostname + " points to " + ip + ". Microsoft requires FCrDNS." });
      } else {
        checks.push({ sev: "pass", title: "rDNS is forward-confirmed (FCrDNS)", detail: ip + " -> " + ptr.hostname + " -> " + ip, fix: null });
      }
    }

    // 2. DKIM
    const dkim = await checkDKIM(domain);
    if (dkim.found === null) {
      checks.push({ sev: "warn", title: "DKIM check failed", detail: "Could not query DKIM selectors.", fix: null });
    } else if (!dkim.found) {
      checks.push({ sev: "fail", title: "No DKIM record found", detail: "Checked selectors: " + DKIM_SELECTORS.join(", "), fix: "Set up DKIM signing for " + domain + ". Microsoft filters weight DKIM heavily." });
    } else {
      checks.push({ sev: "pass", title: "DKIM record found", detail: "Selector: " + dkim.selector, fix: null });
    }

    // 3. DMARC policy
    if (!dmarcVal) {
      checks.push({ sev: "fail", title: "No DMARC record", detail: "Missing _dmarc." + domain + " TXT record.", fix: "Add a DMARC record. Minimum: v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain });
    } else if (dmarcVal.includes("p=none")) {
      checks.push({ sev: "warn", title: "DMARC policy is p=none", detail: dmarcVal, fix: "Microsoft may still deliver but upgrade to p=quarantine or p=reject for better reputation." });
    } else {
      checks.push({ sev: "pass", title: "DMARC policy is enforced (" + (dmarcVal.match(/p=\w+/)?.[0] || "set") + ")", detail: dmarcVal, fix: null });
    }

    // 4. SPF lookup count
    if (!spfVal) {
      checks.push({ sev: "fail", title: "No SPF record to evaluate", detail: "SPF lookup count check skipped.", fix: null });
    } else {
      const lookupCount = countSPFLookups(spfVal);
      if (lookupCount > 10) {
        checks.push({ sev: "fail", title: "SPF exceeds 10 DNS lookup limit (" + lookupCount + " found)", detail: spfVal, fix: "Microsoft strictly enforces the 10-lookup limit. Flatten your SPF record or use an SPF flattening service." });
      } else if (lookupCount >= 8) {
        checks.push({ sev: "warn", title: "SPF approaching 10 DNS lookup limit (" + lookupCount + "/10)", detail: spfVal, fix: "You have " + (10 - lookupCount) + " lookups remaining. Avoid adding more includes." });
      } else {
        checks.push({ sev: "pass", title: "SPF lookup count is within limit (" + lookupCount + "/10)", detail: spfVal, fix: null });
      }
    }

    setMsChecks(checks);
    setMsState("done");
  }

  return (
    <div className="ms-panel">
      <div className="ms-panel-header">
        <div className="ms-panel-title">
          <span className="ms-logo">MS</span>
          Microsoft Deliverability
        </div>
        <div className="ms-actions">
          <button className="btn-ms" onClick={runMsChecks} disabled={msState === "checking"}>
            {msState === "checking" ? "Checking..." : msState === "done" ? "Re-run" : "Run MS Checks"}
          </button>
          <a className="btn-ms" href="https://sendersupport.olc.protection.outlook.com/snds/" target="_blank" rel="noopener noreferrer">
            SNDS Portal ↗
          </a>
        </div>
      </div>

      {msState === "checking" && (
        <div className="ms-checking">Running Microsoft deliverability checks...</div>
      )}

      {msState === "done" && (
        <>
          <div className="ms-checks">
            {msChecks.map((c, i) => (
              <div className="ms-check-row" key={i}>
                <span className={"ms-check-icon " + c.sev}>
                  {c.sev === "pass" ? "PASS" : c.sev === "fail" ? "FAIL" : c.sev === "warn" ? "WARN" : "INFO"}
                </span>
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
                Check whether this IP is enrolled in Microsoft's Junk Mail Reporting Program (JMRP). Enrollment helps senders receive feedback on messages marked as junk by Outlook users.{" "}
                <a className="ms-jmrp-link" href="https://sendersupport.olc.protection.outlook.com/snds/JMRP.aspx" target="_blank" rel="noopener noreferrer">
                  JMRP signup / status ↗
                </a>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function BlacklistChecker({ ip, domain, spfVal, dmarcVal }) {
  const [blState, setBlState] = useState("idle");
  const [blResults, setBlResults] = useState([]);

  async function runCheck() {
    setBlState("checking");
    setBlResults([]);
    const results = await checkAllDNSBLs(ip);
    setBlResults(results);
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
                {r.listed === true && r.delistUrl && (
                  <a className="btn-delist" href={r.delistUrl} target="_blank" rel="noopener noreferrer" title={"Request delisting from " + r.name}>
                    Delist ↗
                  </a>
                )}
              </div>
            </div>
          ))}
          <div className={"bl-summary " + (listedCount > 0 ? "listed" : "clean")}>
            {listedCount > 0
              ? listedCount + " of " + blResults.length + " blacklists returned a listing -- investigate before sending email from this IP."
              : "Not listed on any of the " + blResults.length + " blacklists checked."
            }
          </div>
        </div>
      )}

      <MicrosoftPanel ip={ip} domain={domain} spfVal={spfVal} dmarcVal={dmarcVal} />
    </div>
  );
}

function RecordTable({ records, domain, spfVal, dmarcVal }) {
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
              <BlacklistChecker key={"bl-" + i} ip={r.data} domain={domain} spfVal={spfVal} dmarcVal={dmarcVal} />
            ))}
          </div>
        );
      })}
      {/* DKIM record display */}
      {records.dkim && records.dkim.found && (
        <div className="record-group">
          <div className="record-type-header">DKIM records</div>
          <div className="record-row">
            <span className="rec-type">TXT</span>
            <span className="rec-ttl">--</span>
            <span className="rec-val">{records.dkim.selector}._domainkey &nbsp;→&nbsp; {records.dkim.value}</span>
            <span className="badge badge-ok">DKIM</span>
          </div>
        </div>
      )}
    </div>
  );
}

function PropagationGrid({ prop }) {
  const types = ["A", "MX", "SPF", "DMARC", "DKIM"];
  return (
    <div className="prop-grid">
      <div className="prop-row header-row">
        <span>Type</span>
        <span>Value (Google)</span>
        {RESOLVERS.map(r => <span key={r.name} className="prop-cell" style={{ color: r.color }}>{r.name}</span>)}
      </div>
      {types.map(type => {
        const resolverResults = prop[type];
        if (!resolverResults) return null;
        // DKIM is a single result, not per-resolver array -- handle specially
        if (type === "DKIM") {
          const dkim = prop.DKIM;
          if (!dkim) return null;
          const val = dkim.found ? dkim.selector + "._domainkey (found)" : dkim.found === false ? "not found" : "error";
          return (
            <div className="prop-row" key={type}>
              <span className="prop-type">{type}</span>
              <span className="prop-val">{val}</span>
              {RESOLVERS.map((_, i) => (
                <span key={i} className="prop-cell">
                  {dkim.found === true
                    ? <span className="dot-ok" title="Found" />
                    : dkim.found === false
                      ? <span className="dot-fail" title="Not found" />
                      : <span className="dot-fail" title="Error" />
                  }
                </span>
              ))}
            </div>
          );
        }
        const googleRecs = resolverResults[0];
        let primaryVal = googleRecs ? googleRecs.map(r => r.data).join(", ") : "--";
        if (primaryVal.length > 55) primaryVal = primaryVal.substring(0, 55) + "...";
        return (
          <div className="prop-row" key={type}>
            <span className="prop-type">{type}</span>
            <span className="prop-val">{primaryVal}</span>
            {resolverResults.map((recs, i) => (
              <span key={i} className="prop-cell">
                {recs === null
                  ? <span className="dot-fail" title="Error" />
                  : recs.length === 0
                    ? <span className="dot-fail" title="Not found" />
                    : <span className="dot-ok" title="Found" />
                }
              </span>
            ))}
          </div>
        );
      })}
    </div>
  );
}

export default function App() {
  const [domain, setDomain] = useState("");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressLabel, setProgressLabel] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  async function runScan(d, forceFresh) {
    setScanning(true);
    setResult(null);
    setError("");
    try {
      setProgress(10); setProgressLabel("Fetching A records...");
      const [Ares, AAAAres] = await Promise.all([queryAll(d, "A"), queryAll(d, "AAAA")]);

      setProgress(28); setProgressLabel("Fetching MX records...");
      const MXres = await queryAll(d, "MX");

      setProgress(46); setProgressLabel("Fetching TXT / SPF...");
      const TXTres = await queryAll(d, "TXT");

      setProgress(62); setProgressLabel("Fetching DMARC...");
      const DMARCres = await queryAll("_dmarc." + d, "TXT");

      setProgress(72); setProgressLabel("Checking DKIM selectors...");
      const dkim = await checkDKIM(d);

      setProgress(82); setProgressLabel("Fetching NS + SOA...");
      const [ns, soa] = await Promise.all([fetchNS(d), fetchSOA(d)]);

      // If forceFresh, also query authoritative with cd=1 for key types to surface latest data
      let authRecords = null;
      if (forceFresh) {
        setProgress(90); setProgressLabel("Querying authoritative (no-cache)...");
        const [authA, authMX, authTXT, authDMARC] = await Promise.all([
          queryAuthoritative(d, "A"),
          queryAuthoritative(d, "MX"),
          queryAuthoritative(d, "TXT"),
          queryAuthoritative("_dmarc." + d, "TXT"),
        ]);
        authRecords = { A: authA, MX: authMX, TXT: authTXT, DMARC: authDMARC };
      }

      setProgress(95); setProgressLabel("Analyzing...");

      // Use authoritative records if force-fresh, else use Google (resolver index 0)
      const A     = (forceFresh && authRecords?.A)     ? authRecords.A     : (Ares[0]     || []);
      const AAAA  = AAAAres[0]  || [];
      const MX    = (forceFresh && authRecords?.MX)    ? authRecords.MX    : (MXres[0]    || []);
      const TXT   = (forceFresh && authRecords?.TXT)   ? authRecords.TXT   : (TXTres[0]   || []);
      const spf   = TXT.filter(r => r.data && r.data.includes("v=spf1"));
      const rawDMARC = (forceFresh && authRecords?.DMARC) ? authRecords.DMARC : (DMARCres[0] || []);
      const dmarc = rawDMARC;

      const records = { A, AAAA, MX, TXT, spf, dmarc, dkim };
      const flags = generateFlags(records, d);

      const prop = {
        A:     Ares,
        MX:    MXres,
        SPF:   TXTres.map(recs => recs ? recs.filter(r => r.data && r.data.includes("v=spf1")) : []),
        DMARC: DMARCres,
        DKIM:  dkim,
      };

      const critical = flags.filter(f => f.sev === "critical").length;
      const warnings = flags.filter(f => f.sev === "warning").length;
      const total = A.length + AAAA.length + MX.length + TXT.length + dmarc.length;

      const spfVal   = spf[0]   ? spf[0].data   : null;
      const dmarcVal = dmarc[0] ? dmarc[0].data : null;

      setProgress(100);
      setResult({ domain: d, records, flags, prop, critical, warnings, total, spfVal, dmarcVal, ns, soa, forceFresh });
    } catch(e) {
      setError("Scan failed: " + e.message);
    } finally {
      setScanning(false);
      setProgress(0);
      setProgressLabel("");
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

  const overallStatus = result
    ? result.critical > 0 ? "badge-err" : result.warnings > 0 ? "badge-warn" : "badge-ok"
    : null;

  const overallLabel = result
    ? result.critical > 0 ? "Issues Found" : result.warnings > 0 ? "Warnings" : "All Clear"
    : null;

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
            <input
              className="domain-input"
              type="text"
              placeholder="Enter domain -- e.g. example.com"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter" && !scanning) handleScan(); }}
            />
            <button className="btn-fresh" onClick={handleForceFresh} disabled={!domain.trim() || scanning} title="Bypass resolver cache and query with cd=1 for freshest possible results">
              Force Fresh
            </button>
            <button className="btn-scan" onClick={handleScan} disabled={!domain.trim() || scanning}>
              {scanning ? "Scanning..." : "Scan Domain"}
            </button>
          </div>
          {scanning && (
            <div className="progress-wrap">
              <div className="progress-track">
                <div className="progress-fill" style={{ width: progress + "%" }} />
              </div>
              <div className="progress-label">{progressLabel}</div>
            </div>
          )}
          {error && <div style={{ color: "var(--red)", fontSize: 12, marginTop: 8, fontFamily: "var(--mono)" }}>{error}</div>}
        </div>

        {result && (
          <div className="fade-up">

            {/* NS + SOA info bar */}
            <NSInfoBar ns={result.ns} soa={result.soa} />

            {/* Force-fresh banner */}
            {result.forceFresh && (
              <div className="auth-banner">
                <span>✓</span>
                <span>Force Fresh mode — results fetched with cache bypass (cd=1). These reflect the most current upstream data available.</span>
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
              {result.flags.map((f, i) => <FlagItem key={i} sev={f.sev} icon={f.icon} title={f.title} detail={f.detail} fix={f.fix} />)}
            </CollapsibleSection>

            <CollapsibleSection title="All Records" count={result.total} defaultOpen={true}>
              <RecordTable records={result.records} domain={result.domain} spfVal={result.spfVal} dmarcVal={result.dmarcVal} />
            </CollapsibleSection>

            <CollapsibleSection title="Propagation Status" count={RESOLVERS.length} defaultOpen={true}>
              <PropagationGrid prop={result.prop} />
              <div className="ttl-note">
                Resolvers: {RESOLVERS.map(r => r.name).join(", ")}. Green = found, red = not found. DKIM checked via Google only.
                {result.soa && result.soa.serial && (
                  <span> &nbsp;|&nbsp; Authoritative SOA serial: {result.soa.serial} — if this matches cPanel, your changes are live on the NS.</span>
                )}
              </div>
            </CollapsibleSection>
          </div>
        )}

        {!result && !scanning && (
          <div className="empty-state">
            <div className="empty-icon">[?]</div>
            <div className="empty-title">Enter a domain to begin</div>
            <div className="empty-sub">Checks A, AAAA, MX, SPF, DMARC and DKIM records against Exact Hosting defaults and flags common misconfigurations. Use Force Fresh after making DNS changes in cPanel.</div>
          </div>
        )}

      </div>
    </>
  );
}
