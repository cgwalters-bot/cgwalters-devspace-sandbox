#!/usr/bin/env node
// Limit the agent's network access to a local forward proxy that only
// allows the domains in an allowlist. Run as root.
//   agent-egress.mjs ALLOWLIST LOGFILE
// The proxy (tinyproxy, as its own user) listens on 127.0.0.1:PROXY_PORT;
// nftables rejects every packet the agent sends anywhere but loopback, so
// tools that ignore the proxy variables fail instead of going around it.
// "The agent" is anything in its slice or running as its uid or one of its
// subordinate uids: a rootless container runs as subordinate uids, and one
// started under a lingering user manager is outside the slice, so neither
// match alone covers it. DNS is refused too, also on loopback, since a
// resolver would carry queries (and data in them) out. Denials are logged
// to LOGFILE ('Proxying refused on filtered domain').
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { AGENT_SLICE, AGENT_USER, agentUids, fail, nftApply, run } from "./agent-lib.mjs";

const PROXY_PORT = 3128;
const PROXY_USER = "tinyproxy";
const CONF = "/etc/tinyproxy/agent.conf";
const FILTER = "/etc/tinyproxy/agent-allowlist";
const NFT_TABLE = "agent_egress";
const DNS_PORT = 53;

// One anchored extended regex per domain, matching it and its subdomains.
function filterRegexes(allowlist) {
  return allowlist.split("\n").map((l) => l.replace(/#.*/, "").trim()).filter(Boolean)
    .map((domain) => `^(.+\\.)?${domain.replaceAll(".", "\\.")}$`);
}

function main([allowlist, log]) {
  if (process.getuid() !== 0) fail("must run as root");
  if (!log) fail("usage: agent-egress.mjs ALLOWLIST LOGFILE");
  const uids = agentUids();
  const regexes = filterRegexes(readFileSync(allowlist, "utf8"));
  if (regexes.length === 0) fail(`${allowlist} allows nothing`);
  writeFileSync(FILTER, regexes.join("\n") + "\n");

  // Distribution packages may start their own, unfiltered instance.
  spawnSync("systemctl", ["disable", "--now", "tinyproxy.service"], { stdio: "ignore" });
  run("install", ["-d", "-o", PROXY_USER, "-g", PROXY_USER, dirname(log)]);
  run("install", ["-o", PROXY_USER, "-g", PROXY_USER, "-m", "0644", "/dev/null", log]);
  writeFileSync(CONF, `User ${PROXY_USER}
Group ${PROXY_USER}
Listen 127.0.0.1
Port ${PROXY_PORT}
Timeout 600
MaxClients 100
LogFile "${log}"
LogLevel Notice
PidFile "/run/tinyproxy-agent.pid"
Filter "${FILTER}"
FilterType ere
FilterURLs Off
FilterCaseSensitive Off
FilterDefaultDeny Yes
ConnectPort 443
DisableViaHeader Yes
`);
  run("tinyproxy", ["-c", CONF]);

  // systemd-resolved (Ubuntu) also answers over D-Bus, which no packet
  // filter sees: point resolv.conf at its upstream servers and mask it.
  if (spawnSync("systemctl", ["is-active", "--quiet", "systemd-resolved.service"]).status === 0) {
    run("cp", ["--remove-destination", "/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"]);
    run("systemctl", ["mask", "--runtime", "--now", "systemd-resolved.service"]);
  }

  // The cgroup match needs the slice to exist, and refers to this instance
  // of it: it must stay active (killed, never stopped) while in use.
  run("systemctl", ["start", AGENT_SLICE]);
  const slice = `socket cgroupv2 level 1 "${AGENT_SLICE}"`;
  nftApply(`table inet ${NFT_TABLE}
delete table inet ${NFT_TABLE}
table inet ${NFT_TABLE} {
  set agent_uids { type uid; flags interval; elements = { ${uids.join(", ")} } }
  chain output {
    type filter hook output priority 0; policy accept;
    meta skuid @agent_uids meta l4proto { tcp, udp } th dport ${DNS_PORT} counter reject
    ${slice} meta l4proto { tcp, udp } th dport ${DNS_PORT} counter reject
    meta skuid @agent_uids oif != "lo" counter reject
    ${slice} oif != "lo" counter reject
  }
}
`);
  console.log(`Egress for ${AGENT_USER}: only via http://127.0.0.1:${PROXY_PORT}, to ${regexes.length} allowed domains`);
}

try {
  main(process.argv.slice(2));
} catch (e) {
  fail(e.message);
}
