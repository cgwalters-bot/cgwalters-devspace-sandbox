// Shared by the scripts that run and confine the agent user: how to run a
// command as the agent, and which uids count as the agent.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const AGENT_USER = "agent";
export const AGENT_HOME = `/home/${AGENT_USER}`;
// Everything the agent runs is in this slice: scripts/agent-egress.mjs
// filters on it (with the agent's uids), and the supervisor kills it. A
// service in it can't move itself out, unlike processes under sudo, which
// stay in the calling step's cgroup.
export const AGENT_SLICE = "agent.slice";
const AGENT_PATH = "/usr/local/bin:/usr/bin:/bin";

export function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

// Runs a command, returning its stdout; throws if it fails.
export function run(cmd, args, { input } = {}) {
  const r = spawnSync(cmd, args, { input, encoding: "utf8", stdio: ["pipe", "pipe", "inherit"], maxBuffer: 1 << 28 });
  if (r.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed (${r.error ?? `exit ${r.status}`})`);
  }
  return r.stdout.trim();
}

// Loads an nftables ruleset. From a file: older nft (Ubuntu 24.04) refuses
// to read a pipe with -f -.
export function nftApply(ruleset) {
  const dir = mkdtempSync(join(tmpdir(), "agent-nft-"));
  try {
    writeFileSync(join(dir, "rules.nft"), ruleset);
    run("nft", ["-f", join(dir, "rules.nft")]);
  } finally {
    rmSync(dir, { recursive: true });
  }
}

// The agent's uid and its subordinate uid ranges ("start-end"), which a
// rootless container's processes run as.
export function agentUids() {
  const uid = run("id", ["-u", AGENT_USER]);
  const ranges = readFileSync("/etc/subuid", "utf8").split("\n").map((l) => l.split(":"))
    .filter(([name, start, count]) => name === AGENT_USER && start && count)
    .map(([, start, count]) => `${start}-${Number(start) + Number(count) - 1}`);
  if (ranges.length === 0) {
    throw new Error(`${AGENT_USER} has no subordinate uids in /etc/subuid`);
  }
  return [uid, ...ranges];
}

// The argv that runs CMD as the agent in its slice, with only a fixed
// environment (plus ENV, and the proxy variables for PROXY): nothing of the
// calling step's survives. Its stdio must be pipes, not regular files:
// systemd-run hands them to PID 1 over D-Bus, which refuses those.
export function agentCommand(cmd, { cwd = AGENT_HOME, env = {}, proxy } = {}) {
  const vars = { HOME: AGENT_HOME, USER: AGENT_USER, LOGNAME: AGENT_USER, LANG: "C.UTF-8", PATH: AGENT_PATH };
  if (proxy) {
    for (const name of ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"]) {
      vars[name] = proxy;
    }
    vars.NO_PROXY = vars.no_proxy = "127.0.0.1,localhost";
  }
  Object.assign(vars, env);
  return ["sudo", ["systemd-run", "--quiet", "--collect", "--wait", "--pipe", "--service-type=exec",
    `--slice=${AGENT_SLICE}`, `--uid=${AGENT_USER}`, `--gid=${AGENT_USER}`, `--working-directory=${cwd}`,
    ...Object.entries(vars).map(([k, v]) => `--setenv=${k}=${v}`), "--", ...cmd]];
}

// Runs CMD as the agent; returns {status, stdout} (stdout as a Buffer).
export function asAgent(cmd, opts = {}) {
  const [bin, args] = agentCommand(cmd, opts);
  const r = spawnSync(bin, args, { input: opts.input ?? "", stdio: "pipe", maxBuffer: 1 << 30 });
  return { status: r.status, stdout: r.stdout ?? Buffer.alloc(0) };
}

// Stops everything the agent started: its slice (killed, not stopped, since
// the egress rules refer to that instance of it), a user manager it may have
// started by enabling lingering, and stray processes of its uid.
export function killAgent() {
  for (const args of [["systemctl", "kill", "--signal=KILL", AGENT_SLICE], ["loginctl", "disable-linger", AGENT_USER],
    ["loginctl", "terminate-user", AGENT_USER], ["pkill", "-KILL", "-u", AGENT_USER]]) {
    spawnSync("sudo", args, { stdio: "ignore" });
  }
}
