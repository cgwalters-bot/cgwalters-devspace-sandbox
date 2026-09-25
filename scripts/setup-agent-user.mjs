#!/usr/bin/env node
// Create the unprivileged user that SSH sessions and agent runs use, and
// close what would let it reach the runner user's credentials. Run as root.
//
// Every step runs as runner, which has passwordless sudo; the running steps'
// environments hold ACTIONS_ID_TOKEN_REQUEST_TOKEN, which mints the OIDC
// tokens the Tailscale login trusts. The boundary is the separate uid: it
// can't read another uid's /proc/PID/environ or memory, and has no sudo.
// What else it needs is kept to real exposures of this runner image, which
// is built with umask 000.
import { spawnSync } from "node:child_process";
import { chmodSync, chownSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const AGENT_USER = "agent";
// /dev/kvm is already 0666; the group documents the intent. Not libvirt:
// its polkit rule grants all of qemu:///system, which is root-equivalent.
const AGENT_GROUPS = "kvm";
// The runner's .credentials and the hosted compute agent's token
// (/opt/hca/.settings, RHEL runners only) are world-readable.
const PRIVATE_DIRS = ["/home/runner", "/opt/hca"];
// Sticky world-writable directories, meant to stay that way.
const SHARED_TMP = ["/tmp", "/var/tmp"];
const NFT_TABLE = "agent_user";
// The image leaves this group-writable, and ssh refuses to run with a
// group-writable included config: plain ssh and git over ssh fail for agent.
const SSH_CRYPTO_POLICY = "/etc/crypto-policies/back-ends/openssh.config";
// The image's /etc/environment gives every PAM session runner's
// XDG_RUNTIME_DIR, including agent's systemd user manager, whose session
// bus then doesn't work. Rootless podman needn't use it: cgroupfs instead
// of systemd for its cgroups, and a file for its events.
const CONTAINERS_CONF = `[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"
`;
const METADATA_ADDRESS = "169.254.169.254";

function run(cmd, args) {
  const r = spawnSync(cmd, args, { stdio: ["inherit", "pipe", "inherit"], encoding: "utf8" });
  if (r.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed (${r.error ?? `exit ${r.status}`})`);
  }
  return r.stdout.trim();
}

// Loads an nftables ruleset. From a file: older nft (Ubuntu 24.04) refuses
// to read a pipe with -f -.
function nftApply(ruleset) {
  const dir = mkdtempSync(join(tmpdir(), "agent-nft-"));
  try {
    writeFileSync(join(dir, "rules.nft"), ruleset);
    run("nft", ["-f", join(dir, "rules.nft")]);
  } finally {
    rmSync(dir, { recursive: true });
  }
}

// uid and subordinate uid ranges ("start-end") of a user.
function agentUids(user, subuid) {
  const ranges = subuid.split("\n").map((line) => line.split(":"))
    .filter(([name, start, count]) => name === user && start && count)
    .map(([, start, count]) => `${start}-${Number(start) + Number(count) - 1}`);
  if (ranges.length === 0) {
    throw new Error(`${user} has no subordinate uids in /etc/subuid, which rootless podman needs`);
  }
  return ranges;
}

function main() {
  if (process.getuid() !== 0) {
    throw new Error("must run as root");
  }
  const created = spawnSync("id", [AGENT_USER], { stdio: "ignore" }).status !== 0;
  if (created) {
    // useradd assigns subordinate uids and gids too.
    run("useradd", ["--create-home", "--user-group", "--groups", AGENT_GROUPS, AGENT_USER]);
  }
  const uid = Number(run("id", ["-u", AGENT_USER]));
  const gid = Number(run("id", ["-g", AGENT_USER]));
  // Only into a home just created, which holds nothing of the agent's yet:
  // as root, a link the agent planted would be followed.
  if (created) {
    const home = `/home/${AGENT_USER}`;
    for (const dir of [`${home}/.config`, `${home}/.config/containers`]) {
      mkdirSync(dir, { recursive: true });
      chownSync(dir, uid, gid);
    }
    writeFileSync(`${home}/.config/containers/containers.conf`, CONTAINERS_CONF);
    chownSync(`${home}/.config/containers/containers.conf`, uid, gid);
  }
  const subuids = agentUids(AGENT_USER, readFileSync("/etc/subuid", "utf8"));

  for (const dir of PRIVATE_DIRS.filter((d) => existsSync(d))) {
    chmodSync(dir, 0o700);
  }
  // World-writable system files include ones root loads code from: agent
  // could add a polkit rule granting itself anything, and so become root.
  const prune = SHARED_TMP.flatMap((d) => ["-path", d, "-o"]);
  run("find", ["/", "-xdev", "(", ...prune, "-false", ")", "-prune", "-o",
    "(", "-type", "f", "-o", "-type", "d", ")", "-perm", "-0002", "!", "-perm", "-1000",
    "-exec", "chmod", "o-w", "{}", "+"]);
  if (existsSync(SSH_CRYPTO_POLICY)) {
    chmodSync(SSH_CRYPTO_POLICY, statSync(SSH_CRYPTO_POLICY).mode & 0o7757);
  }

  // Hardening only (the uid split is the boundary): the image lets any
  // process attach to any other of its uid.
  writeFileSync("/proc/sys/kernel/yama/ptrace_scope", "1\n");
  // Nothing the agent does needs the cloud metadata service; its rootless
  // containers run as its subordinate uids.
  nftApply(`table inet ${NFT_TABLE}
delete table inet ${NFT_TABLE}
table inet ${NFT_TABLE} {
  set agent_uids { type uid; flags interval; elements = { ${[uid, ...subuids].join(", ")} } }
  chain output {
    type filter hook output priority 0; policy accept;
    meta skuid @agent_uids ip daddr ${METADATA_ADDRESS} counter reject
  }
}
`);
  console.log(`Created unprivileged user ${AGENT_USER}: ${run("id", [AGENT_USER])}`);
}

try {
  main();
} catch (e) {
  console.error(`error: ${process.argv[1]}: ${e.message}`);
  process.exit(1);
}
