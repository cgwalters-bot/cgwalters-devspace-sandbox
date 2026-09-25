#!/usr/bin/env node
// Check, from a workflow step (as runner), that the agent is contained,
// running things the way the agent step does (agentCommand): no sudo, no
// access to the runner's processes or files, and no network except the
// allowlisting proxy, also not from a rootless container. Exits nonzero if
// any check fails.
//   agent-isolation-check.mjs PROXY_URL ALLOWED_URL DENIED_URL
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { AGENT_HOME, AGENT_USER, asAgent, fail } from "./agent-lib.mjs";

const METADATA_URL = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";
// Small, has curl, and comes from an allowlisted registry.
const CONTAINER_IMAGE = "registry.access.redhat.com/ubi10/ubi-minimal";
// Any uid other than root in the container maps to a subordinate uid.
const CONTAINER_UID = "1000";

const [proxy, allowed, denied] = process.argv.slice(2);
if (!denied) fail("usage: agent-isolation-check.mjs PROXY_URL ALLOWED_URL DENIED_URL");
const deniedHost = new URL(denied).hostname;

// A process of runner's whose environment holds a value only it has, as
// a stand-in for the tokens in real step environments.
const canary = `isolation-canary-${randomBytes(12).toString("hex")}`;
const decoy = spawn("sleep", ["300"], { env: { ...process.env, AGENT_ISOLATION_CANARY: canary }, stdio: "ignore" });
const decoyHasCanary = () => {
  try {
    return readFileSync(`/proc/${decoy.pid}/environ`, "latin1").includes(canary);
  } catch {
    return false;
  }
};
for (let i = 0; i < 50 && !decoyHasCanary(); i++) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
}

let failures = 0;
function expect(want, what, ok) {
  if (ok === (want === "succeed")) {
    console.log(`ok: ${what}`);
  } else {
    console.log(`FAIL: ${what}`);
    failures++;
  }
}
const succeeds = (cmd, opts = {}) => asAgent(cmd, { proxy, ...opts }).status === 0;
const curl = (args) => ["curl", "-sS", "-m", "30", "-o", "/dev/null", ...args];
const inContainer = (cmd) => ["podman", "run", "--rm", "--network=host", "--user", CONTAINER_UID, CONTAINER_IMAGE, ...cmd];
// Every process environment the agent can read, NUL-separated.
const environs = asAgent(["sh", "-c", "cat /proc/[0-9]*/environ 2>/dev/null; true"]).stdout.toString("latin1");

expect("fail", `${AGENT_USER} has no sudo`, succeeds(["sudo", "-n", "true"]));
for (const [pid, what] of [[process.pid, "this step's"], [decoy.pid, "a runner process's"]]) {
  expect("fail", `${AGENT_USER} can't read ${what} environment`, succeeds(["cat", `/proc/${pid}/environ`]));
}
expect("succeed", "runner reads the canary in its own process's environment (control)", decoyHasCanary());
expect("succeed", `${AGENT_USER} reads its own processes' environments (control)`, environs.includes(`HOME=${AGENT_HOME}`));
expect("fail", `no environment ${AGENT_USER} can read holds the canary or ACTIONS_ variables`,
  environs.includes(canary) || environs.includes("ACTIONS_"));
expect("fail", `${AGENT_USER} can't list the runner's home`, succeeds(["ls", "/home/runner"]));
expect("fail", `${AGENT_USER} can't reach ${allowed} directly`, succeeds(curl(["--noproxy", "*", allowed])));
expect("succeed", `${AGENT_USER} reaches ${allowed} through the proxy`, succeeds(curl(["--proxy", proxy, allowed])));
expect("fail", `the proxy refuses ${denied}`, succeeds(curl(["--proxy", proxy, denied])));
expect("fail", `${AGENT_USER} can't resolve names (DNS could carry data out)`, succeeds(["getent", "hosts", deniedHost]));
expect("fail", `${AGENT_USER} can't reach the instance metadata service`,
  succeeds(curl(["--noproxy", "*", "-H", "Metadata:true", METADATA_URL])));
expect("succeed", `${AGENT_USER} pulls ${CONTAINER_IMAGE} through the proxy`, succeeds(["podman", "pull", "-q", CONTAINER_IMAGE]));
// With the host's network, the proxy is the container's loopback too: the
// control shows the container and its curl work, so the refusal is the filter.
expect("succeed", `a container as subordinate uid ${CONTAINER_UID} reaches ${allowed} through the proxy`,
  succeeds(inContainer(curl(["--proxy", proxy, allowed]))));
expect("fail", `a container as subordinate uid ${CONTAINER_UID} can't reach ${denied} directly`,
  succeeds(inContainer(curl(["--noproxy", "*", denied]))));
expect("fail", `a container as subordinate uid ${CONTAINER_UID} can't reach the instance metadata service`,
  succeeds(inContainer(curl(["--noproxy", "*", "-H", "Metadata:true", METADATA_URL]))));

decoy.kill();
if (failures > 0) fail(`${failures} isolation check(s) failed`);
