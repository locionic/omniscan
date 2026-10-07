import { test } from "node:test";
import assert from "node:assert/strict";
import { validateAndPinUrl, type SsrfValidationResult } from "../../src/guard/ssrf.ts";

/**
 * Every case below short-circuits before the `dns.lookup` call in `validateAndPinUrl`,
 * so the suite never touches the network and stays deterministic. Inputs that would
 * reach DNS — real hostnames, and bracketed IPv6 literals — are deliberately absent.
 */

/** Assert an input is rejected with an error mentioning `fragment`, and pin nothing. */
async function rejects(input: string, fragment: string): Promise<SsrfValidationResult> {
  const result = await validateAndPinUrl(input);

  assert.equal(result.valid, false, `expected "${input}" to be rejected`);
  assert.equal(result.url, undefined, `"${input}" should not yield a parsed URL when rejected`);
  assert.equal(result.resolvedIp, undefined, `"${input}" should not pin an IP when rejected`);
  assert.ok(
    result.error?.includes(fragment),
    `expected the error for "${input}" to mention "${fragment}", got: ${result.error}`,
  );

  return result;
}

/** Assert an input is accepted and pins `resolvedIp` without a DNS round-trip. */
async function accepts(input: string, resolvedIp: string): Promise<SsrfValidationResult> {
  const result = await validateAndPinUrl(input);

  assert.equal(result.valid, true, `expected "${input}" to be accepted, got: ${result.error}`);
  assert.equal(result.error, undefined, `"${input}" should not carry an error when accepted`);
  assert.equal(result.resolvedIp, resolvedIp, `"${input}" should pin the literal IP it was given`);

  return result;
}

test("an empty string is rejected as a missing URL", async () => {
  const result = await rejects("", "URL is required");

  // The empty check runs before parsing, so the guard never even builds a URL.
  assert.equal(result.error, "URL is required");
});

test("a javascript: URL is rejected as an invalid format, not a forbidden protocol", async () => {
  // Quirk pinned deliberately: the guard force-prefixes "https://" onto anything that is
  // not already http(s), so `javascript:alert(1)` is parsed as "https://javascript:alert(1)",
  // which WHATWG rejects on the port — not on the scheme. The forbidden-protocol branch is
  // never what catches these inputs. (Same reason file://, ftp:// and gopher:// collapse to
  // the hostnames `file`, `ftp` and `gopher` and go on to hit DNS.)
  const result = await rejects("javascript:alert(1)", "Invalid URL format");

  assert.equal(result.error, "Invalid URL format");
});

test("localhost is rejected as a forbidden local address", async () => {
  const result = await rejects("localhost", "Localhost addresses are strictly forbidden");

  assert.equal(result.error, "Localhost addresses are strictly forbidden");
});

test("loopback and RFC1918 IPv4 literals are rejected", async () => {
  for (const ip of ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1"]) {
    await rejects(ip, `Private/internal IPv4 address '${ip}' is forbidden`);
  }
});

test("link-local, CGNAT, current-network and multicast IPv4 literals are rejected", async () => {
  // 172.31.255.255 closes out 172.16.0.0/12; 169.254.169.254 is the cloud metadata
  // endpoint; 100.64.0.1 opens carrier-grade NAT; 0.0.0.0 is the current network;
  // 224.0.0.1 is the first address of the multicast range.
  for (const ip of ["172.31.255.255", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1"]) {
    await rejects(ip, `Private/internal IPv4 address '${ip}' is forbidden`);
  }
});

test("a public IPv4 literal is accepted and pins the address it was given", async () => {
  const result = await accepts("8.8.8.8", "8.8.8.8");

  assert.equal(result.url?.hostname, "8.8.8.8");
  assert.equal(result.url?.protocol, "https:");
  assert.equal(result.url?.href, "https://8.8.8.8/");
});

test("the IPv4 addresses just outside each private block are accepted", async () => {
  // Boundary pinned as-is: 172.15.255.255 and 172.32.0.1 straddle 172.16.0.0/12, and
  // 100.128.0.1 sits one step above the last carrier-grade NAT address.
  for (const ip of ["172.15.255.255", "172.32.0.1", "100.128.0.1"]) {
    const result = await accepts(ip, ip);

    assert.equal(result.url?.hostname, ip);
  }
});

test("an uppercase HTTP scheme is matched case-insensitively", async () => {
  const result = await accepts("HTTP://1.1.1.1", "1.1.1.1");

  // The scheme test is case-insensitive, so no "https://" is prepended; WHATWG then
  // lowercases the scheme, leaving a plain http: URL rather than a doubled-up one.
  assert.equal(result.url?.protocol, "http:");
  assert.equal(result.url?.href, "http://1.1.1.1/");
  assert.equal(result.url?.hostname, "1.1.1.1");
});

/*
 * NOT COVERED — the IPv6 branch of `validateAndPinUrl` is unreachable through this API.
 *
 * `new URL("https://[::1]").hostname` is the *bracketed* string "[::1]" (WHATWG always
 * serialises IPv6 hosts inside brackets), and `isIP("[::1]")` returns 0. So
 * `directIpVersion` is never 6, and every IPv6 literal — "::1", "fe80::1", "fc00::1",
 * "::ffff:127.0.0.1", even the public "2606:4700:4700::1111" — falls through to the
 * `dns.lookup` branch instead of being matched. `isPrivateIpv6`, including its
 * IPv4-mapped "::ffff:" unwrap, is dead code.
 *
 * Those cases are omitted here because exercising them requires a live DNS round-trip,
 * which would break this suite's offline guarantee, and because their behaviour is
 * environment-dependent: the bracketed literal is treated as a *hostname*, so the result
 * is whatever that resolver does with a name like "[::1]" rather than a verdict of the
 * guard. Bare (unbracketed) IPv6 literals cannot be used as a substitute either — they
 * are rejected earlier as "Invalid URL format", which would pin URL parsing rather than
 * the IPv6 policy.
 *
 * This is a live SSRF gap: "http://[::1]/" and "http://[::ffff:127.0.0.1]/" are not
 * caught by the guard's own IPv6 rules. See the guard fix before relying on those.
 */