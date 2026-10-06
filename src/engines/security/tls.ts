import * as tls from "node:tls";
import type { TlsResult } from "../../types/index.js";

export interface TlsAuditOptions {
  timeoutMs?: number;
}

export function auditTls(hostname: string, port = 443, options: TlsAuditOptions = {}): Promise<TlsResult> {
  const timeoutMs = options.timeoutMs ?? 5000;

  return new Promise((resolve) => {
    let resolved = false;

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname, // SNI support
        rejectUnauthorized: false, // We inspect ourselves so self-signed doesn't throw early
      },
      () => {
        if (resolved) return;
        resolved = true;

        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol() || "Unknown";
        const cipher = socket.getCipher()?.name || "Unknown";
        const authorized = socket.authorized;

        socket.end();

        if (!cert || Object.keys(cert).length === 0) {
          resolve({
            score: 0,
            grade: "F",
            protocol,
            cipher,
            authorized: false,
            vulnerabilities: ["Failed to retrieve peer certificate"],
            recommendations: ["Ensure web server has a valid SSL/TLS certificate installed."],
          });
          return;
        }

        const validFrom = cert.valid_from;
        const validTo = cert.valid_to;
        const validToDate = new Date(validTo);
        const now = new Date();
        const daysRemaining = Math.floor((validToDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

        let score = 100;
        const vulnerabilities: string[] = [];
        const recommendations: string[] = [];

        // Check Certificate Authorization
        if (!authorized) {
          score -= 40;
          vulnerabilities.push(`Untrusted Certificate: ${socket.authorizationError || "Chain validation failed"}`);
          recommendations.push("Replace untrusted or self-signed certificate with one from a recognized Certificate Authority (e.g. Let's Encrypt).");
        }

        // Check Expiration
        if (daysRemaining <= 0) {
          score -= 50;
          vulnerabilities.push("SSL/TLS Certificate is EXPIRED");
          recommendations.push("Renew certificate immediately; browsers will display security warnings to visitors.");
        } else if (daysRemaining < 14) {
          score -= 20;
          recommendations.push(`Certificate expires in ${daysRemaining} days. Renew promptly to avoid downtime.`);
        } else if (daysRemaining < 30) {
          score -= 5;
          recommendations.push(`Certificate expires in ${daysRemaining} days.`);
        }

        // Check Protocol Version
        if (protocol === "TLSv1.3") {
          // Top tier protocol
        } else if (protocol === "TLSv1.2") {
          score -= 5;
          recommendations.push("Upgrade server configuration to support modern TLS 1.3 for enhanced security and 0-RTT handshakes.");
        } else if (protocol === "TLSv1.1" || protocol === "TLSv1") {
          score -= 40;
          vulnerabilities.push(`Deprecated Protocol: ${protocol}`);
          recommendations.push(`Disable deprecated ${protocol}. Restrict server to TLS 1.2 and TLS 1.3.`);
        } else if (protocol.startsWith("SSL")) {
          score -= 60;
          vulnerabilities.push(`Insecure Protocol: ${protocol}`);
          recommendations.push("Disable SSLv2/SSLv3 completely to protect against POODLE and legacy attacks.");
        }

        const finalScore = Math.max(0, Math.min(100, score));
        let grade: "A+" | "A" | "B" | "C" | "D" | "F" = "F";
        if (finalScore >= 95) grade = "A+";
        else if (finalScore >= 85) grade = "A";
        else if (finalScore >= 70) grade = "B";
        else if (finalScore >= 50) grade = "C";
        else if (finalScore >= 30) grade = "D";

        const sans = cert.subjectaltname ? cert.subjectaltname.split(", ").map((s) => s.replace(/^DNS:/, "")) : [];

        resolve({
          score: finalScore,
          grade,
          protocol,
          cipher,
          authorized,
          cert: {
            subject: typeof cert.subject === "object" ? JSON.stringify(cert.subject) : String(cert.subject),
            issuer: typeof cert.issuer === "object" ? JSON.stringify(cert.issuer) : String(cert.issuer),
            validFrom,
            validTo,
            daysRemaining,
            sans,
          },
          vulnerabilities,
          recommendations,
        });
      }
    );

    socket.setTimeout(timeoutMs);
    socket.on("timeout", () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve({
          score: 0,
          grade: "F",
          protocol: "Timeout",
          cipher: "None",
          authorized: false,
          vulnerabilities: ["Connection timed out during TLS handshake"],
          recommendations: ["Verify host is reachable on port 443."],
        });
      }
    });

    socket.on("error", (err) => {
      if (!resolved) {
        resolved = true;
        resolve({
          score: 0,
          grade: "F",
          protocol: "Error",
          cipher: "None",
          authorized: false,
          vulnerabilities: [`TLS Connection Error: ${err.message}`],
          recommendations: ["Ensure target server accepts HTTPS connections on port 443."],
        });
      }
    });
  });
}
