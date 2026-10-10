import * as tls from "node:tls";
import * as net from "node:net";
import { randomBytes } from "node:crypto";
import type { FullAuditReport } from "../types/index.js";
import { buildSubject, renderEmailHtml, renderEmailText, type EmailTemplateOptions } from "../reports/email-template.ts";

export interface EmailRecipient {
  email: string;
  name?: string;
}

export type EmailTransport = (message: EmailMessage) => Promise<void>;

export interface EmailMessage {
  from: string;
  /** Bare addr-spec for the SMTP envelope; `from` may carry a display name. */
  envelopeFrom: string;
  to: EmailRecipient;
  subject: string;
  text: string;
  html: string;
  headers: Record<string, string>;
  attachments: EmailAttachment[];
}

export interface EmailAttachment {
  filename: string;
  contentType: string;
  content: Uint8Array;
}

export interface DispatchEmailInput {
  report: FullAuditReport;
  recipient?: EmailRecipient | string;
  transport?: EmailTransport;
  template?: EmailTemplateOptions;
  from?: string;
  /** Base64 PDF attached to the email. Omit to send the HTML report only. */
  pdf?: Uint8Array;
  attachmentFilename?: string;
}

export interface DispatchResult {
  messageId: string;
  to: string;
  subject: string;
  bytes: number;
  sent: boolean;
  error?: string;
}

const EMAIL_RE = /^[^\s@,;<>"']+@[^\s@,;<>"']+\.[^\s@,;<>"']+$/;

export class EmailValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EmailValidationError";
  }
}

export function isValidEmail(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 254) return false;
  if (trimmed.includes("\r") || trimmed.includes("\n")) return false;
  return EMAIL_RE.test(trimmed);
}

/**
 * Header injection guard. Values reach raw SMTP commands, so CR/LF would let a
 * caller append arbitrary commands to the session.
 */
export function assertHeaderSafe(value: string, label: string): string {
  if (/[\r\n]/.test(value)) {
    throw new EmailValidationError(`${label} must not contain CR or LF characters`);
  }
  return value;
}

export function normalizeRecipient(input: EmailRecipient | string | undefined): EmailRecipient {
  const raw = typeof input === "string" ? input : input?.email;
  if (!raw) {
    throw new EmailValidationError("Recipient email is required");
  }
  const email = raw.trim();
  if (!isValidEmail(email)) {
    throw new EmailValidationError(`Invalid recipient email address: ${raw}`);
  }
  const name = typeof input === "string" ? undefined : input?.name;
  if (name) assertHeaderSafe(name, "Recipient name");
  return { email, name };
}

/**
 * RFC 2047 encodes the display name only; the address itself must stay ASCII so
 * downstream SMTP servers do not reject the envelope.
 */
export function formatAddress(recipient: EmailRecipient): string {
  const name = recipient.name?.trim();
  if (!name) return recipient.email;
  if (/^[\x20-\x7e]*$/.test(name)) return `"${name.replace(/["\\]/g, "\\$&")}" <${recipient.email}>`;
  return `${encodeRfc2047(name)} <${recipient.email}>`;
}

export function encodeRfc2047(value: string): string {
  return `=?UTF-8?B?${Buffer.from(value, "utf8").toString("base64")}?=`;
}

export function sanitizeHeaderValue(value: string): string {
  return value.replace(/[\r\n]+/g, " ").trim();
}

/** Pulls `user@host` out of an RFC 5322 address that may carry a display name. */
export function extractAddrSpec(address: string): string {
  const angle = address.match(/<([^>]*)>/);
  const bare = (angle ? angle[1] : address).trim();
  if (!isValidEmail(bare)) {
    throw new EmailValidationError(`Invalid sender address: ${address}`);
  }
  return bare;
}

export function generateMessageId(domain = "omniscan.io"): string {
  return `<${Date.now().toString(36)}.${randomBytes(12).toString("hex")}@${domain}>`;
}

export function buildMessage(input: DispatchEmailInput, recipient: EmailRecipient, from: string): EmailMessage {
  const { report } = input;
  const envelopeFrom = extractAddrSpec(from);
  const messageId = generateMessageId(envelopeFrom.split("@")[1] ?? "omniscan.io");
  const attachments: EmailAttachment[] = [];

  if (input.pdf && input.pdf.byteLength > 0) {
    attachments.push({
      filename: input.attachmentFilename ?? `omniscan-${report.scanId}.pdf`,
      contentType: "application/pdf",
      content: input.pdf,
    });
  }

  const headers: Record<string, string> = {
    "Message-ID": messageId,
    From: from,
    To: formatAddress(recipient),
    Subject: encodeRfc2047(sanitizeHeaderValue(buildSubject(report))),
    "MIME-Version": "1.0",
    "X-Omniscan-Scan-Id": sanitizeHeaderValue(report.scanId),
    "List-Unsubscribe": `<mailto:unsubscribe@omniscan.io>`,
  };

  return {
    from,
    envelopeFrom,
    to: recipient,
    subject: headers["Subject"],
    text: renderEmailText(report, input.template),
    html: renderEmailHtml(report, input.template),
    headers,
    attachments,
  };
}

/**
 * RFC 5322 requires CRLF line endings. Rendered bodies contain bare LFs, and
 * Gmail's 558-byte line limit plus 8-bit transfer transparency mean naive
 * splitting is not an option, so re-wrap instead.
 */
function toCrlf(text: string): string {
  return text.replace(/\r\n|\r|\n/g, "\r\n").replace(/(^|\r\n)(.{1,990})(?=[\r\n]|$)/g, (_m, lead: string, line: string) =>
    lead.length + line.length > 990 ? `${lead}${line} \r\n=`.replace(" \r\n=", "\r\n=") : lead + line
  );
}

/**
 * Builds the full RFC 5322 payload. Exposed so tests and the PDF pipeline can
 * inspect what would go on the wire without touching the network.
 */
export function serializeMessage(message: EmailMessage): Buffer {
  const boundary = `----=_omniscan_${randomBytes(16).toString("hex")}`;
  const altBoundary = `----=_omni_alt_${randomBytes(16).toString("hex")}`;

  const headers = Object.entries(message.headers)
    .map(([key, value]) => `${key}: ${value}`)
    .join("\r\n");

  const bodyPart = (contentType: string, content: string): string =>
    [
      `--${altBoundary}`,
      `Content-Type: ${contentType}; charset="UTF-8"`,
      "Content-Transfer-Encoding: base64",
      "",
      Buffer.from(content, "utf8").toString("base64"),
    ].join("\r\n");

  const parts = [
    `--${boundary}`,
    `Content-Type: multipart/alternative; boundary="${altBoundary}"`,
    "",
    bodyPart("text/plain", message.text),
    bodyPart("text/html", message.html),
    `--${altBoundary}--`,
  ].join("\r\n");

  let body = parts;
  let contentType = `multipart/alternative; boundary="${altBoundary}"`;

  if (message.attachments.length > 0) {
    const mixed = message.attachments
      .map(
        (att) =>
          [
            `--${boundary}`,
            `Content-Type: ${att.contentType}`,
            "Content-Transfer-Encoding: base64",
            `Content-Disposition: attachment; filename="${sanitizeHeaderValue(att.filename)}"`,
            "",
            Buffer.from(att.content).toString("base64"),
          ].join("\r\n")
      )
      .join("\r\n");

    body = [`--${boundary}`, `Content-Type: multipart/mixed; boundary="${boundary}"`, "", parts, mixed, `--${boundary}--`].join(
      "\r\n"
    );
    contentType = `multipart/mixed; boundary="${boundary}"`;
  }

  const head = [headers, `Content-Type: ${contentType}`, "", ""].join("\r\n");
  return Buffer.from(toCrlf(`${head}${body}`), "utf8");
}

export interface SmtpOptions {
  host: string;
  port?: number;
  username?: string;
  password?: string;
  /** Upgrades to STARTTLS when the server advertises it. Defaults to true. */
  requireTls?: boolean;
  timeoutMs?: number;
}

interface Waiter {
  resolve: (line: string) => void;
  reject: (err: Error) => void;
}

class SmtpSession {
  private buffer = "";
  private lines: string[] = [];
  private waiter: Waiter | null = null;
  private failure: Error | null = null;
  private readonly socket: net.Socket | tls.TLSSocket;
  private readonly timeoutMs: number;

  constructor(socket: net.Socket | tls.TLSSocket, timeoutMs: number) {
    this.socket = socket;
    this.timeoutMs = timeoutMs;
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => this.onData(chunk));
    socket.on("error", (err: Error) => this.fail(err));
    socket.on("close", () => this.fail(new Error("SMTP connection closed unexpectedly")));
  }

  private fail(err: Error): void {
    this.failure = err;
    const waiter = this.waiter;
    this.waiter = null;
    waiter?.reject(err);
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    // A reply is "<code><space><text>"; multi-line replies continue with "<code>-".
    while (true) {
      const match = this.buffer.match(/^(\d{3})([ -])([^\n]*)\r?\n/);
      if (!match) break;
      this.buffer = this.buffer.slice(match[0].length);
      if (match[2] === " ") {
        this.deliver(`${match[1]}${match[3]}`);
      }
    }
  }

  private deliver(line: string): void {
    const waiter = this.waiter;
    if (waiter) {
      this.waiter = null;
      waiter.resolve(line);
    } else {
      this.lines.push(line);
    }
  }

  private read(): Promise<string> {
    if (this.failure) return Promise.reject(this.failure);
    const buffered = this.lines.shift();
    if (buffered !== undefined) return Promise.resolve(buffered);

    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiter = null;
        reject(new Error(`SMTP response timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);

      this.waiter = {
        resolve: (line) => {
          clearTimeout(timer);
          resolve(line);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      };
    });
  }

  async command(line: string, expected: RegExp): Promise<string> {
    if (line !== "") {
      await new Promise<void>((resolve, reject) => {
        this.socket.write(`${line}\r\n`, (err) => (err ? reject(err) : resolve()));
      });
    }
    const response = await this.read();
    if (!expected.test(response)) {
      throw new Error(`SMTP rejected command (wanted ${expected}, got "${response}"): ${line.slice(0, 80)}`);
    }
    return response;
  }

  writeRaw(chunk: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.socket.write(chunk, (err) => (err ? reject(err) : resolve()));
    });
  }

  upgrade(servername: string): Promise<tls.TLSSocket> {
    return new Promise<tls.TLSSocket>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`SMTP STARTTLS handshake timed out after ${this.timeoutMs}ms`)), this.timeoutMs);
      const secure = tls.connect({ socket: this.socket as net.Socket, servername }, () => {
        clearTimeout(timer);
        resolve(secure);
      });
      secure.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  end(): void {
    this.socket.end();
  }
}

/**
 * Minimal SMTP submission client. A dedicated library is not a project dependency,
 * so the subset needed for authenticated submission lives here.
 */
export function createSmtpTransport(options: SmtpOptions): EmailTransport {
  const port = options.port ?? 587;
  const timeoutMs = options.timeoutMs ?? 15_000;
  const requireTls = options.requireTls ?? true;

  return async (message: EmailMessage) => {
    const socket = net.connect({ host: options.host, port });
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`SMTP connect to ${options.host}:${port} timed out`)), timeoutMs);
      socket.once("connect", () => {
        clearTimeout(timer);
        resolve();
      });
      socket.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });

    let session = new SmtpSession(socket, timeoutMs);

    try {
      await session.command("", /^220/);

      const ehlo = await session.command("EHLO omniscan.io", /^250/);
      const capabilities = ehlo.toLowerCase();
      const supportsStartTls = capabilities.includes("starttls");

      if (supportsStartTls) {
        await session.command("STARTTLS", /^220/);
        const secureSocket = await session.upgrade(options.host);
        // Capabilities must be re-read over the encrypted channel.
        session = new SmtpSession(secureSocket, timeoutMs);
        await session.command("EHLO omniscan.io", /^250/);
      } else if (requireTls) {
        throw new Error(`SMTP server ${options.host} does not support STARTTLS (refusing to send in the clear)`);
      }

      if (options.username) {
        if (!supportsStartTls) {
          throw new Error("Refusing to send SMTP credentials over an unencrypted connection");
        }
        await session.command("AUTH LOGIN", /^334/);
        await session.command(Buffer.from(options.username, "utf8").toString("base64"), /^334/);
        await session.command(Buffer.from(options.password ?? "", "utf8").toString("base64"), /^235/);
      }

      await session.command(`MAIL FROM:<${message.envelopeFrom}>`, /^250/);
      await session.command(`RCPT TO:<${message.to.email}>`, /^250/);
      await session.command("DATA", /^354/);

      const payload = serializeMessage(message).toString("utf8");
      // Dot-stuffing: a line consisting of a single "." would terminate DATA early.
      const stuffed = payload.replace(/\r\n\./g, "\r\n..").replace(/^\./, "..");
      await session.writeRaw(`${stuffed}\r\n.\r\n`);
      await session.command("", /^250/);

      await session.command("QUIT", /^221/);
    } finally {
      session.end();
    }
  };
}

/** Collects messages instead of sending them. Used by tests and local preview runs. */
export function createMemoryTransport(sent: EmailMessage[] = []): EmailTransport {
  return async (message: EmailMessage) => {
    sent.push(message);
  };
}

export function resolveFromAddress(input: DispatchEmailInput): string {
  const from = input.from ?? process.env.EMAIL_FROM ?? "OmniScan <reports@omniscan.io>";
  assertHeaderSafe(from, "From address");
  return from;
}

export async function dispatchEmail(input: DispatchEmailInput): Promise<DispatchResult> {
  const recipient = normalizeRecipient(input.recipient ?? input.report.recipientEmail);
  const from = resolveFromAddress(input);
  const message = buildMessage(input, recipient, from);
  const payload = serializeMessage(message);

  const base: DispatchResult = {
    messageId: message.headers["Message-ID"],
    to: recipient.email,
    subject: buildSubject(input.report),
    bytes: payload.byteLength,
    sent: false,
  };

  if (!input.transport) {
    return { ...base, sent: false, error: "No transport supplied; message was rendered but not sent" };
  }

  try {
    await input.transport(message);
    return { ...base, sent: true };
  } catch (err) {
    return { ...base, sent: false, error: (err as Error).message };
  }
}
