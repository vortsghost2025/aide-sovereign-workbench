import { once } from 'node:events';
import { spawn } from 'node:child_process';
import readline from 'node:readline';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function cloneForTranscript(value) {
  return JSON.parse(JSON.stringify(value));
}

export class SshMcpClient {
  constructor({ host, remoteBinary, timeoutMs = 30_000 } = {}) {
    if (!host) throw new Error('host is required');
    if (!remoteBinary) throw new Error('remoteBinary is required');
    this.host = host;
    this.remoteBinary = remoteBinary;
    this.timeoutMs = timeoutMs;
    this.nextId = 1;
    this.pending = new Map();
    this.transcript = [];
    this.stderr = '';
    this.proc = null;
    this.reader = null;
  }

  async start() {
    if (this.proc) return;
    const args = [
      '-T',
      '-o', 'BatchMode=yes',
      '-o', 'ConnectTimeout=10',
      '-o', 'ServerAliveInterval=15',
      '-o', 'ServerAliveCountMax=2',
      this.host,
      `${this.remoteBinary} mcp`
    ];

    this.proc = spawn('ssh', args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true
    });

    this.proc.stderr.setEncoding('utf8');
    this.proc.stderr.on('data', chunk => {
      this.stderr += chunk;
    });

    this.reader = readline.createInterface({ input: this.proc.stdout, crlfDelay: Infinity });
    this.reader.on('line', line => this.#handleLine(line));

    this.proc.on('exit', (code, signal) => {
      const error = new Error(`SSH MCP process exited (code=${code}, signal=${signal || 'none'})`);
      for (const { reject, timer } of this.pending.values()) {
        clearTimeout(timer);
        reject(error);
      }
      this.pending.clear();
    });

    await Promise.race([
      once(this.proc, 'spawn'),
      once(this.proc, 'error').then(([error]) => Promise.reject(error))
    ]);
  }

  #record(direction, message) {
    this.transcript.push({
      at: new Date().toISOString(),
      direction,
      message: cloneForTranscript(message)
    });
  }

  #handleLine(line) {
    const trimmed = line.trim();
    if (!trimmed) return;
    let message;
    try {
      message = JSON.parse(trimmed);
    } catch {
      this.transcript.push({ at: new Date().toISOString(), direction: 'in-non-json', text: trimmed });
      return;
    }
    this.#record('in', message);
    if (message.id === undefined || message.id === null) return;
    const entry = this.pending.get(String(message.id));
    if (!entry) return;
    this.pending.delete(String(message.id));
    clearTimeout(entry.timer);
    if (message.error) entry.reject(new Error(`MCP ${message.error.code}: ${message.error.message}`));
    else entry.resolve(message.result);
  }

  async request(method, params = {}) {
    await this.start();
    const id = this.nextId++;
    const message = { jsonrpc: '2.0', id, method, params };
    this.#record('out', message);

    const response = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(String(id));
        reject(new Error(`MCP request timed out after ${this.timeoutMs}ms: ${method}`));
      }, this.timeoutMs);
      this.pending.set(String(id), { resolve, reject, timer });
    });

    if (!this.proc.stdin.write(`${JSON.stringify(message)}\n`)) {
      await once(this.proc.stdin, 'drain');
    }
    return response;
  }

  async notify(method, params = {}) {
    await this.start();
    const message = { jsonrpc: '2.0', method, params };
    this.#record('out', message);
    if (!this.proc.stdin.write(`${JSON.stringify(message)}\n`)) {
      await once(this.proc.stdin, 'drain');
    }
  }

  async initialize() {
    const result = await this.request('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'aide-obscura-ssh-lab', version: '1' }
    });
    await this.notify('notifications/initialized', {});
    return result;
  }

  async listTools() {
    return this.request('tools/list', {});
  }

  async callTool(name, args = {}) {
    const result = await this.request('tools/call', { name, arguments: args });
    if (result?.isError) {
      const text = result?.content?.find(item => item?.type === 'text')?.text || 'unknown tool error';
      throw new Error(`${name}: ${text}`);
    }
    return result;
  }

  async close() {
    if (!this.proc) return;
    const proc = this.proc;
    if (!proc.stdin.destroyed) proc.stdin.end();
    await Promise.race([
      once(proc, 'exit').catch(() => undefined),
      sleep(2_000)
    ]);
    if (proc.exitCode === null && proc.signalCode === null) proc.kill();
    this.reader?.close();
    this.proc = null;
  }
}

export function toolText(result) {
  return result?.content?.find(item => item?.type === 'text')?.text || '';
}
