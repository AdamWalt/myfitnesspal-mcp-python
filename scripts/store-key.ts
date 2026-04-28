#!/usr/bin/env tsx
/**
 * store-key — one-time CLI to generate and store MFP_SECRET_KEY in the OS keychain.
 * Uses native OS tools (no native Node bindings required):
 *   macOS  → security(1)      — built into every macOS install
 *   Windows → cmdkey / PowerShell — built into Windows
 *   Linux  → secret-tool      — requires libsecret-tools package
 *
 * Usage:
 *   npm run store-key                  # generate a new key and store it
 *   npm run store-key -- --key <val>   # store an existing Fernet key
 *   npm run store-key -- --overwrite   # replace a key that is already stored
 *   npm run store-key -- --delete      # remove the stored key
 *   npm run store-key -- --show        # print the currently stored key
 *
 * Keychain coordinates:
 *   service  : mfp-mcp
 *   account  : MFP_SECRET_KEY
 */

import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';

const SERVICE = 'mfp-mcp';
const ACCOUNT = 'MFP_SECRET_KEY';
const PLATFORM = process.platform; // 'darwin' | 'win32' | 'linux'

// ---------------------------------------------------------------------------
// Keychain abstraction — thin wrappers around OS CLI tools
// ---------------------------------------------------------------------------

function keychainGet(): string | null {
  try {
    if (PLATFORM === 'darwin') {
      return execFileSync(
        'security',
        ['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w'],
        { stdio: ['pipe', 'pipe', 'pipe'] }
      ).toString().trim();
    }
    if (PLATFORM === 'win32') {
      // Use built-in PowerShell/.NET interop — no third-party modules required.
      const ps = `
$target = '${SERVICE}/${ACCOUNT}'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class CredMan {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL {
    public UInt32 Flags; public UInt32 Type; public string TargetName;
    public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public UInt32 CredentialBlobSize; public IntPtr CredentialBlob;
    public UInt32 Persist; public UInt32 AttributeCount; public IntPtr Attributes;
    public string TargetAlias; public string UserName;
  }
  [DllImport("Advapi32.dll", EntryPoint="CredReadW", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool CredRead(string target, int type, int flags, out IntPtr ptr);
  [DllImport("Advapi32.dll", EntryPoint="CredFree", SetLastError=true)]
  public static extern void CredFree(IntPtr ptr);
}
"@
$ptr = [IntPtr]::Zero
if ([CredMan]::CredRead($target, 1, 0, [ref]$ptr)) {
  try {
    $c = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][CredMan+CREDENTIAL])
    if ($c.CredentialBlob -ne [IntPtr]::Zero -and $c.CredentialBlobSize -gt 0) {
      $b = New-Object byte[] $c.CredentialBlobSize
      [Runtime.InteropServices.Marshal]::Copy($c.CredentialBlob, $b, 0, $c.CredentialBlobSize)
      [Text.Encoding]::Unicode.GetString($b).TrimEnd([char]0)
    }
  } finally { [CredMan]::CredFree($ptr) }
}`.trim();
      return spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps], {
        stdio: ['pipe', 'pipe', 'pipe'],
      }).stdout?.toString().trim() || null;
    }
    // Linux — libsecret-tools
    return execFileSync(
      'secret-tool',
      ['lookup', 'service', SERVICE, 'username', ACCOUNT],
      { stdio: ['pipe', 'pipe', 'pipe'] }
    ).toString().trim();
  } catch {
    return null;
  }
}

function keychainSet(key: string): void {
  // Validate: Fernet keys are URL-safe base64 (43 chars + optional padding '=').
  if (!/^[A-Za-z0-9_\-]+=*$/.test(key)) {
    throw new Error('Key contains unexpected characters; aborting to prevent shell injection.');
  }
  if (PLATFORM === 'darwin') {
    // Pass the key via -w arg (no shell involved).
    execFileSync(
      'security',
      ['add-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w', key, '-U'],
      { stdio: 'inherit' }
    );
    return;
  }
  if (PLATFORM === 'win32') {
    // cmdkey doesn't accept stdin; pass via argument — execFileSync avoids shell expansion.
    execFileSync(
      'cmdkey',
      [`/generic:${SERVICE}/${ACCOUNT}`, `/user:${ACCOUNT}`, `/pass:${key}`],
      { stdio: 'inherit' }
    );
    return;
  }
  // Linux — pipe key via stdin to avoid it appearing on the command line.
  spawnSync(
    'secret-tool',
    ['store', '--label=mfp-mcp secret key', 'service', SERVICE, 'username', ACCOUNT],
    { input: key, stdio: ['pipe', 'inherit', 'inherit'] }
  );
}

function keychainDelete(): boolean {
  try {
    if (PLATFORM === 'darwin') {
      execFileSync(
        'security',
        ['delete-generic-password', '-s', SERVICE, '-a', ACCOUNT],
        { stdio: ['pipe', 'pipe', 'pipe'] }
      );
    } else if (PLATFORM === 'win32') {
      execFileSync(
        'cmdkey',
        [`/delete:${SERVICE}/${ACCOUNT}`],
        { stdio: ['pipe', 'pipe', 'pipe'] }
      );
    } else {
      execFileSync(
        'secret-tool',
        ['clear', 'service', SERVICE, 'username', ACCOUNT],
        { stdio: ['pipe', 'pipe', 'pipe'] }
      );
    }
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/** 32 random bytes → URL-safe base64 — identical format to Python's Fernet.generate_key(). */
function generateFernetKey(): string {
  return crypto
    .randomBytes(32)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const result: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--key' && argv[i + 1]) {
      result['key'] = argv[++i];
    } else if (argv[i].startsWith('--')) {
      result[argv[i].slice(2)] = true;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(): void {
  const args = parseArgs(process.argv.slice(2));

  // --show
  if (args['show']) {
    const stored = keychainGet();
    if (!stored) {
      console.error('No key found in keychain.');
      process.exit(1);
    }
    console.log(stored);
    return;
  }

  // --delete
  if (args['delete']) {
    const removed = keychainDelete();
    if (!removed) {
      console.log('Nothing to delete — no key is stored.');
    } else {
      console.log('✅ MFP_SECRET_KEY removed from keychain.');
    }
    return;
  }

  // Guard: key already exists and --overwrite not passed
  const existing = keychainGet();
  if (existing && !args['overwrite']) {
    console.log('⚠️  An MFP_SECRET_KEY is already stored in the keychain.');
    console.log('    Pass --overwrite to replace it, or --show to inspect it.');
    process.exit(0);
  }

  // Resolve key
  const key = typeof args['key'] === 'string' ? args['key'] : generateFernetKey();
  const source = typeof args['key'] === 'string' ? 'provided' : 'generated';

  keychainSet(key);

  console.log(`\n✅ MFP_SECRET_KEY ${existing ? 'updated' : 'stored'} in OS keychain`);
  console.log(`   service : ${SERVICE}`);
  console.log(`   account : ${ACCOUNT}`);
  console.log(`   source  : ${source}\n`);
  console.log('Your key (use this to encrypt MFP_USERNAME / MFP_PASSWORD):');
  console.log(`\n  ${key}\n`);
  console.log('Next — encrypt your credentials with Python:\n');
  console.log('  from cryptography.fernet import Fernet');
  console.log(`  f = Fernet(b"${key}")`);
  console.log('  print("MFP_USERNAME:", f.encrypt(b"your_email@example.com").decode())');
  console.log('  print("MFP_PASSWORD:", f.encrypt(b"your_password").decode())');
  console.log('\nThen add only the encrypted values to your Claude Desktop config (no key in the config).');
}

try {
  main();
} catch (err) {
  console.error('❌ Failed:', (err as Error).message);
  process.exit(1);
}
