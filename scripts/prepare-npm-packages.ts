#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import process from 'node:process';

type TargetMetadata = {
  package: string;
  os: string;
  cpu: string;
};

type Arguments = {
  version?: string;
  artifactsDir?: string;
  outDir: string;
  dryRunPlaceholders: boolean;
  packDryRun: boolean;
};

const PACKAGE = '@casualjim/heimdall-sandbox';
const BINARY = 'heimdall-sandbox';
const TARGETS: Record<string, TargetMetadata> = {
  'x86_64-unknown-linux-gnu': {
    package: '@casualjim/heimdall-sandbox-linux-x64',
    os: 'linux',
    cpu: 'x64',
  },
  'aarch64-unknown-linux-gnu': {
    package: '@casualjim/heimdall-sandbox-linux-arm64',
    os: 'linux',
    cpu: 'arm64',
  },
  'aarch64-apple-darwin': {
    package: '@casualjim/heimdall-sandbox-darwin-arm64',
    os: 'darwin',
    cpu: 'arm64',
  },
};

function parseArguments(argv: string[]): Arguments {
  const args: Arguments = {
    outDir: 'target/npm-packages',
    dryRunPlaceholders: false,
    packDryRun: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    switch (arg) {
      case '--version':
        args.version = requireValue(argv, ++index, arg);
        break;
      case '--artifacts-dir':
        args.artifactsDir = requireValue(argv, ++index, arg);
        break;
      case '--out-dir':
        args.outDir = requireValue(argv, ++index, arg);
        break;
      case '--dry-run-placeholders':
        args.dryRunPlaceholders = true;
        break;
      case '--pack-dry-run':
        args.packDryRun = true;
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  return args;
}

function requireValue(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (!value || value.startsWith('--')) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function workspaceVersion(): string {
  const manifest = readText('Cargo.toml');
  let inWorkspacePackage = false;
  for (const line of manifest.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '[workspace.package]') {
      inWorkspacePackage = true;
      continue;
    }
    if (trimmed.startsWith('[') && trimmed !== '[workspace.package]') {
      inWorkspacePackage = false;
    }
    if (inWorkspacePackage) {
      const match = /^version\s*=\s*"([^"]+)"/.exec(trimmed);
      if (match) {
        return match[1];
      }
    }
  }
  throw new Error('workspace.package.version not found in Cargo.toml');
}

function readText(path: string): string {
  return readFileSync(path, 'utf8');
}

function writeJson(path: string, data: unknown): void {
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}

function writeExecutable(path: string, content: string | Buffer): void {
  writeFileSync(path, content);
  const mode = statSync(path).mode;
  chmodExecutable(path, mode);
}

function chmodExecutable(path: string, mode = statSync(path).mode): void {
  chmodSync(path, mode | 0o111);
}

function findArchive(artifactsDir: string, target: string): string {
  const prefix = `${BINARY}-${target}.tar.`;
  const matches = readdirSync(artifactsDir)
    .filter((entry) => entry.startsWith(prefix))
    .sort();
  if (matches.length === 0) {
    throw new Error(`missing cargo-dist archive for ${target} in ${artifactsDir}`);
  }
  return join(artifactsDir, matches[0]);
}

function extractBinary(archive: string, destination: string): void {
  const list = spawnChecked('tar', ['-tf', archive]).stdout.trim().split('\n');
  const member = list.find((entry) => basename(entry) === BINARY);
  if (!member) {
    throw new Error(`archive ${archive} does not contain ${BINARY}`);
  }
  const binary = spawnChecked('tar', ['-xOf', archive, member], 'buffer').stdout;
  writeExecutable(destination, binary);
}

function packageSlug(packageName: string): string {
  return packageName.replace(/^@casualjim\//, '');
}

function createPlatformPackage(outDir: string, target: string, meta: TargetMetadata, version: string, artifactsDir?: string): string {
  const packageDir = join(outDir, packageSlug(meta.package));
  const binDir = join(packageDir, 'bin');
  mkdirSync(binDir, { recursive: true });
  const binaryPath = join(binDir, BINARY);

  if (!artifactsDir) {
    writeExecutable(binaryPath, "#!/usr/bin/env sh\necho 'placeholder binary for npm package dry-run validation'\n");
  } else {
    extractBinary(findArchive(artifactsDir, target), binaryPath);
  }

  writeJson(join(packageDir, 'package.json'), {
    name: meta.package,
    version,
    description: `Heimdall sandbox CLI binary for ${target}.`,
    license: 'MIT',
    repository: { type: 'git', url: 'git+https://github.com/casualjim/heimdall-sandbox.git' },
    homepage: 'https://github.com/casualjim/heimdall-sandbox',
    os: [meta.os],
    cpu: [meta.cpu],
    bin: { [BINARY]: `bin/${BINARY}` },
    files: ['bin', 'README.md'],
  });
  writeFileSync(join(packageDir, 'README.md'), `# ${meta.package}\n\nPlatform binary package for \`${PACKAGE}\` on \`${target}\`.\n`, 'utf8');
  return packageDir;
}

function createMainPackage(outDir: string, version: string): string {
  const packageDir = join(outDir, 'heimdall-sandbox');
  const binDir = join(packageDir, 'bin');
  mkdirSync(binDir, { recursive: true });
  const optionalDependencies = Object.fromEntries(Object.values(TARGETS).map((meta) => [meta.package, version]));

  writeJson(join(packageDir, 'package.json'), {
    name: PACKAGE,
    version,
    description: 'Process sandbox runtime for Heimdall.',
    license: 'MIT',
    repository: { type: 'git', url: 'git+https://github.com/casualjim/heimdall-sandbox.git' },
    homepage: 'https://github.com/casualjim/heimdall-sandbox',
    bin: { [BINARY]: `bin/${BINARY}.js` },
    optionalDependencies,
    files: ['bin', 'README.md'],
  });

  writeExecutable(
    join(binDir, `${BINARY}.js`),
    `#!/usr/bin/env node
const { spawnSync } = require('node:child_process');
const process = require('node:process');

const packages = {
  'linux:x64': '@casualjim/heimdall-sandbox-linux-x64',
  'linux:arm64': '@casualjim/heimdall-sandbox-linux-arm64',
  'darwin:arm64': '@casualjim/heimdall-sandbox-darwin-arm64',
};

const key = \`${'${process.platform}:${process.arch}'}\`;
const packageName = packages[key];
if (!packageName) {
  console.error(\`Unsupported platform ${'${key}'}. Supported platforms: ${'${Object.keys(packages).join(\', \')}'}\`);
  process.exit(1);
}

let binary;
try {
  binary = require.resolve(\`${'${packageName}'}/bin/heimdall-sandbox\`);
} catch (error) {
  console.error(\`Missing Heimdall platform package ${'${packageName}'}. Reinstall @casualjim/heimdall-sandbox and ensure optional dependencies are enabled.\`);
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: 'inherit' });
if (result.error) {
  console.error(\`Failed to execute ${'${binary}'}: ${'${result.error.message}'}\`);
  process.exit(1);
}
process.exit(result.status ?? 1);
`,
  );
  writeFileSync(
    join(packageDir, 'README.md'),
    `# ${PACKAGE}\n\nRegistry-hosted Heimdall CLI package. Platform binaries are supplied by optional npm dependencies; no GitHub release asset download occurs during install or first run.\n`,
    'utf8',
  );
  return packageDir;
}

function npmPackDryRun(packageDir: string): void {
  spawnChecked('npm', ['pack', '--dry-run'], undefined, packageDir);
}

function spawnChecked(command: string, args: string[], output: 'buffer' | undefined = undefined, cwd?: string): { stdout: string; stderr: string } | { stdout: Buffer; stderr: Buffer } {
  const result = spawnSync(command, args, {
    cwd,
    encoding: output === 'buffer' ? undefined : 'utf8',
    stdio: output === 'buffer' ? ['ignore', 'pipe', 'pipe'] : ['ignore', 'pipe', 'inherit'],
  });
  if (result.status !== 0) {
    const stderr = Buffer.isBuffer(result.stderr) ? result.stderr.toString('utf8') : (result.stderr ?? '');
    throw new Error(`${command} ${args.join(' ')} failed: ${stderr}`);
  }
  return { stdout: result.stdout as never, stderr: result.stderr as never };
}

function main(): void {
  const args = parseArguments(process.argv.slice(2));
  const version = args.version ?? workspaceVersion();
  const artifactsDir = args.dryRunPlaceholders ? undefined : args.artifactsDir;

  if (!artifactsDir && !args.dryRunPlaceholders) {
    throw new Error('--artifacts-dir is required unless --dry-run-placeholders is set');
  }
  if (existsSync(args.outDir)) {
    rmSync(args.outDir, { recursive: true, force: true });
  }
  mkdirSync(args.outDir, { recursive: true });

  const packageDirs = Object.entries(TARGETS).map(([target, meta]) => createPlatformPackage(args.outDir, target, meta, version, artifactsDir));
  packageDirs.push(createMainPackage(args.outDir, version));

  if (args.packDryRun) {
    for (const packageDir of packageDirs) {
      npmPackDryRun(packageDir);
    }
  }

  console.log(packageDirs.join('\n'));
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}
