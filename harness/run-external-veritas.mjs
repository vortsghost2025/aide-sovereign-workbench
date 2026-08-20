import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { THRESHOLDS } from './veritas.mjs';
import { renderExternalRunReport } from './external-run/report.mjs';
import { verifyExternalRun } from './external-run/verify.mjs';

export function parseExternalVeritasArgs(argv = process.argv.slice(2)) {
  const options = { bundle: null, workspace: '.', taskClass: 'code-change', format: 'json', output: null };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--report') options.format = 'report';
    else if (arg === '--bundle' || arg === '--workspace' || arg === '--task-class' || arg === '--output') {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) throw new Error(`${arg} requires a value`);
      index += 1;
      if (arg === '--bundle') options.bundle = path.resolve(value);
      if (arg === '--workspace') options.workspace = path.resolve(value);
      if (arg === '--task-class') options.taskClass = value;
      if (arg === '--output') options.output = path.resolve(value);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!options.help && !options.bundle) throw new Error('--bundle is required');
  if (!(options.taskClass in THRESHOLDS)) throw new Error(`unknown task class: ${options.taskClass}`);
  return options;
}

export function renderExternalHelp() {
  return [
    'Usage: npm run veritas:external -- --bundle <run.json> [options]',
    '',
    'Options:',
    '  --workspace <path>   Git workspace containing base/head commits',
    '  --task-class <class> Veritas evidence threshold class',
    '  --report             Render Markdown instead of JSON',
    '  --output <path>      Write result to a file',
    '  --help               Show this help',
    '',
    `Task classes: ${Object.keys(THRESHOLDS).join(', ')}`
  ].join('\n');
}

export async function runExternalVeritasCli(argv = process.argv.slice(2)) {
  const options = parseExternalVeritasArgs(argv);
  if (options.help) {
    console.log(renderExternalHelp());
    return { exitCode: 0, result: null };
  }
  const bundle = JSON.parse(await fs.readFile(options.bundle, 'utf8'));
  const result = await verifyExternalRun({
    bundle,
    bundlePath: options.bundle,
    workspace: options.workspace,
    taskClass: options.taskClass
  });
  const output = options.format === 'report'
    ? renderExternalRunReport(result)
    : JSON.stringify(result, null, 2);
  if (options.output) {
    await fs.mkdir(path.dirname(options.output), { recursive: true });
    await fs.writeFile(options.output, `${output}\n`, 'utf8');
  } else {
    console.log(output);
  }
  return { exitCode: result.disposition === 'verified' ? 0 : 1, result };
}

const invoked = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invoked) {
  try {
    const { exitCode } = await runExternalVeritasCli();
    process.exitCode = exitCode;
  } catch (error) {
    console.error(`external veritas failed: ${error.message}`);
    process.exitCode = 2;
  }
}
