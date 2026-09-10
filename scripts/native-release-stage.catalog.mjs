// Fixed local bridge to the shared catalog validator. Never imports staged code.
import { readFileSync } from 'node:fs';
import { validateArtifact, transition } from './release-channels.mjs';

try {
  const input = readFileSync(0);
  if (input.length > 2 * 1024 * 1024) throw new Error('Input limit');
  const value = JSON.parse(input);
  const [command, channel, revision, ...extra] = process.argv.slice(2);
  if (extra.length) throw new Error('Arguments');
  let artifact;
  if (command === 'artifact' && channel === undefined) {
    artifact = validateArtifact(value);
  } else if (command === 'selection' && ['dev', 'prod'].includes(channel) && /^(0|[1-9][0-9]*)$/.test(revision ?? '')) {
    const expected = Number(revision);
    if (!Number.isSafeInteger(expected) || expected !== value.revision) throw new Error('Revision changed');
    // transition validates the entire history; this existing dev selection is a no-op.
    // Never call updateChannels or persist the returned state here.
    const dev = value.dev?.heteronetwork;
    if (!dev) throw new Error('No dev artifact');
    transition(value, 'stage', dev, expected);
    artifact = validateArtifact(value[channel]?.heteronetwork);
  } else {
    throw new Error('Arguments');
  }
  if (artifact.component !== 'heteronetwork' || !artifact.native) throw new Error('Native artifact required');
  process.stdout.write(JSON.stringify(artifact));
} catch {
  process.stderr.write('Native catalog validation failed.\n');
  process.exitCode = 1;
}
