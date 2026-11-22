import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

const config = await Bun.file('components.json').json();
if (typeof config.registry !== 'string') throw new Error('components.json has no registry URL');

const registryUrl = `${config.registry.replace(/\/$/, '')}/index.json`;
const registryResponse = await fetch(registryUrl);
if (!registryResponse.ok) throw new Error(`Registry request failed: ${registryResponse.status} ${registryUrl}`);

const index = await registryResponse.json();
const items = Array.isArray(index) ? index : index.items;
if (!Array.isArray(items) || items.length === 0) throw new Error('Registry index has no items');

const names: string[] = [];
const dependencies = new Set<string>();
for (const item of items) {
  if (typeof item.name !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(item.name)) {
    throw new Error(`Invalid registry item name: ${item.name}`);
  }
  names.push(item.name);
  for (const name of [...(item.dependencies ?? []), ...(item.devDependencies ?? [])]) {
    if (typeof name !== 'string') throw new Error(`Invalid package dependency on registry item ${item.name}`);
    dependencies.add(name);
  }
}

const packageUrl = 'https://raw.githubusercontent.com/z00rat/neo-retro/master/package.json';
const packageResponse = await fetch(packageUrl);
if (!packageResponse.ok) throw new Error(`Design-system package request failed: ${packageResponse.status}`);
const designSystemPackage = await packageResponse.json();
const sourceDependencies = { ...designSystemPackage.dependencies, ...designSystemPackage.devDependencies };
const projectPackage = await Bun.file('package.json').json();
const existingDependencies = new Set([
  ...Object.keys(projectPackage.dependencies ?? {}),
  ...Object.keys(projectPackage.devDependencies ?? {}),
]);
for (const name of existingDependencies) {
  if (typeof sourceDependencies[name] === 'string') dependencies.add(name);
}

const updatedDependencies: Record<string, string> = {};
for (const name of dependencies) {
  const version = sourceDependencies[name];
  if (typeof version !== 'string') throw new Error(`No version for ${name} in the design-system package.json`);
  updatedDependencies[name] = version;
}

const skillsTreeUrl = 'https://api.github.com/repos/z00rat/neo-retro/git/trees/master?recursive=1';
const skillsTreeResponse = await fetch(skillsTreeUrl);
if (!skillsTreeResponse.ok) throw new Error(`Skills index request failed: ${skillsTreeResponse.status}`);
const skillsTree = await skillsTreeResponse.json();
if (skillsTree.truncated || !Array.isArray(skillsTree.tree)) {
  throw new Error('Could not read the complete design-system skills tree');
}

const skillsPrefix = 'skills/neo-retro/';
const skillPaths: string[] = skillsTree.tree
  .filter((entry: { path: string; type: string }) => entry.type === 'blob' && entry.path.startsWith(skillsPrefix))
  .map((entry: { path: string }) => entry.path);
if (skillPaths.length === 0) throw new Error('No Neo-Retro skill files found in the design-system repo');

const skills = await Promise.all(
  skillPaths.map(async (path) => {
    const relativePath = path.slice(skillsPrefix.length);
    if (relativePath.split('/').some((part) => !/^[a-zA-Z0-9._-]+$/.test(part) || part === '..')) {
      throw new Error(`Invalid skill file path: ${path}`);
    }
    const rawPath = path.split('/').map(encodeURIComponent).join('/');
    const url = `https://raw.githubusercontent.com/z00rat/neo-retro/master/${rawPath}`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Skill file request failed: ${response.status} ${path}`);
    return { target: `.agents/skills/neo-retro/${relativePath}`, content: await response.text() };
  }),
);

console.log(
  `Found ${names.length} registry items, ${dependencies.size} package dependencies, and ${skills.length} skill files.`,
);
console.log(names.join(', '));
console.log(`Skills: ${skills.map((skill) => skill.target).join(', ')}`);
const answer = prompt('Overwrite these items and sync their package versions? [y/N]');
if (!answer || !/^(y|yes)$/i.test(answer.trim())) {
  console.log('Cancelled.');
  process.exit(0);
}

const update = Bun.spawnSync(['bun', 'x', 'shadcn-svelte@latest', 'add', '--yes', '--overwrite', ...names], {
  stdout: 'inherit',
  stderr: 'inherit',
});
if (update.exitCode !== 0) process.exit(update.exitCode ?? 1);

projectPackage.devDependencies ??= {};
Object.assign(projectPackage.devDependencies, updatedDependencies);
await Bun.write('package.json', `${JSON.stringify(projectPackage, null, 2)}\n`);

for (const skill of skills) {
  await mkdir(dirname(skill.target), { recursive: true });
  await Bun.write(skill.target, skill.content);
}

for (const args of [['install'], ['run', 'format']]) {
  const result = Bun.spawnSync(['bun', ...args], { stdout: 'inherit', stderr: 'inherit' });
  if (result.exitCode !== 0) process.exit(result.exitCode ?? 1);
}
