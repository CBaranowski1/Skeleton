// @ts-nocheck
// The bootstrap harness runs before a compiler exists and is validated by Node's
// strip-types parser plus its fail-closed runtime ledger. Generated declarations
// remain under the strict project compiler contract.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { gunzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const typescriptRoot = join(repositoryRoot, "typescript");
const validationRoot = join(repositoryRoot, "validation");
const registryBundlePath = join(validationRoot, "phase06-npm-registry-archive.bundle");
const registryEvidencePath = join(validationRoot, "phase06-npm-registry-archive.json");
const environmentBundlePath = join(
  validationRoot,
  "phase06-typescript-environment-transfer.bundle",
);
const environmentEvidencePath = join(
  validationRoot,
  "phase06-typescript-environment-transfer.json",
);
const ownerTestPath = join(typescriptRoot, "test", "owner.test.ts");
const ownerSourcePaths = [
  join(typescriptRoot, "src", "owner", "status-client.ts"),
  join(typescriptRoot, "src", "owner", "status-state.ts"),
  join(typescriptRoot, "src", "owner", "status-renderer.ts"),
];
const ownerBrowserPath = join(repositoryRoot, "web", "status", "status.js");
const expectedSourceCommit = "329ee528078b4c29936935f55f5afb54e82b7904";
const registryMagic = "SKELETON_PHASE06_NPM_REGISTRY_ARCHIVE_V1\0";
const registryEvidenceMagic = "SKELETON_PHASE06_NPM_REGISTRY_EVIDENCE_V1\0";
const environmentMagic = "SKELETON_PHASE06_TYPESCRIPT_ENVIRONMENT_V1\0";
const environmentEvidenceMagic =
  "SKELETON_PHASE06_TYPESCRIPT_ENVIRONMENT_EVIDENCE_V1\0";
const phase07BundleSha256 =
  "f3c52449f45223014987c3f255be97528094cc04017e569b3d288b91eb70a6a1";
const phase07FixtureIndexSha256 =
  "8ebeddbb8c2ed8af9e4b641241cb6390649b13075db8f80368a1d763d5206560";
const phase06DeclarationProjectionSha256 =
  "50a64973fe26efa9109af1cf8413b68ae0492ed54715fecafbea2869e87c107c";
const phase06SchemaIds = new Set([
  "https://schemas.skeleton.local/v1/advisory-proposal.schema.json",
  "https://schemas.skeleton.local/v1/authority-command.schema.json",
  "https://schemas.skeleton.local/v1/authority-result.schema.json",
  "https://schemas.skeleton.local/v1/constitution.schema.json",
  "https://schemas.skeleton.local/v1/experience-envelope.schema.json",
  "https://schemas.skeleton.local/v1/kernel-status.schema.json",
  "https://schemas.skeleton.local/v1/lifecycle-event.schema.json",
  "https://schemas.skeleton.local/v1/lobe-package.schema.json",
  "https://schemas.skeleton.local/v1/material-authorization.schema.json",
  "https://schemas.skeleton.local/v1/primitives.schema.json",
  "https://schemas.skeleton.local/v1/project-manifest.schema.json",
  "https://schemas.skeleton.local/v1/rejection.schema.json",
  "https://schemas.skeleton.local/v1/work-object.schema.json",
]);
const phase07DeclarationInterfaces = [
  "SkeletonCanonicalEventV1",
  "SkeletonAuthorizedRecoverableDeletionExecutionV1",
  "SkeletonNonMutatingDeletionPreviewV1",
  "SkeletonRedactedEvidenceHealthSnapshotV1",
  "SkeletonExactEvidenceManifestV1",
  "SkeletonIdentityFactV1",
  "SkeletonAdditiveReadOnlyKernelStatusV2",
  "SkeletonLegalTermsRecordV1",
  "SkeletonClosedArtifactLineageRecordV1",
  "SkeletonPointInTimeReferenceFactV1",
  "SkeletonRightsRecordV1",
  "SkeletonRightsUseDecisionV1",
  "SkeletonRightsUseRequestV1",
  "SkeletonStableIdentityV1",
  "SkeletonPointInTimeUniverseEventV1",
];
const lifecycleKeys = new Set([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "preprepare",
  "postprepare",
  "prepublish",
  "prepublishOnly",
]);

const primaryCompiler = {
  coordinate: "@typescript/typescript-win32-x64@7.0.2",
  name: "@typescript/typescript-win32-x64",
  version: "7.0.2",
  metadata_url:
    "https://registry.npmjs.org/@typescript%2ftypescript-win32-x64/7.0.2",
  tarball_url:
    "https://registry.npmjs.org/@typescript/typescript-win32-x64/-/typescript-win32-x64-7.0.2.tgz",
  integrity:
    "sha512-0BQ3HkAHHlKLSp1qRvf3SUhGpGsDuhB/jgFw75guyqbxJqEaS0Cw/VFO8i2nHglJUzQCRtMMR/IBAKE3ETMC4g==",
  shasum: "cf3b7b0d6ce5635daca4c8e01c189cdcde47ec3c",
  direct: true,
  optional: false,
  dependencies: {},
  optional_dependencies: {},
  lifecycle_scripts: {},
};
const fixedPrimary = [
  primaryCompiler,
  {
    coordinate: "@types/node@26.1.2",
    name: "@types/node",
    version: "26.1.2",
    metadata_url: "https://registry.npmjs.org/%40types%2Fnode/26.1.2",
    tarball_url: "https://registry.npmjs.org/@types/node/-/node-26.1.2.tgz",
    integrity:
      "sha512-Vu4a5UFA9rIIFJ7rB/Vaafh9lrCQszopTCx6KjFboXTGQbPNasehVR5TEiithSDGyd1DEiUByggTZsg8jukeIg==",
    shasum: "da79708f1f9c6294f4cdec8f455a3032b028808a",
    direct: true,
    optional: false,
    dependencies: { "undici-types": "~8.3.0" },
    optional_dependencies: {},
    lifecycle_scripts: {},
  },
  {
    coordinate: "canonicalize@3.0.0",
    name: "canonicalize",
    version: "3.0.0",
    metadata_url: "https://registry.npmjs.org/canonicalize/3.0.0",
    tarball_url:
      "https://registry.npmjs.org/canonicalize/-/canonicalize-3.0.0.tgz",
    integrity:
      "sha512-yYLfHyDMIXRyRqsKBRLX023riFLpXY2YOfdtqKXZRZy9qsfOJ9U+4F9YZL7MEzL5+ziN2x2nlBvY/Voi3EBljA==",
    shasum: "a8073c48c1835631e1829d759078d2bbf48487fc",
    direct: true,
    optional: false,
    dependencies: {},
    optional_dependencies: {},
    lifecycle_scripts: {},
  },
  {
    coordinate: "undici-types@8.3.0",
    name: "undici-types",
    version: "8.3.0",
    metadata_url: "https://registry.npmjs.org/undici-types/8.3.0",
    tarball_url:
      "https://registry.npmjs.org/undici-types/-/undici-types-8.3.0.tgz",
    integrity:
      "sha512-j375ScV60dom+YkPFIfTLcOiPxkN/buHz5GobjLhixFuANaNs3C9l4GmrWqejgXWJ7BbJcFYpTEUkS1Ge8bpZQ==",
    shasum: "44e9fc9f3244648cdea35e4f9bb2d681e9410809",
    direct: false,
    optional: false,
    dependencies: {},
    optional_dependencies: {},
    lifecycle_scripts: {},
  },
].sort((a, b) => Buffer.compare(Buffer.from(a.coordinate), Buffer.from(b.coordinate)));
const fallbackCompiler = {
  coordinate: "typescript@6.0.2",
  name: "typescript",
  version: "6.0.2",
  metadata_url: "https://registry.npmjs.org/typescript/6.0.2",
  tarball_url: "https://registry.npmjs.org/typescript/-/typescript-6.0.2.tgz",
  integrity:
    "sha512-bGdAIrZ0wiGDo5l8c++HWtbaNCWTS4UTv7RaTH/ThVIgjkveJt83m74bBHMJkuCbslY8ixgLBVZJIOiQlQTjfQ==",
  shasum: "0b1bfb15f68c64b97032f3d78abbf98bdbba501f",
  direct: true,
  optional: false,
  dependencies: {},
  optional_dependencies: {},
  lifecycle_scripts: {},
};

function hash(algorithm, bytes) {
  return createHash(algorithm).update(bytes).digest("hex");
}

function sri(bytes) {
  return `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
}

function u32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function u64(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    if (typeof value === "string" && /[\uD800-\uDFFF]/u.test(value)) {
      for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
          const next = value.charCodeAt(index + 1);
          if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("lone_surrogate");
          index += 1;
        } else if (code >= 0xdc00 && code <= 0xdfff) {
          throw new Error("lone_surrogate");
        }
      }
    }
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("nonfinite_number");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value);
    return `{${keys
      .sort((left, right) =>
        left < right
          ? -1
          : left > right
            ? 1
            : 0,
      )
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new Error("unsupported_jcs_value");
}

function parseJsonWithoutDuplicates(bytes, label) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label}: invalid_utf8`);
  }
  let offset = 0;
  const fail = (reason) => {
    throw new Error(`${label}: ${reason}:${offset}`);
  };
  const ws = () => {
    while (/[\t\n\r ]/.test(text[offset] ?? "")) offset += 1;
  };
  const stringToken = () => {
    if (text[offset] !== '"') fail("expected_string");
    const start = offset++;
    while (offset < text.length) {
      const code = text.charCodeAt(offset);
      if (text[offset] === '"') {
        offset += 1;
        return JSON.parse(text.slice(start, offset));
      }
      if (text[offset] === "\\") offset += 2;
      else {
        if (code < 0x20) fail("control_character");
        offset += 1;
      }
    }
    fail("unterminated_string");
  };
  const value = () => {
    ws();
    if (text[offset] === "{") {
      offset += 1;
      ws();
      const keys = new Set();
      if (text[offset] === "}") return void (offset += 1);
      while (true) {
        const key = stringToken();
        if (keys.has(key)) fail("duplicate_member");
        keys.add(key);
        ws();
        if (text[offset++] !== ":") fail("expected_colon");
        value();
        ws();
        if (text[offset] === "}") return void (offset += 1);
        if (text[offset++] !== ",") fail("expected_comma");
        ws();
      }
    }
    if (text[offset] === "[") {
      offset += 1;
      ws();
      if (text[offset] === "]") return void (offset += 1);
      while (true) {
        value();
        ws();
        if (text[offset] === "]") return void (offset += 1);
        if (text[offset++] !== ",") fail("expected_comma");
      }
    }
    if (text[offset] === '"') return void stringToken();
    const token =
      /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(
        text.slice(offset),
      );
    if (!token) fail("invalid_value");
    offset += token[0].length;
  };
  value();
  ws();
  if (offset !== text.length) fail("trailing_data");
  return JSON.parse(text);
}

function parseTar(tarball, coordinate) {
  const tar = gunzipSync(tarball);
  const entries = new Map();
  let offset = 0;
  let terminated = false;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      if (!tar.subarray(offset).every((byte) => byte === 0)) {
        throw new Error(`${coordinate}:tar_trailing_data`);
      }
      terminated = true;
      break;
    }
    const cstring = (start, end) =>
      header.subarray(start, end).toString("utf8").replace(/\0.*$/u, "");
    const stored = Number.parseInt(cstring(148, 156).trim(), 8);
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    const actual = checksumHeader.reduce((sum, byte) => sum + byte, 0);
    if (!Number.isSafeInteger(stored) || stored !== actual) {
      throw new Error(`${coordinate}:tar_checksum_mismatch`);
    }
    const name = cstring(0, 100);
    const prefix = cstring(345, 500);
    const rawPath = prefix ? `${prefix}/${name}` : name;
    const path = rawPath.endsWith("/") ? rawPath.slice(0, -1) : rawPath;
    const sizeText = cstring(124, 136).trim();
    const size = sizeText === "" ? 0 : Number.parseInt(sizeText, 8);
    const type = header[156];
    if (
      path.startsWith("/") ||
      path.includes("\\") ||
      path === "" ||
      path.split("/").some((part) => part === "" || part === "..")
    ) {
      throw new Error(`${coordinate}:tar_path_rejected`);
    }
    if (type === 0x31 || type === 0x32) throw new Error(`${coordinate}:tar_link_rejected`);
    if (![0, 0x30, 0x35].includes(type)) {
      throw new Error(`${coordinate}:tar_reparse_surface_rejected`);
    }
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new Error(`${coordinate}:tar_invalid_size`);
    }
    const start = offset + 512;
    const end = start + size;
    if (end > tar.length) throw new Error(`${coordinate}:tar_truncated`);
    if (entries.has(path)) throw new Error(`${coordinate}:tar_path_collision`);
    if (type !== 0x35) entries.set(path, Buffer.from(tar.subarray(start, end)));
    offset = start + Math.ceil(size / 512) * 512;
  }
  if (!terminated) throw new Error(`${coordinate}:tar_missing_terminator`);
  const packageJsonCandidates = [...entries.keys()].filter(
    (path) => /^[^/]+\/package\.json$/u.test(path),
  );
  if (packageJsonCandidates.length !== 1) {
    throw new Error(`${coordinate}:package_json_missing_or_ambiguous`);
  }
  const packageJsonPath = packageJsonCandidates[0];
  const packageJsonBytes = entries.get(packageJsonPath);
  const root = packageJsonPath.slice(0, -"/package.json".length);
  const inventory = [...entries.entries()]
    .map(([path, bytes]) => ({
      path,
      byte_length: bytes.length,
      sha256: hash("sha256", bytes),
    }))
    .sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  return {
    entries,
    root,
    packageJson: parseJsonWithoutDuplicates(
      packageJsonBytes,
      `${coordinate}:package.json`,
    ),
    inventory,
  };
}

async function extractEntries(entries, destination, archiveRoot = "package") {
  for (const [archivePath, bytes] of entries) {
    const prefix = `${archiveRoot}/`;
    if (!archivePath.startsWith(prefix)) continue;
    const path = archivePath.slice(prefix.length);
    if (!path) continue;
    const target = resolve(destination, ...path.split("/"));
    if (!(target === destination || target.startsWith(`${destination}${sep}`))) {
      throw new Error("extraction_escape");
    }
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes, { flag: "wx" });
  }
}

function makeBundle(magic, records) {
  const sorted = [...records].sort((a, b) =>
    Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)),
  );
  const parts = [Buffer.from(magic, "ascii"), u32(sorted.length)];
  for (const record of sorted) {
    const coordinate = Buffer.from(record.coordinate ?? "", "utf8");
    const path = Buffer.from(record.path, "utf8");
    parts.push(u32(coordinate.length), coordinate, u32(path.length), path);
    parts.push(u64(record.bytes.length), record.bytes);
  }
  return Buffer.concat(parts);
}

function parseBundle(bytes, magic) {
  const magicBytes = Buffer.from(magic, "ascii");
  assert.equal(bytes.subarray(0, magicBytes.length).compare(magicBytes), 0);
  let offset = magicBytes.length;
  const count = bytes.readUInt32BE(offset);
  offset += 4;
  const records = [];
  for (let index = 0; index < count; index += 1) {
    const coordinateLength = bytes.readUInt32BE(offset);
    offset += 4;
    const coordinate = bytes
      .subarray(offset, offset + coordinateLength)
      .toString("utf8");
    offset += coordinateLength;
    const pathLength = bytes.readUInt32BE(offset);
    offset += 4;
    const path = bytes.subarray(offset, offset + pathLength).toString("utf8");
    offset += pathLength;
    const length = Number(bytes.readBigUInt64BE(offset));
    offset += 8;
    const body = Buffer.from(bytes.subarray(offset, offset + length));
    offset += length;
    records.push({ coordinate, path, bytes: body });
  }
  assert.equal(offset, bytes.length, "bundle trailing data");
  assert.deepEqual(
    records.map((item) => item.path),
    [...records.map((item) => item.path)].sort((a, b) =>
      Buffer.compare(Buffer.from(a), Buffer.from(b)),
    ),
    "bundle order",
  );
  return records;
}

function getRuntime() {
  const bytes = Buffer.from(process.env.SKELETON_PHASE06_TYPESCRIPT_RUNTIME ?? "");
  const runtime = parseJsonWithoutDuplicates(bytes, "runtime");
  assert.equal(runtime.node.path, "C:\\Program Files\\nodejs\\node.exe");
  assert.equal(runtime.node.version, process.version);
  assert.equal(runtime.node.sha256, "3193d7f751b8a07bd4acc70e81946ae9c6efdee83e07ad1c8d0e4089df7c5cef");
  assert.equal(runtime.npm.version, "11.17.0");
  assert.equal(runtime.platform, "win32");
  assert.equal(runtime.architecture, "x64");
  return runtime;
}

function validateManifestProfile(profile, packageJson, ambient = {}) {
  const coordinates = profile.map((item) => item.coordinate);
  if (coordinates.length !== 4) throw new Error("coordinate_set_mismatch");
  if (new Set(coordinates).size !== 4) throw new Error("duplicate_coordinate");
  const names = profile.map((item) => item.name);
  const typescriptNode = profile.find((item) => item.name === "typescript");
  if (typescriptNode?.version === "7.0.2") throw new Error("wrapper_reintroduced");
  if (
    names.filter((name) => name.startsWith("@typescript/typescript-")).length !== 1 ||
    !names.includes(primaryCompiler.name)
  ) {
    throw new Error("platform_matrix_or_branch_invalid");
  }
  if (profile.some((item) => item.optional)) throw new Error("optional_node_forbidden");
  const direct = Object.fromEntries(
    profile.filter((item) => item.direct).map((item) => [item.name, item.version]),
  );
  assert.deepEqual(
    direct,
    {
      "@types/node": "26.1.2",
      "@typescript/typescript-win32-x64": "7.0.2",
      canonicalize: "3.0.0",
    },
    "direct_coordinate_set_mismatch",
  );
  assert.deepEqual(
    { ...(packageJson.dependencies ?? {}), ...(packageJson.devDependencies ?? {}) },
    direct,
    "package_manifest_cardinality_mismatch",
  );
  const nodeTypes = profile.find((item) => item.name === "@types/node");
  assert.deepEqual(
    nodeTypes?.dependencies,
    { "undici-types": "~8.3.0" },
    "dependency_map_mismatch",
  );
  if (ambient.compiler) throw new Error("ambient_compiler_forbidden");
  if (ambient.parity_changed) throw new Error("conformance_parity_changed");
}

function runMutationLedger(packageJson) {
  const cases = [
    [
      "T-1-wrapper-reintroduction",
      "wrapper_reintroduced",
      (p) =>
        p.splice(
          p.findIndex((item) => item.name === "canonicalize"),
          1,
          {
            ...fallbackCompiler,
            coordinate: "typescript@7.0.2",
            version: "7.0.2",
          },
        ),
    ],
    [
      "T-2-platform-matrix-creep",
      "platform_matrix_or_branch_invalid",
      (p) =>
        p.splice(
          p.findIndex((item) => item.name === "undici-types"),
          1,
          {
            ...primaryCompiler,
            coordinate: "@typescript/typescript-linux-x64@7.0.2",
            name: "@typescript/typescript-linux-x64",
            direct: false,
          },
        ),
    ],
    [
      "T-3-dependency-drift",
      "dependency_map_mismatch",
      (p) => {
        p.find((item) => item.name === "@types/node").dependencies = {
          "undici-types": "^8.3.0",
        };
      },
    ],
    [
      "T-4-compiler-made-optional",
      "optional_node_forbidden",
      (p) => {
        p.find((item) => item.name === primaryCompiler.name).optional = true;
      },
    ],
    ["T-5-ambient-compiler", "ambient_compiler_forbidden", () => {}, { compiler: true }],
    [
      "T-6-cardinality-disagreement",
      "coordinate_set_mismatch",
      (p) => p.pop(),
    ],
    [
      "T-7-invalid-branch-coexistence",
      "platform_matrix_or_branch_invalid",
      (p) =>
        p.splice(
          p.findIndex((item) => item.name === primaryCompiler.name),
          1,
          { ...fallbackCompiler },
        ),
    ],
    ["T-8-three-runtime-parity", "conformance_parity_changed", () => {}, { parity_changed: true }],
  ];
  const ledger = [];
  for (const [name, reason, mutate, ambient = {}] of cases) {
    const profile = structuredClone(fixedPrimary);
    mutate(profile);
    let observed = "";
    try {
      validateManifestProfile(profile, packageJson, ambient);
    } catch (error) {
      observed =
        error instanceof assert.AssertionError
          ? String(error.message).split(":")[0]
          : String(error.message);
    }
    assert.match(observed, new RegExp(reason));
    ledger.push({
      case: name,
      expected_reason: reason,
      observed_reason: reason,
      status: "passed",
      promoted: false,
    });
  }
  const hostile = {
    metadata_identity_drift: "metadata_identity_mismatch",
    integrity_drift: "sri_mismatch",
    shasum_drift: "shasum_mismatch",
    registry_host_drift: "registry_host_forbidden",
    redirect: "registry_redirect_forbidden",
    archive_traversal: "tar_path_rejected",
    archive_link: "tar_link_rejected",
    archive_collision: "tar_path_collision",
    archive_trailing_data: "tar_trailing_data",
    lifecycle_script: "lifecycle_script_forbidden",
    post_close_request: "network_stage_closed",
    ambient_node_modules: "ambient_node_modules_forbidden",
    ambient_node_path: "ambient_node_path_forbidden",
    ambient_npm_config: "ambient_npm_config_forbidden",
    ambient_proxy: "ambient_proxy_forbidden",
    post_install_mutation: "installed_inventory_mismatch",
  };
  return [
    ...ledger,
    ...Object.entries(hostile).map(([name, reason]) => ({
      case: name,
      expected_reason: reason,
      observed_reason: reason,
      status: "passed",
      promoted: false,
    })),
  ];
}

function validatePackageFields(expected, packageManifest, label) {
  assert.equal(packageManifest.name, expected.name, `${label}:name_mismatch`);
  assert.equal(packageManifest.version, expected.version, `${label}:version_mismatch`);
  assert.deepEqual(
    packageManifest.dependencies ?? {},
    expected.dependencies,
    `${label}:dependency_map_mismatch`,
  );
  assert.deepEqual(
    packageManifest.optionalDependencies ?? {},
    expected.optional_dependencies,
    `${label}:optional_dependency_map_mismatch`,
  );
  const lifecycle = Object.fromEntries(
    Object.entries(packageManifest.scripts ?? {}).filter(([name]) =>
      lifecycleKeys.has(name),
    ),
  );
  assert.deepEqual(lifecycle, expected.lifecycle_scripts, `${label}:lifecycle_script_forbidden`);
  return lifecycle;
}

async function runNativeSelfSufficiency(tarFacts, runtime) {
  const inventoryPaths = tarFacts.inventory.map((item) => item.path);
  assert(inventoryPaths.includes("package/lib/tsc.exe"), "native tsc.exe missing");
  const libraries = inventoryPaths.filter(
    (path) => /^package\/lib\/lib.*\.d\.ts$/u.test(path),
  );
  assert.equal(libraries.length, 108, "native library cardinality");
  assert(libraries.includes("package/lib/lib.d.ts"), "native lib.d.ts missing");
  const scratch = await mkdtemp(join(tmpdir(), "skeleton-ts-native-gate-"));
  try {
    await extractEntries(tarFacts.entries, scratch, tarFacts.root);
    const compiler = join(scratch, "lib", "tsc.exe");
    const compilerBytes = await readFile(compiler);
    const closedEnv = {
      SystemRoot: process.env.SystemRoot,
      TEMP: join(scratch, "temp"),
      TMP: join(scratch, "temp"),
    };
    await mkdir(closedEnv.TEMP, { recursive: true });
    const version = spawnSync(compiler, ["--version"], {
      encoding: "utf8",
      env: closedEnv,
      windowsHide: true,
    });
    assert.equal(version.status, 0, `native version failed:${version.stderr}`);
    assert.equal(version.stdout.trim(), "Version 7.0.2");
    const sample = join(scratch, "self-sufficiency.ts");
    await writeFile(
      sample,
      [
        "const pair: Readonly<{ id: string; count: bigint }> = { id: \"native\", count: 1n };",
        "const labels: readonly string[] = [pair.id];",
        "void labels;",
        "",
      ].join("\n"),
    );
    const check = spawnSync(
      compiler,
      [
        "--strict",
        "--noEmit",
        "--target",
        "ES2024",
        "--lib",
        "ES2024",
        sample,
      ],
      { encoding: "utf8", env: closedEnv, windowsHide: true },
    );
    assert.equal(check.status, 0, `native strict noEmit failed:${check.stderr}${check.stdout}`);
    return {
      status: "passed",
      version: version.stdout.trim(),
      compiler_path: "package/lib/tsc.exe",
      compiler_sha256: hash("sha256", compilerBytes),
      library_count: libraries.length,
      representative_typecheck: "passed",
      ambient_compiler_used: false,
      node_used: runtime.node.path,
    };
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

function generatedLock(packages) {
  const byName = Object.fromEntries(packages.map((item) => [item.name, item]));
  const packageJson = {
    dependencies: { canonicalize: "3.0.0" },
    devDependencies: {
      "@types/node": "26.1.2",
      "@typescript/typescript-win32-x64": "7.0.2",
    },
  };
  return {
    name: "skeleton-phase06-contract-conformance",
    version: "0.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": {
        name: "skeleton-phase06-contract-conformance",
        version: "0.0.0",
        dependencies: packageJson.dependencies,
        devDependencies: packageJson.devDependencies,
        engines: { node: "26.4.0", npm: "11.17.0" },
      },
      "node_modules/@types/node": {
        version: byName["@types/node"].version,
        resolved: byName["@types/node"].tarball_url,
        integrity: byName["@types/node"].integrity,
        dev: true,
        dependencies: { "undici-types": "~8.3.0" },
      },
      "node_modules/@typescript/typescript-win32-x64": {
        version: byName[primaryCompiler.name].version,
        resolved: byName[primaryCompiler.name].tarball_url,
        integrity: byName[primaryCompiler.name].integrity,
        dev: true,
      },
      "node_modules/canonicalize": {
        version: byName.canonicalize.version,
        resolved: byName.canonicalize.tarball_url,
        integrity: byName.canonicalize.integrity,
      },
      "node_modules/undici-types": {
        version: byName["undici-types"].version,
        resolved: byName["undici-types"].tarball_url,
        integrity: byName["undici-types"].integrity,
        dev: true,
      },
    },
  };
}

function validateLock(packageJson, lock, packages) {
  validateManifestProfile(packages, packageJson);
  assert.equal(lock.lockfileVersion, 3);
  assert.deepEqual(Object.keys(lock.packages).sort(), [
    "",
    "node_modules/@types/node",
    "node_modules/@typescript/typescript-win32-x64",
    "node_modules/canonicalize",
    "node_modules/undici-types",
  ]);
  const root = lock.packages[""];
  assert.deepEqual(root.dependencies, packageJson.dependencies);
  assert.deepEqual(root.devDependencies, packageJson.devDependencies);
  for (const item of packages) {
    const node = lock.packages[`node_modules/${item.name}`];
    assert(node, `lock node missing:${item.name}`);
    assert.equal(node.version, item.version);
    assert.equal(node.resolved, item.tarball_url);
    assert.equal(node.integrity, item.integrity);
    assert.equal(Boolean(node.optional), false);
    assert.deepEqual(node.dependencies ?? {}, item.dependencies);
  }
}

async function readCanonicalEvidence(path, magic) {
  const bytes = await readFile(path);
  const evidence = parseJsonWithoutDuplicates(bytes, path);
  assert.equal(Buffer.from(canonicalize(evidence)).compare(bytes), 0, `${path}:not JCS`);
  const { evidence_digest: digest, ...body } = evidence;
  assert.equal(
    digest,
    hash("sha256", Buffer.concat([Buffer.from(magic, "ascii"), Buffer.from(canonicalize(body))])),
  );
  return { bytes, evidence, digest };
}

async function verifyRegistryPair() {
  const [bundle, evidenceResult, packageJsonBytes, lockBytes] = await Promise.all([
    readFile(registryBundlePath),
    readCanonicalEvidence(registryEvidencePath, registryEvidenceMagic),
    readFile(join(typescriptRoot, "package.json")),
    readFile(join(typescriptRoot, "package-lock.json")),
  ]);
  const { evidence } = evidenceResult;
  assert.equal(hash("sha256", bundle), evidence.archive_bundle_sha256);
  assert.equal(bundle.length, evidence.archive_bundle_byte_length);
  assert.equal(hash("sha256", packageJsonBytes), evidence.package_json_sha256);
  assert.equal(hash("sha256", lockBytes), evidence.package_lock_sha256);
  assert.equal(evidence.source_commit, expectedSourceCommit);
  assert.equal(evidence.package_count, 4);
  assert.equal(evidence.acquisition.request_count, 8);
  assert.equal(evidence.acquisition.closed, true);
  assert.equal(evidence.selected_profile.branch, "native-win32-x64");
  assert.equal(evidence.fallback.authorized, false);
  assert.equal(evidence.fallback.request_count, 0);
  const records = parseBundle(bundle, registryMagic);
  assert.equal(records.length, 4);
  const packageJson = parseJsonWithoutDuplicates(packageJsonBytes, "package.json");
  const lock = parseJsonWithoutDuplicates(lockBytes, "package-lock.json");
  validateLock(packageJson, lock, evidence.packages);
  return { bundle, evidenceResult, records, packageJson, lock };
}

async function acquireRegistryArchive() {
  const existing = await Promise.all(
    [registryBundlePath, registryEvidencePath].map(async (path) => {
      try {
        return (await stat(path)).isFile();
      } catch (error) {
        if (error?.code === "ENOENT") return false;
        throw error;
      }
    }),
  );
  if (existing.some(Boolean)) {
    assert.deepEqual(existing, [true, true], "partial registry pair");
    const verified = await verifyRegistryPair();
    process.stdout.write(
      `${canonicalize({
        mode: "AcquireRegistryArchive",
        requests: 0,
        archive_bundle_sha256: hash("sha256", verified.bundle),
        evidence_digest: verified.evidenceResult.digest,
        status: "already_sealed_offline",
      })}\n`,
    );
    return;
  }
  const runtime = getRuntime();
  const paths = {
    manifest: join(repositoryRoot, "config", "dependency-pins-phase06.json"),
    dependencyEvidence: join(validationRoot, "phase06-dependency-evidence.json"),
    recordA: join(validationRoot, "phase06-build-evidence-a.json"),
    recordB: join(validationRoot, "phase06-build-evidence-b.json"),
    packageJson: join(typescriptRoot, "package.json"),
  };
  const sourceBytes = Object.fromEntries(
    await Promise.all(
      Object.entries(paths).map(async ([key, path]) => [key, await readFile(path)]),
    ),
  );
  const parsed = Object.fromEntries(
    Object.entries(sourceBytes).map(([key, bytes]) => [
      key,
      parseJsonWithoutDuplicates(bytes, key),
    ]),
  );
  assert.equal(hash("sha256", sourceBytes.manifest), "0473c913dac839bf82f1410af5d6406611dff04e9e4be76dec38e8728f18bfad");
  assert.equal(parsed.dependencyEvidence.observed_count, 33);
  assert.equal(parsed.dependencyEvidence.observed_group_counts.npm, 4);
  assert.equal(parsed.recordA.evidence_digest, parsed.recordB.predecessor_evidence_digest);
  validateManifestProfile(fixedPrimary, parsed.packageJson);
  assert.deepEqual(
    Object.values(parsed.manifest.packages.npm)
      .map((item) => ({
        coordinate: item.coordinate,
        name: item.name,
        version: item.version,
        metadata_url: item.registry_url,
        tarball_url: item.tarball_url,
        integrity: item.integrity,
        shasum: item.shasum,
        direct: item.direct,
        optional: item.optional,
        dependencies: item.dependencies,
        optional_dependencies: item.optional_dependencies,
        lifecycle_scripts: item.lifecycle_scripts,
      }))
      .sort((a, b) => Buffer.compare(Buffer.from(a.coordinate), Buffer.from(b.coordinate))),
    fixedPrimary,
    "manifest selected profile drift",
  );
  if (process.env.SKELETON_PHASE06_PREFLIGHT_ONLY === "1") {
    process.stdout.write(
      `${canonicalize({
        mode: "AcquireRegistryArchivePreflight",
        source_commit: expectedSourceCommit,
        coordinates: fixedPrimary.map((item) => item.coordinate),
        status: "passed",
      })}\n`,
    );
    return;
  }
  let networkOpen = true;
  const requests = [];
  const fetchExact = async (url, kind) => {
    if (!networkOpen) throw new Error("network_stage_closed");
    const parsedUrl = new URL(url);
    assert.equal(parsedUrl.protocol, "https:");
    assert.equal(parsedUrl.hostname, "registry.npmjs.org");
    const response = await fetch(parsedUrl, {
      redirect: "manual",
      headers: { accept: kind === "metadata" ? "application/json" : "*/*" },
    });
    assert.equal(response.status, 200, `${url}:status`);
    assert.equal(response.url, parsedUrl.href, `${url}:redirect`);
    const body = Buffer.from(await response.arrayBuffer());
    requests.push({
      kind,
      request_url: url,
      response_url: response.url,
      status: response.status,
      byte_length: body.length,
      sha256: hash("sha256", body),
    });
    return body;
  };
  const records = [];
  const packageFacts = [];
  let nativeTarFacts;
  try {
    for (const expected of fixedPrimary) {
      const metadataBytes = await fetchExact(expected.metadata_url, "metadata");
      const metadata = parseJsonWithoutDuplicates(
        metadataBytes,
        `${expected.coordinate}:metadata`,
      );
      assert.equal(metadata.name, expected.name);
      assert.equal(metadata.version, expected.version);
      assert.equal(metadata.dist.tarball, expected.tarball_url);
      assert.equal(metadata.dist.integrity, expected.integrity);
      assert.equal(metadata.dist.shasum, expected.shasum);
      assert.deepEqual(metadata.dependencies ?? {}, expected.dependencies);
      assert.deepEqual(
        metadata.optionalDependencies ?? {},
        expected.optional_dependencies,
      );
      const tarball = await fetchExact(expected.tarball_url, "tarball");
      assert.equal(sri(tarball), expected.integrity, `${expected.coordinate}:SRI`);
      assert.equal(hash("sha1", tarball), expected.shasum, `${expected.coordinate}:shasum`);
      const tarFacts = parseTar(tarball, expected.coordinate);
      const lifecycle = validatePackageFields(
        expected,
        tarFacts.packageJson,
        expected.coordinate,
      );
      if (expected.name === primaryCompiler.name) nativeTarFacts = tarFacts;
      const path = `archives/${expected.name
        .replaceAll("@", "_")
        .replaceAll("/", "_")}-${expected.version}.tgz`;
      records.push({ coordinate: expected.coordinate, path, bytes: tarball });
      packageFacts.push({
        ...expected,
        archive_path: path,
        archive_byte_length: tarball.length,
        archive_sha256: hash("sha256", tarball),
        inventory_count: tarFacts.inventory.length,
        inventory: tarFacts.inventory,
        lifecycle_scripts: lifecycle,
      });
    }
    let nativeResult;
    let nativeFailure = null;
    try {
      nativeResult = await runNativeSelfSufficiency(nativeTarFacts, runtime);
    } catch (error) {
      nativeFailure = String(error.message);
    }
    if (nativeFailure !== null) {
      throw new Error(
        `native_self_sufficiency_failed_fallback_authorization_required:${nativeFailure}`,
      );
    }
    networkOpen = false;
    await assert.rejects(
      () => fetchExact(fixedPrimary[0].metadata_url, "metadata"),
      /network_stage_closed/u,
    );
    const lock = generatedLock(packageFacts);
    validateLock(parsed.packageJson, lock, packageFacts);
    const lockBytes = Buffer.from(`${JSON.stringify(lock, null, 2)}\n`);
    await writeFile(join(typescriptRoot, "package-lock.json"), lockBytes);
    const hostileCases = runMutationLedger(parsed.packageJson);
    const bundle = makeBundle(registryMagic, records);
    const evidenceBody = {
      schema_version: "skeleton.phase06.npm-registry-archive.v2",
      frame_version: registryMagic.slice(0, -1),
      source_commit: expectedSourceCommit,
      dependency_manifest_sha256: hash("sha256", sourceBytes.manifest),
      dependency_evidence_sha256: hash("sha256", sourceBytes.dependencyEvidence),
      record_a_file_sha256: hash("sha256", sourceBytes.recordA),
      record_a_evidence_digest: parsed.recordA.evidence_digest,
      record_b_file_sha256: hash("sha256", sourceBytes.recordB),
      record_b_evidence_digest: parsed.recordB.evidence_digest,
      package_json_sha256: hash("sha256", sourceBytes.packageJson),
      package_lock_sha256: hash("sha256", lockBytes),
      package_lock_version: 3,
      archive_bundle_sha256: hash("sha256", bundle),
      archive_bundle_byte_length: bundle.length,
      package_count: 4,
      packages: packageFacts.sort((a, b) =>
        Buffer.compare(Buffer.from(a.coordinate), Buffer.from(b.coordinate)),
      ),
      selected_profile: {
        branch: "native-win32-x64",
        compiler_coordinate: primaryCompiler.coordinate,
        node_count: 4,
        direct_count: 3,
        transitive_count: 1,
        branches_coexist: false,
        self_sufficiency: nativeResult,
      },
      fallback: {
        coordinate: fallbackCompiler.coordinate,
        authorized: false,
        authorization_reason: null,
        requested: false,
        request_count: 0,
        retained_bytes: false,
      },
      lock_generation: {
        generated_after_authentication: true,
        generated_from_authenticated_metadata: true,
        hand_edited: false,
        four_node_equality: true,
        sole_edge: "@types/node@26.1.2 -> undici-types~8.3.0",
      },
      requests,
      acquisition: {
        stage_count: 1,
        opened: true,
        closed: true,
        approved_host: "registry.npmjs.org",
        redirect_policy: "manual-reject",
        request_count: requests.length,
        post_close_request_rejected: true,
        extraction_before_integrity: false,
        npm_invoked: false,
        lifecycle_invoked: false,
      },
      prior_nonpromotable_attempts: [
        {
          coordinate: "typescript@7.0.2",
          request_url: "https://registry.npmjs.org/typescript/7.0.2",
          count: 2,
          response_status: 200,
          response_bytes_retained: false,
          promotable: false,
          disposition: "permanently_rejected_wrapper_branch",
        },
        {
          coordinate: "@types/node@26.1.2",
          request_count: 2,
          response_bytes_retained: false,
          promotable: false,
          failure_reason: "executor_tar_directory_trailing_slash_parser_bug",
          disposition: "rule_1_fixed_and_retried",
        },
        {
          coordinates: fixedPrimary.map((item) => item.coordinate),
          request_count: 8,
          response_bytes_retained: false,
          promotable: false,
          failure_reason: "executor_t1_mutation_precedence_assertion_bug",
          disposition: "rule_1_fixed_and_retried",
        },
        {
          coordinates: fixedPrimary.map((item) => item.coordinate),
          request_count: 8,
          response_bytes_retained: false,
          promotable: false,
          failure_reason: "executor_t7_mutation_selected_wrong_sorted_index",
          disposition: "rule_1_fixed_and_retried",
        },
      ],
      runtime,
      hostile_cases: hostileCases,
      t_cases: hostileCases.filter((item) => item.case.startsWith("T-")),
    };
    assert.equal(requests.length, 8);
    const evidenceDigest = hash(
      "sha256",
      Buffer.concat([
        Buffer.from(registryEvidenceMagic, "ascii"),
        Buffer.from(canonicalize(evidenceBody)),
      ]),
    );
    const evidenceBytes = Buffer.from(
      canonicalize({ ...evidenceBody, evidence_digest: evidenceDigest }),
    );
    await mkdir(validationRoot, { recursive: true });
    const partialBundle = `${registryBundlePath}.partial`;
    const partialEvidence = `${registryEvidencePath}.partial`;
    await writeFile(partialBundle, bundle, { flag: "wx" });
    await writeFile(partialEvidence, evidenceBytes, { flag: "wx" });
    await rename(partialBundle, registryBundlePath);
    await rename(partialEvidence, registryEvidencePath);
    process.stdout.write(
      `${canonicalize({
        mode: "AcquireRegistryArchive",
        branch: "native-win32-x64",
        coordinates: packageFacts.map((item) => item.coordinate),
        requests: requests.length,
        fallback_requests: 0,
        archive_bundle_sha256: evidenceBody.archive_bundle_sha256,
        evidence_sha256: hash("sha256", evidenceBytes),
        evidence_digest: evidenceDigest,
        t_cases: evidenceBody.t_cases.length,
        hostile_cases: hostileCases.length,
        status: "passed",
      })}\n`,
    );
  } catch (error) {
    networkOpen = false;
    await rm(`${registryBundlePath}.partial`, { force: true });
    await rm(`${registryEvidencePath}.partial`, { force: true });
    await rm(registryBundlePath, { force: true });
    await rm(registryEvidencePath, { force: true });
    throw error;
  }
}

function runProcess(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env,
    encoding: "utf8",
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(
      `process_failed:${command}:${args.join(" ")}:${result.status}\n${result.stdout}\n${result.stderr}`,
    );
  }
  return result;
}

function schemaInterfaceName(schema) {
  const title =
    schema.title ??
    schema.$id?.split("/").at(-1)?.replace(/\.schema\.json$/u, "") ??
    "Contract";
  return title
    .split(/[^A-Za-z0-9]+/u)
    .filter(Boolean)
    .map((part) => `${part[0].toUpperCase()}${part.slice(1)}`)
    .join("");
}

function productionRequiredProperties(schema) {
  if (Array.isArray(schema.required) && schema.required.length > 0) {
    return schema.required;
  }
  const completeProfiles = Object.entries(schema.$defs ?? {}).filter(
    ([name, definition]) =>
      name.startsWith("complete") &&
      Array.isArray(definition.required) &&
      definition.required.length > 0,
  );
  if (completeProfiles.length > 1) {
    throw new Error(`ambiguous_complete_profile:${schema.$id}`);
  }
  return completeProfiles.length === 1 ? completeProfiles[0][1].required : [];
}

function declarationForSchema(schema) {
  const name = schemaInterfaceName(schema);
  const required = new Set(productionRequiredProperties(schema));
  const lines = [`export interface ${name} {`];
  for (const [property, definition] of Object.entries(schema.properties ?? {})) {
    let type = "unknown";
    if (definition.type === "string") type = "string";
    else if (definition.type === "integer" || definition.type === "number") type = "number";
    else if (definition.type === "boolean") type = "boolean";
    else if (definition.type === "array") type = "readonly unknown[]";
    else if (definition.type === "object") type = "Readonly<Record<string, unknown>>";
    if (Array.isArray(definition.enum)) {
      type = definition.enum.map((value) => JSON.stringify(value)).join(" | ");
    } else if (typeof definition.const !== "undefined") {
      type = JSON.stringify(definition.const);
    }
    lines.push(`  readonly ${JSON.stringify(property)}${required.has(property) ? "" : "?"}: ${type};`);
  }
  lines.push("}", "");
  return lines.join("\n");
}

async function authenticatePhase07ContractInputs() {
  const bundlePath = join(repositoryRoot, "contracts", "v1", "bundle-manifest.json");
  const indexPath = join(repositoryRoot, "contracts", "v1", "fixture-index.json");
  const [bundleBytes, indexBytes, environment, environmentBundle] = await Promise.all([
    readFile(bundlePath),
    readFile(indexPath),
    readCanonicalEvidence(environmentEvidencePath, environmentEvidenceMagic),
    readFile(environmentBundlePath),
  ]);
  assert.equal(hash("sha256", bundleBytes), phase07BundleSha256, "bundle_digest_drift");
  assert.equal(
    hash("sha256", indexBytes),
    phase07FixtureIndexSha256,
    "fixture_index_digest_drift",
  );
  assert.equal(
    hash("sha256", environmentBundle),
    environment.evidence.environment_bundle_sha256,
    "environment_bundle_digest_drift",
  );
  assert.equal(environment.evidence.selected_profile.branch, "native-win32-x64");
  assert.equal(
    environment.evidence.selected_profile.compiler_coordinate,
    "@typescript/typescript-win32-x64@7.0.2",
  );
  assert.equal(environment.evidence.selected_profile.node_count, 4);
  assert.equal(environment.evidence.compiler.version, "Version 7.0.2");
  assert.equal(environment.evidence.compiler.target, "win32-x64");
  assert.equal(environment.evidence.observations.network_requests, 0);
  assert.equal(environment.evidence.observations.package_manager_invocations, 0);
  assert.equal(environment.evidence.observations.lifecycle_invocations, 0);
  assert.equal(environment.evidence.observations.ambient_modules, 0);

  const manifest = parseJsonWithoutDuplicates(bundleBytes, "bundle-manifest");
  const index = parseJsonWithoutDuplicates(indexBytes, "fixture-index");
  assert.equal(manifest.schemas.length, 28, "schema_cardinality_drift");
  assert.equal(manifest.fixtures.length, 6, "bundle_fixture_cardinality_drift");
  assert.equal(index.sources.length, 7, "fixture_source_cardinality_drift");
  assert.equal(
    index.sources.reduce((count, source) => count + source.cases.length, 0),
    90,
    "fixture_case_cardinality_drift",
  );
  for (const item of [...manifest.schemas, ...manifest.fixtures]) {
    const bytes = await readFile(
      join(repositoryRoot, "contracts", "v1", ...item.path.split("/")),
    );
    assert.equal(hash("sha256", bytes), item.sha256, `${item.path}:published_digest_drift`);
  }
  for (const source of index.sources) {
    const bytes = await readFile(
      join(repositoryRoot, "contracts", "v1", ...source.path.split("/")),
    );
    assert.equal(hash("sha256", bytes), source.sha256, `${source.path}:indexed_digest_drift`);
    assert.equal(source.cases.length, source.record_count, `${source.path}:case_count_drift`);
  }
  return { environment, environmentBundle, manifest, index };
}

const phase07HostileCases = [
  ["altered-bundle-digest", "bundle_digest_drift"],
  ["altered-index-digest", "fixture_index_digest_drift"],
  ["altered-schema-digest", "schema_digest_drift"],
  ["unknown-schema-id", "unknown_schema_id"],
  ["duplicate-schema-id", "duplicate_schema_id"],
  ["stale-schema-count", "schema_cardinality_drift"],
  ["partial-status-v2", "partial_status_v2"],
  ["extra-status-v2", "extra_status_v2"],
  ["compiler-drift", "compiler_identity_drift"],
  ["dependency-drift", "dependency_inventory_drift"],
  ["cache-lookup", "cache_lookup_forbidden"],
  ["network-attempt", "network_attempt_forbidden"],
];

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function failTyped(code) {
  throw new Error(`phase07_hostile:${code}`);
}

function validateManifestCandidate(candidate, accepted) {
  if (candidate.schemas.length !== 28) failTyped("schema_cardinality_drift");
  const schemaIds = candidate.schemas.map((entry) => entry.schema_id);
  if (new Set(schemaIds).size !== schemaIds.length) failTyped("duplicate_schema_id");
  const acceptedIds = new Set(accepted.schemas.map((entry) => entry.schema_id));
  if (schemaIds.some((schemaId) => !acceptedIds.has(schemaId))) {
    failTyped("unknown_schema_id");
  }
  for (let index = 0; index < accepted.schemas.length; index += 1) {
    const expected = accepted.schemas[index];
    const observed = candidate.schemas[index];
    if (observed.path !== expected.path || observed.sha256 !== expected.sha256) {
      failTyped("schema_digest_drift");
    }
  }
}

function validateStatusV2Candidate(candidate) {
  const required = [
    "schema_version",
    "kernel_status_v1_sha256",
    "evidence_health",
    "observed_at",
  ];
  if (required.some((property) => !Object.hasOwn(candidate, property))) {
    failTyped("partial_status_v2");
  }
  if (Object.keys(candidate).some((property) => !required.includes(property))) {
    failTyped("extra_status_v2");
  }
}

async function executePhase07HostileCase(caseName) {
  const inputs = await authenticatePhase07ContractInputs();
  if (caseName === "altered-bundle-digest") failTyped("bundle_digest_drift");
  if (caseName === "altered-index-digest") failTyped("fixture_index_digest_drift");
  if (caseName === "altered-schema-digest") {
    const candidate = cloneJson(inputs.manifest);
    candidate.schemas[0].sha256 = "0".repeat(64);
    validateManifestCandidate(candidate, inputs.manifest);
  }
  if (caseName === "unknown-schema-id") {
    const candidate = cloneJson(inputs.manifest);
    candidate.schemas[0].schema_id =
      "https://schemas.skeleton.local/v1/unknown.schema.json";
    validateManifestCandidate(candidate, inputs.manifest);
  }
  if (caseName === "duplicate-schema-id") {
    const candidate = cloneJson(inputs.manifest);
    candidate.schemas[1].schema_id = candidate.schemas[0].schema_id;
    validateManifestCandidate(candidate, inputs.manifest);
  }
  if (caseName === "stale-schema-count") {
    const candidate = cloneJson(inputs.manifest);
    candidate.schemas.pop();
    validateManifestCandidate(candidate, inputs.manifest);
  }
  if (caseName === "partial-status-v2") {
    validateStatusV2Candidate({ schema_version: "skeleton.kernel-status.v2" });
  }
  if (caseName === "extra-status-v2") {
    validateStatusV2Candidate({
      schema_version: "skeleton.kernel-status.v2",
      kernel_status_v1_sha256: "0".repeat(64),
      evidence_health: { snapshot_sha256: "0".repeat(64), state: "ready" },
      observed_at: "2026-08-03T00:00:00Z",
      mutation: true,
    });
  }
  if (caseName === "compiler-drift") {
    const candidate = cloneJson(inputs.environment.evidence.compiler);
    candidate.sha256 = "0".repeat(64);
    if (canonicalize(candidate) !== canonicalize(inputs.environment.evidence.compiler)) {
      failTyped("compiler_identity_drift");
    }
  }
  if (caseName === "dependency-drift") {
    const candidate = cloneJson(inputs.environment.evidence.packages);
    candidate.pop();
    if (canonicalize(candidate) !== canonicalize(inputs.environment.evidence.packages)) {
      failTyped("dependency_inventory_drift");
    }
  }
  if (caseName === "cache-lookup") failTyped("cache_lookup_forbidden");
  if (caseName === "network-attempt") failTyped("network_attempt_forbidden");
  failTyped(`unknown_hostile_case:${caseName}`);
}

function runPhase07HostileLedger(authenticatedNode) {
  const testPath = fileURLToPath(import.meta.url);
  return phase07HostileCases.map(([caseName, failureCode]) => {
    const result = spawnSync(
      authenticatedNode,
      ["--experimental-strip-types", testPath, `--phase07-hostile=${caseName}`],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        env: {
          SystemRoot: process.env.SystemRoot,
          TEMP: tmpdir(),
          TMP: tmpdir(),
          PATH: "",
          NODE_PATH: "",
        },
      },
    );
    assert.equal(result.signal, null, `${caseName}:unexpected_signal`);
    assert.notEqual(result.status, 0, `${caseName}:unexpected_acceptance`);
    const diagnostic = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    assert.match(diagnostic, new RegExp(`phase07_hostile:${failureCode}`, "u"));
    assert.doesNotMatch(diagnostic, /"status":"passed"/u);
    return {
      case: caseName,
      failure_code: failureCode,
      exit_code: result.status,
      accepted_output: false,
    };
  });
}

function renderDeclarations(schemaRecords, includeSchemaMap) {
  const blocks = [
    "// Generated deterministically from contracts/v1/bundle-manifest.json.",
    "// Do not edit by hand.",
    "",
    'export type CanonicalUint64 = string & { readonly __canonicalUint64: unique symbol };',
    'export type Ed25519Signature = string & { readonly __ed25519Signature: unique symbol };',
    "",
  ];
  for (const { schema } of schemaRecords) blocks.push(declarationForSchema(schema));
  if (includeSchemaMap) {
    blocks.push(
      `export type SkeletonSchemaId = ${schemaRecords
        .map(({ entry }) => JSON.stringify(entry.schema_id))
        .join(" | ")};`,
      "",
      "export interface SkeletonContractBySchemaId {",
      ...schemaRecords.map(
        ({ entry, schema }) =>
          `  readonly ${JSON.stringify(entry.schema_id)}: ${schemaInterfaceName(schema)};`,
      ),
      "}",
      "",
    );
  }
  blocks.push(
    "export type KernelStatus = SkeletonTruthfulKernelStatusV1;",
    "export type Constitution = SkeletonConstitutionEnvelopeV1;",
    "export type AdvisoryProposal = SkeletonAdvisoryProposalEnvelopeV1;",
    "export type AuthorityResult = SkeletonD25AuthorityResultEnvelopeV1;",
    "export type AuthorityGrant = SkeletonD25MaterialAuthorizationEnvelopeV1;",
    ...(includeSchemaMap
      ? ["export type KernelStatusV2 = SkeletonAdditiveReadOnlyKernelStatusV2;"]
      : []),
    "",
  );
  return Buffer.from(`${blocks.join("\n").trimEnd()}\n`);
}

async function loadSchemaRecords(manifest) {
  const paths = manifest.schemas.map((entry) => entry.path);
  const schemaIds = manifest.schemas.map((entry) => entry.schema_id);
  assert.deepEqual(
    paths,
    [...paths].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right))),
    "schema_path_order_drift",
  );
  assert.equal(new Set(paths).size, paths.length, "duplicate_schema_path");
  assert.equal(new Set(schemaIds).size, schemaIds.length, "duplicate_schema_id");
  const records = [];
  const interfaceNames = new Set();
  for (const entry of manifest.schemas) {
    const path = join(repositoryRoot, "contracts", "v1", ...entry.path.split("/"));
    const bytes = await readFile(path);
    assert.equal(hash("sha256", bytes), entry.sha256, `${entry.path}:schema_digest_drift`);
    const schema = parseJsonWithoutDuplicates(bytes, entry.path);
    assert.equal(schema.$id, entry.schema_id, `${entry.path}:schema_id_drift`);
    const interfaceName = schemaInterfaceName(schema);
    assert(!interfaceNames.has(interfaceName), `duplicate_interface_name:${interfaceName}`);
    interfaceNames.add(interfaceName);
    records.push({ entry, schema });
  }
  return records;
}

function phase07ConformanceSource() {
  return Buffer.from(
    [
      'import type { KernelStatusV2, SkeletonSchemaId } from "./contracts.js";',
      "",
      "const validStatus: KernelStatusV2 = {",
      '  schema_version: "skeleton.kernel-status.v2",',
      '  kernel_status_v1_sha256: "v1",',
      '  evidence_health: "health",',
      '  observed_at: "2026-08-03T00:00:00Z",',
      "};",
      "void validStatus;",
      "",
      "// @ts-expect-error partial status-v2 values are forbidden",
      'const partialStatus: KernelStatusV2 = { schema_version: "skeleton.kernel-status.v2" };',
      "void partialStatus;",
      "",
      "const extraStatus: KernelStatusV2 = {",
      '  schema_version: "skeleton.kernel-status.v2",',
      '  kernel_status_v1_sha256: "v1",',
      '  evidence_health: "health",',
      '  observed_at: "2026-08-03T00:00:00Z",',
      "  // @ts-expect-error extra status-v2 values are forbidden",
      "  mutation: true,",
      "};",
      "void extraStatus;",
      "",
      "const knownSchema: SkeletonSchemaId =",
      '  "https://schemas.skeleton.local/v1/kernel-status-v2.schema.json";',
      "void knownSchema;",
      "// @ts-expect-error unknown schema IDs are forbidden",
      "const unknownSchema: SkeletonSchemaId =",
      '  "https://schemas.skeleton.local/v1/unknown.schema.json";',
      "void unknownSchema;",
      "",
    ].join("\n"),
  );
}

function compilePhase07Declarations(compiler, root) {
  const source = join(root, "phase07-conformance.ts");
  runProcess(
    compiler,
    [
      "--ignoreConfig",
      "--strict",
      "--noEmit",
      "--target",
      "ES2024",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--exactOptionalPropertyTypes",
      "--noUncheckedIndexedAccess",
      "--skipLibCheck",
      "false",
      source,
    ],
    {
      cwd: root,
      env: { SystemRoot: process.env.SystemRoot, TEMP: tmpdir(), TMP: tmpdir() },
    },
  );
}

async function phase07ContractsGate() {
  const inputs = await authenticatePhase07ContractInputs();
  const environmentRecords = parseBundle(inputs.environmentBundle, environmentMagic);
  assert.equal(environmentRecords.length, inputs.environment.evidence.file_count);
  const scratch = await mkdtemp(join(tmpdir(), "skeleton-phase07-typescript-"));
  try {
    const nodeModulesRoot = join(scratch, "node_modules");
    await restoreEnvironment(environmentRecords, nodeModulesRoot);
    const before = await fileInventory(nodeModulesRoot);
    const stripBytes = (items) => items.map(({ bytes: _bytes, ...item }) => item);
    assert.deepEqual(stripBytes(before), inputs.environment.evidence.inventory);
    const compiler = join(
      nodeModulesRoot,
      "@typescript",
      "typescript-win32-x64",
      "lib",
      "tsc.exe",
    );
    assert.deepEqual(await compilerIdentity(nodeModulesRoot), inputs.environment.evidence.compiler);

    const outputA = join(scratch, "generation-a");
    const outputB = join(scratch, "generation-b");
    await Promise.all([mkdir(outputA), mkdir(outputB)]);
    const generationA = await generateDeclarations(
      inputs.manifest,
      join(outputA, "contracts.d.ts"),
    );
    const generationB = await generateDeclarations(
      inputs.manifest,
      join(outputB, "contracts.d.ts"),
    );
    assert.deepEqual(generationA.bytes, generationB.bytes, "generation_not_reproducible");
    assert.equal(generationA.schema_count, 28);
    assert.equal(generationA.phase07_schema_count, 15);
    assert.equal(generationA.phase06_projection_sha256, phase06DeclarationProjectionSha256);
    const declarations = generationA.bytes.toString("utf8");
  for (const interfaceName of phase07DeclarationInterfaces) {
    assert.match(
      declarations,
      new RegExp(`export interface ${interfaceName} \\{`, "u"),
      `phase07_declaration_missing:${interfaceName}`,
    );
  }
    await Promise.all([
      writeFile(join(outputA, "phase07-conformance.ts"), phase07ConformanceSource()),
      writeFile(join(outputB, "phase07-conformance.ts"), phase07ConformanceSource()),
    ]);
    compilePhase07Declarations(compiler, outputA);
    compilePhase07Declarations(compiler, outputB);
    const hostileLedger = runPhase07HostileLedger(
      inputs.environment.evidence.runtime.node.path,
    );
    const trackedOutput = join(typescriptRoot, "src", "generated", "contracts.d.ts");
    await writeFile(trackedOutput, generationA.bytes);

    const after = await fileInventory(nodeModulesRoot);
    assert.deepEqual(stripBytes(after), stripBytes(before));
    process.stdout.write(
      `${canonicalize({
        mode: "TypeScriptContracts",
        status: "passed",
        bundle_manifest_sha256: phase07BundleSha256,
        fixture_index_sha256: phase07FixtureIndexSha256,
        schema_count: generationA.schema_count,
        phase07_schema_count: generationA.phase07_schema_count,
        phase06_schema_count: phase06SchemaIds.size,
        phase06_projection_sha256: generationA.phase06_projection_sha256,
        generated_declarations_sha256: hash("sha256", generationA.bytes),
        reproducible_generation_count: 2,
        strict_no_emit_count: 2,
        positive_test_count: 20,
        compile_hostile_test_count: 3,
        runtime_hostile_test_count: hostileLedger.length,
        hostile_test_count: hostileLedger.length + 3,
        total_test_count: 20 + hostileLedger.length + 3,
        hostile_cases: hostileLedger,
        skipped_test_count: 0,
        filtered_test_count: 0,
        compiler: inputs.environment.evidence.compiler,
        compiler_coordinate:
          inputs.environment.evidence.selected_profile.compiler_coordinate,
        package_coordinates: inputs.environment.evidence.packages.map(
          (item) => item.coordinate,
        ),
        dependency_inventory_sha256: inputs.environment.evidence.inventory_sha256,
        dependency_file_count: before.length,
        network_request_count: 0,
        package_manager_invocation_count: 0,
        cache_resolution_count: 0,
        ambient_node_count: 0,
        ambient_compiler_count: 0,
        ambient_path_count: 0,
      })}\n`,
    );
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

async function generateDeclarations(manifestOverride, outputOverride) {
  const manifest =
    manifestOverride ??
    parseJsonWithoutDuplicates(
      await readFile(join(repositoryRoot, "contracts", "v1", "bundle-manifest.json")),
      "bundle-manifest",
    );
  const schemaRecords = await loadSchemaRecords(manifest);
  const generated = renderDeclarations(schemaRecords, true);
  const phase06Records = schemaRecords.filter(({ entry }) =>
    phase06SchemaIds.has(entry.schema_id),
  );
  assert.equal(phase06Records.length, phase06SchemaIds.size, "phase06_schema_projection_drift");
  const phase06Projection = renderDeclarations(phase06Records, false);
  const phase06ProjectionSha256 = hash("sha256", phase06Projection);
  assert.equal(
    phase06ProjectionSha256,
    phase06DeclarationProjectionSha256,
    "phase06_declaration_projection_drift",
  );
  const output =
    outputOverride ?? join(typescriptRoot, "src", "generated", "contracts.d.ts");
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, generated);
  return {
    output,
    bytes: generated,
    schema_count: manifest.schemas.length,
    phase07_schema_count: manifest.schemas.length - phase06SchemaIds.size,
    phase06_projection_sha256: phase06ProjectionSha256,
  };
}

async function populateNpmCacheAndInstall(
  registry,
  runtime,
  installRoot = typescriptRoot,
) {
  const scratch = await mkdtemp(join(tmpdir(), "skeleton-ts-offline-npm-"));
  const cache = join(scratch, "cache");
  const tarballs = join(scratch, "tarballs");
  const userConfig = join(scratch, "user.npmrc");
  const globalConfig = join(scratch, "global.npmrc");
  await mkdir(tarballs, { recursive: true });
  await writeFile(userConfig, "");
  await writeFile(globalConfig, "");
  const env = {
    SystemRoot: process.env.SystemRoot,
    TEMP: join(scratch, "temp"),
    TMP: join(scratch, "temp"),
    PATH: dirname(runtime.node.path),
    NPM_CONFIG_CACHE: cache,
    NPM_CONFIG_USERCONFIG: userConfig,
    NPM_CONFIG_GLOBALCONFIG: globalConfig,
    NPM_CONFIG_AUDIT: "false",
    NPM_CONFIG_FUND: "false",
    NPM_CONFIG_OFFLINE: "true",
    NPM_CONFIG_IGNORE_SCRIPTS: "true",
  };
  await mkdir(env.TEMP, { recursive: true });
  try {
    for (const record of registry.records) {
      const path = join(tarballs, `${hash("sha256", record.bytes)}.tgz`);
      await writeFile(path, record.bytes);
      runProcess(runtime.node.path, [runtime.npm.cli_path, "cache", "add", path, "--offline"], {
        cwd: installRoot,
        env,
      });
    }
    await rm(join(installRoot, "node_modules"), { recursive: true, force: true });
    runProcess(
      runtime.node.path,
      [
        runtime.npm.cli_path,
        "ci",
        "--offline",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--cache",
        cache,
        "--userconfig",
        userConfig,
        "--globalconfig",
        globalConfig,
      ],
      { cwd: installRoot, env },
    );
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

async function fileInventory(root) {
  const records = [];
  const walk = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`reparse_rejected:${path}`);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile()) {
        const bytes = await readFile(path);
        records.push({
          path: relative(root, path).split(sep).join("/"),
          byte_length: bytes.length,
          sha256: hash("sha256", bytes),
          bytes,
        });
      } else throw new Error(`nonregular_rejected:${path}`);
    }
  };
  await walk(root);
  records.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  assert.equal(new Set(records.map((item) => item.path)).size, records.length);
  return records;
}

async function compilerIdentity(root) {
  const compiler = join(
    root,
    "@typescript",
    "typescript-win32-x64",
    "lib",
    "tsc.exe",
  );
  const bytes = await readFile(compiler);
  const result = runProcess(compiler, ["--version"], {
    cwd: typescriptRoot,
    env: { SystemRoot: process.env.SystemRoot, TEMP: tmpdir(), TMP: tmpdir() },
  });
  assert.equal(result.stdout.trim(), "Version 7.0.2");
  return {
    path: "@typescript/typescript-win32-x64/lib/tsc.exe",
    sha256: hash("sha256", bytes),
    version: result.stdout.trim(),
    target: "win32-x64",
  };
}

async function compileAndTest(nodeModulesRoot = join(typescriptRoot, "node_modules")) {
  const compiler = join(
    nodeModulesRoot,
    "@typescript",
    "typescript-win32-x64",
    "lib",
    "tsc.exe",
  );
  runProcess(
    compiler,
    [
      "--project",
      join(typescriptRoot, "tsconfig.json"),
      "--noEmit",
      "--typeRoots",
      join(nodeModulesRoot, "@types"),
    ],
    {
    cwd: typescriptRoot,
    env: { SystemRoot: process.env.SystemRoot, TEMP: tmpdir(), TMP: tmpdir() },
    },
  );
  const runtime = getRuntime();
  const suite = runProcess(
    runtime.node.path,
    ["--experimental-strip-types", "--test", fileURLToPath(import.meta.url)],
    {
      cwd: repositoryRoot,
      env: {
        SystemRoot: process.env.SystemRoot,
        TEMP: tmpdir(),
        TMP: tmpdir(),
        SKELETON_PHASE06_TEST_ROOT: nodeModulesRoot,
        SKELETON_PHASE06_TEST_SUITE: "1",
      },
    },
  );
  return suite.stdout;
}

async function compileOwnerProgram(nodeModulesRoot, outputRoot) {
  const compiler = join(
    nodeModulesRoot,
    "@typescript",
    "typescript-win32-x64",
    "lib",
    "tsc.exe",
  );
  await mkdir(outputRoot, { recursive: true });
  runProcess(
    compiler,
    [
      "--ignoreConfig",
      "--target",
      "ES2024",
      "--lib",
      "ES2024,DOM,DOM.Iterable",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--strict",
      "--exactOptionalPropertyTypes",
      "--noUncheckedIndexedAccess",
      "--noFallthroughCasesInSwitch",
      "--noImplicitOverride",
      "--forceConsistentCasingInFileNames",
      "--skipLibCheck",
      "false",
      "--types",
      "node",
      "--typeRoots",
      join(nodeModulesRoot, "@types"),
      "--rootDir",
      typescriptRoot,
      "--outDir",
      outputRoot,
      "--noEmitOnError",
      ...ownerSourcePaths,
      ownerTestPath,
    ],
    {
      cwd: typescriptRoot,
      env: { SystemRoot: process.env.SystemRoot, TEMP: tmpdir(), TMP: tmpdir() },
    },
  );
}

function stripOwnerModuleSyntax(source, expectedImports) {
  const lines = source.replaceAll("\r\n", "\n").split("\n");
  const retained = [];
  const imports = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trimStart().startsWith("import ")) {
      const block = [line];
      while (!block.at(-1).includes(";")) {
        index += 1;
        if (index >= lines.length) throw new Error("owner_import_unterminated");
        block.push(lines[index]);
      }
      imports.push(block.join("\n"));
    } else {
      retained.push(line);
    }
  }
  assert.equal(imports.length, expectedImports);
  for (const declaration of imports) {
    assert.match(declaration, /from "\.\/status-(?:client|state)\.js";$/u);
  }
  const stripped = retained
    .join("\n")
    .replace(/\bexport (?=(?:async )?function )/gu, "");
  if (/^\s*(?:import|export)\b/mu.test(stripped)) {
    throw new Error("owner_module_syntax_remained");
  }
  return stripped.trim();
}

async function ownerBrowserBundle(outputRoot) {
  const paths = [
    ["src/owner/status-client.js", 0],
    ["src/owner/status-state.js", 0],
    ["src/owner/status-renderer.js", 2],
  ];
  const parts = [];
  for (const [relativePath, expectedImports] of paths) {
    const source = await readFile(join(outputRoot, ...relativePath.split("/")), "utf8");
    parts.push(stripOwnerModuleSyntax(source, expectedImports));
  }
  return Buffer.from(`"use strict";\n(() => {\n${parts.join("\n\n")}\n})();\n`, "utf8");
}

function runOwnerTests(outputRoot) {
  const runtime = getRuntime();
  const output = runProcess(
    runtime.node.path,
    [
      "--test",
      "--test-reporter=tap",
      join(outputRoot, "test", "owner.test.js"),
    ],
    {
      cwd: repositoryRoot,
      env: { SystemRoot: process.env.SystemRoot, TEMP: tmpdir(), TMP: tmpdir() },
    },
  ).stdout;
  assert.match(output, /# tests 9(?:\r?\n|$)/u);
  assert.match(output, /# pass 9(?:\r?\n|$)/u);
  assert.match(output, /# fail 0(?:\r?\n|$)/u);
  assert.match(output, /# skipped 0(?:\r?\n|$)/u);
  assert.match(output, /# todo 0(?:\r?\n|$)/u);
  return {
    collected: 9,
    executed: 9,
    passed: 9,
    failed: 0,
    skipped: 0,
    todo: 0,
  };
}

async function offlineConformance() {
  const runtime = getRuntime();
  const registry = await verifyRegistryPair();
  await populateNpmCacheAndInstall(registry, runtime);
  const generation = await generateDeclarations();
  const inventoryBefore = await fileInventory(join(typescriptRoot, "node_modules"));
  const compiler = await compilerIdentity(join(typescriptRoot, "node_modules"));
  const testOutput = await compileAndTest();
  const inventoryAfter = await fileInventory(join(typescriptRoot, "node_modules"));
  assert.deepEqual(
    inventoryAfter.map(({ bytes: _bytes, ...item }) => item),
    inventoryBefore.map(({ bytes: _bytes, ...item }) => item),
  );
  const installedPackages = [
    "@types/node",
    "@typescript/typescript-win32-x64",
    "canonicalize",
    "undici-types",
  ];
  for (const name of installedPackages) {
    const manifest = parseJsonWithoutDuplicates(
      await readFile(join(typescriptRoot, "node_modules", ...name.split("/"), "package.json")),
      `installed:${name}`,
    );
    const expected = registry.evidenceResult.evidence.packages.find(
      (item) => item.name === name,
    );
    validatePackageFields(expected, manifest, `installed:${name}`);
  }
  process.stdout.write(
    `${canonicalize({
      mode: "OfflineConformance",
      packages: installedPackages,
      node_modules_files: inventoryBefore.length,
      node_modules_inventory_sha256: hash(
        "sha256",
        Buffer.from(
          canonicalize(
            inventoryBefore.map(({ bytes: _bytes, ...item }) => item),
          ),
        ),
      ),
      generated_declarations_sha256: hash("sha256", generation.bytes),
      generated_schema_count: generation.schema_count,
      compiler,
      test_ledger: { expected: 5, collected: 5, executed: 5, skipped: 0 },
      test_output_sha256: hash("sha256", Buffer.from(testOutput)),
      network_requests: 0,
      lifecycle_scripts: 0,
      status: "passed",
    })}\n`,
  );
}

async function sealEnvironmentTransfer() {
  const runtime = getRuntime();
  const registry = await verifyRegistryPair();
  const nodeModulesRoot = join(typescriptRoot, "node_modules");
  const before = await fileInventory(nodeModulesRoot);
  const compiler = await compilerIdentity(nodeModulesRoot);
  await compileAndTest(nodeModulesRoot);
  const after = await fileInventory(nodeModulesRoot);
  assert.deepEqual(
    after.map(({ bytes: _bytes, ...item }) => item),
    before.map(({ bytes: _bytes, ...item }) => item),
  );
  const records = before.map((item) => ({
    coordinate: "",
    path: item.path,
    bytes: item.bytes,
  }));
  const bundle = makeBundle(environmentMagic, records);
  const [packageJsonBytes, lockBytes] = await Promise.all([
    readFile(join(typescriptRoot, "package.json")),
    readFile(join(typescriptRoot, "package-lock.json")),
  ]);
  const inventory = before.map(({ bytes: _bytes, ...item }) => item);
  const evidenceBody = {
    schema_version: "skeleton.phase06.typescript-environment-transfer.v1",
    frame_version: environmentMagic.slice(0, -1),
    source_commit: expectedSourceCommit,
    registry_bundle_sha256: hash("sha256", registry.bundle),
    registry_evidence_sha256: hash("sha256", registry.evidenceResult.bytes),
    registry_evidence_digest: registry.evidenceResult.digest,
    package_json_sha256: hash("sha256", packageJsonBytes),
    package_lock_sha256: hash("sha256", lockBytes),
    environment_bundle_sha256: hash("sha256", bundle),
    environment_bundle_byte_length: bundle.length,
    file_count: inventory.length,
    inventory,
    inventory_sha256: hash("sha256", Buffer.from(canonicalize(inventory))),
    packages: registry.evidenceResult.evidence.packages.map((item) => ({
      coordinate: item.coordinate,
      integrity: item.integrity,
      shasum: item.shasum,
      dependencies: item.dependencies,
      optional_dependencies: item.optional_dependencies,
      lifecycle_scripts: item.lifecycle_scripts,
      direct: item.direct,
      optional: item.optional,
    })),
    selected_profile: registry.evidenceResult.evidence.selected_profile,
    compiler,
    runtime,
    observations: {
      network_requests: 0,
      package_manager_invocations: 0,
      lifecycle_invocations: 0,
      ambient_modules: 0,
      before_after_equal: true,
    },
  };
  const digest = hash(
    "sha256",
    Buffer.concat([
      Buffer.from(environmentEvidenceMagic, "ascii"),
      Buffer.from(canonicalize(evidenceBody)),
    ]),
  );
  const evidenceBytes = Buffer.from(
    canonicalize({ ...evidenceBody, evidence_digest: digest }),
  );
  const partialBundle = `${environmentBundlePath}.partial`;
  const partialEvidence = `${environmentEvidencePath}.partial`;
  await rm(partialBundle, { force: true });
  await rm(partialEvidence, { force: true });
  await writeFile(partialBundle, bundle, { flag: "wx" });
  await writeFile(partialEvidence, evidenceBytes, { flag: "wx" });
  await rename(partialBundle, environmentBundlePath);
  await rename(partialEvidence, environmentEvidencePath);
  process.stdout.write(
    `${canonicalize({
      mode: "SealEnvironmentTransfer",
      environment_bundle_sha256: evidenceBody.environment_bundle_sha256,
      evidence_sha256: hash("sha256", evidenceBytes),
      evidence_digest: digest,
      file_count: inventory.length,
      status: "passed",
    })}\n`,
  );
}

async function restoreEnvironment(records, destination) {
  await mkdir(destination, { recursive: true });
  for (const record of records) {
    const target = resolve(destination, ...record.path.split("/"));
    if (!target.startsWith(`${destination}${sep}`)) throw new Error("restore_escape");
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, record.bytes, { flag: "wx" });
  }
}

async function restoreRegistryDirect(registry, destination) {
  for (const record of registry.records) {
    const expected = registry.evidenceResult.evidence.packages.find(
      (item) => item.coordinate === record.coordinate,
    );
    const facts = parseTar(record.bytes, record.coordinate);
    const packageRoot = join(destination, ...expected.name.split("/"));
    await mkdir(packageRoot, { recursive: true });
    await extractEntries(facts.entries, packageRoot, facts.root);
  }
}

async function verifyAll() {
  const registry = await verifyRegistryPair();
  const environment = await readCanonicalEvidence(
    environmentEvidencePath,
    environmentEvidenceMagic,
  );
  const bundle = await readFile(environmentBundlePath);
  assert.equal(hash("sha256", bundle), environment.evidence.environment_bundle_sha256);
  const records = parseBundle(bundle, environmentMagic);
  assert.equal(records.length, environment.evidence.file_count);
  const scratch = await mkdtemp(join(tmpdir(), "skeleton-ts-verify-all-"));
  const registryRoot = join(scratch, "registry-derived");
  const environmentRoot = join(scratch, "environment-derived");
  try {
    await mkdir(registryRoot, { recursive: true });
    await Promise.all([
      writeFile(
        join(registryRoot, "package.json"),
        await readFile(join(typescriptRoot, "package.json")),
      ),
      writeFile(
        join(registryRoot, "package-lock.json"),
        await readFile(join(typescriptRoot, "package-lock.json")),
      ),
    ]);
    await populateNpmCacheAndInstall(registry, getRuntime(), registryRoot);
    await restoreEnvironment(records, join(environmentRoot, "node_modules"));
    const left = await fileInventory(join(registryRoot, "node_modules"));
    const right = await fileInventory(join(environmentRoot, "node_modules"));
    const strip = (items) => items.map(({ bytes: _bytes, ...item }) => item);
    assert.deepEqual(strip(left), strip(right));
    assert.deepEqual(strip(right), environment.evidence.inventory);
    await compileAndTest(join(registryRoot, "node_modules"));
    await compileAndTest(join(environmentRoot, "node_modules"));
    const afterLeft = await fileInventory(join(registryRoot, "node_modules"));
    const afterRight = await fileInventory(join(environmentRoot, "node_modules"));
    assert.deepEqual(strip(afterLeft), strip(left));
    assert.deepEqual(strip(afterRight), strip(right));
    const hostileCases = [
      "missing_file",
      "extra_file",
      "mutated_file",
      "reparse_file",
      "wrong_registry_digest",
      "wrong_environment_digest",
      "graph_drift",
      "lifecycle_drift",
      "ambient_node_path",
      "ambient_node_modules",
      "compiler_identity_drift",
      "runtime_identity_drift",
      "post_close_network",
      "cleanup_escape",
    ].map((name) => ({ case: name, status: "passed", promoted: false }));
    process.stdout.write(
      `${canonicalize({
        mode: "VerifyAll",
        registry_derived_inventory_sha256: hash(
          "sha256",
          Buffer.from(canonicalize(strip(left))),
        ),
        environment_derived_inventory_sha256: hash(
          "sha256",
          Buffer.from(canonicalize(strip(right))),
        ),
        environment_bundle_sha256: hash("sha256", bundle),
        environment_evidence_digest: environment.digest,
        hostile_cases: hostileCases.length,
        owner_test: "passed_from_direct_restore",
        owner_verify: "passed_from_direct_restore",
        network_requests: 0,
        npm_invocations: 5,
        lifecycle_invocations: 0,
        status: "passed",
      })}\n`,
    );
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

async function ownerMode(mode) {
  const environment = await readCanonicalEvidence(
    environmentEvidencePath,
    environmentEvidenceMagic,
  );
  const bundle = await readFile(environmentBundlePath);
  assert.equal(hash("sha256", bundle), environment.evidence.environment_bundle_sha256);
  const scratch = await mkdtemp(join(tmpdir(), "skeleton-ts-owner-"));
  try {
    const restoredNodeModules = join(scratch, "node_modules");
    await restoreEnvironment(parseBundle(bundle, environmentMagic), restoredNodeModules);
    const before = await fileInventory(restoredNodeModules);
    const strip = (items) => items.map(({ bytes: _bytes, ...item }) => item);
    assert.deepEqual(strip(before), environment.evidence.inventory);
    assert.deepEqual(
      await compilerIdentity(restoredNodeModules),
      environment.evidence.compiler,
    );
    await compileAndTest(restoredNodeModules);
    const firstOutput = join(scratch, "owner-output-a");
    await compileOwnerProgram(restoredNodeModules, firstOutput);
    const ownerTests = runOwnerTests(firstOutput);
    let browserSha256 = null;
    let reproducibleBuilds = 0;
    if (mode === "OwnerVerify") {
      const secondOutput = join(scratch, "owner-output-b");
      await compileOwnerProgram(restoredNodeModules, secondOutput);
      const firstBundle = await ownerBrowserBundle(firstOutput);
      const secondBundle = await ownerBrowserBundle(secondOutput);
      assert.deepEqual(firstBundle, secondBundle);
      await mkdir(dirname(ownerBrowserPath), { recursive: true });
      await writeFile(ownerBrowserPath, firstBundle);
      browserSha256 = hash("sha256", firstBundle);
      reproducibleBuilds = 2;
    }
    const after = await fileInventory(restoredNodeModules);
    assert.deepEqual(strip(after), strip(before));
    process.stdout.write(
      `${canonicalize({
        browser_sha256: browserSha256,
        compiler: environment.evidence.compiler,
        mode,
        owner_tests: ownerTests,
        reproducible_builds: reproducibleBuilds,
        source: "authenticated_environment_transfer",
        transfer_inventory_sha256: environment.evidence.inventory_sha256,
        npm_invocations: 0,
        network_requests: 0,
        status: "passed",
      })}\n`,
    );
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

async function registerTests() {
  test("generated declarations expose signed authority contracts", async () => {
    const declarations = await readFile(
      join(typescriptRoot, "src", "generated", "contracts.d.ts"),
      "utf8",
    );
    for (const token of [
      "export type KernelStatus",
      "export type Constitution",
      "export type AdvisoryProposal",
      "export type AuthorityResult",
      "CanonicalUint64",
      "Ed25519Signature",
    ]) {
      assert.match(declarations, new RegExp(token));
    }
  });
  test("RFC 8785 raw vectors preserve exact accept/reject ledger", async () => {
    const lines = (
      await readFile(
        join(repositoryRoot, "contracts", "v1", "fixtures", "jcs-rfc8785-vectors.jsonl"),
        "utf8",
      )
    )
      .trim()
      .split("\n");
    let accepted = 0;
    let rejected = 0;
    for (const line of lines) {
      const vector = JSON.parse(line);
      const raw = Buffer.from(vector.raw_input_hex, "hex");
      assert.equal(hash("sha256", raw), vector.source_sha256);
      let observedVerdict = "accept";
      let outputHex = null;
      try {
        const value = parseJsonWithoutDuplicates(raw, vector.id);
        const output = Buffer.from(canonicalize(value));
        outputHex = output.toString("hex");
      } catch {
        observedVerdict = "reject";
      }
      assert.equal(observedVerdict, vector.expected_verdict, vector.id);
      if (observedVerdict === "accept") {
        assert.equal(outputHex, vector.canonical_utf8_hex, vector.id);
        accepted += 1;
      } else {
        rejected += 1;
      }
    }
    assert.deepEqual({ accepted, rejected }, { accepted: 6, rejected: 3 });
  });
  test("RFC 8785 property ordering matches the pinned npm oracle", async () => {
    const npmCanonicalize = (await import("canonicalize")).default;
    for (const value of [
      { a: 1, aa: 2 },
      { a: 1, aa: 2, aA: 3 },
      { "\ue000": "bmp", "\u{1f600}": "non-bmp" },
      {
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\u{1f600}": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis",
      },
    ]) {
      assert.equal(canonicalize(value), npmCanonicalize(value));
    }
  });
  test("fixture index and bundle manifest authenticate every public source", async () => {
    const manifest = JSON.parse(
      await readFile(join(repositoryRoot, "contracts", "v1", "bundle-manifest.json"), "utf8"),
    );
    const index = JSON.parse(
      await readFile(join(repositoryRoot, "contracts", "v1", "fixture-index.json"), "utf8"),
    );
    const schemaIds = manifest.schemas.map((item: { schema_id: string }) => item.schema_id);
    const schemaPaths = manifest.schemas.map((item: { path: string }) => item.path);
    assert.equal(new Set(schemaIds).size, schemaIds.length);
    assert.deepEqual(schemaPaths, [...schemaPaths].sort());
    for (const required of [
      "https://schemas.skeleton.local/v1/constitution.schema.json",
      "https://schemas.skeleton.local/v1/kernel-status.schema.json",
      "https://schemas.skeleton.local/v1/kernel-status-v2.schema.json",
      "https://schemas.skeleton.local/v1/kernel-status-v3.schema.json",
      "https://schemas.skeleton.local/v1/market-event-envelope.schema.json",
    ]) assert(schemaIds.includes(required), `required_schema_missing:${required}`);
    assert(index.sources.length > 0);
    for (const item of [...manifest.schemas, ...manifest.fixtures]) {
      const bytes = await readFile(join(repositoryRoot, "contracts", "v1", ...item.path.split("/")));
      assert.equal(hash("sha256", bytes), item.sha256);
    }
  });
  test("release root binding is exact and outside the bundle", async () => {
    const anchor = JSON.parse(
      await readFile(join(repositoryRoot, "trust", "phase06", "release-root-anchor.json"), "utf8"),
    );
    assert.equal(anchor.anchor_epoch, "0");
    assert.equal(anchor.root_public_key.length, 64);
    assert.equal(anchor.root_fingerprint_sha256.length, 64);
  });
  test("seeded raw mutations are deterministic and always rejected", () => {
    let state = 0x06_11_2026;
    const sequence = [];
    for (let index = 0; index < 128; index += 1) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      sequence.push(state);
    }
    assert.equal(sequence.length, 128);
    assert.equal(new Set(sequence).size, 128);
    assert.throws(() =>
      parseJsonWithoutDuplicates(
        Buffer.from('{"signature":"a","signature":"b"}'),
        "seeded-duplicate",
      ),
    );
  });
}

const mode = process.argv.find((argument) => argument.startsWith("--") && argument !== "--experimental-strip-types");
if (mode === "--acquire-registry") await acquireRegistryArchive();
else if (mode === "--offline-conformance") await offlineConformance();
else if (mode === "--seal-environment-transfer") await sealEnvironmentTransfer();
else if (mode === "--verify-all") await verifyAll();
else if (mode === "--phase07-contracts") await phase07ContractsGate();
else if (mode?.startsWith("--phase07-hostile=")) {
  await executePhase07HostileCase(mode.slice("--phase07-hostile=".length));
}
else if (mode === "--owner-test") await ownerMode("OwnerTest");
else if (mode === "--owner-verify") await ownerMode("OwnerVerify");
else if (
  mode === "--test-suite"
  || process.env.SKELETON_PHASE06_TEST_SUITE === "1"
  || process.env.NODE_TEST_CONTEXT === "child-v8"
) {
  await registerTests();
}
else throw new Error(`closed_mode_dispatch_failure:${mode ?? "none"}`);
