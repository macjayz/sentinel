/**
 * Records real JSON-RPC responses from several public Ethereum endpoints into a fixture
 * corpus, used by the normalization tests in packages/shared.
 *
 * Normalization is the load-bearing piece of cross-provider verification (detector D2):
 * too little and honest providers look like they disagree over formatting, too much and
 * genuinely different values collide into one hash. Hand-written fixtures cannot prove
 * either way — only real provider output can, because the formatting differences are
 * exactly the ones nobody thinks to invent.
 *
 * Every call is pinned to one concrete block so the responses stay comparable and the
 * corpus stays stable when re-recorded. Re-run with:
 *
 *   npx tsx scripts/record-normalization-corpus.ts
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

type Endpoint = { name: string; url: string };

const ENDPOINTS: Endpoint[] = [
  { name: "publicnode", url: "https://ethereum-rpc.publicnode.com" },
  { name: "drpc", url: "https://eth.drpc.org" },
  { name: "blastapi", url: "https://eth-mainnet.public.blastapi.io" },
  { name: "onfinality", url: "https://eth.api.onfinality.io/public" },
  { name: "mevblocker", url: "https://rpc.mevblocker.io" }
];

const CORPUS_DIR = join(process.cwd(), "packages", "shared", "corpus");

// Well-known mainnet contracts, chosen because their state at a finalized block is stable.
const USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function rpc(url: string, method: string, params: unknown[]): Promise<unknown> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(30_000)
  });

  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    // Rate-limited public endpoints answer with an HTML error page rather than JSON.
    throw new Error(`non-JSON response (HTTP ${response.status}): ${text.slice(0, 80)}`);
  }
}

/** One retry with a pause: these are shared public endpoints and they do throttle. */
async function rpcWithRetry(url: string, method: string, params: unknown[]): Promise<unknown> {
  try {
    return await rpc(url, method, params);
  } catch {
    await sleep(2_000);
    return rpc(url, method, params);
  }
}

async function main() {
  const headBody = (await rpc(ENDPOINTS[0].url, "eth_blockNumber", [])) as { result?: string };
  if (typeof headBody.result !== "string") throw new Error("could not resolve head");

  // Deep enough that no realistic reorg can move it, shallow enough that free endpoints
  // still hold the state. Going much further back turns every state-reading call into an
  // archive request, which most public endpoints refuse.
  const head = Number.parseInt(headBody.result, 16);
  const blockNumber = head - 32;
  const blockTag = `0x${blockNumber.toString(16)}`;

  const blockBody = (await rpc(ENDPOINTS[0].url, "eth_getBlockByNumber", [blockTag, false])) as {
    result?: { transactions?: string[] };
  };
  const sampleTx = blockBody.result?.transactions?.[0];
  if (!sampleTx) throw new Error("pinned block has no transactions to sample");

  const calls: { id: string; method: string; params: unknown[] }[] = [
    { id: "eth_getBalance", method: "eth_getBalance", params: [WETH, blockTag] },
    { id: "eth_getCode", method: "eth_getCode", params: [USDC, blockTag] },
    { id: "eth_getStorageAt", method: "eth_getStorageAt", params: [USDC, "0x0", blockTag] },
    {
      id: "eth_getTransactionCount",
      method: "eth_getTransactionCount",
      params: ["0xd8da6bf26964af9d7eed9e03e53415d37aa96045", blockTag]
    },
    // decimals() — a uint8 returned as a padded 32-byte word, the case where stripping
    // leading zeros from DATA would be catastrophic.
    { id: "eth_call_decimals", method: "eth_call", params: [{ to: USDC, data: "0x313ce567" }, blockTag] },
    { id: "eth_call_totalSupply", method: "eth_call", params: [{ to: USDC, data: "0x18160ddd" }, blockTag] },
    { id: "eth_getBlockByNumber", method: "eth_getBlockByNumber", params: [blockTag, false] },
    { id: "eth_getTransactionReceipt", method: "eth_getTransactionReceipt", params: [sampleTx] },
    {
      id: "eth_getLogs",
      method: "eth_getLogs",
      params: [{ address: USDC, topics: [TRANSFER_TOPIC], fromBlock: blockTag, toBlock: blockTag }]
    }
  ];

  await mkdir(CORPUS_DIR, { recursive: true });

  const manifest = {
    chainId: "1",
    blockNumber: String(blockNumber),
    blockTag,
    recordedAt: new Date().toISOString(),
    endpoints: ENDPOINTS.map((endpoint) => endpoint.name),
    note: "Raw JSON-RPC bodies as returned by each endpoint. Re-record with scripts/record-normalization-corpus.ts"
  };

  for (const call of calls) {
    const responses: Record<string, unknown> = {};

    for (const endpoint of ENDPOINTS) {
      try {
        responses[endpoint.name] = await rpcWithRetry(endpoint.url, call.method, call.params);
        process.stdout.write(".");
      } catch (error) {
        process.stdout.write("x");
        responses[endpoint.name] = {
          __recorderError: error instanceof Error ? error.message : "unknown"
        };
      }

      await sleep(250);
    }

    await writeFile(
      join(CORPUS_DIR, `${call.id}.json`),
      `${JSON.stringify({ method: call.method, params: call.params, responses }, null, 2)}\n`
    );
    console.log(` ${call.id}`);
  }

  await writeFile(join(CORPUS_DIR, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`\nRecorded ${calls.length} calls at block ${blockNumber} from ${ENDPOINTS.length} endpoints.`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
