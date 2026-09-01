import { createSentinelRpcClient } from "@sentinel/web3";

const client = createSentinelRpcClient({
  projectId: process.env.SENTINEL_PROJECT_ID ?? "demo",
  apiKey: process.env.SENTINEL_API_KEY ?? "dev-sentinel-key",
  endpoint: process.env.SENTINEL_ENDPOINT ?? "http://localhost:8080",
  rpcUrl: process.env.EVM_RPC_URL ?? "https://ethereum.publicnode.com",
  serviceName: "web3-rpc-example",
  chainId: 1,
  provider: "publicnode"
});

const blockNumber = await client.request({ method: "eth_blockNumber", params: [] });
console.log({ blockNumber });
