import bodyParser from "body-parser";
import express from "express";
import { sentinelExpress } from "@sentinel/sdk-node";

const app = express();

app.use(bodyParser.json());
app.use(
  sentinelExpress({
    projectId: "demo",
    apiKey: process.env.SENTINEL_API_KEY ?? "dev-sentinel-key",
    endpoint: process.env.SENTINEL_ENDPOINT ?? "http://localhost:8080",
    serviceName: "example-api",
    redaction: {
      fields: ["cardNumber", "walletPrivateKey"]
    }
  })
);

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.post("/graphql", (req, res) => {
  res.json({ data: { operationName: req.body.operationName ?? "anonymous" } });
});

app.post("/rpc", (req, res) => {
  if (req.body.method === "eth_sendRawTransaction") {
    return res.status(401).json({ error: "signature rejected" });
  }

  res.json({ jsonrpc: "2.0", id: req.body.id, result: "0x1" });
});

app.listen(4000, () => {
  console.log("Example API listening on http://localhost:4000");
});
