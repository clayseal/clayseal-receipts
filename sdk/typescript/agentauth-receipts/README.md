# AgentAuth Receipts TypeScript

Dependency-light TypeScript wrappers for agent tools. The API intentionally
matches the common Vercel AI SDK tool shape: a tool object has `description`,
`parameters`, and an `execute(args)` function.

```ts
import { withAgentAuthReceipt } from "@agentauth/receipts";

const scoreTransaction = {
  description: "Score a transaction.",
  parameters: { type: "object", properties: { score: { type: "number" } } },
  execute: async ({ score }: { score: number }) => ({
    decision: "approve",
    fraud_score: score,
  }),
};

const tool = withAgentAuthReceipt(
  "score_transaction",
  scoreTransaction,
  {
    async record({ toolName, action, args, result }) {
      // Send to an AgentAuth receipt service, local audit writer, or test double.
      return { receiptId: `${toolName}:${action}`, proof: { args, result } };
    },
  },
);
```

Use `withAgentAuthMetadata()` when the caller should receive
`{ output, _agentauth_receipt }` instead of the original tool result.
