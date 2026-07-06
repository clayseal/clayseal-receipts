export type AgentAuthReceiptMetadata = {
  receiptId?: string;
  sessionId?: string;
  policySatisfied?: boolean;
  decisionOutcome?: string;
  policyViolations?: readonly string[];
  authorityVersion?: string;
  proof?: unknown;
};

export type ReceiptRecordInput<TArgs, TResult> = {
  toolName: string;
  action: string;
  args: TArgs;
  result: TResult;
};

export type ReceiptRecorder<TArgs = unknown, TResult = unknown> = {
  record(input: ReceiptRecordInput<TArgs, TResult>): Promise<AgentAuthReceiptMetadata>;
};

export type ExecutableTool<TArgs, TResult> = {
  description?: string;
  parameters?: unknown;
  execute(args: TArgs): Promise<TResult> | TResult;
};

export type ReceiptedToolOptions = {
  action?: string;
  includeMetadata?: boolean;
};

export type ReceiptedToolResult<TResult> = {
  output: TResult;
  _agentauth_receipt: AgentAuthReceiptMetadata;
};

export type ReceiptedTool<TArgs, TResult> = ExecutableTool<
  TArgs,
  TResult | ReceiptedToolResult<TResult>
> & {
  readonly agentauth: {
    readonly toolName: string;
    readonly action: string;
  };
};

export async function recordReceipt<TArgs, TResult>(
  recorder: ReceiptRecorder<TArgs, TResult>,
  input: ReceiptRecordInput<TArgs, TResult>,
): Promise<AgentAuthReceiptMetadata> {
  return recorder.record(input);
}

export function withAgentAuthReceipt<TArgs, TResult>(
  toolName: string,
  tool: ExecutableTool<TArgs, TResult>,
  recorder: ReceiptRecorder<TArgs, TResult>,
  options: ReceiptedToolOptions = {},
): ReceiptedTool<TArgs, TResult> {
  const action = options.action ?? `typescript.tool.${toolName}`;
  const wrapped: ReceiptedTool<TArgs, TResult> = {
    agentauth: { toolName, action },
    async execute(args: TArgs): Promise<TResult | ReceiptedToolResult<TResult>> {
      const result = await tool.execute(args);
      const receipt = await recorder.record({ toolName, action, args, result });
      if (options.includeMetadata) {
        return { output: result, _agentauth_receipt: receipt };
      }
      return result;
    },
  };
  if (tool.description !== undefined) {
    wrapped.description = tool.description;
  }
  if (tool.parameters !== undefined) {
    wrapped.parameters = tool.parameters;
  }
  return wrapped;
}

export function withAgentAuthMetadata<TArgs, TResult>(
  toolName: string,
  tool: ExecutableTool<TArgs, TResult>,
  recorder: ReceiptRecorder<TArgs, TResult>,
  options: Omit<ReceiptedToolOptions, "includeMetadata"> = {},
): ReceiptedTool<TArgs, TResult> {
  return withAgentAuthReceipt(toolName, tool, recorder, {
    ...options,
    includeMetadata: true,
  });
}
