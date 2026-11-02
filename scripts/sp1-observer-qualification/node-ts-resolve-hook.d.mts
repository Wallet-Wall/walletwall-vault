// Types of node-ts-resolve-hook.mjs for the TypeScript suite (the hook itself is plain JavaScript, Node built-ins only).
export function tsCandidate(
  specifier: string,
  parentURL: string | undefined,
  isFile: (fileUrl: string) => boolean,
): string | null;
export function resolve(
  specifier: string,
  context: { parentURL?: string },
  next: (specifier: string, context: { parentURL?: string }) => Promise<unknown>,
): Promise<unknown>;
