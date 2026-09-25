// Deliberately a tokenizer for straight-line commands, never a shell evaluator.
export function tokenize(command: string): string[] | undefined {
  if (/[`]|\$\(|[|;&<>]/.test(command)) return undefined;
  const tokens: string[] = [];
  let token = '';
  let quote = '';
  let active = false;
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (c === '\\' && quote !== "'") {
      if (i + 1 >= command.length) return undefined;
      token += command[++i];
      active = true;
    } else if (quote) {
      if (c === quote) quote = '';
      else token += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      active = true;
    } else if (/\s/.test(c)) {
      if (active) tokens.push(token);
      token = '';
      active = false;
    } else {
      token += c;
      active = true;
    }
  }
  if (quote) return undefined;
  if (active) tokens.push(token);
  return tokens;
}
export function flag(tokens: string[], ...names: string[]): string | undefined {
  for (let i = 0; i < tokens.length; i++)
    for (const name of names) {
      if (tokens[i] === name) return tokens[i + 1];
      if (tokens[i].startsWith(`${name}=`)) return tokens[i].slice(name.length + 1);
    }
  return undefined;
}
export function runImage(
  tokens: string[],
): { reference: string; index: number } | undefined {
  const argumentFlags = new Set([
    '-e',
    '--env',
    '--env-file',
    '-v',
    '--volume',
    '--mount',
    '-w',
    '--workdir',
    '--name',
    '--network',
    '-p',
    '--publish',
    '--entrypoint',
    '-u',
    '--user',
    '--platform',
    '--pull',
    '--label',
  ]);
  const switches = new Set(['--rm', '-i', '-t', '-it', '--init']);
  for (let i = 2; i < tokens.length; i++) {
    const token = tokens[i];
    if (argumentFlags.has(token)) {
      i++;
      continue;
    }
    if (
      switches.has(token) ||
      (token.includes('=') && argumentFlags.has(token.split('=')[0]))
    )
      continue;
    if (token.startsWith('-')) return undefined;
    return { reference: token, index: i };
  }
  return undefined;
}
export function balancedQuotes(command: string): boolean {
  let quote = '';
  for (let i = 0; i < command.length; i++) {
    const char = command[i];
    if (char === '\\' && quote !== "'") {
      i++;
      continue;
    }
    if (quote) {
      if (char === quote) quote = '';
    } else if (char === "'" || char === '"') quote = char;
  }
  return quote === '';
}
