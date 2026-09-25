import { Lexer, Parser } from '@actions/expressions';
import {
  ContextAccess,
  type Expr,
  Grouping,
  IndexAccess,
  Literal,
} from '@actions/expressions/ast';
import { TokenType } from '@actions/expressions/lexer';
import { type Identity, unknownValue, type Value } from './model.js';
export type Scope = Map<string, Value>;
export function hasStatusCheck(condition: unknown): boolean {
  const expression = String(condition ?? '').replace(/^\s*\$\{\{\s*|\s*\}\}\s*$/g, '');
  try {
    const { tokens } = new Lexer(expression).lex();
    return tokens.some(
      (token, index) =>
        token.type === TokenType.IDENTIFIER &&
        /^(success|failure|cancelled|always)$/i.test(token.lexeme) &&
        tokens[index + 1]?.type === TokenType.LEFT_PAREN &&
        tokens[index - 1]?.type !== TokenType.DOT,
    );
  } catch {
    // An unreadable condition cannot prove that a dependency skip propagates.
    return true;
  }
}
function access(expr: Expr): string | undefined {
  if (expr instanceof Grouping) return access(expr.group);
  if (expr instanceof ContextAccess) return expr.name.lexeme;
  if (expr instanceof IndexAccess && expr.index instanceof Literal) {
    const parent = access(expr.expr);
    return parent ? `${parent}.${expr.index.literal.coerceString()}` : undefined;
  }
}
export function resolveValue(raw: unknown, scope: Scope): Value {
  const text = String(raw ?? '');
  let unknown = false;
  const trace: string[] = [];
  const result = text.replace(/\$\{\{([\s\S]*?)\}\}/g, (_expression, body: string) => {
    try {
      const ast = new Parser(
        new Lexer(body).lex().tokens,
        [
          'steps',
          'needs',
          'env',
          'github',
          'inputs',
          'vars',
          'matrix',
          'job',
          'runner',
          'secrets',
        ],
        [],
      ).parse();
      if (ast instanceof Literal) return ast.literal.coerceString();
      const path = access(ast)?.toLowerCase();
      if (path === 'github.sha') {
        trace.push('github.sha (source revision, not an image digest)');
        return '__samebyte_github_sha__';
      }
      const value = path && scope.get(path);
      if (value) {
        trace.push(...value.trace, body.trim());
        unknown ||= value.unknown;
        return value.unknown ? '__samebyte_unknown__' : value.text;
      }
    } catch {
      /* Invalid and unsupported expressions cannot prove identity. */
    }
    trace.push('Unresolved GitHub expression');
    unknown = true;
    return '__samebyte_unknown__';
  });
  if (result.includes('${{')) unknown = true;
  return { text: result, trace, unknown };
}
export function bind(scope: Scope, key: string, value: Value): void {
  scope.set(key.toLowerCase(), { ...value, trace: [...value.trace, key] });
}
export function environment(
  scope: Scope,
  values: Record<string, unknown> | undefined,
): Scope {
  const next = new Map(scope);
  for (const [name, raw] of Object.entries(values ?? {})) {
    const value = resolveValue(raw, scope);
    bind(next, `env.${name}`, value);
    next.set(`shell.${name}`, {
      ...value,
      trace: [...value.trace, `env.${name}`],
    });
  }
  return next;
}
export function shellValue(raw: string, scope: Scope): Value {
  const result = resolveValue(raw, scope);
  result.text = result.text.replace(
    /\$(?:\{([A-Za-z_][\w]*)\}|([A-Za-z_][\w]*))/g,
    (matched: string, braced: string, plain: string, offset: number) => {
      let quote = '';
      for (let i = 0; i < offset; i++) {
        const char = result.text[i];
        if (char === '\\' && quote !== "'") {
          i++;
          continue;
        }
        if (quote) {
          if (char === quote) quote = '';
        } else if (char === "'" || char === '"') quote = char;
      }
      if (quote === "'" || result.text[offset - 1] === '\\') return matched;
      const name = braced || plain;
      const value = scope.get(`shell.${name}`);
      if (!value) {
        result.unknown = true;
        result.trace.push(`Unresolved shell variable: ${name}`);
        return '__samebyte_unknown__';
      }
      result.unknown ||= value.unknown;
      result.trace.push(...value.trace, `$${name}`);
      return value.unknown ? '__samebyte_unknown__' : value.text;
    },
  );
  return result;
}
export function identity(value: Value): Identity {
  const base = { reference: value.text, trace: value.trace, concrete: false };
  if (
    value.unknown ||
    !value.text ||
    /[\s$`]/.test(value.text) ||
    value.text.includes('__samebyte_unknown__')
  )
    return { ...base, kind: 'unknown' };
  const match = /^(?:(.+)@)?(sha256:[a-fA-F0-9]{64}|__samebyte_digest_[\w]+__)$/.exec(
    value.text,
  );
  if (match)
    return {
      ...base,
      kind: 'immutable',
      key: match[2].startsWith('sha256:') ? match[2].toLowerCase() : match[2],
      repository: match[1],
      concrete: match[2].startsWith('sha256:'),
    };
  if (value.text.includes('@') || value.text.startsWith('sha256:'))
    return { ...base, kind: 'unknown' };
  if (/^[\w][\w./:-]*$/.test(value.text))
    return {
      ...base,
      kind: 'mutable',
      repository: value.text.replace(/:[^/:]+$/, ''),
    };
  return { ...base, kind: 'unknown' };
}
export { unknownValue };
