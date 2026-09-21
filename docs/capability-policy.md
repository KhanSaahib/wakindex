# Capability policy input validation

## Description

The runtime capability evaluator in `wakindex.capability_policy` uses JSON revision documents.
It is separate from the static scanner's `wakindex-policy.toml` format.

Selectors must belong to the rule's capability. File capabilities and `proc.spawn` accept `path`
or `path_prefix`; network capabilities accept `host`; `tool.invoke` accepts `tool`, `method`, or
both. `cred.use` currently supports only `any`. Every capability supports `any: true` by itself.
Unsupported combinations reject the entire revision rather than ignoring a constraint.

File requests must identify an absolute, NUL-free `resource:file:` path even when an `any` rule
matches. Matching is lexical and does not resolve symlinks or establish an OS enforcement
boundary. The supervisor and OS perimeter must supply and enforce the actual resource identity.

Supplied usage counters must use known budget names and non-negative integer values. Booleans,
negative values, floats (including NaN), strings and unknown names are rejected with a policy
validation error. Validation occurs when constructing the request and again before evaluation.
Counters and monotonic timing come from the caller; the evaluator reads neither clocks nor OS
resource counters. Missing counters remain unchecked, so callers must provide every configured
counter before treating the result as a budget authorization. `explain` names the exceeded limit.

Accepted rule and budget mappings must also be immutable. Input validation does not establish
or certify a production enforcement boundary.
