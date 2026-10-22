# Fixture provenance — undefined_shapes (Rego, synthetic)

Not derived from any external toolchain, and not a policy bundle: there is
no manifest, fetch plan or guidance here, and nothing loads it through
`PolicyBundle`. It is a table of *expression shapes*, one entrypoint each,
built so `tests/test_undefined_shapes.py` can pin how OPA treats an
undefined operand in each -- the same question `test_cel_policy.py` asks of
cel-python with a synthesized `checks.cel.json`, so the two engines are
measured side by side on the same shapes.

The undefined operand is `format_int(input.n, input.base)` with
`input.base = 7`. OPA's `format_int` supports bases 2, 8, 10 and 16 only;
any other base makes the call **undefined**, not an error, which is exactly
the shape of evidence a parsing builtin cannot parse (`json.unmarshal` on
non-JSON, `base64url.decode` on non-base64). `base = 10` is the control.

- Package: `policybundle.examples.undefined_shapes`.
- Entrypoints, and what each measured against OPA 1.17.1 on the undefined
  input (`[]` is undefined; the control column is `base = 10`):

  | entrypoint                  | shape                                    | undefined   | control   |
  |-----------------------------|------------------------------------------|-------------|-----------|
  | `not_undefined_rule`        | `not <partial rule whose body is undefined>` | **true**  | undefined |
  | `not_undefined_function`    | `not <partial function call, body undefined>` | **true** | undefined |
  | `count_comprehension_zero`  | `count([... undefined legs ...]) == 0`   | **true**    | undefined |
  | `positive`                  | `<undefined> == "5"`                     | undefined   | true      |
  | `every_undefined`           | `every n in ns { <undefined> }`          | undefined   | undefined |
  | `max_undefined`             | `max([... undefined ...])`               | undefined   | 3         |
  | `not_builtin_hoisted`       | `not format_int(n, base) == "5"`         | undefined   | undefined |
  | `allow`                     | `default false; positive`                | false       | true      |
  | `failed_checks`             | `not allow; not helper` → `"the_check"`  | `["the_check"]` | `[]`  |

  The first three are the fail-open shapes: an uncomputable operand becomes
  a pass. `failed_checks` is the same `not <undefined>` idiom on the side
  where it is correct -- it is how a reason gets reported at all -- and is
  pinned so the hazard is stated precisely: the shape on the *allow* side.

- Uses only stock OPA builtins (`format_int`, `count`, `max`); no custom
  host builtin, so no `capabilities.json` is needed to build it.

## Rebuild

```sh
P=policybundle/examples/undefined_shapes
opa build -t wasm \
  -e $P/not_undefined_rule -e $P/not_undefined_function \
  -e $P/count_comprehension_zero -e $P/positive -e $P/every_undefined \
  -e $P/max_undefined -e $P/not_builtin_hoisted \
  -e $P/allow -e $P/failed_checks \
  policy.rego -o /tmp/us.tar.gz
tar xzf /tmp/us.tar.gz -C /tmp policy.wasm
cp /tmp/policy.wasm .
```
