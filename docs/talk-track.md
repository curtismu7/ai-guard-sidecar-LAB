# Talk track (4 to 6 minutes)

Setup: `npm run build && npm start`, open `http://127.0.0.1:6500/`. Run the reset procedure at the bottom first.

## The pitch

"An agent gateway can hand every prompt and every answer to an external guardrail sidecar and act on what comes back. This app lets you watch that decision, break the sidecar on purpose, and see what fail closed versus fail open really means."

## Live steps

1. **Orient (30 s).** Point at the header badges (`DEMO`) and the story strip. Say: "Four steps: the gateway sends text, the sidecar returns findings, a finding at or above the category threshold blocks, and if the sidecar fails a toggle decides. All of it is simulated, offline."
2. **Benign prompt.** In "1. Pick something to try" choose **Benign prompt**, click **Run scenario**. Say: "No findings means allow. The gateway only sees an empty list."
3. **Direct prompt injection.** Choose **Direct prompt injection**, **Run scenario**. Point at "Findings and the decision" and "The /inspect exchange". Say: "This is the exact JSON the gateway sent and the answer it got. A finding at or above the threshold blocks before the upstream is called."
4. **Diagram.** Click **Simulate** in "How the check flows". Drag a box, change the speed, click **Reset**. Say: "Same run, played hop by hop."
5. **Thresholds.** In "Block thresholds" move the `prompt_injection` slider and watch the last decision flip. Say: "Thresholds are a policy choice, not a property of the detector."
6. **PII in a response.** Choose **PII leaking in a response**, **Run scenario**. Say: "The request is clean. Only response-direction scanning stops the leak, and the log shows masked values."
7. **Per-key guardrail.** Choose **A2A message, per-key guardrail**, **Run scenario**, then use the run buttons under "Result" to switch between the two keys. Say: "Same message, an enforcing key blocks, an observe-only key allows with an alert."
8. **Sidecar outage.** In "When the sidecar fails" pick **502 error** in the fault injector, then click **Show fail closed vs fail open**. Say: "Closed blocks everything, even harmless text, while the sidecar is down. Open lets even an attack through."
9. **What the stand-in misses.** In "What the stand-in misses" click **Try this text** on each example. Say: "A paraphrase gets through and a harmless sentence is blocked. Real classifiers have their own errors; this shows the trade-off."
10. **Close.** Show the "Decision log" and say: "Every decision, masked, in memory only."

## H2 2026 release: data protection (Ping release claims, UNVERIFIED on our tenant)

Open the **H2 2026 release** tab. The banner **Ping release claim, UNVERIFIED on our tenant** is on both tabs: the release (dated 2026-11-02) is not on our tenant, so every product claim here is Ping's, from its deck "ID4AI Workforce - H2 2026", slides 50 and 53. The app's own engine is a small teaching model; its counts are its own and are never Ping's.

Say the challenge first (a Ping claim): "Authorization cannot see content: an agent following hidden instructions can exfiltrate data within policy."

1. **Numbers (30 s).** Point at "Ping's numbers, and this app's own". Say: "Ping says 23 kinds, 364 secret detectors, 47 behavioural rules and 411 in total. Those are Ping's figures, not measured by us. The right column is what this little engine actually ships, computed live."
2. **Personal-data kinds.** In "Personal-data kinds" press **Original five**, then tick one more kind, then **All** and **None**. Say: "Detection is per kind. Every numeric kind has a real check digit: the table shows a valid sample found and a near miss not found, computed now." Then run a value of that kind under "Try it through the gateway" with the kind off and on.
3. **Secret detectors.** Tick the switch "Run this app's … bundled secret detectors" and run a made-up key under "Try it through the gateway". Say: "The category has no slider, so it blocks at high: that is this app's own rule for a category it has no slider for."
4. **Your own rules.** Press **Load two example rules**, then **Add these rules**, then run an example ticket number. Then press **Load an example with one bad rule** and **Add these rules**. Say: "One bad rule refuses the whole paste and nothing is added. The pattern is never shown back."
5. **Prompt logging.** In "Prompt logging, sealed to a key only you hold" press **Generate a key pair in this browser**, tick Enabled, press **Save the settings**, run some text, then press **Open in this page** on the record. Say: "The server sealed it to the public key and has no way to open it. Only this page holds the private half." Turn Enabled off or remove the key to show that nothing is recorded without a public key.

### Ping says, and this app ships

| What | Ping says | This app ships |
| --- | --- | --- |
| Personal-data kinds | 23 (deck claim), went from 5 to 23 | 11 (lab-invented), the app's own illustrative set (default selection: 5) |
| Secret and credential detectors | 364 (deck claim) | 12 (lab-invented), the app's own examples |
| Behavioural rules | 47 (deck claim) | 8 (lab-invented), the app's stand-in injection and jailbreak rules |
| Maintained rules in total | 411 (deck claim), 47 behavioural + 364 secret = 411 | not comparable: the app does not claim a rule total |

The app's own sets, from its engine: 11 personal-data kinds (card, ssn, iban, aba-routing, ca-sin, es-dni, uk-nino, health-id, dob, email, phone; the original five are on by default) and 12 bundled secret detectors (lab-aws-access-key-id, lab-github-token, lab-slack-token, lab-payment-secret-key, lab-private-key-block, lab-jwt, lab-google-api-key, lab-npm-token, lab-url-password, lab-bearer-token, lab-generic-assignment, lab-openai-style-key).

### Where each field comes from

| Field or claim | Source | Note |
| --- | --- | --- |
| piiKinds (swagger: PIIKinds) | console swagger name (schema only) | The console swagger lists PIIKinds on modelAIGuardConfig as detector ids. Only the field name is from the swagger; this app spells it camelCase and uses its own kind ids. |
| detection is per kind | deck claim | Deck slide 53: "Personal data, your way", numeric kinds checksum-validated, detection per kind. |
| the kinds in the catalogue and which are on by default | lab-invented | This app's own illustrative set. The default selection is the original five so the first demo behaves as before. Ping's list of 23 is not reproduced or guessed. |
| the check digit for each numeric kind | lab reading | A reading of public formats (Luhn, mod 97, mod 11, mod 23, a 3-7-1 weighted sum). Not a claim about Ping's validators. |
| ID, Description, Category, Severity, Keywords, Pattern, Entropy, Allowlist, ValueGroup | console swagger name (schema only) | Field names of modelAIGuardCustomRule in the console swagger. A name proves a field exists, not how it behaves. |
| the TOML keys: id, description, regex, keywords, entropy, secretGroup, category, severity, [rules.allowlist].regexes | lab reading | A reading of the gitleaks rule format. Pattern source is the standard "your own formats paste in unchanged" (deck slide 53) as the app understands it. |
| one bad rule refuses the whole paste | lab reading | The console swagger's description of imodelAIGuardRuleImport says so; how the product behaves is unverified. |
| the category names a pasted rule may use, and what the gateway does with them | lab-invented | The gateway here has sliders only for prompt_injection, jailbreak and pii. Any other category (secrets, data_exfiltration, malicious_content) blocks at high, the demo's existing rule for a category it does not know, so the rule's Severity decides. |
| the caps on a paste (size, lines, rules, matches) | lab-invented | Limits chosen for a safe local demo. |
| 23 kinds, 364 secret detectors, 47 behavioural rules, 411 rules | deck claim | Ping's figures from slide 53, uncited in the deck. Shown only in the "Ping says" column. |
| the "this app ships" column | lab-invented | Computed from this app's own engine at request time. These are the app's examples, not a measure of the product. |
| four outcomes: allow, alert, sanitize, block | deck claim | Deck slide 53. This app models allow, alert and block; it does not model sanitize. |
| Enabled, PublicKey (X25519 JWK), KeyID, Surfaces, IncludeResponses, MaxBytes | console swagger name (schema only) | Field names of modelPromptLogConfig in the console swagger. |
| nothing is recorded without a public key | lab reading | The swagger says so; this app follows it. |
| prompts sealed to your key, opened only with your private key | deck claim | Deck slides 50 and 53: "Privilege never holds it". |
| the sealed-record envelope (X25519 + HKDF-SHA256 + AES-256-GCM), the surfaces this app produces, caps, the ring of 100 records | lab-invented | The product's format is not public. The envelope is this app's own and is shown so the round trip can be proved. |
| anything measured on our tenant | measured (our note) | Nothing. The release is not on our tenant; nothing here has been measured. |

### Why it matters (Ping claims, UNVERIFIED on our tenant)

**AIGuard (deck slide 53)**

- Challenge: Authorization cannot see content: an agent following hidden instructions can exfiltrate data within policy.
- Technical: Content inspected in and out across MCP, A2A, LLM and coding-agent traffic; deterministic rules add no availability dependency.
- Business: A fraction of the cost of one incident; framework-mapped evidence for AI governance sign-off.

**Prompt Logging (deck slide 50)**

- Challenge: Retaining prompts is what investigations need and what teams refuse to hand a vendor.
- Technical: Content sealed to your public key, decrypted only in your console session; Privilege never holds the private half.
- Business: Forensic retention becomes acceptable to security and legal.

### Cut on purpose

The deck's "sanitize" outcome (redact the offending span and forward the rest) is not modelled: this app allows, alerts or blocks. Its detectors are examples, not Ping's sets. Behavioural scoring, framework tagging and the model-based second layer are not modelled either.

## If asked, say this

- **What is simulated:** the gateway, the upstream, the sidecar and the detector. No network, no real tenant, no model.
- **UNVERIFIED:** the `/inspect` request and response shapes and the gateway behaviour are as understood from a demo environment and are UNVERIFIED against product documentation. Check the docs before relying on any detail.
- **What this does not prove:** nothing about real detection quality, defaults, thresholds, severities or licensing. The detector is a fixed list of keyword and pattern rules, not a model. The role names `assistant_response` and `a2a_message` are this demo's own choice.

## Likely questions

1. **Is this the real product?** No. It is a teaching model with a stand-in detector.
2. **Will it catch paraphrased attacks?** This one does not, on purpose. A real model's misses depend on that model.
3. **Why block on a threshold per category?** So you can tune the trade-off between false alarms and misses; the defaults here are demo choices.
4. **Fail closed or open?** Closed is safe but an outage stops traffic; open is available but unchecked. It is a risk decision per application.
5. **Does it send my text anywhere?** No. It binds to loopback only, makes no outbound calls, and keeps state in memory.

## Reset before the next demo

Click **Reset** in the diagram controls, set the fault injector back to **None**, make sure **Sidecar Fail Closed** is ON (defaults), or run `curl -s -X POST http://127.0.0.1:6500/api/reset -H 'content-type: application/json'`. This restores defaults, clears the fault, empties the decision log, removes your pasted rules, sets the personal-data kinds back to the original five, switches the secrets rail off and clears the prompt-log settings and records. Private keys held in the page's memory are kept: press **Forget all keys** in the H2 2026 release tab (or reload the page). Run `npm run doctor` if anything looks off.
