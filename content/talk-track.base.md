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

<!-- generated:h2 -->

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
