# Two-minute PhishLens demo

Before presenting: run the test suite and browser checks; open the app at http://127.0.0.1:4173; verify the demo presets; load a local model if using AI; then disconnect the internet. Use only the supplied `.example` presets and documentation IP addresses.

| Time | Action | What to say |
|---|---|---|
| 0:00–0:15 | Show the input and local-processing indicator. | “Campus links arrive in messages, documents, and QR codes. We make the actual destination visible before the click.” |
| 0:15–0:30 | Choose Campus notice. | “The actual host is clear. Safe means our configured rules found no warning sign; it does not verify the site.” |
| 0:30–0:45 | Choose Long lab link. | “A long URL, hyphens, and a custom port do not automatically make a link dangerous. This approved-domain example stays Safe.” |
| 0:45–1:05 | Choose The @ disguise. | “The campus name is user information. The actual destination is other.example. Here is the exact rule and next step.” |
| 1:05–1:30 | Choose Hidden destination and show Destination X-Ray. | “The outside uses an approved host, but this parameter contains a deceptive destination. We decode its text locally. We have not visited it or claimed the server will redirect.” |
| 1:30–1:45 | Choose Short link, then source Random sticker. | “The destination is unknown, so Review is honest. The sticker adds source caution without changing the URL rule.” |
| 1:45–2:00 | Show the explanation and rule checklist. | “The same policy applies across departments. Students see the destination, the evidence, and what to do next—all locally.” |

## Optional judge questions

- Local AI: request the explanation in advance if the model has a cold-start delay; explain that rules determine the verdict and the local model supplies wording. Never present fixed fallback text as model output.
- QR: upload `deceptive-qr.png`. Its decoded text enters the identical URL checker.
- Consistency: compare Computer science and Library department presets.
- Accessibility: operate the page by keyboard and read the concise summary. Optional speech uses device-local voices only.
- Boundary: show malformed IPv6 or an unfamiliar international name receiving Review.
- Privacy: open browser Network tools while analyzing a new input. No submitted destination should be contacted.

Do not claim perfect detection, a verified redirect, a globally unique invention, or a measured real-world accuracy percentage based on this synthetic test set.
