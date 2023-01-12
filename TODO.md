- [ ] vault integration

- [ ] for "serve" testing: does using an HTTP proxy offload the DNS? so we could use it to fake it?

- [ ] commands for importing into various trusts (system (win/mac/linux) / firefox / idk what else)

- [ ] cert testing

- [ ] more env variable support for less verbose commands
- [ ] prompts to avoid endless CLI args for stuff like names

- [ ] do combinatoric test for certificate requirements, and document my findings
    - only need to see if chrome says it's malformed, doesn't need to be trusted. So don't worry about trusting the CA.
- [ ] support arbitrary cert chaining
- [ ] name constraints