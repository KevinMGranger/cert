- [ ] vault integration

- [ ] for "serve" testing: does using an HTTP proxy offload the DNS? so we could use it to fake it?

- [ ] commands for importing into various trusts (system (win/mac/linux) / firefox / idk what else)

- [ ] cert testing

- [ ] figure out a piping strategy:
  generating things in one step and using them for a later one should be easy.
  But how often will that be used? And if you need to tee anyway, why not just do that ourselves?
  Maybe the strategy of pointing to the generated files and passing JSON context information
  is the best strategy? e.g.
  `cert new-ca --cout ca.pem --kout ca.key ... | cert new-leaf --cout leaf.pem --leaf.key`

- [ ] more env variable support for less verbose commands
- [ ] prompts to avoid endless CLI args for stuff like names (will need to do it manually instead of per-flag)

- [ ] do combinatoric test for certificate requirements, and document my findings
    - only need to see if chrome says it's malformed, doesn't need to be trusted. So don't worry about trusting the CA.
- [ ] support arbitrary cert chaining
- [ ] name constraints

- [ ] trust tests based on badssl.com
  - [ ] do they do name constraints?
  - [ ] is it even maintained? no-common-name is expired instead of just missing it