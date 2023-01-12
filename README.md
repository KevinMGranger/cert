# cert: generate x509 certificates for testing.

Like [`mkcert`](mkcert.dev), but with slightly more options, 

# command hierarchy

- [ ] consider: does it make more sense to think in terms of "intermediate / leaf" rather than "ca / leaf"?

## nested, see below
- key
  - new
  - view
- ca
  - new
  - sign
    (do we use this for any csr? anything special for cross-signing? in the latter case it's a cert rather than a CSR)
- leaf
- vault
- serve

or do we not do subcommands? verb-noun form? leaning towards that more. Sometimes arguments rather than options make sense.
_plugins / domains_ like vault make more sense as a sub-subcommand.

## flat, verb-noun

- new-key
- view-key

- CAs go here, but...
- TODO: do we work in terms of CSRs instead? with piping?
- let's see if we can make the workflow as similar to vault as possible

- sign-cert
- TODO: is cross-signing a different thing entirely?
- hmm, is the fact that you can "sign" a cert builder already a shortcut, instead of a CSR being created?

- test-trust
- import

# vault support

- do we make this limited? we don't set up anything for you, just let you integrate?
- or the opposite, let it do a full "we'll set up a dev CA for you"
- OOOOOH, we implement actions as reified-- if we do requests ourselves instead of using HVAC,
  then we can also dump it in terms of vault cli commands-- it's a relatively easy conversion!