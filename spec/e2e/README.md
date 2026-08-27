# End-to-end suite

Full SAML flows against `spec/rails_app`:

- **IdP** — `SamlIdpController`, which mounts `SamlIdp::Controller` exactly as a
  host application would.
- **SP** — `SamlController`, a strict ruby-saml Service Provider.

The two are addressed on different hosts (`idp.example.test` / `sp.example.test`)
so `Destination` and ACS-URL validation stay meaningful. `SamlFlow`
(`spec/support/saml_flow.rb`) drives the whole journey through Rack: follow the
redirect, fill in the login form, submit the auto-POST form to the ACS.

**The SP is the adversary of the IdP.** It verifies signatures, digests,
conditions, audience, destination and InResponseTo, and reports what it saw as
JSON. It never renders assertion content it has not cryptographically validated,
so a spec asserting on `name_id` is asserting on a *verified* value.

## Running

```bash
make test          # everything
make e2e           # end-to-end flows only
make docker-test   # everything, in Docker (what CI runs)
make docker-e2e
make syntax        # parse everything under the oldest supported Ruby
```

### Ruby version floor

`saml_idp.gemspec` declares `required_ruby_version >= 2.5` and the CI matrix
runs Ruby 2.5 through 3.3. This suite runs on all of them, so it must avoid
Ruby 3.0+ syntax — endless method definitions especially — until the floor is
raised. `make syntax` catches that locally; verified green on
Ruby 2.5 / Rails 5.2, Ruby 2.7 / Rails 6.1 and Ruby 3.3 / Rails 7.2.

## Driving scenarios

The IdP maps `x_*` request parameters onto `encode_response` options, so one
controller covers every option combination:

| knob | effect |
|---|---|
| `x_algorithm` | `sha1` / `sha256` / `sha384` / `sha512` |
| `x_signed_assertion` | sign the assertion (default true) |
| `x_signed_message` | sign the Response element |
| `x_encrypt` | emit an `EncryptedAssertion` |
| `x_compress` | deflate the Response before base64 |
| `x_name_id_format` | `email_address` / `persistent` / `transient` |
| `x_expiry`, `x_session_expiry` | Conditions and SessionNotOnOrAfter |
| `x_audience`, `x_authn_context` | override audience / AuthnContextClassRef |
| `x_encrypted_key` | sign with a passphrase-protected private key |

Two request headers switch IdP-side policy for one request, making
configuration-dependent paths reachable: `X-E2E-Require-Signed-Request` and
`X-E2E-SP-Profile` (`unknown` / `no-cert` / `bad-cert` / `no-acs` /
`foreign-host`). SP-side options ride in `RelayState`, because the auto-POST to
the ACS arrives from the IdP carrying none of the SP's original parameters.

## Coverage (83 examples)

| Area | Covered |
|---|---|
| Bindings | HTTP-Redirect (signed query string), HTTP-POST (enveloped signature), auto-POST response delivery |
| SSO | SP-initiated, IdP-initiated (unsolicited), RelayState, InResponseTo correlation |
| Algorithms | sha1/256/384/512 — acceptance **and** the declared SignatureMethod/DigestMethod URIs |
| Response modes | signed assertion, signed message, message-only signing, encrypted assertion, sign-then-encrypt, compression, passphrase-protected key |
| Assertion | NameID formats ×3, AttributeStatement names/formats/multi-value, Conditions, AudienceRestriction, AuthnContext, SessionIndex, SessionNotOnOrAfter, SubjectConfirmationData |
| SLO | SP-initiated over Redirect and POST, IdP-initiated via `LogoutRequestBuilder`, status code, issuer, InResponseTo, RelayState, and the raw-vs-Base64 return shape of `encode_response` |
| Metadata | served, well-formed, signed, entityID matches emitted Issuer, SSO/SLO endpoints, NameIDFormats, published cert matches signing cert, parseable by ruby-saml |
| Request validation | every reachable `SamlIdp::Request` outcome: signed/unsigned, tampered query signature, swapped payload, `empty_certificate`, `not_allowed_host`, unknown SP, ACS-URL fallback |
| Rejection | tampered digest, tampered signature, swapped subject, stripped signature, altered Destination, wrong audience, expired conditions, InResponseTo mismatch, malformed SAML, missing SAMLRequest, and no content leaked on rejection |

Several specs deliberately pin **current** behaviour that is expected to change
(the unreachable `:sp_not_found`, the `encode_response` return-shape asymmetry).
They are commented as such, with a pointer to `docs/FINDINGS.md`, so a refactor
has to change them on purpose rather than by accident.

Still open: XSD schema conformance against the OASIS schemas, a real browser leg
for the auto-POST `onload`, and a second SP implementation for cross-library
interop.
