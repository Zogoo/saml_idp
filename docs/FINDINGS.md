# Findings surfaced while building the e2e suite

Every item below was found by making the harness work, and each is reproducible
against the committed environment. They are gem behaviours, not harness bugs.

## 1. A nil logger turns every rejection path into a 500

`Configurator#initialize` ([lib/saml_idp/configurator.rb:38]) captures the logger
**by value**:

```ruby
self.logger = (defined?(::Rails) && Rails.respond_to?(:logger)) ? Rails.logger : ->(msg) { puts msg }
```

If `Rails.logger` is still `nil` when `SamlIdp.configure` runs, `config.logger`
is permanently `nil`. `Request#log` ([lib/saml_idp/request.rb:87-93]) then takes
the `else` branch and calls `nil.info`:

```
NoMethodError: undefined method `info' for nil
  lib/saml_idp/request.rb:91:in `log'
  lib/saml_idp/request.rb:127:in `valid?'
```

The happy path never logs, so this only fires when a request is **rejected** —
the moment error handling matters most. Fix: guard the nil, or resolve the
logger lazily instead of at construction.

## 2. Response `Issuer` and metadata `entityID` come from different settings

`Controller#issuer_uri` ([lib/saml_idp/controller.rb:125]) emits
`config.base_saml_location` as the Response `<Issuer>`, while
`MetadataBuilder#entity_id` ([lib/saml_idp/metadata_builder.rb:126]) publishes
`config.entity_id` (falling back to `base_saml_location`).

SAML 2.0 requires the `Issuer` to be the IdP's entityID. Configure the two
differently and the IdP emits assertions no SP configured from its own published
metadata will accept — with a confusing error. The gem does not enforce or warn.
`spec/features/metadata_spec.rb` pins the invariant.

## 3. `:sp_not_found` is unreachable

`Request#service_provider` ([lib/saml_idp/request.rb:189]):

```ruby
ServiceProvider.new((service_provider_finder[issuer] || {}).merge(identifier: issuer))
```

`identifier` is always merged in, so the attribute hash is never empty, so
`ServiceProvider#valid?` (`attributes.present?`) is always true whenever the
issuer is non-blank. A finder returning `nil` for an unknown issuer therefore
yields a "valid" service provider.

Verified: a request from a completely unknown issuer is **not** rejected as
`:sp_not_found`. It is stopped later by the response-host check
(`:not_allowed_host`). A deployment with permissive `response_hosts` loses that
backstop too.

## 4. Two different certificate input contracts

`config.x509_certificate` accepts a full PEM, but `encryption[:cert]` is passed
to `Encryptor#openssl_cert` ([lib/saml_idp/encryptor.rb:32-36]), which does
`OpenSSL::X509::Certificate.new(Base64.decode64(cert))` — that requires bare DER
base64. Handing it a PEM raises:

```
OpenSSL::X509::CertificateError: PEM_read_bio_X509: no start line
```

See `E2E::SP_CERT_B64` in `e2e/idp/app.rb` for the workaround.

## 5. `git ls-files` noise in containers

`saml_idp.gemspec` shells out to `git ls-files` for `test_files` and
`executables`. In a container built without `.git` this prints
`fatal: not a git repository` twice on every run. Harmless, but it is the first
thing anyone reading CI output will ask about.

---

Previously identified in the code review and **not yet fixed** — the negative
specs that would pin them belong in the security PR:

- `Request#valid_external_signature?` returns a truthy `errors` array from its
  `rescue`, so a malformed SP cert bypasses redirect-binding signature checks.
- `xml_security.rb` resolves `//ds:DigestValue` absolutely and `//*[@ID=...]`
  unanchored — XML Signature Wrapping surface.
- `Request.from_deflated_request` inflates without a size cap (zip bomb).
- `digests_match?` uses `==` rather than a constant-time comparison.

---

# What `saml_idp_rails` reveals about the low-level API

`saml_idp_rails` is the intended consumer of this gem. Reading it is the
clearest available specification of what the low-level layer must provide.

## 6. Per-request global reconfiguration leaks state across tenants

`SamlIdpController#load_config` is a `before_action` that calls
`SamlConfig#configure_saml_idp`, which calls `::SamlIdp.configure` — on **every
request**. `SamlIdp.config` is a single module-level object
([lib/saml_idp.rb:14], `@config ||= Configurator.new`), shared by every thread:

```
SamlIdp.config object_ids across 4 threads: [3160]   -> ONE shared instance
```

With two tenants configuring concurrently, requests read the other tenant's
configuration:

```
tenant-A: 300/300 requests read ANOTHER tenant's config
tenant-B: 299/300 requests read ANOTHER tenant's config
```

Commit `bda1269` ("Thread safe configurator") narrowed this by making the
builders take explicit certificates, and `saml_idp_rails` does pass
`public_cert` / `private_key` / `pv_key_password` per call. But these reads
remain global, and each is a cross-tenant leak:

| Read | What races |
|---|---|
| `request.rb:258` `config.service_provider.finder` | which SP the request is validated against |
| `assertion_builder.rb:133` `config.attributes` | which attributes are released |
| `assertion_builder.rb:172` `config.name_id.formats` | NameID format and value |
| `assertion_builder.rb:55` `config.session_expiry` | session lifetime |
| `controller.rb:125` `config.base_saml_location` | the emitted `Issuer` |
| `signable.rb:42` `config.reference_id_generator` | assertion IDs |
| `fingerprint.rb:4` `SamlIdp.config.algorithm` | fingerprint digest |

**Requirement:** the low-level API must be instance-based — configuration passed
per operation, not assigned to a global. This is the single strongest argument
for the refactor.

## 7. Multi-SP is already solved outside the gem

`saml_idp_rails` routes on a `:uuid` path segment (`config/routes.rb`) and
resolves the SP from the request via `saml_config_finder`. The lambda it hands
to `config.service_provider.finder` **ignores its `issuer` argument entirely**
(`saml_config.rb:101`). So the gem's issuer-based lookup is dead weight for its
own primary consumer.

**Requirement:** the gem should take an already-resolved service provider as
input. Whether an application supports one SP or many is its decision.

## 8. Binding encoding belongs in the gem

`SamlIdpController#initiate_slo` encodes the LogoutRequest itself:

```ruby
SAMLRequest: binding == :get ? Base64.encode64(logout_request) : logout_request,
```

Neither branch is correct: HTTP-Redirect requires DEFLATE → base64 → URL-encode,
and HTTP-POST requires base64. `slo_request` does its own
`Zlib::Deflate.deflate(...)[2..-5]` at line 34. The gem produces raw XML and
leaves wire encoding to callers, so each caller reinvents it — and gets it wrong.

**Requirement:** binding encode/decode must be a first-class part of the gem.

## 9. The consumer's own TODO list is the refactor backlog

Every one of these points at this gem:

| Location | Wants |
|---|---|
| `saml_idp_controller.rb:30` | SLO endpoint + binding selection moved into the gem |
| `saml_idp_controller.rb:41` | IdP-initiated SLO moved into the gem |
| `saml_idp_controller.rb:51` | use the SP's digest method instead of hard-coded SHA256 |
| `saml_idp_controller.rb:74` | remove the attribute-service endpoint |
| `saml_sp_config.rb:17` | metadata post-processing (Set→Array, unspecified cert) moved into the gem |
| `saml_config.rb:118` | eliminate raw-metadata usage |
| `saml_config.rb:124` | remove `metadata_persister` |
| `saml_config.rb:145,170` | remove lambda-based getters for NameID and attributes |
| `saml_config.rb:166` | fix `nameFormat` vs `name_format` inconsistency |

Note also that `saml_idp_rails.gemspec` already requires **Ruby >= 3.4.1** and
**Rails >= 8.0.1** — so raising this gem's floor is not constrained by its
primary consumer.

## 10. `encode_response` returns different shapes for authn and logout

`Controller#encode_response` returns **Base64** for an AuthnResponse
(`SamlResponse#build` → `encoded_message`) but **raw XML** for a LogoutResponse
(`encode_logout_response` calls `LogoutResponseBuilder#signed`, not `#encoded` —
even though `#encoded` exists on `LogoutBuilder`).

Callers must therefore know which kind of response they just asked for and
encode accordingly. `saml_idp_rails` does exactly this by hand at
`SamlIdpController#slo_request`. Pinned by `spec/e2e/slo_spec.rb`.

## 11. `SamlIdp::Controller` occupies `@saml_request` in the host controller

`Controller#decode_request` assigns `@saml_request` on the including class, so a
host application cannot use that (very natural) instance variable name for its
own outgoing request. Hit while building this suite: a view rendered
`#<SamlIdp::Request:0x...>` into a hidden form field. An included module writing
to an unprefixed ivar in its host's namespace is a hazard worth removing.
