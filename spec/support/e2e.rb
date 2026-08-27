# frozen_string_literal: true

require 'rack/test'
require 'nokogiri'
require 'json'

# Shared fixtures, configuration and flow driver for the end-to-end suite.
#
# The whole flow runs against spec/rails_app: SamlIdpController is the IdP,
# SamlController is a strict ruby-saml Service Provider. They are addressed on
# different hosts so Destination and ACS-URL validation stay meaningful.
module E2E
  Principal = Struct.new(:email, :given_name, :groups, :persistent_id, :transient_id,
                         keyword_init: true)

  CERT_DIR = File.expand_path('certificates', __dir__)

  IDP_CERT     = File.read(File.join(CERT_DIR, 'e2e_idp.crt'))
  IDP_KEY      = File.read(File.join(CERT_DIR, 'e2e_idp.key'))
  IDP_KEY_ENC  = File.read(File.join(CERT_DIR, 'e2e_idp_encrypted.key'))
  IDP_KEY_PASS = 'e2e-passphrase'
  SP_CERT      = File.read(File.join(CERT_DIR, 'e2e_sp.crt'))
  SP_KEY       = File.read(File.join(CERT_DIR, 'e2e_sp.key'))

  # SamlIdp::Encryptor Base64.decode64s a String cert, so it needs bare DER
  # base64 -- unlike config.x509_certificate, which takes a full PEM.
  SP_CERT_B64 = SP_CERT.gsub(/-----(BEGIN|END) CERTIFICATE-----/, '').gsub(/\s+/, '')

  IDP_HOST = 'idp.example.test'
  SP_HOST  = 'sp.example.test'
  IDP_BASE = "http://#{IDP_HOST}"
  SP_BASE  = "http://#{SP_HOST}"

  IDP_ENTITY_ID = "#{IDP_BASE}/saml"
  SP_ENTITY_ID  = "#{SP_BASE}/saml/metadata"
  SP_ACS_URL    = "#{SP_BASE}/saml/consume"
  SP_SLS_URL    = "#{SP_BASE}/saml/sls"

  # Per-request policy switches, so paths that depend on IdP configuration are
  # reachable without restarting anything.
  def self.policy
    Thread.current[:e2e_policy] ||= {}
  end

  def self.with_policy(overrides)
    previous = policy
    Thread.current[:e2e_policy] = previous.merge(overrides)
    yield
  ensure
    Thread.current[:e2e_policy] = previous
  end

  def self.configure_idp!
    SamlIdp.configure do |config|
      # Must be explicit: Configurator captures Rails.logger by value and would
      # otherwise leave a nil logger, turning every rejection into a 500.
      config.logger = Logger.new(File::NULL)

      config.x509_certificate = IDP_CERT
      config.secret_key       = IDP_KEY
      config.password         = nil
      config.algorithm        = :sha256

      config.organization_name = 'saml_idp e2e'
      config.organization_url  = IDP_BASE
      # SAML 2.0 requires the emitted Issuer to equal the published entityID.
      # The gem sources them from different settings, so keep them aligned.
      config.base_saml_location = IDP_ENTITY_ID
      config.entity_id          = IDP_ENTITY_ID

      config.single_service_post_location     = "#{IDP_BASE}/saml/auth"
      config.single_service_redirect_location = "#{IDP_BASE}/saml/auth"
      config.single_logout_service_post_location     = "#{IDP_BASE}/saml/logout"
      config.single_logout_service_redirect_location = "#{IDP_BASE}/saml/logout"
      config.attribute_service_location = "#{IDP_BASE}/saml/attributes"

      config.name_id.formats = {
        '1.1' => { email_address: ->(p) { p.email } },
        '2.0' => {
          persistent: ->(p) { p.persistent_id },
          transient:  ->(p) { p.transient_id }
        }
      }

      config.attributes = {
        emailAddress: { name: 'email-address', getter: ->(p) { p.email } },
        GivenName:    { name: 'given-name',    getter: ->(p) { p.given_name } },
        Groups:       { name: 'groups',        getter: ->(p) { p.groups } }
      }

      config.technical_contact.company       = 'saml_idp e2e'
      config.technical_contact.given_name    = 'Test'
      config.technical_contact.sur_name      = 'Contact'
      config.technical_contact.email_address = 'e2e@example.test'

      config.service_provider.finder = ->(_issuer) { service_provider_attributes }
    end
  end

  def self.service_provider_attributes
    base = {
      acs_url: SP_ACS_URL,
      assertion_consumer_logout_service_url: SP_SLS_URL,
      cert: SP_CERT,
      fingerprint: SamlIdp::Fingerprint.certificate_digest(SP_CERT, :sha256),
      response_hosts: [SP_HOST],
      sign_authn_request: policy.fetch(:require_signed_request, true)
    }

    case policy[:sp_profile]
    when 'unknown'      then nil
    when 'no-cert'      then base.merge(cert: nil, fingerprint: nil)
    when 'bad-cert'     then base.merge(cert: 'not-a-certificate')
    when 'no-acs'       then base.merge(acs_url: nil, assertion_consumer_logout_service_url: nil)
    when 'foreign-host' then base.merge(response_hosts: ['somewhere-else.example.test'])
    else base
    end
  end

  # ruby-saml settings for the Service Provider side.
  def self.sp_settings(overrides = {})
    s = OneLogin::RubySaml::Settings.new
    s.sp_entity_id = SP_ENTITY_ID
    s.issuer       = SP_ENTITY_ID
    s.assertion_consumer_service_url = SP_ACS_URL
    s.single_logout_service_url      = SP_SLS_URL
    s.assertion_consumer_logout_service_url = SP_SLS_URL

    s.idp_entity_id       = IDP_ENTITY_ID
    s.idp_sso_service_url = "#{IDP_BASE}/saml/auth"
    s.idp_slo_service_url = "#{IDP_BASE}/saml/logout"
    s.idp_cert = IDP_CERT

    s.certificate = SP_CERT
    s.private_key = SP_KEY

    signed = overrides.fetch('signed_request', 'true') != 'false'
    s.security[:authn_requests_signed]   = signed
    s.security[:logout_requests_signed]  = signed
    s.security[:logout_responses_signed] = signed
    s.security[:embed_sign]              = overrides['embed_sign'] == 'true'
    s.security[:want_assertions_signed]  = overrides.fetch('want_assertions_signed', 'true') != 'false'
    s.security[:digest_method]    = XMLSecurity::Document::SHA256
    s.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
    s.security[:strict_audience_validation] = true
    # Long-lived self-signed test certs; expiry checks would only add a
    # calendar-dependent failure.
    s.security[:check_idp_cert_expiration] = false
    s.security[:check_sp_cert_expiration]  = false
    s
  end
end
