# The Identity Provider under test. Every SAML-affecting option is driven by an
# `x_*` request parameter so one controller covers each supported combination.
class SamlIdpController < ApplicationController
  include SamlIdp::Controller

  before_action :add_view_path
  around_action :with_policy_headers
  before_action :require_valid_saml_request, only: %i[new create logout]

  # Carried through the login form so a scenario's options survive the
  # credential round trip.
  KNOBS = %w[
    x_algorithm x_signed_assertion x_signed_message x_encrypt x_compress
    x_name_id_format x_expiry x_session_expiry x_audience x_authn_context
    x_encrypted_key
  ].freeze

  def new
    render template: 'saml_idp/idp/new'
  end

  def create
    if params[:email].blank? && params[:password].blank?
      return render template: 'saml_idp/idp/new'
    end

    person = idp_authenticate(params[:email], params[:password])
    if person.nil?
      @saml_idp_fail_msg = 'Incorrect email or password.'
      return render template: 'saml_idp/idp/new'
    end

    @saml_response = encode_response(person, response_options)
    @destination = saml_acs_url
    render template: 'saml_idp/idp/saml_post', layout: false
  end

  def show
    render xml: SamlIdp.metadata.signed
  end

  # SP-initiated Single Logout: answer the LogoutRequest.
  #
  # NOTE the asymmetry: encode_response returns Base64 for an AuthnResponse
  # (SamlResponse#build) but RAW XML for a LogoutResponse
  # (Controller#encode_logout_response calls LogoutResponseBuilder#signed, not
  # #encoded). Callers must encode it themselves -- saml_idp_rails does the same
  # thing at SamlIdpController#slo_request. Pinned by spec/e2e/slo_spec.rb.
  def logout
    @saml_response = Base64.strict_encode64(encode_response(current_principal, response_options))
    @destination = saml_logout_url
    render template: 'saml_idp/idp/saml_post', layout: false
  end

  # IdP-initiated SSO: no AuthnRequest, so audience and ACS URL must be supplied.
  def unsolicited
    @saml_response = encode_authn_response(
      current_principal,
      response_options.merge(acs_url: E2E::SP_ACS_URL, audience_uri: E2E::SP_ENTITY_ID)
    )
    @destination = E2E::SP_ACS_URL
    render template: 'saml_idp/idp/saml_post', layout: false
  end

  # IdP-initiated Single Logout. The gem exposes no wrapper, so the builder is
  # driven directly -- exactly as saml_idp_rails does.
  def initiate_slo
    logout_request = SamlIdp::LogoutRequestBuilder.new(
      response_id: SecureRandom.uuid,
      issuer_uri: SamlIdp.config.base_saml_location,
      saml_slo_url: E2E::SP_SLS_URL,
      name_id: params.fetch(:name_id, 'user@example.test'),
      algorithm: OpenSSL::Digest::SHA256,
      public_cert: E2E::IDP_CERT,
      private_key: E2E::IDP_KEY
    ).signed

    # NOT @saml_request: SamlIdp::Controller already owns that ivar in the
    # including controller (Controller#decode_request assigns it).
    @outgoing_saml_request = Base64.strict_encode64(logout_request)
    @destination = E2E::SP_SLS_URL
    render template: 'saml_idp/idp/saml_post', layout: false
  end

  private

  def require_valid_saml_request
    decode_request(params[:SAMLRequest], params[:Signature], params[:SigAlg], params[:RelayState])
    return if valid_saml_request?

    render json: { ok: false, errors: saml_request.errors }, status: :forbidden
  end

  # Lets a scenario switch IdP-side policy for the duration of one request.
  def with_policy_headers
    overrides = {}
    if (signed = request.headers['X-E2E-Require-Signed-Request'])
      overrides[:require_signed_request] = signed != 'false'
    end
    if (profile = request.headers['X-E2E-SP-Profile'])
      overrides[:sp_profile] = profile
    end

    E2E.with_policy(overrides) { yield }
  end

  def idp_authenticate(_email, _password)
    current_principal
  end

  def current_principal
    @current_principal ||= E2E::Principal.new(
      email: params[:email].presence || 'user@example.test',
      given_name: 'Ada',
      groups: %w[admins engineers],
      persistent_id: 'persistent-id-0001',
      transient_id: 'transient-id-0001'
    )
  end

  # A knob counts as set only when it carries a value: the login form
  # round-trips every knob as a hidden field, so unset ones arrive as "".
  def response_options
    opts = {}
    opts[:algorithm] = params[:x_algorithm].to_sym if params[:x_algorithm].present?
    opts[:signed_assertion] = flag(:x_signed_assertion) if params[:x_signed_assertion].present?
    opts[:signed_message] = flag(:x_signed_message) if params[:x_signed_message].present?
    opts[:compress] = flag(:x_compress) if params[:x_compress].present?
    opts[:expiry] = params[:x_expiry].to_i if params[:x_expiry].present?
    opts[:session_expiry] = params[:x_session_expiry].to_i if params[:x_session_expiry].present?
    opts[:audience_uri] = params[:x_audience] if params[:x_audience].present?
    opts[:authn_context_classref] = params[:x_authn_context] if params[:x_authn_context].present?
    opts[:name_id_formats] = name_id_formats_for(params[:x_name_id_format]) if params[:x_name_id_format].present?

    if params[:x_encrypt].present? && flag(:x_encrypt)
      opts[:encryption] = {
        cert: E2E::SP_CERT_B64,
        block_encryption: 'aes256-cbc',
        key_transport: 'rsa-oaep-mgf1p'
      }
    end

    if params[:x_encrypted_key].present? && flag(:x_encrypted_key)
      opts[:private_key] = E2E::IDP_KEY_ENC
      opts[:pv_key_password] = E2E::IDP_KEY_PASS
    end

    opts
  end

  def name_id_formats_for(key)
    case key.to_sym
    when :email_address then { '1.1' => { email_address: ->(p) { p.email } } }
    when :persistent    then { '2.0' => { persistent: ->(p) { p.persistent_id } } }
    when :transient     then { '2.0' => { transient: ->(p) { p.transient_id } } }
    else raise ArgumentError, "unknown name id format #{key}"
    end
  end

  def flag(name)
    %w[1 true yes].include?(params[name].to_s.downcase)
  end

  def knob_fields
    KNOBS.map { |k| view_context.hidden_field_tag(k, params[k]) }.join.html_safe
  end
  helper_method :knob_fields

  def add_view_path
    prepend_view_path(File.expand_path('../../app/views', __dir__))
  end
end
