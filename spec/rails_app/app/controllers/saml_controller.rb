# A deliberately STRICT SAML 2.0 Service Provider, built on ruby-saml.
#
# This is the adversary of the IdP: it verifies signatures, digests, conditions,
# audience, destination and InResponseTo, and reports what it saw as JSON. It
# must never render assertion content it has not cryptographically validated --
# otherwise the end-to-end suite cannot fail on a broken signature.
class SamlController < ApplicationController
  DSIG_NS      = 'http://www.w3.org/2000/09/xmldsig#'
  ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion'

  # Options the SP needs at ACS/SLS time ride along in RelayState: the auto-POST
  # arrives from the IdP carrying none of the SP's original query parameters.
  ACS_OPTS = %w[want_assertions_signed signed_request embed_sign].freeze

  # --- SP-initiated SSO -----------------------------------------------------

  def login
    settings = E2E.sp_settings(request.query_parameters)
    knobs = SamlIdpController::KNOBS.each_with_object({}) do |k, h|
      h[k] = params[k] if params[k].present?
    end

    if params[:binding] == 'post'
      settings.idp_sso_service_binding = :post
      fields = OneLogin::RubySaml::Authrequest.new
                                              .create_params(settings, 'RelayState' => relay_state)
      auto_post("#{E2E::IDP_BASE}/saml/auth", fields.merge(knobs))
    else
      settings.idp_sso_service_binding = :redirect
      url = OneLogin::RubySaml::Authrequest.new.create(settings, 'RelayState' => relay_state)
      url += "&#{knobs.to_query}" if knobs.any?
      redirect_to url, allow_other_host: true
    end
  end

  # --- Assertion Consumer Service -------------------------------------------

  def consume
    return render_json(400, ok: false, errors: ['missing SAMLResponse']) if params[:SAMLResponse].blank?

    settings = E2E.sp_settings(carried_options)
    opts = {}
    opts[:matches_request_id] = params[:expected_request_id] if params[:expected_request_id].present?

    response = OneLogin::RubySaml::Response.new(params[:SAMLResponse], settings: settings, **opts)
    response.soft = true
    valid = response.is_valid?

    payload = { ok: valid, errors: response.errors, relay_state: params[:RelayState] }
    payload.merge!(assertion_details(response)) if valid

    render_json(valid ? 200 : 401, payload)
  end

  # --- SP-initiated SLO -----------------------------------------------------

  def sp_logout
    settings = E2E.sp_settings(request.query_parameters)
    settings.name_identifier_value = params[:name_id].presence || 'user@example.test'
    settings.sessionindex = params[:session_index] if params[:session_index].present?

    if params[:binding] == 'post'
      settings.idp_slo_service_binding = :post
      fields = OneLogin::RubySaml::Logoutrequest.new
                                                .create_params(settings, 'RelayState' => relay_state)
      auto_post("#{E2E::IDP_BASE}/saml/logout", fields)
    else
      settings.idp_slo_service_binding = :redirect
      redirect_to OneLogin::RubySaml::Logoutrequest.new.create(settings, 'RelayState' => relay_state),
                  allow_other_host: true
    end
  end

  # --- Single Logout Service ------------------------------------------------

  def sls
    return sls_request if params[:SAMLRequest].present?
    return render_json(400, ok: false, errors: ['missing SAMLResponse']) if params[:SAMLResponse].blank?

    logout_response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], E2E.sp_settings(carried_options))
    logout_response.soft = true
    valid = logout_response.validate

    render_json(valid ? 200 : 401,
                ok: valid,
                errors: logout_response.errors,
                issuer: logout_response.issuer,
                in_response_to: logout_response.in_response_to,
                status_code: logout_response.status_code,
                relay_state: params[:RelayState])
  end

  def metadata
    render xml: OneLogin::RubySaml::Metadata.new.generate(E2E.sp_settings, true)
  end

  private

  # IdP-initiated logout: the SP receives a LogoutRequest and must verify it.
  def sls_request
    logout_request = OneLogin::RubySaml::SloLogoutrequest.new(
      params[:SAMLRequest], settings: E2E.sp_settings(carried_options)
    )
    logout_request.soft = true
    valid = logout_request.is_valid?

    render_json(valid ? 200 : 401,
                ok: valid,
                errors: logout_request.errors,
                request_id: logout_request.id,
                issuer: logout_request.issuer,
                name_id: valid ? logout_request.name_id : nil,
                relay_state: params[:RelayState])
  end

  def assertion_details(response)
    {
      name_id: response.name_id,
      name_id_format: response.name_id_format,
      attributes: response.attributes.to_h.transform_values { |v| Array(v) },
      issuer: response.issuers.first,
      destination: response.destination,
      in_response_to: response.in_response_to,
      audiences: response.audiences,
      not_before: response.not_before&.utc&.iso8601,
      not_on_or_after: response.not_on_or_after&.utc&.iso8601,
      session_expires_at: response.session_expires_at&.utc&.iso8601,
      session_index: response.sessionindex,
      assertion_encrypted: response.assertion_encrypted?,
      response_signed: signed_element_names(response).include?('Response'),
      assertion_signed: signed_element_names(response).include?('Assertion'),
      authn_context: authn_context(response)
    }
  end

  # ruby-saml exposes REXML documents, not Nokogiri ones.
  def signed_element_names(response)
    document = response.decrypted_document || response.document
    REXML::XPath.match(document, '//ds:Signature', 'ds' => DSIG_NS).map { |node| node.parent.name }
  end

  def authn_context(response)
    document = response.decrypted_document || response.document
    REXML::XPath.first(document, '//saml:AuthnContextClassRef', 'saml' => ASSERTION_NS)&.text
  end

  def relay_state
    base = params[:RelayState].presence || "#{E2E::SP_BASE}/done"
    carried = ACS_OPTS.each_with_object({}) { |k, h| h[k] = params[k] if params[k].present? }
    return base if carried.empty?

    uri = URI(base)
    existing = uri.query ? Rack::Utils.parse_nested_query(uri.query) : {}
    uri.query = existing.merge(carried).to_query
    uri.to_s
  end

  def carried_options
    raw = params[:RelayState].to_s
    return {} if raw.empty?

    query = URI(raw).query
    query ? Rack::Utils.parse_nested_query(query) : {}
  rescue URI::InvalidURIError
    {}
  end

  def auto_post(action, fields)
    @destination = action
    @fields = fields
    render template: 'saml_idp/idp/auto_post', layout: false
  end

  def render_json(status, payload)
    render json: payload, status: status
  end
end
