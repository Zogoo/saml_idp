# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Single Logout Profile' do
  describe 'SP-initiated logout over HTTP-Redirect' do
    it 'returns a LogoutResponse the SP cryptographically accepts' do
      result = flow.slo(binding: :redirect).json

      expect(result['errors']).to be_empty
      expect(result['ok']).to be true
      expect(result['status_code']).to eq('urn:oasis:names:tc:SAML:2.0:status:Success')
      expect(result['issuer']).to eq("#{E2E::IDP_BASE}/saml")
    end

    it 'correlates the LogoutResponse with the LogoutRequest' do
      page = flow.get("#{E2E::SP_BASE}/saml/sp/logout?binding=redirect")
      request_id = request_id_from_redirect(page)

      result = flow.follow(page).json

      expect(result['in_response_to']).to eq(request_id)
    end

    it 'preserves RelayState' do
      result = flow.slo(binding: :redirect, sp: { 'RelayState' => 'https://sp.example.test/after-logout' }).json

      expect(result['relay_state']).to eq('https://sp.example.test/after-logout')
    end
  end

  describe 'SP-initiated logout over HTTP-POST' do
    it 'returns a LogoutResponse the SP cryptographically accepts' do
      result = flow.slo(binding: :post, sp: { 'embed_sign' => 'true' }).json

      expect(result['errors']).to be_empty
      expect(result['ok']).to be true
      expect(result['status_code']).to eq('urn:oasis:names:tc:SAML:2.0:status:Success')
    end
  end

  describe 'IdP-initiated logout' do
    # Driven through SamlIdp::LogoutRequestBuilder, which the gem never calls
    # itself -- saml_idp_rails instantiates it directly, so it is public API.
    subject(:result) do
      flow.follow(flow.get("#{E2E::IDP_BASE}/saml/initiate_slo?name_id=user@example.test")).json
    end

    it 'produces a LogoutRequest the SP cryptographically accepts' do
      expect(result['errors']).to be_empty
      expect(result['ok']).to be true
    end

    it 'identifies the subject being logged out' do
      expect(result['name_id']).to eq('user@example.test')
    end

    it 'is issued by the IdP entity' do
      expect(result['issuer']).to eq("#{E2E::IDP_BASE}/saml")
    end

    it 'carries a request ID' do
      expect(result['request_id']).to match(/\A_/)
    end
  end

  describe 'the shape of what encode_response returns' do
    # Pins CURRENT behaviour. encode_response returns Base64 for an
    # AuthnResponse (SamlResponse#build) but RAW XML for a LogoutResponse
    # (Controller#encode_logout_response calls LogoutResponseBuilder#signed
    # rather than #encoded), so every caller has to encode it themselves.
    # saml_idp_rails does exactly that. See docs/FINDINGS.md #10.
    it 'is Base64 for an AuthnResponse' do
      value = idp_response_page.doc.at_css('input[name=SAMLResponse]')['value']

      expect(value).to match(/\A[A-Za-z0-9+\/=]+\z/)
      expect(Base64.decode64(value)).to include('<samlp:Response')
    end

    it 'is raw XML for a LogoutResponse, and the caller must encode it' do
      builder = SamlIdp::LogoutResponseBuilder.new(
        response_id: 'abc', issuer_uri: E2E::IDP_ENTITY_ID,
        saml_slo_url: E2E::SP_SLS_URL, saml_request_id: 'req-1',
        algorithm: OpenSSL::Digest::SHA256,
        public_cert: E2E::IDP_CERT, private_key: E2E::IDP_KEY
      )

      expect(builder.signed).to start_with('<LogoutResponse')
      expect(builder.encoded).to match(/\A[A-Za-z0-9+\/=]+\z/)
    end
  end
end
