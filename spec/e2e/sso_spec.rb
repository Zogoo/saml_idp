# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Web Browser SSO Profile' do
  describe 'HTTP-Redirect binding (signed AuthnRequest in the query string)' do
    it 'completes SSO and the SP cryptographically accepts the assertion' do
      result = flow.sso(binding: :redirect).json

      expect(result['errors']).to be_empty
      expect(result['ok']).to be true
      expect(result['name_id']).to eq('user@example.test')
      expect(result['issuer']).to eq("#{E2E::IDP_BASE}/saml")
      expect(result['destination']).to eq(E2E::SP_ACS_URL)
      expect(result['assertion_signed']).to be true
    end

    it 'preserves RelayState across the round trip' do
      result = flow.sso(binding: :redirect, sp: { 'RelayState' => 'https://sp.example.test/deep/link' }).json

      expect(result['relay_state']).to eq('https://sp.example.test/deep/link')
    end
  end

  describe 'HTTP-POST binding (AuthnRequest with an enveloped signature)' do
    it 'completes SSO and the SP cryptographically accepts the assertion' do
      result = flow.sso(binding: :post, sp: { 'embed_sign' => 'true' }).json

      expect(result['errors']).to be_empty
      expect(result['ok']).to be true
      expect(result['name_id']).to eq('user@example.test')
      expect(result['assertion_signed']).to be true
    end
  end

  describe 'request/response correlation' do
    it 'echoes the AuthnRequest ID in InResponseTo' do
      page = flow.start_login(binding: :redirect)
      request_id = request_id_from_redirect(page)

      result = flow.follow(page)
      result = flow.submit_form(result)
      result = flow.submit_form(result).json

      expect(result['in_response_to']).to eq(request_id)
    end

    it 'restricts the audience to the SP entity ID' do
      result = flow.sso.json

      expect(result['audiences']).to eq([E2E::SP_ENTITY_ID])
    end
  end

  describe 'user identity' do
    it 'carries the authenticated subject through to the SP' do
      result = flow.sso(email: 'someone.else@example.test').json

      expect(result['name_id']).to eq('someone.else@example.test')
    end
  end

end
