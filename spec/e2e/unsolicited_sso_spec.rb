# frozen_string_literal: true

require 'spec_helper'

# IdP-initiated SSO: the IdP issues an assertion with no AuthnRequest to answer.
RSpec.describe 'IdP-initiated (unsolicited) SSO' do
  subject(:result) { flow.follow(flow.get("#{E2E::IDP_BASE}/saml/unsolicited")).json }

  it 'is accepted by the SP' do
    expect(result['errors']).to be_empty
    expect(result['ok']).to be true
    expect(result['name_id']).to eq('user@example.test')
  end

  it 'omits InResponseTo, because there was no request' do
    expect(result['in_response_to']).to be_nil
  end

  it 'still restricts the audience to the SP' do
    expect(result['audiences']).to eq([E2E::SP_ENTITY_ID])
  end

  it 'still signs the assertion' do
    expect(result['assertion_signed']).to be true
  end
end
