# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Response construction modes' do
  it 'signs the assertion by default and leaves the response message unsigned' do
    result = flow.sso.json

    expect(result['ok']).to be true
    expect(result['assertion_signed']).to be true
    expect(result['response_signed']).to be false
  end

  it 'signs the response message when asked, in addition to the assertion' do
    result = flow.sso(knobs: { 'x_signed_message' => 'true' }).json

    expect(result['errors']).to be_empty
    expect(result['response_signed']).to be true
    expect(result['assertion_signed']).to be true
  end

  it 'can sign only the response message, leaving the assertion unsigned' do
    result = flow.sso(
      knobs: { 'x_signed_message' => 'true', 'x_signed_assertion' => 'false' },
      sp: { 'want_assertions_signed' => 'false' }
    ).json

    expect(result['errors']).to be_empty
    expect(result['response_signed']).to be true
    expect(result['assertion_signed']).to be false
  end

  it 'encrypts the assertion when encryption options are supplied' do
    result = flow.sso(knobs: { 'x_encrypt' => 'true' }).json

    expect(result['errors']).to be_empty
    expect(result['assertion_encrypted']).to be true
    expect(result['name_id']).to eq('user@example.test')
  end

  it 'keeps the subject out of the cleartext response when encrypting' do
    page = idp_response_page(knobs: { 'x_encrypt' => 'true' })
    xml = Base64.decode64(page.doc.at_css('input[name=SAMLResponse]')['value'])

    expect(xml).to include('EncryptedAssertion')
    expect(xml).not_to include('user@example.test')
  end

  it 'signs the assertion before encrypting it' do
    result = flow.sso(knobs: { 'x_encrypt' => 'true' }).json

    expect(result['assertion_signed']).to be true
  end

  it 'accepts a deflate-compressed response' do
    result = flow.sso(knobs: { 'x_compress' => 'true' }).json

    expect(result['errors']).to be_empty
    expect(result['name_id']).to eq('user@example.test')
  end

  it 'signs with a passphrase-protected private key' do
    result = flow.sso(knobs: { 'x_encrypted_key' => 'true' }).json

    expect(result['errors']).to be_empty
    expect(result['assertion_signed']).to be true
  end
end
