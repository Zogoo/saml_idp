# frozen_string_literal: true

require 'spec_helper'

# These are the tests that give the suite its teeth. Every one of them must FAIL
# to authenticate. If a refactor ever makes one of these pass, a security
# control has been lost.
RSpec.describe 'Rejection paths' do
  describe 'the SP refuses a tampered assertion' do
    it 'rejects a modified DigestValue' do
      page = idp_response_page
      result = tamper_and_post(page) do |xml|
        xml.sub(%r{<ds:DigestValue>[^<]+</ds:DigestValue>},
                '<ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>')
      end

      expect(result.json['ok']).to be false
      expect(result.status).to eq(401)
    end

    it 'rejects a modified SignatureValue' do
      page = idp_response_page
      result = tamper_and_post(page) do |xml|
        xml.sub(%r{<ds:SignatureValue>[^<]+</ds:SignatureValue>},
                '<ds:SignatureValue>bm90LWEtc2lnbmF0dXJl</ds:SignatureValue>')
      end

      expect(result.json['ok']).to be false
    end

    it 'rejects a subject swapped after signing' do
      page = idp_response_page
      result = tamper_and_post(page) { |xml| xml.sub('user@example.test', 'attacker@evil.test') }

      expect(result.json['ok']).to be false
      expect(result.json).not_to have_key('name_id')
    end

    it 'rejects an assertion with the signature stripped out' do
      page = idp_response_page
      result = tamper_and_post(page) { |xml| xml.gsub(%r{<ds:Signature[^>]*>.*?</ds:Signature>}m, '') }

      expect(result.json['ok']).to be false
    end

    it 'rejects a response redirected to a different Destination' do
      page = idp_response_page
      result = tamper_and_post(page) { |xml| xml.sub(%(Destination="#{E2E::SP_ACS_URL}"), 'Destination="https://evil.test/acs"') }

      expect(result.json['ok']).to be false
    end

    it 'rejects an assertion issued for a different audience' do
      result = flow.sso(knobs: { 'x_audience' => 'https://someone-else.example.test/metadata' }).json

      expect(result['ok']).to be false
      expect(result['errors'].join(' ')).to match(/audience/i)
    end

    it 'rejects an assertion whose validity window has closed' do
      result = flow.sso(knobs: { 'x_expiry' => '-3600' }).json

      expect(result['ok']).to be false
    end

    it 'rejects a response that does not answer the request the SP sent' do
      page = idp_response_page
      saml_response = page.doc.at_css('input[name=SAMLResponse]')['value']
      result = flow.post_to_acs(saml_response, 'expected_request_id' => '_some-other-request-id')

      expect(result.json['ok']).to be false
      expect(result.json['errors'].join(' ')).to match(/InResponseTo/i)
    end

    it 'never leaks assertion content alongside a rejection' do
      page = idp_response_page
      result = tamper_and_post(page) { |xml| xml.sub('user@example.test', 'attacker@evil.test') }

      expect(result.body).not_to include('attacker@evil.test')
    end
  end

  describe 'the IdP refuses a bad AuthnRequest' do
    it 'rejects an unsigned AuthnRequest when the SP profile requires signing' do
      page = flow.sso_up_to_idp(binding: :post, sp: { 'signed_request' => 'false' })

      expect(page.status).to eq(403)
      expect(page.json['errors']).to include('invalid_embedded_signature')
    end

    it 'rejects a redirect-binding request whose query signature was tampered with' do
      page = flow.start_login(binding: :redirect)
      tampered = tamper_query(page.location, 'Signature') { |v| mangle_base64(v) }
      result = flow.get(tampered)

      expect(result.status).to eq(403)
      expect(result.json['errors']).to include('invalid_external_signature')
    end

    it 'rejects a redirect-binding request whose payload was swapped under the signature' do
      good = flow.start_login(binding: :redirect).location
      other = flow.start_login(binding: :redirect).location
      swapped_request = URI.decode_www_form(URI(other).query).to_h.fetch('SAMLRequest')
      tampered = tamper_query(good, 'SAMLRequest') { swapped_request }
      result = flow.get(tampered)

      expect(result.status).to eq(403)
      expect(result.json['errors']).to include('invalid_external_signature')
    end

    it 'rejects a SAMLRequest that is not valid SAML at all' do
      result = flow.get("#{E2E::IDP_BASE}/saml/auth?SAMLRequest=#{CGI.escape(Base64.strict_encode64('<nonsense/>'))}")

      expect(result.status).to eq(403)
      expect(result.json['errors']).not_to be_empty
    end

    it 'rejects a missing SAMLRequest' do
      result = flow.get("#{E2E::IDP_BASE}/saml/auth")

      expect(result.status).to eq(403)
      expect(result.json['errors']).not_to be_empty
    end
  end

  def tamper_query(location, key)
    uri = URI(location.to_s)
    params = URI.decode_www_form(uri.query).to_h
    params[key] = yield(params.fetch(key))
    uri.query = URI.encode_www_form(params)
    uri.to_s
  end

  # Flips a character while keeping the value valid base64.
  def mangle_base64(value)
    decoded = Base64.decode64(value)
    flipped = decoded.dup
    flipped[0] = (flipped[0].ord ^ 0xFF).chr
    Base64.strict_encode64(flipped)
  end
end
