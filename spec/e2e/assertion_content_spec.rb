# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Assertion content' do
  describe 'NameID formats' do
    {
      'email_address' => ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', 'user@example.test'],
      'persistent'    => ['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',   'persistent-id-0001'],
      'transient'     => ['urn:oasis:names:tc:SAML:2.0:nameid-format:transient',    'transient-id-0001']
    }.each do |knob, (format, value)|
      it "emits a #{knob} NameID" do
        result = flow.sso(knobs: { 'x_name_id_format' => knob }).json

        expect(result['errors']).to be_empty
        expect(result['name_id_format']).to eq(format)
        expect(result['name_id']).to eq(value)
      end
    end
  end

  describe 'AttributeStatement' do
    it 'releases every configured attribute with its configured Name' do
      result = flow.sso.json

      expect(result['attributes']).to eq(
        'email-address' => ['user@example.test'],
        'given-name'    => ['Ada'],
        'groups'        => %w[admins engineers]
      )
    end

    it 'declares the URI attribute name format and the friendly name' do
      page = idp_response_page
      doc = Nokogiri::XML(Base64.decode64(page.doc.at_css('input[name=SAMLResponse]')['value']))
      attr = doc.at_xpath("//*[local-name()='Attribute'][@FriendlyName='GivenName']")

      expect(attr['NameFormat']).to eq('urn:oasis:names:tc:SAML:2.0:attrname-format:uri')
      expect(attr['Name']).to eq('given-name')
    end
  end

  describe 'Conditions' do
    it 'sets NotBefore in the past and NotOnOrAfter according to the expiry' do
      result = flow.sso(knobs: { 'x_expiry' => '900' }).json

      not_before = Time.parse(result['not_before'])
      not_on_or_after = Time.parse(result['not_on_or_after'])

      expect(not_before).to be < Time.now.utc
      expect(not_on_or_after - not_before).to be_within(30).of(960) # 900 + 60s clock skew
    end

    it 'is rejected by the SP once NotOnOrAfter has passed' do
      result = flow.sso(knobs: { 'x_expiry' => '-3600' }).json

      expect(result['ok']).to be false
      expect(result['errors'].join(' ')).to match(/not_on_or_after|expired|Current time/i)
    end

    it 'restricts the audience to the requesting SP' do
      result = flow.sso.json

      expect(result['audiences']).to eq([E2E::SP_ENTITY_ID])
    end
  end

  describe 'AuthnStatement' do
    it 'defaults to the Password authentication context' do
      result = flow.sso.json

      expect(result['authn_context']).to eq('urn:oasis:names:tc:SAML:2.0:ac:classes:Password')
    end

    it 'honours an explicit AuthnContextClassRef' do
      ref = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
      result = flow.sso(knobs: { 'x_authn_context' => ref }).json

      expect(result['authn_context']).to eq(ref)
    end

    it 'omits SessionNotOnOrAfter when no session expiry is configured' do
      result = flow.sso.json

      expect(result['session_expires_at']).to be_nil
    end

    it 'emits SessionNotOnOrAfter when a session expiry is configured' do
      result = flow.sso(knobs: { 'x_session_expiry' => '1800' }).json

      expect(result['errors']).to be_empty
      expect(result['session_expires_at']).not_to be_nil
      expect(Time.parse(result['session_expires_at'])).to be > Time.now.utc
    end

    it 'carries a SessionIndex' do
      result = flow.sso.json

      expect(result['session_index']).to match(/\A_/)
    end
  end

  describe 'SubjectConfirmationData' do
    it 'binds the assertion to the ACS URL and the original request' do
      page = flow.start_login(binding: :redirect)
      page = flow.follow(page)
      page = flow.submit_form(page)
      doc = Nokogiri::XML(Base64.decode64(page.doc.at_css('input[name=SAMLResponse]')['value']))
      scd = doc.at_xpath("//*[local-name()='SubjectConfirmationData']")

      expect(scd['Recipient']).to eq(E2E::SP_ACS_URL)
      expect(scd['InResponseTo']).to match(/\A_/)
      expect(Time.parse(scd['NotOnOrAfter'])).to be > Time.now.utc
    end

    it 'uses the bearer confirmation method' do
      page = idp_response_page
      doc = Nokogiri::XML(Base64.decode64(page.doc.at_css('input[name=SAMLResponse]')['value']))
      sc = doc.at_xpath("//*[local-name()='SubjectConfirmation']")

      expect(sc['Method']).to eq('urn:oasis:names:tc:SAML:2.0:cm:bearer')
    end
  end
end
