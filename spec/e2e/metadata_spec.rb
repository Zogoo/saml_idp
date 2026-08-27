# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'IdP metadata' do
  let(:doc) { Nokogiri::XML(idp_metadata_xml) }
  let(:md) { { 'md' => 'urn:oasis:names:tc:SAML:2.0:metadata' } }

  it 'is served as XML' do
    page = flow.get("#{E2E::IDP_BASE}/saml/metadata")

    expect(page.status).to eq(200)
    expect(page.headers['content-type']).to include('xml')
  end

  it 'is a well-formed EntityDescriptor' do
    expect(doc.errors).to be_empty
    expect(doc.root.name).to eq('EntityDescriptor')
  end

  it 'publishes an entityID equal to the Issuer the IdP actually emits' do
    issuer = flow.sso.json.fetch('issuer')

    expect(doc.root['entityID']).to eq(issuer)
  end

  it 'carries a signature that verifies against the published certificate' do
    expect(doc.at_xpath("//*[local-name()='Signature']")).not_to be_nil
    expect(Saml::XML::Document.parse(idp_metadata_xml).valid_signature?('', idp_fingerprint)).to be_truthy
  end

  it 'advertises the SSO endpoints for both supported bindings' do
    locations = doc.xpath('//md:IDPSSODescriptor/md:SingleSignOnService', md).map do |node|
      [node['Binding'], node['Location']]
    end

    expect(locations).to include(
      ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', "#{E2E::IDP_BASE}/saml/auth"],
      ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', "#{E2E::IDP_BASE}/saml/auth"]
    )
  end

  it 'advertises the SLO endpoints for both supported bindings' do
    locations = doc.xpath('//md:IDPSSODescriptor/md:SingleLogoutService', md).map do |node|
      [node['Binding'], node['Location']]
    end

    expect(locations).to include(
      ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', "#{E2E::IDP_BASE}/saml/logout"],
      ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', "#{E2E::IDP_BASE}/saml/logout"]
    )
  end

  it 'publishes the signing certificate the assertions are actually signed with' do
    published = doc.at_xpath("//md:KeyDescriptor[@use='signing']//*[local-name()='X509Certificate']", md)
                   .text.gsub(/\s+/, '')
    actual = File.read(File.join(E2E::CERT_DIR, 'e2e_idp.crt'))
                 .gsub(/-----(BEGIN|END) CERTIFICATE-----/, '').gsub(/\s+/, '')

    expect(published).to eq(actual)
  end

  it 'declares the NameID formats it can issue' do
    formats = doc.xpath('//md:IDPSSODescriptor/md:NameIDFormat', md).map(&:text)

    expect(formats).to include(
      'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
    )
  end

  it 'declares SAML 2.0 protocol support' do
    descriptor = doc.at_xpath('//md:IDPSSODescriptor', md)

    expect(descriptor['protocolSupportEnumeration']).to eq('urn:oasis:names:tc:SAML:2.0:protocol')
  end

  it 'can be consumed by ruby-saml as IdP metadata' do
    parser = OneLogin::RubySaml::IdpMetadataParser.new
    settings = parser.parse(idp_metadata_xml)

    expect(settings.idp_entity_id).to eq("#{E2E::IDP_BASE}/saml")
    expect(settings.idp_sso_service_url).to eq("#{E2E::IDP_BASE}/saml/auth")
    expect(settings.idp_slo_service_url).to eq("#{E2E::IDP_BASE}/saml/logout")
    expect(settings.idp_cert_multi || settings.idp_cert).not_to be_nil
  end

end
