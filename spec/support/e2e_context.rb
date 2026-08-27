# frozen_string_literal: true

require 'base64'
require 'time'
require 'zlib'
require 'cgi'

RSpec.shared_context 'e2e' do
  before { E2E.configure_idp! }

  let(:flow) { SamlFlow.new(RailsApp::Application) }

  def idp_metadata_xml
    @idp_metadata_xml ||= flow.get("#{E2E::IDP_BASE}/saml/metadata").body
  end

  def idp_response_page(**kwargs)
    flow.idp_response_page(**kwargs)
  end

  # Mutates a SAMLResponse taken off the IdP's auto-POST form and re-posts it.
  def tamper_and_post(page, &mutation)
    field = page.doc.at_css('input[name=SAMLResponse]') or
      raise "no SAMLResponse on page (#{page.status}): #{page.body[0, 400]}"
    xml = Base64.decode64(field['value'])
    mutated = mutation.call(xml)
    raise 'mutation was a no-op' if mutated == xml

    flow.post_to_acs(Base64.strict_encode64(mutated))
  end

  def idp_fingerprint
    SamlIdp::Fingerprint.certificate_digest(E2E::IDP_CERT, :sha256)
  end

  def saml_response_xml(page)
    Base64.decode64(page.doc.at_css('input[name=SAMLResponse]')['value'])
  end

  def request_id_from_redirect(page)
    raw = URI.decode_www_form(URI(page.location).query).to_h.fetch('SAMLRequest')
    xml = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(Base64.decode64(raw))
    Nokogiri::XML(xml).root['ID']
  end
end

RSpec.configure do |config|
  config.define_derived_metadata(file_path: %r{spec/e2e/}) { |meta| meta[:e2e] = true }
  config.include_context 'e2e', :e2e
end
