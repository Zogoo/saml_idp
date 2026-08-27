# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Signature algorithms' do
  SIGNATURE_METHODS = {
    'sha1'   => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    'sha256' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'sha384' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
    'sha512' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
  }.freeze

  DIGEST_METHODS = {
    'sha1'   => 'http://www.w3.org/2000/09/xmldsig#sha1',
    'sha256' => 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha384' => 'http://www.w3.org/2001/04/xmldsig-more#sha384',
    'sha512' => 'http://www.w3.org/2001/04/xmlenc#sha512'
  }.freeze

  SIGNATURE_METHODS.each_key do |algorithm|
    describe algorithm do
      it 'produces an assertion the SP accepts' do
        result = flow.sso(knobs: { 'x_algorithm' => algorithm }).json

        expect(result['errors']).to be_empty
        expect(result['name_id']).to eq('user@example.test')
      end

      it 'declares the matching SignatureMethod and DigestMethod' do
        page = idp_response_page(knobs: { 'x_algorithm' => algorithm })
        xml = Base64.decode64(page.doc.at_css('input[name=SAMLResponse]')['value'])
        doc = Nokogiri::XML(xml)
        ns = { 'ds' => 'http://www.w3.org/2000/09/xmldsig#' }

        expect(doc.at_xpath('//ds:SignatureMethod', ns)['Algorithm'])
          .to eq(SIGNATURE_METHODS.fetch(algorithm))
        expect(doc.at_xpath('//ds:DigestMethod', ns)['Algorithm'])
          .to eq(DIGEST_METHODS.fetch(algorithm))
      end
    end
  end
end
