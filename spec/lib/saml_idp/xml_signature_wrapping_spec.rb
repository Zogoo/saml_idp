require 'spec_helper'

# XML Signature Wrapping (XSW).
#
# XMLDSig signs the element named by <ds:Reference URI="#id">, and says nothing
# about where in the document that element sits. So an attacker who has seen one
# signed request - they travel through the user's browser, they are not secret -
# can keep the signed element intact, wrap it in XML of their own, and have the
# signature verify while the library reads the outer, attacker controlled copy.
#
# Every example here keeps the captured signature byte-for-byte valid over the
# element it was made for. The requests must be rejected because the signature
# does not cover what we read, not because the signature was broken.
RSpec.describe "XML signature wrapping", security: true do
  include SamlRequestMacros
  include SecurityHelpers

  let(:acs_url) { "https://foo.example.com/saml/consume" }
  let(:sp_fingerprint) { SamlIdp::Fingerprint.certificate_digest(sp_x509_cert) }

  # A genuine, signed AuthnRequest as produced by an SP (ruby-saml).
  let(:signed_authn_request) do
    decode_saml_request(make_saml_request(acs_url, true)).sub(/\A<\?xml[^>]*\?>/, '')
  end

  # A genuine, signed LogoutRequest as produced by an SP (ruby-saml).
  let(:signed_logout_request) do
    decode_saml_request(make_saml_sp_slo_request(security_options: { embed_sign: true })['SAMLRequest'])
      .sub(/\A<\?xml[^>]*\?>/, '')
  end

  def element_id(xml)
    Nokogiri::XML(xml).root['ID']
  end

  # The attacker's own AuthnRequest, with the captured signed one buried inside.
  def wrap(inner, attributes: {}, extra_children: "", element: "samlp:AuthnRequest")
    attrs = {
      "ID" => "_evil",
      "Version" => "2.0",
      "IssueInstant" => "2026-01-01T00:00:00Z"
    }.merge(attributes).map { |k, v| %(#{k}="#{v}") }.join(" ")

    <<~XML.strip
      <#{element} xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" #{attrs}>
        <saml:Issuer>http://example.com/issuer</saml:Issuer>
        #{extra_children}
        #{inner}
      </#{element}>
    XML
  end

  before { idp_configure(acs_url, true) }

  describe "SamlIdp::Request" do
    it "accepts an untampered signed AuthnRequest" do
      request = SamlIdp::Request.new(signed_authn_request)

      expect(request.valid?).to be true
      expect(request.errors).to be_empty
    end

    it "accepts an untampered signed LogoutRequest" do
      request = SamlIdp::Request.new(signed_logout_request)

      expect(request.valid?).to be true
      expect(request.errors).to be_empty
    end

    # The scenario from the report: a signed AuthnRequest nested inside an
    # attacker authored one. Before the fix this validated, and every value the
    # IdP went on to use came from the outer element.
    context "when a signed AuthnRequest is wrapped in an attacker authored one" do
      let(:wrapped) do
        wrap(signed_authn_request,
             attributes: { "ForceAuthn" => "false", "AssertionConsumerServiceURL" => "https://attacker.example/steal" })
      end

      it "rejects the request" do
        request = SamlIdp::Request.new(wrapped)

        expect(request.valid?).to be false
        expect(request.errors).to include(:invalid_embedded_signature)
      end

      # Guards the reason for rejection: the captured signature is still
      # perfectly valid over the element it was made for. What we refuse to do
      # is treat that as a signature over the element we read.
      it "leaves the inner signature cryptographically valid" do
        document = Saml::XML::Document.parse(wrapped)

        expect(
          document.valid_signature?(sp_x509_cert, sp_fingerprint,
                                    signed_element_id: element_id(signed_authn_request))
        ).to be true

        expect(
          document.valid_signature?(sp_x509_cert, sp_fingerprint,
                                    signed_element_id: "_evil")
        ).to be false
      end

      it "reads the request off the outer element, so that element is what must be signed" do
        request = SamlIdp::Request.new(wrapped)

        expect(request.request_id).to eq("_evil")
      end
    end

    # Same wrapping, but the outer element reuses the signed element's ID so the
    # reference still resolves to "an element with that ID".
    it "rejects a wrapper that reuses the signed element's ID" do
      wrapped = wrap(signed_authn_request, attributes: { "ID" => element_id(signed_authn_request) })
      request = SamlIdp::Request.new(wrapped)

      expect(request.valid?).to be false
      expect(request.errors).to include(:invalid_embedded_signature)
    end

    # The signed element does not have to be a direct child - hiding it in a
    # legal container such as <samlp:Extensions> is the usual variant.
    it "rejects a signed request hidden inside samlp:Extensions" do
      wrapped = wrap("", extra_children: "<samlp:Extensions>#{signed_authn_request}</samlp:Extensions>")
      request = SamlIdp::Request.new(wrapped)

      expect(request.valid?).to be false
      expect(request.errors).to include(:invalid_embedded_signature)
    end

    it "rejects a wrapped LogoutRequest and never reads the attacker's NameID" do
      wrapped = wrap(
        signed_logout_request,
        attributes: { "ID" => "_evil_slo" },
        extra_children: <<~XML.strip,
          <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">victim@example.com</saml:NameID>
          <samlp:SessionIndex>victim-session-1</samlp:SessionIndex>
        XML
        element: "samlp:LogoutRequest"
      )
      request = SamlIdp::Request.new(wrapped)

      expect(request.valid?).to be false
      expect(request.errors).to include(:invalid_embedded_signature)
    end

    it "rejects a request whose signed element was modified" do
      tampered = signed_authn_request.sub(
        %r{AssertionConsumerServiceURL='[^']*'},
        "AssertionConsumerServiceURL='https://foo.example.com/attacker'"
      )
      request = SamlIdp::Request.new(tampered)

      expect(request.valid?).to be false
      expect(request.errors).to include(:invalid_embedded_signature)
    end

    it "reads the message off the document root only" do
      wrapped = wrap(signed_authn_request, attributes: { "ID" => "_evil" })
      request = SamlIdp::Request.new(wrapped)

      # the outer element is the message; nothing is picked up from the nested one
      expect(request.request_id).to eq("_evil")
      expect(request.send(:authn_request)['AssertionConsumerServiceURL']).to be_nil
    end

    it "ignores a message that is not the document root" do
      request = SamlIdp::Request.new("<Wrapper>#{signed_authn_request}</Wrapper>")

      expect(request.authn_request?).to be false
      expect(request.logout_request?).to be false
      expect(request.valid?).to be false
    end
  end

  describe "SamlIdp::XMLSecurity::SignedDocument" do
    let(:document) { SamlIdp::XMLSecurity::SignedDocument.new(signed_authn_request) }
    let(:base64_cert) { document.elements["//ds:X509Certificate"].text }

    it "validates a signature that covers the root" do
      expect(document.validate_doc(base64_cert, false)).to be true
    end

    it "refuses a signature that does not cover the requested element" do
      wrapped = SamlIdp::XMLSecurity::SignedDocument.new(wrap(signed_authn_request))

      expect { wrapped.validate_doc(base64_cert, false) }.to(
        raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError, /Signed element mismatch/)
      )
      expect(wrapped.validate_doc(base64_cert, true)).to be false
    end

    it "refuses a reference that points somewhere other than the signed element" do
      detached = signed_authn_request.sub(/URI='#[^']*'/, "URI='#somewhere-else'")
      expect {
        SamlIdp::XMLSecurity::SignedDocument.new(detached).validate_doc(base64_cert, false)
      }.to raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError, /does not cover the signed element/)
    end

    it "refuses a signature carrying more than one reference" do
      extra_reference = signed_authn_request.sub(
        %r{(<ds:Reference URI='[^']*'>.*?</ds:Reference>)}m,
        '\1\1'
      )
      expect {
        SamlIdp::XMLSecurity::SignedDocument.new(extra_reference).validate_doc(base64_cert, false)
      }.to raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError, /exactly one Reference/)
    end

    it "refuses a transform it does not implement" do
      xslt = signed_authn_request.sub(
        %r{<ds:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n\#'>},
        "<ds:Transform Algorithm='http://www.w3.org/TR/1999/REC-xslt-19991116'>"
      )
      expect {
        SamlIdp::XMLSecurity::SignedDocument.new(xslt).validate_doc(base64_cert, false)
      }.to raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError, /Unsupported transform/)
    end

    it "refuses a document where the signed ID is not unique" do
      id = element_id(signed_authn_request)
      duplicated = signed_authn_request.sub(
        "<saml:Issuer>",
        "<samlp:Extensions><samlp:Decoy ID='#{id}'/></samlp:Extensions><saml:Issuer>"
      )
      expect {
        SamlIdp::XMLSecurity::SignedDocument.new(duplicated).validate_doc(base64_cert, false)
      }.to raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError, /Duplicate element ID/)
    end
  end
end
