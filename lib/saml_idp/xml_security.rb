# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require "rexml/document"
require "rexml/xpath"
require "openssl"
require 'nokogiri'
require "digest/sha1"
require "digest/sha2"

module SamlIdp
  module XMLSecurity
    class SignedDocument < REXML::Document
      ValidationError = Class.new(StandardError)
      C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
      DSIG = "http://www.w3.org/2000/09/xmldsig#"
      ENVELOPED_SIG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
      # XMLDSig lets a signature declare arbitrary transforms (XPath filters,
      # XSLT, ...). We only ever apply "strip the enveloped signature, then
      # canonicalize", so anything else must be rejected rather than ignored.
      ALLOWED_TRANSFORMS = [
        ENVELOPED_SIG,
        C14N,
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        "http://www.w3.org/2006/12/xml-c14n11"
      ].freeze

      attr_accessor :signed_element_id

      def initialize(response)
        super(response)
        extract_signed_element_id
      end

      # A signature is only meaningful when it covers the element the caller is
      # going to read. XMLDSig itself gives no such guarantee: <ds:Reference>
      # names an element by ID and says nothing about where that element sits in
      # the document, so a genuinely signed element can be wrapped in attacker
      # controlled XML that the application reads instead (XML Signature
      # Wrapping).
      #
      # `options[:signed_element_id]` is how the caller states which element it
      # consumes. The signature is accepted only when it is enveloped in exactly
      # that element and its single Reference points back at it. Callers that
      # consume the whole message (every SAML protocol message - see SAML 2.0
      # Core 5.4.2) can omit the option and get the document root.
      def validate(idp_base64_cert, idp_cert_fingerprint, soft = true, options = {})
        document, target, sig_element = signature_context(options)
        base64_cert = certificate_for(idp_base64_cert, idp_cert_fingerprint, sig_element)
        validate_signature(base64_cert, document, target, sig_element)
      rescue ValidationError
        raise unless soft
        false
      end

      def validate_doc(base64_cert, soft = true, options = {})
        document, target, sig_element = signature_context(options)
        validate_signature(base64_cert, document, target, sig_element)
      rescue ValidationError
        raise unless soft
        false
      end

      def fingerprint_cert(cert, sig_element = nil)
        # pick algorithm based on the doc's digest algorithm
        digest_method =
          if sig_element
            sig_element.at_xpath('./ds:SignedInfo/ds:Reference/ds:DigestMethod', 'ds' => DSIG)
          else
            ref_elem = REXML::XPath.first(self, "//ds:Reference", { "ds" => DSIG })
            REXML::XPath.first(ref_elem, "ds:DigestMethod", { "ds" => DSIG })
          end
        algorithm(digest_method).hexdigest(cert.to_der)
      end

      def fingerprint_cert_sha1(cert)
        OpenSSL::Digest::SHA1.hexdigest(cert.to_der)
      end

      private

      # Resolves the element the signature has to cover, together with the
      # signature enveloped in it. SAML 2.0 Core 5.4.1 requires signatures over
      # assertions and protocol messages to be enveloped, so the signature is a
      # child of the element it signs - looking it up through the target rather
      # than through "the first //ds:Signature in the document" is what keeps
      # the two halves bound together.
      def signature_context(options = {})
        document = Nokogiri.parse(to_s)
        raise ValidationError.new("Document has no root element") if document.root.nil?

        expected_id = options[:signed_element_id].to_s
        target =
          if expected_id.empty?
            document.root
          else
            matches = elements_with_id(document, expected_id)
            unless matches.length == 1
              raise ValidationError.new(
                "Expected exactly one element with ID #{expected_id.inspect}, found #{matches.length}"
              )
            end
            matches.first
          end

        sig_element = target.at_xpath('./ds:Signature', 'ds' => DSIG)
        if sig_element.nil?
          raise ValidationError.new("Signed element mismatch: <#{target.name}> has no enveloped signature")
        end

        [document, target, sig_element]
      end

      def certificate_for(idp_base64_cert, idp_cert_fingerprint, sig_element)
        # get cert from the signature we are about to validate
        cert_element = sig_element.at_xpath('.//ds:X509Certificate', 'ds' => DSIG)
        if cert_element
          idp_base64_cert = cert_element.text
          cert_text    = Base64.decode64(idp_base64_cert)
          cert         = OpenSSL::X509::Certificate.new(cert_text)

          # check cert matches registered idp cert
          fingerprint = fingerprint_cert(cert, sig_element)
          sha1_fingerprint = fingerprint_cert_sha1(cert)
          plain_idp_cert_fingerprint = idp_cert_fingerprint.to_s.gsub(/[^a-zA-Z0-9]/, "").downcase

          if fingerprint != plain_idp_cert_fingerprint && sha1_fingerprint != plain_idp_cert_fingerprint
            raise ValidationError.new("Fingerprint mismatch")
          end
        end

        if idp_base64_cert.nil? || idp_base64_cert.empty?
          raise ValidationError.new("Certificate validation is required, but it doesn't exist.")
        end

        idp_base64_cert
      end

      def validate_signature(base64_cert, document, target, sig_element)
        signed_info_element = sig_element.at_xpath('./ds:SignedInfo', 'ds' => DSIG)
        raise ValidationError.new("SignedInfo is missing") if signed_info_element.nil?

        # SAML 2.0 Core 5.4.2: a signature carries exactly one reference, to the
        # ID of the element being signed.
        references = signed_info_element.xpath('./ds:Reference', 'ds' => DSIG)
        unless references.length == 1
          raise ValidationError.new("Expected exactly one Reference, found #{references.length}")
        end
        reference = references.first

        target_id = target['ID'].to_s
        raise ValidationError.new("Signed element has no ID") if target_id.empty?

        unless reference['URI'].to_s == "##{target_id}"
          raise ValidationError.new(
            "Reference URI #{reference['URI'].inspect} does not cover the signed element"
          )
        end

        # An ID has to identify one element, otherwise "the element with this
        # ID" is ambiguous and the digest can be checked against a different
        # element than the one we validated.
        unless elements_with_id(document, target_id).length == 1
          raise ValidationError.new("Duplicate element ID #{target_id.inspect}")
        end

        transforms = reference.xpath('./ds:Transforms/ds:Transform', 'ds' => DSIG).map { |node| node['Algorithm'] }
        unless transforms.include?(ENVELOPED_SIG)
          raise ValidationError.new("Enveloped signature transform is required")
        end
        unsupported_transforms = transforms - ALLOWED_TRANSFORMS
        unless unsupported_transforms.empty?
          raise ValidationError.new("Unsupported transform(s): #{unsupported_transforms.join(', ')}")
        end

        digest_value_element = reference.at_xpath('./ds:DigestValue', 'ds' => DSIG)
        raise ValidationError.new("DigestValue is missing") if digest_value_element.nil?
        digest_value = Base64.decode64(digest_value_element.text)
        digest_algorithm = algorithm(reference.at_xpath('./ds:DigestMethod', 'ds' => DSIG))
        digest_canon_algorithm = reference_canon_algorithm(reference, signed_info_element)

        signature_value_element = sig_element.at_xpath('./ds:SignatureValue', 'ds' => DSIG)
        raise ValidationError.new("SignatureValue is missing") if signature_value_element.nil?
        signature = Base64.decode64(signature_value_element.text)
        signature_algorithm = algorithm(signed_info_element.at_xpath('./ds:SignatureMethod', 'ds' => DSIG))

        # canonicalize SignedInfo while the signature is still in place, so that
        # it sees the namespaces in scope at its original position
        canon_string = signed_info_element.canonicalize(
          canon_algorithm(signed_info_element.at_xpath('./ds:CanonicalizationMethod', 'ds' => DSIG))
        )

        # apply the enveloped-signature transform
        sig_element.remove

        # check digest
        canon_hashed_element = target.canonicalize(digest_canon_algorithm, extract_inclusive_namespaces)
        unless digests_match?(digest_algorithm.digest(canon_hashed_element), digest_value)
          raise ValidationError.new("Digest mismatch")
        end

        # verify signature
        cert = OpenSSL::X509::Certificate.new(Base64.decode64(base64_cert))
        unless cert.public_key.verify(signature_algorithm.new, signature, canon_string)
          raise ValidationError.new("Key validation error")
        end

        true
      end

      def elements_with_id(document, id)
        document.xpath('//*[@ID]').select { |node| node['ID'] == id }
      end

      # The canonicalization applied to the referenced element comes from the
      # Reference's own transforms; SignedInfo's CanonicalizationMethod is only
      # a fallback for signers that leave it implicit.
      def reference_canon_algorithm(reference, signed_info_element)
        transform = reference.xpath('./ds:Transforms/ds:Transform', 'ds' => DSIG).to_a.reverse.find do |node|
          node['Algorithm'] != ENVELOPED_SIG
        end
        canon_algorithm(transform || signed_info_element.at_xpath('./ds:CanonicalizationMethod', 'ds' => DSIG))
      end

      def digests_match?(hash, digest_value)
        hash == digest_value
      end

      def extract_signed_element_id
        reference_element       = REXML::XPath.first(self, "//ds:Signature/ds:SignedInfo/ds:Reference", {"ds"=>DSIG})
        self.signed_element_id  = reference_element.attribute("URI").value[1..-1] unless reference_element.nil?
      end

      def canon_algorithm(element)
        algorithm = element.attribute('Algorithm').value if element
        case algorithm
        when "http://www.w3.org/2001/10/xml-exc-c14n#"         then Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
        when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" then Nokogiri::XML::XML_C14N_1_0
        when "http://www.w3.org/2006/12/xml-c14n11"            then Nokogiri::XML::XML_C14N_1_1
        else                                                        Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
        end
      end

      def algorithm(element)
        algorithm = element.attribute("Algorithm").value if element
        algorithm = algorithm && algorithm =~ /sha(.*?)$/i && $1.to_i
        case algorithm
        when 256 then OpenSSL::Digest::SHA256
        when 384 then OpenSSL::Digest::SHA384
        when 512 then OpenSSL::Digest::SHA512
        else
          OpenSSL::Digest::SHA1
        end
      end

      def extract_inclusive_namespaces
        if element = REXML::XPath.first(self, "//ec:InclusiveNamespaces", { "ec" => C14N })
          prefix_list = element.attributes.get_attribute("PrefixList").value
          prefix_list.split(" ")
        else
          []
        end
      end
    end
  end
end
