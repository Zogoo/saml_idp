require 'builder'
module SamlIdp
  class AssertionBuilder
    attr_accessor :reference_id
    attr_accessor :issuer_uri
    attr_accessor :name_id
    attr_accessor :audience_uri
    attr_accessor :saml_request_id
    attr_accessor :saml_acs_url
    attr_accessor :raw_algorithm
    attr_accessor :signature

    def initialize(reference_id, issuer_uri, name_id, audience_uri, saml_request_id, saml_acs_url, raw_algorithm)
      self.reference_id = reference_id
      self.issuer_uri = issuer_uri
      self.name_id = name_id
      self.audience_uri = audience_uri
      self.saml_request_id = saml_request_id
      self.saml_acs_url = saml_acs_url
      self.raw_algorithm = raw_algorithm
    end

    def digest
      @digest ||= encode
    end

    def raw
      @raw ||= fresh
    end

    def rebuild
      fresh
    end

    def encode
      Base64.encode64(algorithm.digest(raw)).gsub(/\n/, '')
    end
    private :encode

    def algorithm
      algorithm_check = raw_algorithm || SamlIdp.config.algorithm
      return algorithm_check if algorithm_check.respond_to?(:digest)
      case algorithm_check
      when :sha256
        OpenSSL::Digest::SHA256
      when :sha384
        OpenSSL::Digest::SHA384
      when :sha512
        OpenSSL::Digest::SHA512
      else
        OpenSSL::Digest::SHA1
      end
    end
    private :algorithm

    def fresh
      builder.Assertion xmlns: "urn:oasis:names:tc:SAML:2.0:assertion",
        ID: reference_string,
        IssueInstant: now_iso,
        Version: "2.0" do |assertion|
          assertion.Issuer issuer_uri
          assertion << signature if signature
          assertion.Subject do |subject|
            subject.NameID name_id, Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            subject.SubjectConfirmation Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer" do |confirmation|
              confirmation.SubjectConfirmationData InResponseTo: saml_request_id,
                NotOnOrAfter: not_on_or_after_subject,
                Recipient: saml_acs_url
            end
          end
          assertion.Conditions NotBefore: not_before, NotOnOrAfter: not_on_or_after_condition do |conditions|
            conditions.AudienceRestriction do |restriction|
              restriction.Audience audience_uri
            end
          end
          assertion.AttributeStatement do |attr_statement|
            attr_statement.Attribute Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" do |attr|
              attr.AttributeValue name_id
            end
          end
          assertion.AuthnStatment AuthnInstant: now_iso, SessionIndex: reference_string do |statement|
            statement.AuthnContext do |context|
              context.AuthnContextClassRef "urn:federation:authentication:windows"
            end
          end
        end
    end
    private :fresh

    def reference_string
      "_#{reference_id}"
    end
    private :reference_string

    def now
      @now ||= Time.now.utc
    end
    private :now

    def now_iso
      iso { now }
    end
    private :now_iso

    def not_before
      iso { now - 5 }
    end
    private :not_before

    def not_on_or_after_condition
      iso { now + 60 * 60 }
    end
    private :not_on_or_after_condition

    def not_on_or_after_subject
      iso { now + 3 * 60 }
    end
    private :not_on_or_after_subject

    def iso
      yield.iso8601
    end
    private :iso

    def builder
      @builder ||= Builder::XmlMarkup.new
    end
    private :builder
  end
end
