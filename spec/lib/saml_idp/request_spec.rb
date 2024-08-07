require 'spec_helper'
module SamlIdp
  describe Request do
    let(:issuer) { 'localhost:3000' }
    let(:raw_authn_request) do
      "<samlp:AuthnRequest AssertionConsumerServiceURL='http://localhost:3000/saml/consume' Destination='http://localhost:1337/saml/auth' ID='_af43d1a0-e111-0130-661a-3c0754403fdb' IssueInstant='2013-08-06T22:01:35Z' Version='2.0' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'><saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>#{issuer}</saml:Issuer><samlp:NameIDPolicy AllowCreate='true' Format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'/><samlp:RequestedAuthnContext Comparison='exact'><saml:AuthnContextClassRef xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"
    end

    describe "deflated request" do
      let(:deflated_request) { Base64.encode64(Zlib::Deflate.deflate(raw_authn_request, 9)[2..-5]) }

      subject { described_class.from_deflated_request deflated_request }

      it "inflates" do
        expect(subject.request_id).to eq("_af43d1a0-e111-0130-661a-3c0754403fdb")
      end

      it "handles invalid SAML" do
        req = described_class.from_deflated_request "bang!"
        expect(req.valid?).to eq(false)
      end
    end

    describe "authn request" do
      subject { described_class.new raw_authn_request }

      it "has a valid request_id" do
        expect(subject.request_id).to eq("_af43d1a0-e111-0130-661a-3c0754403fdb")
      end

      it "has a valid acs_url" do
        expect(subject.acs_url).to eq("http://localhost:3000/saml/consume")
      end

      it "has a valid service_provider" do
        expect(subject.service_provider).to be_a ServiceProvider
      end

      it "has a valid service_provider" do
        expect(subject.service_provider).to be_truthy
      end

      it "has a valid issuer" do
        expect(subject.issuer).to eq("localhost:3000")
      end

      it "has a valid valid_signature" do
        expect(subject.valid_signature?).to be_truthy
      end

      it "should return acs_url for response_url" do
        expect(subject.response_url).to eq(subject.acs_url)
      end

      it "is a authn request" do
        expect(subject.authn_request?).to eq(true)
      end

      it "fetches internal request" do
        expect(subject.request['ID']).to eq(subject.request_id)
      end

      it 'has a valid authn context' do
        expect(subject.requested_authn_context).to eq('urn:oasis:names:tc:SAML:2.0:ac:classes:Password')
      end

      context 'the issuer is empty' do
        let(:issuer) { nil }
        let(:logger) { ->(msg) { puts msg } }

        before do
          allow(SamlIdp.config).to receive(:logger).and_return(logger)
        end

        it 'is invalid' do
          expect(subject.issuer).to_not eq('')
          expect(subject.issuer).to be_nil
          expect(subject.valid?).to eq(false)
        end

        context 'a Ruby Logger is configured' do
          let(:logger) { Logger.new($stdout) }

          before do
            allow(logger).to receive(:info)
          end

          it 'logs an error message' do
            expect(subject.valid?).to be false
            expect(logger).to have_received(:info).with('Unable to find service provider for issuer ')
          end
        end

        context 'a Logger-like logger is configured' do
          let(:logger) do
            Class.new {
              def info(msg); end
            }.new
          end

          before do
            allow(logger).to receive(:info)
          end

          it 'logs an error message' do
            expect(subject.valid?).to be false
            expect(logger).to have_received(:info).with('Unable to find service provider for issuer ')
          end
        end

        context 'a logger lambda is configured' do
          let(:logger) { double }

          before { allow(logger).to receive(:call) }

          it 'logs an error message' do
            expect(subject.valid?).to be false
            expect(logger).to have_received(:call).with('Unable to find service provider for issuer ')
          end
        end
      end

      context "when signature provided in authn request" do
        let(:auth_request) { OneLogin::RubySaml::Authrequest.new }
        let(:sp_setting) { saml_settings("https://foo.example.com/saml/consume", true) }
        let(:raw_authn_request) { CGI.unescape(auth_request.create(sp_setting).split("=").last) }

        subject { described_class.from_deflated_request raw_authn_request }

        before do
          idp_configure("http://localhost:3000/saml/consume", true)
        end

        context "when AuthnRequest signature validation is enabled" do
          before do
            SamlIdp.configure do |config|
              config.service_provider.finder = lambda { |_issuer_or_entity_id|
                {
                  response_hosts: [URI("http://localhost:3000/saml/consume").host],
                  acs_url: "http://localhost:3000/saml/consume",
                  cert: sp_x509_cert,
                  fingerprint: SamlIdp::Fingerprint.certificate_digest(sp_x509_cert),
                  assertion_consumer_logout_service_url: 'https://foo.example.com/saml/logout',
                  sign_authn_request: true
                }
              }
            end
          end

          it "returns true" do
            expect(subject.send(:validate_auth_request_signature?)).to be true
          end

          it "validates the signature" do
            allow(subject).to receive(:signature).and_return(nil)
            allow(subject).to receive(:valid_signature?).and_call_original

            expect(subject.valid_signature?).to be true
          end
        end

        context "when AuthnRequest signature validation is disabled" do
          before do
            SamlIdp.configure do |config|
              config.service_provider.finder = lambda { |_issuer_or_entity_id|
                {
                  response_hosts: [URI("http://localhost:3000/saml/consume").host],
                  acs_url: "http://localhost:3000/saml/consume",
                  cert: sp_x509_cert,
                  fingerprint: SamlIdp::Fingerprint.certificate_digest(sp_x509_cert),
                  assertion_consumer_logout_service_url: 'https://foo.example.com/saml/logout',
                  sign_authn_request: false
                }
              }
            end
          end

          it "returns false" do
            expect(subject.send(:validate_auth_request_signature?)).to be false
          end

          it "does not validate the signature and return true" do
            allow(subject).to receive(:signature).and_return(nil)
            allow(subject).to receive(:valid_signature?).and_call_original

            expect(subject.valid_signature?).to be true
          end
        end
      end

      context "when signature provided as external params" do
        let(:auth_request) { OneLogin::RubySaml::Authrequest.new }
        let(:sp_setting) { saml_settings("https://foo.example.com/saml/consume", true, security_options: { embed_sign: false }) }
        let(:saml_response) { auth_request.create(sp_setting) }
        let(:query_params) { CGI.parse(URI.parse(saml_response).query) }
        let(:raw_authn_request) { query_params['SAMLRequest'].first }
        let(:signature) { query_params['Signature'].first }
        let(:sig_algorithm) { query_params['SigAlg'].first }

        before do
          idp_configure("http://localhost:3000/saml/consume", true)
        end

        subject do
          described_class.from_deflated_request(
            raw_authn_request,
            saml_request: raw_authn_request,
            relay_state: query_params['RelayState'].first,
            sig_algorithm: sig_algorithm,
            signature: signature
          )
        end

        context "when AuthnRequest signature validation is enabled" do
          before do
            SamlIdp.configure do |config|
              config.service_provider.finder = lambda { |_issuer_or_entity_id|
                {
                  response_hosts: [URI("http://localhost:3000/saml/consume").host],
                  acs_url: "http://localhost:3000/saml/consume",
                  cert: sp_x509_cert,
                  fingerprint: SamlIdp::Fingerprint.certificate_digest(sp_x509_cert),
                  assertion_consumer_logout_service_url: 'https://foo.example.com/saml/logout',
                  sign_authn_request: true
                }
              }
            end
          end

          it "validate certificates and return valid" do
            expect(subject.valid_external_signature?).to be true
          end
        end

        context "when AuthnRequest signature validation is disabled" do
          before do
            SamlIdp.configure do |config|
              config.service_provider.finder = lambda { |_issuer_or_entity_id|
                {
                  response_hosts: [URI("http://localhost:3000/saml/consume").host],
                  acs_url: "http://localhost:3000/saml/consume",
                  cert: sp_x509_cert,
                  fingerprint: SamlIdp::Fingerprint.certificate_digest(sp_x509_cert),
                  assertion_consumer_logout_service_url: 'https://foo.example.com/saml/logout',
                  sign_authn_request: false
                }
              }
            end
          end

          it "skip signature validation and return valid" do
            expect(subject.valid_external_signature?).to be true
          end
        end
      end
    end

    describe "logout request" do
      context 'when POST binding' do
        let(:raw_logout_request) { "<LogoutRequest ID='_some_response_id' Version='2.0' IssueInstant='2010-06-01T13:00:00Z' Destination='http://localhost:3000/saml/logout' xmlns='urn:oasis:names:tc:SAML:2.0:protocol'><Issuer xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>http://example.com</Issuer><NameID xmlns='urn:oasis:names:tc:SAML:2.0:assertion' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'>some_name_id</NameID><SessionIndex>abc123index</SessionIndex></LogoutRequest>" }

        subject { described_class.new raw_logout_request }

        it "has a valid request_id" do
          expect(subject.request_id).to eq('_some_response_id')
        end

        it "should be flagged as a logout_request" do
          expect(subject.logout_request?).to eq(true)
        end

        it "should have a valid name_id" do
          expect(subject.name_id).to eq('some_name_id')
        end

        it "should have a session index" do
          expect(subject.session_index).to eq('abc123index')
        end

        it "should have a valid issuer" do
          expect(subject.issuer).to eq('http://example.com')
        end

        it "fetches internal request" do
          expect(subject.request['ID']).to eq(subject.request_id)
        end

        it "should return logout_url for response_url" do
          expect(subject.response_url).to eq(subject.logout_url)
        end
      end

      context 'when signature provided as external param' do
        let!(:uri_query) { make_saml_sp_slo_request(security_options: { embed_sign: false }) }
        let(:raw_saml_request) { uri_query['SAMLRequest'] }
        let(:relay_state) { uri_query['RelayState'] }
        let(:siging_algorithm) { uri_query['SigAlg'] }
        let(:signature) { uri_query['Signature'] }

        subject do
          described_class.from_deflated_request(
            raw_saml_request,
            saml_request: raw_saml_request,
            relay_state: relay_state,
            sig_algorithm: siging_algorithm,
            signature: signature
          )
        end

        it "should validate the request" do
          allow(ServiceProvider).to receive(:new).and_return(
            ServiceProvider.new(
              issuer: "http://example.com/issuer",
              cert: sp_x509_cert,
              response_hosts: ["example.com"],
              assertion_consumer_logout_service_url: "http://example.com/logout"
            )
          )
          expect(subject.valid?).to be true
        end
      end
    end
  end
end
