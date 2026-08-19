# frozen_string_literal: true

require 'spec_helper'

# Every SamlIdp::Request outcome, driven end to end. The error symbols are
# public API that host applications branch on, so they are pinned here.
#
# Service-provider *resolution* is expected to move out of the gem. These specs
# exist to protect the refactor: they record what the code does today so that a
# change of behaviour is a deliberate decision rather than an accident.
RSpec.describe 'AuthnRequest validation' do
  def request_with(profile, binding: :redirect, sp: {})
    flow.sso_up_to_idp(binding: binding, sp: sp, headers: { 'X-E2E-SP-Profile' => profile })
  end

  it 'accepts a well-formed signed request from a known SP' do
    page = request_with('default')

    expect(page.status).to eq(200)
    expect(page.body).to include('Sign in')
  end

  it 'reports empty_certificate when the SP has no cert to verify against' do
    page = request_with('no-cert')

    expect(page.status).to eq(403)
    expect(page.json['errors']).to include('empty_certificate')
  end

  it 'reports not_allowed_host when the ACS URL host is not whitelisted' do
    page = request_with('foreign-host')

    expect(page.status).to eq(403)
    expect(page.json['errors']).to include('not_allowed_host')
  end

  describe 'an issuer that resolves to no service provider' do
    # Pins CURRENT behaviour, which is not the intended behaviour.
    # ServiceProvider#valid? tests `attributes.present?`, and
    # Request#service_provider always merges `identifier: issuer` into the
    # finder result -- so the hash is never empty and :sp_not_found is
    # unreachable. The request is only stopped later, by the host check.
    # See e2e/FINDINGS.md #3.
    it 'is rejected by the host check rather than as an unknown SP' do
      page = request_with('unknown')

      expect(page.status).to eq(403)
      expect(page.json['errors']).to include('not_allowed_host')
      expect(page.json['errors']).not_to include('sp_not_found')
    end

    it 'does not issue an assertion' do
      expect(request_with('unknown').body).not_to include('SAMLResponse')
    end
  end

  describe 'AssertionConsumerServiceURL supplied by the request' do
    # Documented behaviour: with no acs_url configured, the URL from the
    # AuthnRequest is used instead (Request#acs_url).
    it 'is honoured when the SP config has none' do
      page = request_with('no-acs')

      expect(page.status).to eq(200)
      expect(page.body).to include('Sign in')
    end

    # ...but it is attacker-controlled, so response_hosts must still gate it.
    it 'is still constrained by response_hosts' do
      page = request_with('foreign-host')

      expect(page.status).to eq(403)
      expect(page.json['errors']).to include('not_allowed_host')
    end
  end

  it 'refuses to issue an assertion for any rejected profile' do
    %w[unknown no-cert foreign-host].each do |profile|
      expect(request_with(profile).body).not_to include('SAMLResponse'), "#{profile} leaked a response"
    end
  end
end
