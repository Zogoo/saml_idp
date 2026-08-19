# frozen_string_literal: true

require 'rack/test'
require 'nokogiri'
require 'json'

# Drives a complete SAML web-browser SSO / SLO flow against spec/rails_app the
# way a browser would: follow the redirect, fill in the login form, submit the
# auto-POST form to the ACS. IdP and SP are addressed on different hosts, so
# Destination and ACS-URL checks stay meaningful.
class SamlFlow
  MAX_HOPS = 10

  Page = Struct.new(:status, :headers, :body, :uri, keyword_init: true) do
    def json
      JSON.parse(body)
    end

    def doc
      Nokogiri::HTML(body)
    end

    def location
      headers['location'] || headers['Location']
    end
  end

  def initialize(app)
    @session = Rack::Test::Session.new(app)
  end

  # --- high level flows -----------------------------------------------------

  # Full SP-initiated SSO. Returns the SP's ACS verdict.
  def sso(binding: :redirect, knobs: {}, sp: {}, headers: {}, email: nil)
    page = follow(start_login(binding: binding, knobs: knobs, sp: sp, headers: headers), headers: headers)
    return page if page.status >= 400

    page = submit_form(page, extra: email ? { 'email' => email } : {}, headers: headers)
    return page if page.status >= 400

    submit_form(page, headers: headers)
  end

  # SP-initiated Single Logout. Needs no user interaction, so the whole chain runs.
  def slo(binding: :redirect, sp: {}, name_id: 'user@example.test', headers: {})
    query = sp.merge(binding: binding.to_s, name_id: name_id)
    follow(get(url("#{E2E::SP_BASE}/saml/sp/logout", query), headers: headers), headers: headers)
  end

  # Starts SSO but stops at the IdP, returning whatever the IdP replied.
  def sso_up_to_idp(binding: :redirect, knobs: {}, sp: {}, headers: {})
    follow(start_login(binding: binding, knobs: knobs, sp: sp, headers: headers), headers: headers)
  end

  # Runs SSO up to the IdP's auto-POST form, without delivering it to the SP.
  def idp_response_page(knobs: {}, sp: {}, headers: {})
    page = follow(start_login(binding: :redirect, knobs: knobs, sp: sp, headers: headers), headers: headers)
    submit_form(page, headers: headers)
  end

  def start_login(binding: :redirect, knobs: {}, sp: {}, headers: {})
    get(url("#{E2E::SP_BASE}/saml/sp/login", sp.merge(knobs).merge(binding: binding.to_s)), headers: headers)
  end

  # Posts an arbitrary (usually tampered) SAMLResponse straight at the ACS.
  def post_to_acs(saml_response, extra = {})
    post("#{E2E::SP_BASE}/saml/consume", { 'SAMLResponse' => saml_response }.merge(extra))
  end

  # --- flow primitives ------------------------------------------------------

  # Follows redirects and auto-submits any auto-POST form until reaching a page
  # that needs a decision (the login form) or a final response.
  def follow(page, headers: {}, hops: MAX_HOPS)
    hops.times do
      if page.status.between?(300, 399) && page.location
        page = get(absolute(page.location, page.uri), headers: headers)
        next
      end
      return page unless auto_post?(page)

      page = submit_form(page, headers: headers)
    end
    raise "exceeded #{MAX_HOPS} hops; last status #{page.status}"
  end

  # Submits the first <form> on the page, merging `extra` over its inputs.
  def submit_form(page, extra: {}, headers: {})
    form = page.doc.at_css('form') or raise "no form in response (#{page.status}):\n#{page.body[0, 600]}"
    action = form['action'].to_s.empty? ? page.uri.to_s : absolute(form['action'], page.uri).to_s
    fields = {}
    form.css('input').each do |input|
      name = input['name']
      next if name.nil? || name.empty?
      next if input['type'] == 'submit' && name != 'commit'

      fields[name] = input['value'].to_s
    end
    fields.merge!(extra)

    if form['method'].to_s.downcase == 'get'
      get(url(action, fields), headers: headers)
    else
      post(action, fields, headers: headers)
    end
  end

  def auto_post?(page)
    page.status == 200 && page.body.include?('document.forms[0].submit()')
  end

  # --- raw requests ---------------------------------------------------------

  def get(uri, headers: {})
    uri = URI(uri.to_s)
    @session.get(uri.to_s, {}, env_for(headers))
    page_from(uri)
  end

  def post(uri, form = {}, headers: {})
    uri = URI(uri.to_s)
    @session.post(uri.to_s, form, env_for(headers))
    page_from(uri)
  end

  private

  def page_from(uri)
    res = @session.last_response
    Page.new(status: res.status, headers: res.headers, body: res.body.to_s, uri: uri)
  end

  def env_for(headers)
    headers.each_with_object({}) do |(key, value), env|
      env["HTTP_#{key.upcase.tr('-', '_')}"] = value
    end
  end

  def url(base, query = {})
    uri = URI(base.to_s)
    return uri if query.empty?

    existing = uri.query ? URI.decode_www_form(uri.query).to_h : {}
    uri.query = URI.encode_www_form(existing.merge(query.transform_keys(&:to_s)).reject { |_, v| v.nil? })
    uri
  end

  def absolute(location, base)
    URI.join(base.to_s, location.to_s)
  end
end
