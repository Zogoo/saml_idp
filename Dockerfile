# Runs the saml_idp test suite, including the end-to-end SAML flows.
FROM ruby:3.3-slim

RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends build-essential libyaml-dev git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first so code edits do not invalidate the bundle layer.
COPY Gemfile saml_idp.gemspec ./
COPY lib/saml_idp/version.rb lib/saml_idp/version.rb
RUN bundle install

COPY . .

CMD ["bundle", "exec", "rspec"]
