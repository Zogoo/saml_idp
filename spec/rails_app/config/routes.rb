RailsApp::Application.routes.draw do
  # Identity Provider
  get  '/saml/auth'         => 'saml_idp#new'
  post '/saml/auth'         => 'saml_idp#create'
  match '/saml/logout'      => 'saml_idp#logout', via: %i[get post]
  get  '/saml/metadata'     => 'saml_idp#show'
  get  '/saml/unsolicited'  => 'saml_idp#unsolicited'
  get  '/saml/initiate_slo' => 'saml_idp#initiate_slo'

  # Service Provider
  get  '/saml/sp/login'     => 'saml#login'
  get  '/saml/sp/logout'    => 'saml#sp_logout'
  post '/saml/consume'      => 'saml#consume'
  match '/saml/sls'         => 'saml#sls', via: %i[get post]
  get  '/saml/sp/metadata'  => 'saml#metadata'
end
