require 'authlogic_facebook_sso/acts_as_authentic'
require 'authlogic_facebook_sso/session'
require 'authlogic_facebook_sso/helper'

if ActiveRecord::Base.respond_to?(:add_acts_as_authentic_module)
  ActiveRecord::Base.send(:include, AuthlogicFacebookSso::ActsAsAuthentic)
  Authlogic::Session::Base.send(:include, AuthlogicFacebookSso::Session)
  ActionController::Base.helper AuthlogicFacebookSso::Helper
end
