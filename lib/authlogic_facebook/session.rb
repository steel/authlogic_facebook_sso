module AuthlogicFacebook
  module Session
    class InvalidSignature < StandardError; end
    class SignatureExpired < StandardError; end

    def self.included(klass)
      klass.class_eval do
        extend Config
        include Methods
      end
    end

    module Config
      # REQUIRED
      #
      # Specify your api_key.
      #
      # * <tt>Default:</tt> nil
      # * <tt>Accepts:</tt> String
      def facebook_api_key(value=nil)
        rw_config(:facebook_api_key, value, nil)
      end
      alias_method :facebook_api_key=, :facebook_api_key

      # REQUIRED
      #
      # Specify your secret_key.
      #
      # * <tt>Default:</tt> nil
      # * <tt>Accepts:</tt> String
      def facebook_secret_key(value=nil)
        rw_config(:facebook_secret_key, value, nil)
      end
      alias_method :facebook_secret_key=, :facebook_secret_key

      # What user field should be used for the facebook UID?
      #
      # * <tt>Default:</tt> :facebook_uid
      # * <tt>Accepts:</tt> Symbol
      def facebook_uid_field(value=nil)
        rw_config(:facebook_uid_field, value, :facebook_uid)
      end
      alias_method :facebook_uid_field=, :facebook_uid_field

      # What extended permissions should be requested from the user?
      #
      # * <tt>Default:</tt> []
      # * <tt>Accepts:</tt> Array of Strings
      def facebook_permissions(value=nil)
        rw_config(:facebook_permissions, value, [])
      end
      alias_method :facebook_permissions=, :facebook_permissions

      # Should a new user be automatically created if there is no user with
      # given facebook uid?
      #
      # * <tt>Default:</tt> false
      # * <tt>Accepts:</tt> Boolean
      def facebook_auto_register(value=true)
        rw_config(:facebook_auto_register, value, false)
      end
      alias_method :facebook_auto_register=, :facebook_auto_register
    end

    module Methods
      def self.included(klass)
        klass.class_eval do
          validate :validate_by_facebook, :if => :authenticating_with_facebook?
        end
      end

      # Clears out the block if we are authenticating with Facebook so that we
      # can redirect without a DoubleRender error.
      def save(&block)
        block = nil if !self.facebook_callback?
        super(&block)
      end

      def facebook_api_key
        self.class.facebook_api_key
      end

      def facebook_secret_key
        self.class.facebook_secret_key
      end

      protected
      # Override this if you want only some requests to use facebook
      def authenticating_with_facebook?
        !self.facebook_api_key.blank? && !self.facebook_secret_key.blank?
      end

      private
      def validate_by_facebook
        if self.facebook_callback?
          facebook_uid = verified_facebook_params[:user]
          self.attempted_record = klass.first(:conditions => {facebook_uid_field => facebook_uid})

          if self.attempted_record || !self.auto_register?
            return !!self.attempted_record
          else
            self.attempted_record = klass.new
            self.attempted_record.send(:"#{facebook_uid_field}=", facebook_uid)
            if self.attempted_record.respond_to?(:before_connect)
              self.attempted_record.before_connect(verified_facebook_params)
            end

            return self.attempted_record.save
          end
        else
          controller.redirect_to(self.facebook_login_url)
          return false
        end
      end

      def verified_facebook_params
        return @verified_facebook_params if defined?(@verified_facebook_params)

        unverified_params = {}
        controller.params.each_pair do |key, value|
          if key.match(/^fb_sig_/)
            unverified_params[key.sub(/^fb_sig_/, '')] = value
          end
        end

        raw_string = unverified_params.map{|*a| a.join('=')}.sort.join
        raw_string << self.facebook_secret_key
        signature = Digest::MD5.hexdigest(raw_string)

        if signature != controller.params['fb_sig']
          raise Authlogic::Session::IncorrectSignature
        elsif Time.at(controller.params['fb_sig_expires'].to_i) < Time.now
          raise Authlogic::Session::SignatureExpired
        end

        @verified_facebook_params = unverified_params
      end

      def auto_register?
        self.class.facebook_auto_register_value
      end

      def facebook_uid_field
        self.class.facebook_uid_field
      end

      def facebook_callback?
        !controller.params['fb_sig'].blank?
      end

      def facebook_permissions
        self.class.facebook_permissions
      end

      def facebook_login_url
        params = {'api_key' => self.facebook_api_key,
                  'req_perms' => self.facebook_permissions.join(','),
                  'next' => controller.request.request_uri,
                  'v' => '1.0',
                  'connect_display' => 'popup',
                  'fbconnect' => 'true',
                  'return_session' => 'true'}

        url = 'http://www.facebook.com/login.php?'
        params.each_pair{|k,v| url << "#{k}=#{CGI.escape(v)}"}

        return url
      end
    end
  end
end
