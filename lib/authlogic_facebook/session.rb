module AuthlogicFacebook
  module Session
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

      # What user field should be used for the facebook session key?
      #
      # * <tt>Default:</tt> :facebook_session
      # * <tt>Accepts:</tt> Symbol
      def facebook_session_field(value=nil)
        rw_config(:facebook_session_field, value, :facebook_session)
      end
      alias_method :facebook_session_field=, :facebook_session_field

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
          attr_accessor :facebook_uid, :facebook_session
          validate :validate_by_facebook, :if => :authenticating_with_facebook?
        end
      end

      # Hooks into credentials to print out meaningful credentials for Facebook connect.
      def credentials
        if self.authenticating_with_facebook?
          details = {
            :facebook_uid => self.send(self.facebook_uid_field),
            :facebook_session => self.send(self.facebook_session_field)
          }
        else
          super
        end
      end

      # Hooks into credentials so that you can pass :facebook_uid and :facebook_session keys.
      def credentials=(value)
        super
        values = value.is_a?(Array) ? value : [value]
        if values.first.is_a?(Hash)
          hash = values.first.with_indifferent_access
          self.facebook_uid = hash[:facebook_uid].to_i if hash.key?(:facebook_uid)
          self.facebook_session = hash[:facebook_session]
        end
      end

      protected

      def facebook_auto_register?
        self.class.facebook_auto_register
      end

      def facebook_uid_field
        self.class.facebook_uid_field
      end

      def facebook_session_field
        self.class.facebook_session_field
      end

      def facebook_api_params_provided?
        return @facebook_api_params_provided_p if defined? @facebook_api_params_provided_p

        @facebook_api_params_provided_p =
            (!self.class.facebook_api_key.blank? && !self.class.facebook_secret_key.blank? && true) ||
                warn("Expected #{self.class.name} to declare Facebook API key and secret.  Not authenticating using Facebook." || false)
      end

      # Override this if you want only some requests to use facebook
      def authenticating_with_facebook?
        self.facebook_api_params_provided? && !authenticating_with_unauthorized_record?
      end

      def unverified_facebook_params
        return @unverified_facebook_params if defined? @unverified_facebook_params

        begin
          params = ActiveSupport::JSON.decode(self.controller.params['session'] || '')
        rescue StandardError
          params = {}
        end

        @unverified_facebook_params = params.is_a?(Hash) ? params : {}
      end

      def facebook_callback?
        !self.unverified_facebook_params['uid'].blank?
      end

      def facebook_session
        return @facebook_session if defined?(@facebook_session)

        session_key = self.unverified_facebook_params['session_key']

        uid = nil
        params = {'session_key' => session_key, 'format' => 'JSON'}
        10.times do
          begin
            uid = MiniFB.call(self.class.facebook_api_key,
                              self.class.facebook_secret_key,
                              'Users.getLoggedInUser', params)
            break
          rescue Errno::ECONNRESET, EOFError => e
            exception = e
          end
        end

        if !uid
          raise exception
        end

        @facebook_session = {'uid' => uid, 'session_key' => session_key}
      end

      def validate_by_facebook
        if self.facebook_callback?
          fb_uid = self.facebook_session['uid']
          self.attempted_record = klass.first(:conditions => { self.facebook_uid_field => fb_uid })

          if self.attempted_record || !self.facebook_auto_register?
            !!self.attempted_record
          else
            self.attempted_record = klass.new
            self.attempted_record.send(:"#{facebook_uid_field}=", fb_uid)
            if self.attempted_record.respond_to?(:before_connect)
              self.attempted_record.send(:before_connect, self.facebook_session)
            end

            self.attempted_record.save(false)
          end
        else
          false
        end
      end

      def facebook_login_params
        {
          'api_key' => self.class.facebook_api_key,
          'req_perms' => self.class.facebook_permissions.join(','),
          'next' => self.controller.request.url,
          'v' => '1.0',
          'connect_display' => 'popup',
          'fbconnect' => 'true',
          'return_session' => 'true'
        }
      end

      def facebook_login_url
        params = self.facebook_login_params.map do |key, value|
          "#{CGI.escape(key)}=#{CGI.escape(value)}"
        end

        "http://www.facebook.com/login.php?#{params.join('&')}"
      end
    end
  end
end
