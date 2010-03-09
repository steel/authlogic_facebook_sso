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
      def facebook_auto_register(value=nil)
        rw_config(:facebook_auto_register, value, false)
      end
      alias_method :facebook_auto_register=, :facebook_auto_register
      alias_method :facebook_auto_register?, :facebook_auto_register

      # What is the name of the method that should be called in the event of
      # a successful authentication via facebook connect?
      #
      # * <tt>Default:</tt> :during_connect
      # * <tt>Accepts:</tt> Symbol
      def facebook_connect_callback(value=nil)
        rw_config(:facebook_connect_callback, value, :during_connect)
      end
      alias_method :facebook_connect_callback=, :facebook_connect_callback
    end

    module Methods
      def self.included(klass)
        klass.class_eval do
          attr_accessor :facebook_uid, :facebook_session
          validate :validate_by_facebook, :if => :authenticating_with_facebook?
          delegate :facebook_auto_register?, :facebook_uid_field, :facebook_session_field, :facebook_api_key, :facebook_secret_key, :facebook_connect_callback,
              :to => "self.class"
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

      def facebook_api_params_provided?
        return @facebook_api_params_provided_p if defined? @facebook_api_params_provided_p

        @facebook_api_params_provided_p =
            (!self.facebook_api_key.blank? && !self.facebook_secret_key.blank? && true) ||
                warn("Expected #{self.class.name} to declare Facebook API key and secret.  Not authenticating using Facebook." || false)
      end

      # Override this if you want only some requests to use facebook
      def authenticating_with_facebook?
        self.facebook_api_params_provided? && !authenticating_with_unauthorized_record?
      end

      def validate_by_facebook
        return false unless self.facebook_uid && self.facebook_session

        found_record = klass.first(:conditions => { self.facebook_uid_field => self.facebook_uid })

        if found_record || self.facebook_auto_register?
          self.attempted_record = found_record || klass.new

          # use #send in case the attributes are protected
          self.attempted_record.send(:"#{self.facebook_session_field}=", self.facebook_session)
          unless found_record
            self.attempted_record.send(:"#{self.facebook_uid_field}=", self.facebook_uid)

            [:persistence, :single_access].each do |token|
              self.attempted_record.send("reset_#{token}_token") if self.attempted_record.respond_to? "#{token}_token"
            end
          end

          if self.attempted_record.respond_to?(self.facebook_connect_callback)
            self.attempted_record.send(self.facebook_connect_callback, self.details)
          end

          self.attempted_record.save(false)
        else
          errors.add_to_base(I18n.t('error_messages.facebook_connect_by_unregistered_user',
              :default => 'Your Facebook account is not connected to any registered users on file.'))

          false
        end
      end
    end
  end
end
