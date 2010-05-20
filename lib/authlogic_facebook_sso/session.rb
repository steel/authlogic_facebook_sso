require 'digest/md5'

module AuthlogicFacebookSso
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
      # Your Facebook API key.
      #
      # * <tt>Default:</tt> nil
      # * <tt>Accepts:</tt> String
      def facebook_api_key(value=nil)
        rw_config(:facebook_api_key, value, nil)
      end
      alias_method :facebook_api_key=, :facebook_api_key

      # REQUIRED
      #
      # Your Facebook API secret key.
      #
      # * <tt>Default:</tt> nil
      # * <tt>Accepts:</tt> String
      def facebook_secret_key(value=nil)
        rw_config(:facebook_secret_key, value, nil)
      end
      alias_method :facebook_secret_key=, :facebook_secret_key

      # Which user field should be used for the facebook UID?
      #
      # * <tt>Default:</tt> :facebook_uid
      # * <tt>Accepts:</tt> Symbol
      def facebook_uid_field(value=nil)
        rw_config(:facebook_uid_field, value, :facebook_uid)
      end
      alias_method :facebook_uid_field=, :facebook_uid_field

      # Which user field should be used for the facebook access token?
      #
      # * <tt>Default:</tt> :facebook_access_token
      # * <tt>Accepts:</tt> Symbol
      def facebook_access_token_field(value=nil)
        rw_config(:facebook_access_token_field, value, :facebook_access_token)
      end
      alias_method :facebook_access_token_field=, :facebook_access_token_field

      # Which user attr_writer should be used for the (full) name for
      # a new user when facebook_auto_register is enabled?
      #
      # * <tt>Default:</tt> :name
      # * <tt>Accepts:</tt> Symbol
      def facebook_name_field(value=nil)
        rw_config(:facebook_name_field, value, :name)
      end
      alias_method :facebook_name_field=, :facebook_name_field

      # Which User attr_writer should be used for facebook username (if
      # one exists) for a new user when facebook_auto_register is enabled?
      #
      # * <tt>Default:</tt> :facebook_username
      # * <tt>Accepts:</tt> Symbol
      def facebook_username_field(value=nil)
        rw_config(:facebook_username_field, value, :facebook_username)
      end
      alias_method :facebook_username_field=, :facebook_username_field

      # Should a new user be automatically created if there is no user with
      # given facebook uid?
      #
      # * <tt>Default:</tt> false
      # * <tt>Accepts:</tt> Boolean
      def facebook_auto_register(value=nil)
        rw_config(:facebook_auto_register, value, false)
      end
      alias_method :facebook_auto_register=, :facebook_auto_register

      def facebook_auto_register?
        if self.facebook_auto_register.is_a? Proc
          self.facebook_auto_register.call
        else
          self.facebook_auto_register
        end
      end

      # Which method should be called before the event of a successful
      # authentication via facebook connect?
      #
      # * <tt>Default:</tt> :during_connect
      # * <tt>Accepts:</tt> Symbol
      def facebook_connect_callback(value=nil)
        rw_config(:facebook_connect_callback, value, :before_facebook_connect)
      end
      alias_method :facebook_connect_callback=, :facebook_connect_callback
    end

    module Methods
      def self.included(klass)
        klass.class_eval do
          attr_accessor :facebook_name, :facebook_username
          validate :validate_by_facebook, :if => :authenticating_with_facebook?
          delegate :facebook_auto_register?, :facebook_uid_field, :facebook_access_token_field,
              :facebook_api_key, :facebook_secret_key, :facebook_connect_callback,
              :facebook_name_field, :facebook_username_field, :to => "self.class"
        end
      end

      # For printing out meaningful credentials
      def credentials
        if self.authenticating_with_facebook?
          {
            :facebook_cookie => self.raw_cookie
          }
        else
          super
        end
      end

      # Allow facebook values to be passed in to aid in account creation
      def credentials=(value)
        super
        values = value.is_a?(Array) ? value : [value]
        if values.first.is_a?(Hash)
          hash = values.first.with_indifferent_access
          self.facebook_name = hash[:facebook_name]
          self.facebook_username = hash[:facebook_username]

          hash
        end
      end
      
      protected
      
      def authenticate_with_facebook
        @authenticate_with_facebook ||= false
      end
      
      # Cookie set by the Facebook JS SDK
      def raw_cookie
        @raw_cookie ||= controller.cookies["fbs_#{self.facebook_api_key}"]
      end

      def facebook_api_keys_provided?
        (!self.facebook_api_key.blank? && !self.facebook_secret_key.blank?) ||
            warn("Expected #{self.class.name} to declare Facebook API key and secret. Not authenticating using Facebook." || false)
      end

      # Override this if you only want some requests to use facebook
      def authenticating_with_facebook?
        !authenticating_with_unauthorized_record? && self.facebook_api_keys_provided? && self.raw_cookie
      end

      def cookie_data
        @cookie_data ||= self.raw_cookie.
            split('&').
            map { |pair| pair.split('=') }.
            inject({}) do |hash, (key, value)|
              hash[key] = value; hash
            end
      end

      def valid_cookie?
        payload = self.cookie_data.
            sort_by(&:first).
            reject { |(key, _)| 'sig' == key }.
            inject('') do |payload, (key, value)|
              payload << "#{key}=#{value}"
            end

        Digest::MD5.hexdigest(payload + self.facebook_secret_key) == self.cookie_data['sig']
      end

      def facebook_uid
        @facebook_uid ||= self.cookie_data['uid'].to_i
      end

      def facebook_access_token
        @facebook_access_token ||= self.cookie_data['access_token']
      end

      def validate_by_facebook
        if !self.valid_cookie?
          errors.add_to_base(I18n.t('error_messages.facebook_connect_failed', :default => 'Authentication via Facebook Connect failed.'))
          return
        end

        self.attempted_record = klass.where(self.facebook_uid_field => self.facebook_uid).first || klass.new

        if !self.attempted_record.new_record? || self.facebook_auto_register?
          self.attempted_record.send(:"#{self.facebook_access_token_field}=", self.facebook_access_token)

          if self.attempted_record.new_record?
            self.attempted_record.send(:"#{self.facebook_uid_field}=", self.facebook_uid)
            self.attempted_record.send(:"#{self.facebook_name_field}=", self.facebook_name) if self.attempted_record.respond_to? "#{self.facebook_name_field}="
            self.attempted_record.send(:"#{self.facebook_username_field}=", self.facebook_username) if self.attempted_record.respond_to?("#{self.facebook_username_field}=") && !self.facebook_username.blank?

            [:persistence, :single_access].each do |token|
              self.attempted_record.send("reset_#{token}_token") if self.attempted_record.respond_to? "#{token}_token"
            end
          end

          if self.attempted_record.respond_to?(self.facebook_connect_callback)
            self.attempted_record.send(self.facebook_connect_callback, self)
          end
        else
          errors.add_to_base(I18n.t('error_messages.facebook_connect_by_unregistered_user', :default => 'Your Facebook account is not connected to any registered user on file.'))
        end
      end

    end
  end
end
