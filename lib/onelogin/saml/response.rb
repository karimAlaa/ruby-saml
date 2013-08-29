require "xml_security"
require "time"
#require "openssl"
#require "digest"
#require "Base64"

module Onelogin::Saml

  class Response
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
    DSIG      = "http://www.w3.org/2000/09/xmldsig#"

    attr_accessor :options, :response, :document, :settings, :decrypted_data

    def initialize(response, options = {})
      raise ArgumentError.new("Response cannot be nil") if response.nil?
      self.options  = options
		
      self.response = response
      self.document = XMLSecurity::SignedDocument.new(Base64.decode64(response))
		Logging.debug "Decoded response:\n#{ document }"
	  puts "response in gem is #{response}"
	  
    end
	
	def decrypt(pk)
		if !REXML::XPath.first(document, "//xenc:EncryptedData").nil?
		#data is encrypted

		
		private_key=pk
		encrypted_data = REXML::XPath.first(document, "//xenc:EncryptedData")
		key_info = REXML::XPath.first(encrypted_data, "//ds:KeyInfo")   
		encrypted_key = REXML::XPath.first(key_info, "//xenc:EncryptedKey")
		key_cipher = REXML::XPath.first(encrypted_key, "//xenc:CipherData/xenc:CipherValue")
		key = decrypt_key(key_cipher.text, private_key)
		
		
		cipher_data = REXML::XPath.first(document, "//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue")
		decrypted=decrypt_cipher_data(key, cipher_data.text)
		puts "decrypted before adjusting is #{decrypted}"
		stop=-1;
		(decrypted.length-1).downto(0).each do |i|
			if decrypted[i]==">"
				stop=i;
				break;
			end
			break if stop!=-1
		end
		decrypted=decrypted[0..stop]
		puts "Decrypted string issss #{decrypted}"
		#decrypted_data= XMLSecurity::SignedDocument.new(decrypted)
		self.decrypted_data= XMLSecurity::SignedDocument.new(decrypted)
		#now replace encrypted with decrypted
		#enc=REXML::XPath.first(document, "//saml2:EncryptedAssertion")
		#document.root.delete(enc)
		#puts "Decrypted is #{document.to_s}"
	else
		decrypted_data=nil
	end
	
	end

    def is_valid?(connect)
      validate(soft = true, connect)
    end

    def validate!
      validate(soft = false)
    end

    # The value of the user identifier as designated by the initialization request response
    def name_id
		puts "decrypted data is #{decrypted_data}"
		puts "decrypted data is #{self.decrypted_data.inspect}"
		if decrypted_data.nil?
			@name_id ||= begin
				node = REXML::XPath.first(document, "/p:Response/a:Assertion[@ID='#{document.signed_element_id[1,document.signed_element_id.size]}']/a:Subject/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
				node ||=  REXML::XPath.first(document, "/p:Response[@ID='#{document.signed_element_id[1,document.signed_element_id.size]}']/a:Assertion/a:Subject/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
				node.nil? ? nil : node.text
			end
		else
			@name_id ||= begin
				node = REXML::XPath.first(decrypted_data, "//a:Assertion/a:Subject/a:NameID", { "a" => ASSERTION })
				node.nil? ? nil : node.text
			end
		end
    end

    # A hash of alle the attributes with the response. Assuming there is only one value for each key
    def attributes
      #need to decrypt first!
	puts "decrypted data is #{decrypted_data}"
	puts "decrypted data is #{self.decrypted_data.inspect}"
	  if decrypted_data.nil?
		@attr_statements ||= begin
			result = {}

			stmt_element = REXML::XPath.first(document, "/p:Response/a:Assertion/a:AttributeStatement", { "p" => PROTOCOL, "a" => ASSERTION })
			return {} if stmt_element.nil?

			stmt_element.elements.each do |attr_element|
				name  = attr_element.attributes["Name"]
				friendly_name= attr_element.attributes["FriendlyName"]
				value = attr_element.elements.first.text

				result[name] = [friendly_name,value]
			end

			result.keys.each do |key|
				result[key.intern] = result[key]
			end

			result
		  end	
		else
		 @attr_statements ||= begin
			result = {}

			stmt_element = REXML::XPath.first(decrypted_data, "//a:Assertion/a:AttributeStatement", {"a" => ASSERTION })
			puts "stmt element is #{stmt_element.inspect}"
			return {} if stmt_element.nil?

			stmt_element.elements.each do |attr_element|
				name  = attr_element.attributes["Name"]
				friendly_name= attr_element.attributes["FriendlyName"]
				value = attr_element.elements.first.text

				result[name] = [friendly_name,value]
			end

			result.keys.each do |key|
				result[key.intern] = result[key]
			end

			result
		end	
	end
	end
    # When this user session should expire at latest
    def session_expires_at
      @expires_at ||= begin
        node = REXML::XPath.first(document, "/p:Response/a:Assertion/a:AuthnStatement", { "p" => PROTOCOL, "a" => ASSERTION })
        parse_time(node, "SessionNotOnOrAfter")
      end
    end

    # Conditions (if any) for the assertion to run
    def conditions
      @conditions ||= begin
        REXML::XPath.first(document, "/p:Response/a:Assertion[@ID='#{document.signed_element_id[1,document.signed_element_id.size]}']/a:Conditions", { "p" => PROTOCOL, "a" => ASSERTION })
      end
    end

    private

    def validation_error(message)
      raise ValidationError.new(message)
    end

	def decrypt_key(key_wrap_cipher, private_key, ssl_padding=OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      # TODO: Encrypted method is assumed t obe rsa-oaep-mgf1p 
      from_key = OpenSSL::PKey::RSA.new(private_key)
      key_wrap_str = Base64.decode64(key_wrap_cipher)
      from_key.private_decrypt(key_wrap_str, ssl_padding)        
	end

	def decrypt_cipher_data(key_cipher, cipher_data)
      cipher_data_str = Base64.decode64(cipher_data)      
      mcrypt_iv = cipher_data_str[0..15]
	  cipher_data_str = cipher_data_str[16..-1]
      # TODO: Encryption method algorithm is assumed to be aes256-cbc.
      cipher = OpenSSL::Cipher::Cipher.new("aes-128-cbc")
      cipher.decrypt
      cipher.key = key_cipher
      cipher.iv = mcrypt_iv  
	  cipher.padding = 0
      result = cipher.update(cipher_data_str)
#      puts cipher.final
	  result << cipher.final
	end

    def validate(soft = true, connect)
		
		# prime the IdP metadata before the document validation. 
		# The idp_cert needs to be populated before the validate_response_state method
		if settings 
			Onelogin::Saml::Metadata.new(settings, connect).get_idp_metadata
		end
		
      return false if validate_response_state(soft) == false
      return false if validate_conditions(soft) == false
		
		# Just in case a user needs to toss out the signature validation,
		# I'm adding in an option for it.  (Sometimes canonicalization is a bitch!)
		return true if options[:skip_validation]
		
		# document.validte populates the idp_cert
      return false if document.validate(settings, soft, connect) == false
		
		return true
    end

    def validate_response_state(soft = true)
      if response.empty?
        return soft ? false : validation_error("Blank response")
      end

      if settings.nil?
        return soft ? false : validation_error("No settings on response")
      end
		
		if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
        return soft ? false : validation_error("No fingerprint or certificate on settings")
      end
		
      true
    end
    
    def get_fingerprint
      if settings.idp_cert
        cert = OpenSSL::X509::Certificate.new(settings.idp_cert)
        Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(":")
      else
        settings.idp_cert_fingerprint
      end
    end

    def validate_conditions(soft = true)
      return true if conditions.nil?
      return true if options[:skip_conditions]

      if not_before = parse_time(conditions, "NotBefore")
        if Time.now.utc < not_before
          return soft ? false : validation_error("Current time is earlier than NotBefore condition")
        end
      end

      if not_on_or_after = parse_time(conditions, "NotOnOrAfter")
        if Time.now.utc >= not_on_or_after
          return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
        end
      end

      true
    end

    def parse_time(node, attribute)
      if node && node.attributes[attribute]
        Time.parse(node.attributes[attribute])
      end
    end
  end
end
