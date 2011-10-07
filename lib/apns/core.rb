# Copyright (c) 2009 James Pozdena, 2010 Justin.tv
#  
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#  
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#  
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
 
module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  # Host for push notification service
  # production: gateway.push.apple.com
  # development: gateway.sandbox.apple.com
  @host = 'gateway.sandbox.push.apple.com'
  @port = 2195

  # Host for feedback service
  # production: feedback.push.apple.com
  # development: feedback.sandbox.apple.com
  @feedback_host = 'feedback.sandbox.push.apple.com'
  @feedback_port = 2196

  @cache_connections = false
  @connections = {}

  class << self
    attr_accessor :host, :port, :feedback_host, :feedback_port, :pem, :pass, :cache_connections, :cert
  end

  def self.establish_notification_connection
    if @cache_connections
      begin
        get_connection(host, port)
        return true
      rescue
      end
    end
    return false
  end

  def self.has_notification_connection?
    return has_connection?(host, port)
  end

  def self.send_notification(device_token, message)
    with_notification_connection do |conn|
      conn.write(packaged_notification(device_token, message))
      conn.flush
    end
  end
  
  def self.send_notifications(notifications)
    self.with_notification_connection do |conn|
      completed = []
      notifications.collect do |n|
        id = rand(10**9)
        conn.write(self.packaged_notification(n[0], n[1], id))
        completed << [ id, n ]
      end
      conn.flush
      if IO.select([ conn ], nil, nil, 5)
        conn.read(1).unpack('c') and conn.read(1).unpack('c')
        id = conn.read(4).unpack('L')[0]
        error_index = completed.index { |c| c[0] == id }
        completed = completed[error_index+1..-1].collect { |c| c[1] }
        send_notifications(completed)
      end
    end
  end
  
  def self.feedback
    apns_feedback = []
    with_feedback_connection do |conn|
      # Read buffers data from the OS, so it's probably not
      # too inefficient to do the small reads
      while data = conn.read(38)
        apns_feedback << parse_feedback_tuple(data)
      end
    end
    
    return apns_feedback
  end

  protected

  # Each tuple is in the following format:
  #
  #              timestamp | token_length (32) | token
  # bytes:  4 (big-endian)      2 (big-endian) | 32
  #
  # timestamp - seconds since the epoch, in UTC
  # token_length - Always 32 for now
  # token - 32 bytes of binary data specifying the device token
  #
  def self.parse_feedback_tuple(data)
    feedback = data.unpack('N1n1H64')
    {:feedback_at => Time.at(feedback[0]), :length => feedback[1], :device_token => feedback[2] }
  end

  def self.packaged_notification(device_token, message, id=rand(10**9))
    pt = self.packaged_token(device_token)
    pm = self.packaged_message(message)
    [1, id, 0, 0, 32, pt, 0, pm.size, pm].pack("cLNcca*cca*")
  end
  
  def self.packaged_token(device_token)
    [device_token.gsub(/[\s|<|>]/,'')].pack('H*')
  end
  
  def self.packaged_message(message)
    if message.is_a?(Hash)
      message.to_json
    elsif message.is_a?(String)
      '{"aps":{"alert":"'+ message + '"}}'
    else
      raise "Message needs to be either a hash or string"
    end
  end
  
  def self.with_notification_connection(&block)
    with_connection(host, port, &block)
  end

  def self.with_feedback_connection(&block)
    # Explicitly disable the connection cache for feedback
    cache_temp = @cache_connections
    @cache_connections = false

    with_connection(feedback_host, feedback_port, &block)

  ensure
    @cache_connections = cache_temp
  end
 
  private

  def self.open_connection(host, port)
    raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless pem
    self.cert ||= pem
    raise "Your pem file (#{pem}) does not exist!" unless File.exist?(pem)
    raise "Your cert file (#{cert}) does not exist!" unless File.exist?(cert)
    
    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(cert))
    context.key  = OpenSSL::PKey::RSA.new(File.read(pem), pass)

    retries = 0
    begin
      sock         = TCPSocket.new(host, port)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock, context)
      ssl.connect
      return ssl, sock
    rescue SystemCallError
      if (retries += 1) < 5
        sleep 1
        retry
      else
        # Too many retries, re-raise this exception
        raise
      end
    end
  end

  def self.has_connection?(host, port)
    @connections.has_key?([host,port])
  end

  def self.create_connection(host, port)
    @connections[[host, port]] = open_connection(host, port)
  end

  def self.find_connection(host, port)
    @connections[[host, port]]
  end

  def self.remove_connection(host, port)
    if has_connection?(host, port)
      ssl, sock = @connections.delete([host, port])
      ssl.close
      sock.close
    end
  end

  def self.reconnect_connection(host, port)
    remove_connection(host, port)
    create_connection(host, port)
  end

  def self.get_connection(host, port)
    if @cache_connections
      # Create a new connection if we don't have one
      unless has_connection?(host, port)
        create_connection(host, port)
      end

      ssl, sock = find_connection(host, port)
      # If we're closed, reconnect
      if ssl.closed?
        reconnect_connection(host, port)
        find_connection(host, port)
      else
        return [ssl, sock]
      end
    else
      open_connection(host, port)
    end
  end

  def self.with_connection(host, port, &block)
    retries = 0
    begin
      ssl, sock = get_connection(host, port)
      yield ssl if block_given?

      unless @cache_connections
        ssl.close
        sock.close
      end
    rescue Errno::ECONNABORTED, Errno::EPIPE, Errno::ECONNRESET
      if (retries += 1) < 5
        remove_connection(host, port)
        retry
      else
        # too-many retries, re-raise
        raise
      end
    end
  end
end
