require 'certlint'
require 'socket'
require 'openssl'

# eh, maybe improve this.
def certToIdentifier cert
  return cert.subject.to_s
end

def messageToPair message
  # Why can't this be statically defined?
  messageTypeToDescription = {
    "I" => "Informational",
    "N" => "Notice",
    "W" => "Warning",
    "E" => "Error",
    "F" => "Failure",
  }
  pair = /(.): (.*)/.match(message).captures
  pair[0] = messageTypeToDescription[pair[0]]
  return pair
end

def organizeMessages(hash, messages)
  pairs = messages.map {|m| messageToPair(m)}
  pairs.each do |type, message|
    if not hash.has_key?(type)
      hash[type] = [message]
    else
      hash[type] << message
    end
  end
end

class LintController < ApplicationController
  def lint
    @chain = {}
    if params[:lint].has_key?('host') and params[:lint][:host].length > 0
      uri = URI(params[:lint][:host])
      socket = TCPSocket.new uri.host, uri.port
      sslcontext = OpenSSL::SSL::SSLContext.new
      sslsocket = OpenSSL::SSL::SSLSocket.new socket, sslcontext
      sslsocket.connect
      sslsocket.peer_cert_chain.each do |cert|
        der = cert.to_der()
        messages = CertLint::CABLint.lint(der)
        id = certToIdentifier(cert)
        @chain[id] = {}
        organizeMessages(@chain[id], messages)
      end
    end

    if params[:lint].has_key?('root')
      root = params[:lint][:root].read
      if root.include? '-BEGIN CERTIFICATE-'
        messages, der = CertLint::PEMLint.lint(root, 'CERTIFICATE')
      else
        messages = []
        der = root
      end
      messages += CertLint::CABLint.lint(der)
      x509Cert = OpenSSL::X509::Certificate.new der
      id = certToIdentifier(x509Cert)
      @chain[id] = {}
      organizeMessages(@chain[id], messages)
    end
  end
end
