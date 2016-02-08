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
  messageTranslations = {
    "E: CA certificates must include commonName in subject" =>
    "N: CA certificates should include commonName in subject for compatibility"
  }
  if messageTranslations.has_key?(message)
    message = messageTranslations[message]
  end
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
    @errors = []
    @chain = {}
    if params[:lint].has_key?('host') and params[:lint][:host].length > 0
      begin
        @host = params[:lint][:host]
        uri = URI(@host)
        socket = TCPSocket.new uri.host, uri.port
        sslcontext = OpenSSL::SSL::SSLContext.new
        sslsocket = OpenSSL::SSL::SSLSocket.new socket, sslcontext
        sslsocket.hostname = uri.host
        sslsocket.connect
        sslsocket.peer_cert_chain.each do |cert|
          der = cert.to_der()
          begin
            messages = CertLint::CABLint.lint(der)
          rescue Exception => certlintException
            messages = ["F: Fatal error: CertLint::CABLint.lint failed"]
          end
          id = certToIdentifier(cert)
          @chain[id] = {}
          organizeMessages(@chain[id], messages)
        end
      rescue Exception => e
        @errors << e.message
      end
    end

    if params[:lint].has_key?('root')
      begin
        @root = params[:lint][:root]
        rootData = params[:lint][:root].read
        if rootData.include? '-BEGIN CERTIFICATE-'
          messages, der = CertLint::PEMLint.lint(rootData, 'CERTIFICATE')
        else
          messages = []
          der = rootData
        end
        begin
          messages += CertLint::CABLint.lint(der)
        rescue Exception => certlintException
          messages += ["F: Fatal error: CertLint::CABLint.lint failed"]
        end
        x509Cert = OpenSSL::X509::Certificate.new der
        id = certToIdentifier(x509Cert)
        @chain[id] = {}
        organizeMessages(@chain[id], messages)
      rescue Exception => e
        @errors << e.message
      end
    end
  end
end
