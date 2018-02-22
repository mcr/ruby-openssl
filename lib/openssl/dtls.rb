# frozen_string_literal: false
=begin
= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2001 GOTOU YUUZOU <gotoyuzo@notwork.org>
  All rights reserved.

= Licence
  This program is licensed under the same licence as Ruby.
  (See the file 'LICENCE'.)
=end

require "openssl/buffering"
require "io/nonblock"

module OpenSSL
  module SSL
    class DTLSContext < SSLContext
      DEFAULT_PARAMS = { # :nodoc:
        :min_version => OpenSSL::SSL::TLS1_2_VERSION,
        :verify_mode => OpenSSL::SSL::VERIFY_PEER,
        :verify_hostname => true,
        :options => -> {
          opts = OpenSSL::SSL::OP_ALL
          opts &= ~OpenSSL::SSL::OP_DONT_INSERT_EMPTY_FRAGMENTS
          opts |= OpenSSL::SSL::OP_NO_COMPRESSION
          opts
        }.call
      }

      # call-seq:
      #    DTLSContext.new           -> ctx
      #    DTLSContext.new(:TLSv1)   -> ctx
      #    DTLSContext.new("SSLv23") -> ctx
      #
      # Creates a new DTLS context.
      #   This differs from an SSL context because the DTLS_method() is setup.
      #   This arranges to do the right UDP things which involve recvfrom()/sendto() rather than
      #   read/write() down at the BIO layer.
      #
      # If an argument is given, #ssl_version= is called with the value. Note
      # that this form is deprecated. New applications should use #min_version=
      # and #max_version= as necessary.
      def initialize(version = nil)
        super(version)
        # other stuff?
      end
    end

    class DTLSSocket < SSLSocket
      # parent does:
      # attr_reader :hostname
      attr_accessor :connected
      attr_accessor :dsthost, :dstport
      attr_accessor :non_blocking

      def connected?
        !!@connected
      end

      # call-seq:
      #   ssl.session -> aSession
      #
      # Returns the SSLSession object currently used, or nil if the session is
      # not established.
      def session
        SSL::Session.new(self)
      rescue SSL::Session::SessionError
        nil
      end

      def sync
        true
      end

      # generally used by CoAP mechanisms
      def sendmsg(message, size, dsthost, dstport)
        if !connected?
          # connect the socket up.
          #STDERR.puts "connecting to #{dsthost}:#{dstport}"
          @io.connect(dsthost, dstport)

          # start the DTLS.
          #STDERR.puts "DTLS to #{dsthost}:#{dstport}"
          connect
          @connected = true
        end
        syswrite(message)
      end

      alias_method :send, :sendmsg

      def recvfrom(size, flags = nil)
        if @non_blocking
          #STDERR.puts "starting recvfrom_nonblock sleep"
          sleep 1
          data = sysread_nonblock(size)
          #STDERR.puts "Received: #{data.size} bytes"
        else
          #STDERR.puts "starting recvfrom sleep"
          sleep 1
          data = sysread(size)
          #STDERR.puts "Received: #{data.size} bytes"
        end

        # fake as if it was recvfrom, which returns origin
        # XXX fix family here.
        [data, ["AF_INET6", @dstport, nil, @dsthost]]
      end

      private
    end

    ##
    # DTLSServer represents a TCP/IP server socket with Datagram TLS (DTLS)
    # XXX, unclear this is even useful.
    class DTLSServer < SSLServer
      # Creates a new instance of SSLServer.
      # * _srv_ is an instance of TCPServer.
      # * _ctx_ is an instance of OpenSSL::SSL::SSLContext.
      def initialize(svr, ctx)
        super(svr, ctx)
        @start_immediately = true  # not sure.
      end

      # See TCPServer#listen for details.
      def listen(backlog=5)
        # UDP sockets have no backlog configuration.
        # do nothing
        true
      end

      # See BasicSocket#shutdown for details.
      def shutdown(how=Socket::SHUT_RDWR)
        # UDP sockets do not have shutdown semantics, but TLS does
        @svr.shutdown(how)
      end

      # Works similar to TCPServer#accept.
      def accept
        # Socket#accept returns [socket, addrinfo].
        # TCPServer#accept returns a socket.
        # The following comma strips addrinfo.
        sock, = @svr.accept
        begin
          ssl = OpenSSL::SSL::DTLSSocket.new(sock, @ctx)
          ssl.sync_close = true
          ssl.accept if @start_immediately
          ssl
        rescue Exception => ex
          if ssl
            ssl.close
          else
            sock.close
          end
          raise ex
        end
      end

      # See IO#close for details.
      def close
        @svr.close
      end
    end
  end
end
