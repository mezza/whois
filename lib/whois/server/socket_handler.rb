# frozen_string_literal: true

#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2024 Simone Carletti <weppos@weppos.net>
#++


require "socket"
require "whois/errors"


module Whois
  class Server
    # The SocketHandler is the default query handler provided with the
    # Whois library. It performs the WHOIS query using a synchronous
    # socket connection.
    class SocketHandler
      CONNECT_TIMEOUT = 10
      READ_TIMEOUT = 10

      # Array of connection errors to rescue
      # and wrap into a {Whois::ConnectionError}
      RESCUABLE_CONNECTION_ERRORS = [
        SystemCallError,
        SocketError,
      ].freeze

      # Performs the Socket request.
      #
      # @todo *args might probably be a Hash.
      #
      # @param  [String] query
      # @param  [Array] args
      # @return [String]
      #
      def call(query, *args)
        execute(query, *args)
      rescue *RESCUABLE_CONNECTION_ERRORS => e
        raise ConnectionError, "#{e.class}: #{e.message}"
      end

      # Executes the low-level Socket connection.
      #
      # It opens the socket passing given +args+,
      # sends the +query+ and reads the response.
      #
      # @param  [String] query
      # @param  [Array] args
      # @return [String]
      #
      # @api private
      #
      def execute(query, host, port, local_host = nil, local_port = nil)
        client = Socket.tcp(host, port, local_host, local_port, connect_timeout: CONNECT_TIMEOUT)
        client.write("#{query}\r\n")

        content = +"".b
        begin
          while (chunk = client.read_nonblock(1024, exception: false))
            case chunk
            when :wait_readable
              IO.select([client], nil, nil, READ_TIMEOUT) || break
            when nil
              break
            else
              content << chunk
            end
          end
        rescue Errno::ECONNRESET
          # Some servers reset the connection after sending the response
          # instead of closing it gracefully. If we have data, treat it as EOF.
          raise if content.empty?
        end

        content.force_encoding("UTF-8")
      ensure
        client&.close
      end
    end
  end
end
