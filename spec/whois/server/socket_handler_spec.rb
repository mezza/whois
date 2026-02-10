# frozen_string_literal: true

require "spec_helper"
require "whois/server/socket_handler"

describe Whois::Server::SocketHandler do
  describe "#call" do
    [Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ECONNREFUSED, Errno::ETIMEDOUT, Errno::EPIPE, SocketError].each do |error|
      it "re-raises #{error} as Whois::ConnectionError" do
        handler = described_class.new
        expect(handler).to receive(:execute).and_raise(error)

        expect {
          handler.call("example.test", "whois.test", 43)
        }.to raise_error(Whois::ConnectionError, "#{error}: #{error.new.message}")
      end

      it "executes a socket connection for given args" do
        socket = instance_double(Socket)
        expect(socket).to receive(:write).with("example.test\r\n")
        expect(socket).to receive(:read_nonblock).with(1024, exception: false).and_return("response data")
        expect(socket).to receive(:read_nonblock).with(1024, exception: false).and_return(nil)
        expect(socket).to receive(:close)

        expect(Socket).to receive(:tcp)
          .with("whois.test", 43, nil, nil, connect_timeout: 10)
          .and_return(socket)

        handler = described_class.new
        result = handler.call("example.test", "whois.test", 43)
        expect(result).to eq("response data")
      end
    end

    it "treats ECONNRESET as EOF when data has already been received" do
      socket = instance_double(Socket)
      expect(socket).to receive(:write).with("example.test\r\n")
      expect(socket).to receive(:read_nonblock).with(1024, exception: false).and_return("partial data")
      expect(socket).to receive(:read_nonblock).with(1024, exception: false).and_raise(Errno::ECONNRESET)
      expect(socket).to receive(:close)

      expect(Socket).to receive(:tcp)
        .with("whois.test", 43, nil, nil, connect_timeout: 10)
        .and_return(socket)

      handler = described_class.new
      result = handler.call("example.test", "whois.test", 43)
      expect(result).to eq("partial data")
    end

    it "raises ECONNRESET as ConnectionError when no data has been received" do
      socket = instance_double(Socket)
      expect(socket).to receive(:write).with("example.test\r\n")
      expect(socket).to receive(:read_nonblock).with(1024, exception: false).and_raise(Errno::ECONNRESET)
      expect(socket).to receive(:close)

      expect(Socket).to receive(:tcp)
        .with("whois.test", 43, nil, nil, connect_timeout: 10)
        .and_return(socket)

      handler = described_class.new
      expect {
        handler.call("example.test", "whois.test", 43)
      }.to raise_error(Whois::ConnectionError)
    end

    it "uses the provided timeout for connect and read" do
      socket = instance_double(Socket)
      expect(socket).to receive(:write).with("example.test\r\n")
      expect(socket).to receive(:read_nonblock).with(1024, exception: false).and_return(:wait_readable)
      expect(IO).to receive(:select).with([socket], nil, nil, 30).and_return(nil)
      expect(socket).to receive(:close)

      expect(Socket).to receive(:tcp)
        .with("whois.test", 43, nil, nil, connect_timeout: 30)
        .and_return(socket)

      handler = described_class.new
      handler.call("example.test", "whois.test", 43, timeout: 30)
    end
  end
end
