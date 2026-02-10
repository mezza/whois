# frozen_string_literal: true

require "spec_helper"

describe Whois::Client do
  describe "#initialize" do
    it "accepts a zero parameters" do
      expect { described_class.new }.not_to raise_error
    end

    it "accepts a settings parameter" do
      expect { described_class.new({ foo: "bar" }) }.not_to raise_error
    end


    it "accepts a timeout setting with a value in seconds" do
      client = described_class.new(timeout: 100)
      expect(client.timeout).to eq(100)
    end

    it "accepts a timeout setting with a nil value" do
      client = described_class.new(timeout: nil)
      expect(client.timeout).to be_nil
    end

    it "accepts a block" do
      described_class.new do |client|
        expect(client).to be_instance_of(described_class)
      end
    end


    it "defaults timeout setting to DEFAULT_TIMEOUT" do
      client = described_class.new
      expect(client.timeout).to eq(described_class::DEFAULT_TIMEOUT)
    end

    it "sets settings to given argument, except timeout" do
      client = described_class.new(timeout: nil, foo: "bar")
      expect(client.settings).to eq({ foo: "bar" })
    end
  end

  describe "#lookup" do
    it "converts the argument to string" do
      query = ["example", ".", "test"]
      query.instance_eval do
        def to_s
          join
        end
      end

      server = Whois::Server::Adapters::Base.new(:tld, "test", "whois.test")
      expect(server).to receive(:lookup).with("example.test")
      expect(Whois::Server).to receive(:guess).with("example.test").and_return(server)

      described_class.new.lookup(query)
    end

    it "converts the argument to downcase" do
      server = Whois::Server::Adapters::Base.new(:tld, "test", "whois.test")
      expect(server).to receive(:lookup).with("example.test")
      expect(Whois::Server).to receive(:guess).with("example.test").and_return(server)

      described_class.new.lookup("Example.TEST")
    end

    it "detects email" do
      expect {
        described_class.new.lookup("weppos@weppos.net")
      }.to raise_error(Whois::ServerNotSupported)
    end

    it "works with domain with no whois" do
      Whois::Server.define(:tld, "nowhois", nil, adapter: Whois::Server::Adapters::None)

      expect {
        described_class.new.lookup("domain.nowhois")
      }.to raise_error(Whois::NoInterfaceError, /no whois server/)
    end

    it "works with domain with web whois" do
      Whois::Server.define(:tld, "webwhois", nil, adapter: Whois::Server::Adapters::Web, url: "http://www.example.com/")

      expect {
        described_class.new.lookup("domain.webwhois")
      }.to raise_error(Whois::WebInterfaceError, /www\.example\.com/)
    end

    it "passes timeout to the server via settings" do
      server = Whois::Server::Adapters::Base.new(:tld, "test", "whois.test")
      expect(server).to receive(:lookup).with("example.test")
      expect(Whois::Server).to receive(:guess).with("example.test").and_return(server)

      client = described_class.new(timeout: 30)
      client.lookup("example.test")
      expect(server.options[:timeout]).to eq(30)
    end

    it "passes nil timeout to the server when set to nil" do
      server = Whois::Server::Adapters::Base.new(:tld, "test", "whois.test")
      expect(server).to receive(:lookup).with("example.test")
      expect(Whois::Server).to receive(:guess).with("example.test").and_return(server)

      client = described_class.new(timeout: nil)
      client.lookup("example.test")
      expect(server.options[:timeout]).to be_nil
    end
  end

  # FIXME: use RSpec metadata
  need_connectivity do
    describe "#query" do
      it "sends a query for given domain" do
        record = described_class.new.lookup("weppos.it")
        expect(record.match?(/Domain:\s+weppos\.it/)).to be(true)
        expect(record.match?(/Created:/)).to be(true)
      end
    end
  end
end
