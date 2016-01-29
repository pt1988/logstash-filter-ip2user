# encoding: utf-8
require 'spec_helper'
require "logstash/filters/example"

describe LogStash::Filters::Example do
  describe "Set to start timer" do
    let(:config) do <<-CONFIG
      filter {
        timer {
          command => "start"
        }
      }
    CONFIG
    end

    sample("command" => "start/gettime") do
      expect(subject).to include("commond")
      expect(subject['command']).to eq('start')
    end
  end
end
