#!/usr/bin/ruby
##################
#File = livehosts.rb
#Author = Brandon McCann
#Last edited 10/2/2012

require 'rubygems'
require 'nmap/parser'

# make sure argument was passed to script
unless ARGV.length > 0
  puts "\nthis will list output of NSE scripts\n"
  puts "\nUSAGE:\t./nseoutput.rb <nmap xml file>\r\n\n"
  exit!
end

# parse the xml file for all scripts run
parser = Nmap::Parser.parsefile("#{ARGV[0]}")
parser.hosts do |host|
	host.scripts do | script|
		puts "[+] " + host.addr + " " + script.id + " " + script.output
	end
end