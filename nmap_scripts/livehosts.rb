#!/usr/bin/ruby
##################
#File = livehosts.rb
#Author = Brandon McCann
#Last edited 8/7/2012

require 'rubygems'
require 'nmap/parser'

# make sure argument was passed to script
unless ARGV.length > 0
  puts "\nlivehosts.rb will take an nmap xml file and list live hosts to stdout \n"
  puts "\nUSAGE:\t./livehosts.rb <nmap xml file>\r\n\n"
  exit!
end

# parse the xml file for only hosts alive
parser = Nmap::Parser.parsefile("#{ARGV[0]}")
parser.hosts("up") do |host|
  puts "#{host.addr}"
end
