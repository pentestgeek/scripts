#!/usr/bin/ruby
#
# Author: zeknox - www.pentestgeek.com
#
# Description: 	This script will pingsweep all networks defined
# 				in <ip_addrs.txt> and output live systems to hosts
# 				folder and raw nmap output is placed in pingsweep
# 				folder that script was run from
#
#######################################################################
require 'netaddr'

# require program to run as root
if ENV["USER"] != "root"
  puts "\n[-] must run as root\n\n"
  exit
end

# check to make sure an argument was passed
if ARGV.size != 1 then
  puts "\n[-] Usage: ./start.rb <ip_addrs.txt>\n\n"
  exit
end

# import subnets from file into array
subnets = []
File.open(ARGV[0] , "r") do |file|
  while (subnet = file.gets)
	# validate all networks are cidr format
	if not subnet =~ /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}\b/
		puts "[-] #{subnet.chomp} is not a valid subnet"
		exit
	end
  	subnets << subnet
  end
end

# check if folder structure is created, if not create it
def check_exists(folder)
  if File.exists?(folder)
    return true
  else
    return false
  end
end

def create_folder(folder)
  system("mkdir #{folder}")
end

["pingsweep","hosts"].each do |folder|
  if !check_exists(folder)
    create_folder(folder)
  end
end

# method to convert cidr to network
def cidr_convert(net)
	net = NetAddr::CIDR.create("#{net.chomp}")
	net.network
end

# method to pingsweep network using nmap
def pingsweep(subnet)
	net = cidr_convert("#{subnet}")
	puts "[+] Running pingsweep scan against #{subnet.chomp}"
	system("nmap -sP #{subnet.chomp} -oA pingsweep/#{net}_sweep > /dev/null 2>&1")
end

# method to find live hosts
def livehosts(subnet)
	hosts = []
	net = cidr_convert("#{subnet}")
	File.open("pingsweep/#{net}_sweep.gnmap" , "r") do |file|
		# place only live ips in host array
		while (line = file.gets)
			next unless line.match(/Up/)
			hosts << line.split(' ').to_s.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/)
		end

        # write live hosts to a file hosts.txt
        if hosts.empty?
        	puts "[-] No live hosts in network: #{subnet.chomp}"
        else
	       	puts "[+] #{hosts.length} live hosts in #{subnet.chomp}"
        	puts "[+] Writing live hosts to file: #{Dir.pwd}/hosts/#{net}_hosts.txt\n"
        	
        	hosts.each do |host|
        		File.open("hosts/#{net}_hosts.txt" , 'a+') {|f| f.write("#{host}\n") }
        	end
        end
    end
end

subnets.each do |subnet|
	# pingsweep each subnet
	pingsweep(subnet)

	# write livehosts to file
	livehosts(subnet)
end