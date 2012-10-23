#!/usr/bin/ruby -w
##############################################################################
# Usage: ruby nessus_http_api.rb <targets_file>
#
# This script accepts a file of IP addresses to be used for external testing. 
# The file is parsed and nmap run against the targets on off hours creating 
# output files which are uploaded to nessus. Nessus scans are then kicked
# off and when done results are emailed back to the user. 
#
# Written by smilingraccoon@gmail.com
##############################################################################
require 'uri'
require 'net/https'
require 'net/smtp'
require 'openssl'
require 'optparse'

## Constant variables, change as you see fit
MAIL_SERVER = 'smtp.comcast.net'
FROMEMAIL = 'scans@domain.com'
BOUNDARY = "---------------------------BOUNDARY--1234567890" 

# require program to run as root
if ENV["USER"] != "root"
  puts "\n[-] Must run as root\n\n"
  exit
end

options = {}
optparse = OptionParser.new do |opts|
	opts.banner = "\r\nhttp://www.pentestgeek.com/ - Written by smilingraccoon and Zeknox\r\n\r\n"
	opts.banner += "Usage: ruby nessus_http_api.rb [options] <targets_file>\r\n"
	opts.banner += "Example: nessus_http_api.rb -u root -p toor -c pentestgeek.com -e smilingraccoon@gmail.com targets.txt\r\n\r\n"
	options[:server] = "https://127.0.0.1:8834/"
	options[:port] = "8834"
	options[:username] = "root"
	options[:password] = nil
	options[:client] = "Clientname"
# Removes sleep till off hours and displays HTTP reponse codes
	options[:verbose] = false
	options[:sleep] = false
	options[:email] = nil
	options[:policy] = "Internal Network Scan"
	options[:attachment]
	
	opts.on( '-v', '--verbose', 'Output more information' ) do
		options[:verbose] = true
	end
	
	opts.on( '-n', '--server IP', 'The IP address of the Nessus server' ) do |url|
		options[:server] = "https://" + url + ":8834/"
	end

	opts.on( '--port PORT', 'The port of the Nessus server' ) do |url|
		options[:port] = "https://" + url + ":8834/"
	end
	
	opts.on( '-u', '--username USER', 'Username of Nessus account' ) do |user|
		options[:username] = user
	end
	
	opts.on( '-p', '--password PASS', 'Password to Nessus account' ) do |pass|
		options[:password] = pass
	end

	opts.on( '-c', '--client CLIENTNAME', 'The name of the client' ) do |client|
		options[:client] = client
	end
	
	opts.on( '-e', '--email EMAIL', 'The email to return results to' ) do |email|
		options[:email] = email
	end	

	opts.on( '-s', '--sleep', 'Sleep tille 6pm' ) do
		options[:sleep] = true
	end	

	opts.on( '-a', '--attach', 'Attaches the Nessus file to email' ) do
		options[:attachment] = true
	end	
	
	opts.on_tail( '-h', '--help', 'Display this screen' ) do
		puts opts
		exit
	end
	
	opts.parse!
end

# make sure argument was passed to script
unless ARGV.length > 0 
	puts "Usage: ruby nessus_http_api.rb <targets_file>"
	exit!
else
	log = ''
	targetFile = File.new(ARGV[0], "r")
	targetList = targetFile.read
	log << "Target list is: \n#{targetList}"
end

def make_connection (req, options)
	attempts = 0
	begin
		response = $https.request(req)
	rescue Exception 
		attempts = attempts + 1
		puts "\n[-] Connect could not be established...retrying"
		retry unless attempts > 2
		puts "\n[-] Cannot connect, check #{options[:server]}" unless attempts < 2
		exit
	end
	print response if options[:verbose]
	return response
end

# Grab directory name to be used in naming files
#customerName = /201[2-9]\/(.*?)\/.*/.match(File.absolute_path(targetFile))[1]
# Sleep till off hours
def delay_start()
	time = Time.new
	if time.hour < 17
		puts "Sleeping until off hours...#{17 - time.hour}:#{sprintf("%02d",60 - time.min)} to go"
		sleep 3600*(17 - time.hour) - 60*(time.min)
	end
end

def time()
	Time.new
end

# Kick off nmap scans
def execute_nmap(targetFile, client)
	begin
		time = time()
		nmapStart = time.inspect
		dir = ""+File.absolute_path(targetFile).chomp(File.basename(targetFile))
		targetFile.close
		system("if [ ! -d \"#{dir}nmap\" ]; then mkdir #{dir}nmap; fi")
		system("nmap --open -sT -n -r -vvv -P0 -oA #{dir}nmap/#{client+".log"} -iL #{File.absolute_path(targetFile)}")
		nmapScan = "#{dir}nmap/#{client}.log.xml"
		time = time()
		nmapDone = time.inspect
		return nmapStart, nmapDone, nmapScan, dir
	rescue
		puts "[-] We had issues running nmap"
		puts "[-] Exiting program"
		exit!
	end
end

# method to login to nessus and obtain a token
def nessus_login(log, options)
	begin
		# Parses URL
		url = URI.parse(options[:server])
		# Make HTTP post request to login page.
		req = Net::HTTP::Post.new(url.path + "login")
		# Set post data to login information.
		req.set_form_data({ "login" => options[:username], "password" => options[:password] })
		# Creates HTTPS for communication
		$https = Net::HTTP.new( url.host, url.port )
		$https.use_ssl = true
		$https.verify_mode = OpenSSL::SSL::VERIFY_NONE
		# Makes the connection to nessus and logs in. Return data from server is parse to acquire token.
		response = make_connection(req, options)
		token = /<token>(.*)<\/token>/.match(response.body)[1]
		log << "Token is: #{token}\n"
		# Makes new req to get policy list
		req = Net::HTTP::Post.new(url.path + "policy/list")
		req.set_form_data({ "token" => token })
		return req, url, token
	rescue Exception => e
		puts e.message
		puts "[-] We had issues logging into nessus"
		puts "[-] Exiting program"
		exit!
	end
end

# Sleep till off hours
delay_start if options[:sleep]

# run nmap against targetFile
puts "[+] Executing nmap against hosts"
nmapStart, nmapDone, nmapScan, dir = execute_nmap(targetFile, options[:client])
puts "\n[+] Completed executing nmap against hosts"

# login to nesus with credentials
puts "[+] Logging into Nessus with crednetials"
req, url, token = nessus_login(log, options)

policyID = ''
# Grabs the policy, iterate the lines and looks for the policy name. 
# When found sets previous policyID to var to be used when policy id is required by nessus.
make_connection(req, options).body.each_line do |line|
	next unless line =~ /policyID|policyName/
	if line =~ /policyID/
		policyID = /<policyID>(.*)<\/policyID>/.match(line)[1]
	else 
		policyName = /<policyName>(.*)<\/policyName>/.match(line)[1]
		if policyName == options[:policy]
			break
		end
	end
end

# Makes new req to upload the XML file from nmap
req = Net::HTTP::Post.new(url.path + "file/upload")

# Creates the body of the HTTPS request and sets proper HTTP content parameters for file

post_body = []
post_body << "--#{BOUNDARY}\r\n"
post_body << "Content-Disposition: form-data; name=\"Filedata\"; filename=\"#{File.basename(nmapScan)}\"\r\n"
post_body << "Content-Type: text/xml\r\n"
post_body << "\r\n"
post_body << File.read(nmapScan)
post_body << "\r\n--#{BOUNDARY}--\r\n"

# Adding parameters to the HTTP header
req["Content-Type"] = "multipart/form-data; boundary=#{BOUNDARY}"
req["Cookie"] = "token=#{token}"
req.body = post_body.join

#req.each_header {|key,value| puts "#{key} = #{value}"}
make_connection(req, options)

# Download a copy of the report
req = Net::HTTP::Post.new(url.path + "policy/download")
req.set_form_data({ "token" => token, "policy_id" => policyID })

# Set up parameters to pull correct policy
policySettings = {}
policySettings["token"] = token
policySettings["policy_id"] = policyID
policySettings["policy_name"] = options[:policy]

# Booleans to look for tags within the nessus configuration xml, first section is server preferences
serverPreferences = true
pluginPreferences = false
familySelection = false
individualPlugin = false
tempKey = ''
make_connection(req, options).body.each_line do |line|
	if line =~ /^<\/ServerPreferences>$/
		serverPreferences = false
	elsif line =~ /^<PluginsPreferences>$/
		pluginPreferences = true
	elsif line =~ /<FamilySelection>/
		familySelection = true
		pluginPreferences = false
	elsif line =~ /<IndividualPluginSelection>/
		individualPlugin = true
		familySelection = false
	end
	# If still in server preferences section, look for name and value and add to hash
	if(serverPreferences)
		if line =~ /<name>.*<\/name>/
			tempKey = /<name>(.*)<\/name>/.match(line)[1]
		elsif line =~ /<value>.*<\/value>/
			policySettings[tempKey] = /<value>(.*)<\/value>/.match(line)[1]
		end
	# If in plugins preferences section, look for fullName and preferenceValue and add to hash
	elsif(pluginPreferences)
		if line =~ /<fullName>.*<\/fullName>/
			tempKey = /<fullName>(.*)<\/fullName>/.match(line)[1]
		elsif line =~ /<preferenceValue[s]{0,1}>.*<\/preferenceValue[s]{0,1}>/
			policySettings[tempKey] = /<preferenceValue[s]{0,1}>(.*)<\/preferenceValue[s]{0,1}>/.match(line)[1]
		end
	# If in family selection section, look for FamilyName and Status and add to hash
	elsif(familySelection)
		if line =~ /<FamilyName>.*<\/FamilyName>/
			tempKey = "plugin_selection.family." + /<FamilyName>(.*)<\/FamilyName>/.match(line)[1]
		elsif line =~ /<Status>.*<\/Status>/
			policySettings[tempKey] = /<Status>(.*)<\/Status>/.match(line)[1]
		end
	elsif(individualPlugin)
		if line =~ /<PluginId>.*<\/PluginId>/
			tempKey = "plugin_selection.individual_plugin." + /<PluginId>(.*)<\/PluginId>/.match(line)[1]
		elsif line =~ /<Status>.*<\/Status>/
			policySettings[tempKey] = /<Status>(.*)<\/Status>/.match(line)[1]
		end
	end
end

# Makes new req to edit policy
req = Net::HTTP::Post.new(url.path + "policy/edit")

# Make the change to the Nmap nasl with new file.
policySettings["Nmap (XML file importer)[file]:File containing XML results :"] = File.basename(nmapScan)
req.set_form_data(policySettings)

# Log settings used and actual URL body for edit policy
nessus_log = ''
policySettings.each { |key, value| nessus_log << "#{key} is #{value}\n"}
log << "HTTP Request for edit is: \n#{req.body}"

make_connection(req, options)

targetList.tr_s('\n',',')
targetList.gsub(/\s/, ",")


# Setting up scan based on previously acquired policy ID and passes it nmap file name to use for report name.
req = Net::HTTP::Post.new(url.path + "scan/new")
req.set_form_data({ "token" => token, "policy_id" => policyID, \
"scan_name" => File.basename(nmapScan).chomp(".log.xml"), \
"target" => targetList })

time = Time.new
scanStart = time.inspect
uuid = ''
# Starts the scan, interates response and grabs the UUID of the scan for later use.
make_connection(req, options).body.each_line do |line|
	next unless line =~ /uuid/
	uuid = /<uuid>(.*)<\/uuid>/.match(line)[1]
end

req = Net::HTTP::Post.new(url.path + "scan/list")
req.set_form_data({ "token" => token })

print "\nStarting nessus scan"
# While the uuid of the scan is showing up in the scan lists sleep until it is no longer there (scan done)
while (make_connection(req, options).body =~ /<uuid>#{uuid}<\/uuid>/)
	3.times do
		sleep 10
		print "."
	end
end
# Timestamp for when the report finished
time = Time.new
scanDone = time.inspect
puts "\nScan done at #{scanDone}"

# Download the report 
req = Net::HTTP::Post.new(url.path + "file/report/download")
req.set_form_data({ "token" => token , "report" => uuid})
report = make_connection(req, options).body

# Setting up var scope
reportMsg = ''
currentHost = ''
hostArray = Array.new
overallRating = {"critical" => 0,"high" => 0,"medium" => 0,"low" => 0,"info" => 0}
rating = {"critical" => 0,"high" => 0,"medium" => 0,"low" => 0,"info" => 0}
hostCount = 0
portCount = 0
# For the downloaded report, parse it by host and pull statistics out
report.each_line do |line|
	# Find host IP, increase count by one, and reset the rating stats
	if line =~ /<ReportHost name=".*">/
		currentHost = /<ReportHost name="(.*)">/.match(line)[1]
		rating = {"critical" => 0,"high" => 0,"medium" => 0,"low" => 0,"info" => 0}
		hostCount += 1
	# Find end of host, write rating stats to var and re initial array of ports
	elsif line =~ /<\/ReportHost>/
		reportMsg << "IP: #{sprintf("%15s", currentHost)}\tC: #{sprintf("%2d", rating["critical"])}\tH: #{sprintf("%2d", rating["high"])}\tM: #{sprintf("%2d", rating["medium"])}\tL: #{sprintf("%2d", rating["low"])}\tI: #{sprintf("%2d", rating["info"])}\tPorts: #{hostArray.sort.join(", ")}\n" 
		portCount += hostArray.length
		hostArray = Array.new
	# Find line with port and finding, add port to array and rating to hashes of device and overall ratings
	elsif line =~ /<ReportItem .*port=".*"/
		temp = /<ReportItem .*port="(.*?)".*severity="(.*?)"/.match(line)
		hostArray.push(temp[1].to_i) unless hostArray.include?(temp[1].to_i) or temp[1]=="0"
		if temp[2] == "0"
			rating["info"] += 1
			overallRating["info"] += 1
		elsif temp[2] == "1"
			rating["low"] += 1
			overallRating["low"] += 1
		elsif temp[2] == "2"
			rating["medium"] += 1
			overallRating["medium"] += 1
		elsif temp[2] == "3"
			rating["high"] += 1
			overallRating["high"] += 1
		elsif temp[2] == "4"
			rating["critical"] += 1
			overallRating["critical"] += 1
		else
			# The f@$k you do to get here?
			puts temp[2]
		end
	end
end	
puts reportMsg
log << reportMsg
log << "Hosts scanned:\t\t#{sprintf("%2d", hostCount)}"
log << "Overall ratings:\t\tC: #{sprintf("%2d", overallRating["critical"])}\tH: #{sprintf("%2d", overallRating["high"])}\tM: #{sprintf("%2d", overallRating["medium"])}\tL: #{sprintf("%2d", overallRating["low"])}\tI: #{sprintf("%2d", overallRating["info"])}"

# Build email
mail =<<EOF
From: Nessus Scans <#{FROMEMAIL}>
To: Tom <#{options[:email]}>
Subject: External report done for #{options[:client]}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=#{BOUNDARY}

--#{BOUNDARY}
Content-Type: text/plain
Content-Transfer-Encoding:8bit

Nmap started:\t#{nmapStart}
Nmap ended:\t#{nmapDone}

Scan started:\t#{scanStart}
Scan ended:\t#{scanDone}

Hosts scanned:    \t#{hostCount}\t\tPorts scanned:#{sprintf("%2d", portCount)}
Total findings:\t\tC: #{sprintf("%2d", overallRating["critical"])}\tH: #{sprintf("%2d", overallRating["high"])}\tM: #{sprintf("%2d", overallRating["medium"])}\tL: #{sprintf("%2d", overallRating["low"])}\tI: #{sprintf("%2d", overallRating["info"])}

#{reportMsg}
EOF

# Encode the report in base64
encodedReport = [report].pack("m") if options[:attachment]

# Build attachment section of email and attach fil e
attachment =<<EOF
--#{BOUNDARY}
Content-Type: text/xml; name=\"#{File.basename(nmapScan)}\"
Content-Transfer-Encoding:base64
Content-Disposition: attachment; filename="#{File.basename(nmapScan)}"

#{encodedReport}
--#{BOUNDARY}--
EOF


if options[:attachment] 
	mail << attachment
end

begin 
	Net::SMTP.start(MAIL_SERVER, 25) do |smtp|
		smtp.sendmail(mail, FROMEMAIL,[options[:email]])
	end
rescue Exception => e  
	print "Exception occured: #{e}" 
end  

logFile = File.new("#{dir}script.log",'w')
logFile.write(log)
logFile.close

logFile = File.new("#{dir}nessus.log",'w')
logFile.write(nessus_log)
logFile.close