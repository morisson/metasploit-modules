require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner


	def initialize
		super(
				'Name' => 'SAPRouter Port Scanner',
				'Description' => 'This module allows for mapping ACLs and identify open/closed ports accessible on hosts through a saprouter',
				'Author' => ['Bruno Morisson <bm[at]integrity.pt>', # metasploit module
							'nmonkee'], # saprouter packet building code from sapcat.rb
				'References' =>
						[
						# General
						['URL', 'http://help.sap.com/saphelp_nw70/helpdata/EN/4f/992dfe446d11d189700000e8322d00/frameset.htm'],
						['URL', 'http://help.sap.com/saphelp_dimp50/helpdata/En/f8/bb960899d743378ccb8372215bb767/content.htm'],
						['URL', 'http://labs.mwrinfosecurity.com/blog/2012/09/13/sap-smashing-internet-windows/'] ,
						['URL','http://scn.sap.com/docs/DOC-17124'] # SAP default ports
						],
				'License' => MSF_LICENSE
		)

		register_options(
				[
						OptString.new('SAPROUTER_HOST', [true, "SAPRouter address", ""]),
						OptString.new('SAPROUTER_PORT', [true, "SAPRouter TCP port", "3299"]),
						OptString.new('MODE', [true, "Connection Mode: 0 for NI_MSG_IO (SAP), 1 for NI_RAW_IO (TCP), 2 for NI_ROUT_IO (ROUTER) ", "0"]),
						OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "3200-3299"]),
						OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000]),
						OptInt.new('CONCURRENCY', [true, "The number of concurrent ports to check per host", 10]),
				], self.class)

		deregister_options('RPORT')

	end


	def run_host(ip)

		timeout = datastore['TIMEOUT'].to_i
		ports = Rex::Socket.portspec_crack(datastore['PORTS'])
		mode = datastore['MODE'].to_i
		sap_host = datastore['SAPROUTER_HOST']
		sap_port = datastore['SAPROUTER_PORT']

		if ports.empty?
			print_error("Error: No valid ports specified")
			return
		end

		if mode > 2
			print_error("Error: invalid MODE: #{mode}")
			return
		end

		vprint_status("Scanning #{ip}")

		while (ports.length > 0)
			t = []
			r = []
			begin
				1.upto(datastore['CONCURRENCY']) do
					this_port = ports.shift
					break if not this_port
					t << framework.threads.spawn("Module(#{self.refname})-#{ip}:#{this_port}", false, this_port) do |port|

						route_data=''

						routes = {sap_host => sap_port, ip => port}

						ni_packet = 'NI_ROUTE' + [0, 2, 39, 2, mode, 0, 0, 1].pack('c*')

						first = false

						routes.each do |host, port|

							route_item = host.to_s.dup << [0].pack('c*') << port.to_s.dup << [0].pack('c*') << [0].pack('c*')

							if !first
								route_data = route_data << [route_item.length].pack('N') << route_item
								first = true
							else
								route_data = route_data << route_item
							end
						end

						ni_packet << [route_data.length - 4].pack('N') << route_data
						ni_packet = [ni_packet.length].pack('N') << ni_packet

						begin
							s = connect(false,
								{
								'RPORT' => sap_port,
								'RHOST' => sap_host,
								'ConnectTimeout' => (timeout / 1000.0)
								}
							)

							s.write(ni_packet, ni_packet.length)
							response = s.get()

							vprint_error("#{ip}:#{port} - response packet: #{response}")

							case response
								when /NI_RTERR/
									case response
										when /timed out/
											print_error ("#{ip}:#{port} - connection timed out")
										when /refused/
											print_error("#{ip}:#{port} - TCP closed")
											r << [ip, port, "closed"]
										when /denied/
											print_error("#{ip}:#{port} - blocked by ACL")
										when /invalid/
											print_error("#{ip}:#{port} - invalid route")
										when /reacheable/
											print_error("#{ip}:#{port} - unreachable")
										else
											vprint_error("#{ip}:#{port} - unknown error message")
									end
								when /NI_PONG/
									print_good("#{ip}:#{port} - TCP OPEN")
									r << [ip, port, "open"]
								else
									vprint_error("#{ip}:#{port} - unknown response")
							end

						rescue ::Rex::ConnectionRefused
							print_error("#{ip}:#{port} - Unable to connect to SAPRouter #{sap_host}:#{sap_port} - Connection Refused")

						rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
						rescue ::Rex::Post::Meterpreter::RequestError
						rescue ::Interrupt
							raise $!
						rescue ::Exception => e
							print_error("#{ip}:#{port} exception #{e.class} #{e} #{e.backtrace}")
						ensure
							disconnect(s) rescue nil
						end
					end
				end
				t.each { |x| x.join }

			rescue ::Timeout::Error
			ensure
				t.each { |x| x.kill rescue nil }
			end

			r.each do |res|
				report_service(:host => res[0], :port => res[1], :state => res[2])
			end
		end
	end

end
