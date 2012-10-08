#!/usr/bin/env ruby

=begin

Copyright (c) 2012, Critical Research LLC [ admin/at/critical.io ]
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

    * Neither the name of the Critical Research LLC nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Large portions of this script were derived from the Metasploit Framework:


Copyright (C) 2006-2012, Rapid7 Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

    * Neither the name of Rapid7 LLC nor the names of its contributors
	  may be used to endorse or promote products derived from this software
	  without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=end

class Probes

	#
	# The probe definitions
	#

	def probe_pkt_dns(ip)
		data = [rand(0xffff)].pack('n') +
		"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+
		"\x07"+ "VERSION"+
		"\x04"+ "BIND"+
		"\x00\x00\x10\x00\x03"

		return [data, 53]
	end

	def probe_pkt_netbios(ip)
		data =
		[rand(0xffff)].pack('n')+
		"\x00\x00\x00\x01\x00\x00\x00\x00"+
		"\x00\x00\x20\x43\x4b\x41\x41\x41"+
		"\x41\x41\x41\x41\x41\x41\x41\x41"+
		"\x41\x41\x41\x41\x41\x41\x41\x41"+
		"\x41\x41\x41\x41\x41\x41\x41\x41"+
		"\x41\x41\x41\x00\x00\x21\x00\x01"

		return [data, 137]
	end

	def probe_pkt_portmap(ip)
		data =
		[
			rand(0xffffffff), # XID
			0,              # Type
			2,              # RPC Version
			100000,         # Program ID
			2,              # Program Version
			4,              # Procedure
			0, 0,   # Credentials
			0, 0,   # Verifier
		].pack('N*')

		return [data, 111]
	end

	def probe_pkt_mssql(ip)
		return ["\x02", 1434]
	end

	def probe_pkt_ntp(ip)
		data =
			"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3"
		return [data, 123]
	end


	def probe_pkt_sentinel(ip)
		return ["\x7a\x00\x00\x00\x00\x00", 5093]
	end

	def probe_pkt_snmp1(ip)
		name = 'public'
		xid = rand(0x100000000)
		pdu =
			"\x02\x01\x00" +
			"\x04" + [name.length].pack('c') + name +
			"\xa0\x1c" +
			"\x02\x04" + [xid].pack('N') +
			"\x02\x01\x00" +
			"\x02\x01\x00" +
			"\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01" +
			"\x01\x01\x00\x05\x00"
		head = "\x30" + [pdu.length].pack('C')
		data = head + pdu
		[data, 161]
	end

	def probe_pkt_snmp2(ip)
		name = 'public'
		xid = rand(0x100000000)
		pdu =
			"\x02\x01\x01" +
			"\x04" + [name.length].pack('c') + name +
			"\xa1\x19" +
			"\x02\x04" + [xid].pack('N') +
			"\x02\x01\x00" +
			"\x02\x01\x00" +
			"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01" +
			"\x05\x00"
		head = "\x30" + [pdu.length].pack('C')
		data = head + pdu
		[data, 161]
	end

	def probe_pkt_db2disco(ip)
		data = "DB2GETADDR\x00SQL05000\x00"
		[data, 523]
	end

	def probe_pkt_citrix(ip) # Server hello packet from citrix_published_bruteforce
		data =
			"\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00"
		return [data, 1604]
	end

	def probe_pkt_pca_st(ip)
		return ["ST", 5632]
	end

	def probe_pkt_pca_nq(ip)
		return ["NQ", 5632]
	end

end

probes = Probes.new
probes.methods.grep(/^probe_/).each do |m|
	data,port = probes.send(m, "127.0.0.1")
	name = m.to_s.gsub('probe_pkt_', '')
	path = ::File.join(::File.dirname(__FILE__), "..", "packets", "#{name}_#{port}.pkt")
	::File.open(path, "wb") do |fd|
		fd.write(data)
	end
end
