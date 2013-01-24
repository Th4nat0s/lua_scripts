-- Count http requests by clients
-- Usage tshark -r mycap.pcap -Xlua_script:ddos_http.lua > /dev/null

-- declare the tap
tap_http_rq = nil

-- declare ip list array
IP = {} 
VALUE = nil
COUNT = nil
CLIENT_IP = nil

-- tap declaration, will create a event on each http.request
tap_http_rq = Listener.new(nil,"http.request")

-- will get the parsed header
client_f = Field.new("ip.src")

-- this function is called at the end of the capture
function tap_http_rq.draw()
	debug("Request Http Stats: " )
	for VALUE,COUNT in pairs(IP) do debug(COUNT .. "," .. VALUE) end
end

-- theses function are called each time the filter of the tap matches
function tap_http_rq.packet()
	CLIENT_IP = tostring(client_f())
	if IP[CLIENT_IP] == nil then
		IP[CLIENT_IP] = 1
	else
		IP[CLIENT_IP] = IP[CLIENT_IP] + 1
	end
end

