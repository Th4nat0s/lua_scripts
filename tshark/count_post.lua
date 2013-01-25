-- Count http post requests
-- Usage tshark -r mycap.pcap -Xlua_script:count_post.lua

-- declare the tap
tap_http_rq = nil

-- declare counters
C_POST = 0

-- tap declaration, will create a event on each http.request and response
tap_http_rq = Listener.new(nil,"http.request")

-- will get the parsed header
method_f = Field.new("http.request.method")

-- this function is called at the end of the capture
function tap_http_rq.draw()
	debug("Post Request: " .. C_POST)
end

-- theses function are called each time the filter of the tap matches
function tap_http_rq.packet()
	method = string.upper(tostring(method_f()))
	if method == "POST" then 
		C_POST = C_POST + 1
	end
end

