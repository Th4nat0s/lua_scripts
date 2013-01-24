-- Count http requests by type
-- Usage tshark -r mycap.pcap -Xlua_script:stat_http.lua

-- declare the tap
tap_http_rq = nil
tap_http_rp = nil

-- declare counters
C_GET = 0
C_POST = 0
C_HEAD = 0
C_OTHER = 0
R_100 = 0
R_200 = 0
R_300 = 0
R_400 = 0
R_500 = 0
R_666 = 0

-- tap declaration, will create a event on each http.request and response
tap_http_rq = Listener.new(nil,"http.request")
tap_http_rp = Listener.new(nil,"http.response")

-- will get the parsed header
method_f = Field.new("http.request.method")
code_f = Field.new("http.response.code")

-- this function is called at the end of the capture
function tap_http_rq.draw()
	debug("Request Http Stats: " .. (C_GET+C_POST+C_HEAD+C_OTHER))
	debug("* GET: " .. C_GET )
	debug("* POST: " .. C_POST )
	debug("* HEAD: " .. C_HEAD )
	debug("* OTHER: " .. C_OTHER )
end
function tap_http_rp.draw()
	debug("Response Http Stats: " .. (R_100+R_200+R_300+R_400+R_500+R_666))
	debug("* 1xx: " .. R_100 )
	debug("* 2xx: " .. R_200 )
	debug("* 3xx: " .. R_300 )
	debug("* 4xx: " .. R_400 )
	debug("* 5xx: " .. R_500 )
	debug("* Unk: " .. R_666 )
end


-- theses function are called each time the filter of the tap matches
function tap_http_rq.packet()
	method = string.upper(tostring(method_f()))
	if method == "GET" then C_GET = C_GET + 1
	elseif method == "POST" then C_POST = C_POST + 1
	elseif method == "HEAD" then C_HEAD = C_HEAD + 1
	else C_OTHER = C_OTHER + 1
	end
end

function tap_http_rp.packet()
  code = tonumber(tostring(code_f()))
 	if (code >= 200 and code <= 299) then R_200 = R_200 + 1
  elseif (code >= 100 and code <= 199) then R_100 = R_100 + 1
  elseif (code >= 300 and code <= 399) then R_300 = R_300 + 1
  elseif (code >= 400 and code <= 499) then R_400 = R_400 + 1
  elseif (code >= 500 and code <= 599) then R_500 = R_500 + 1
  else R_666 = R_666 + 1
  end
end

