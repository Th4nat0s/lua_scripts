-- Find GET/CONNECT/POST HTTP requests answered by RST

-- Usefull to find sick backends or SLB
-- Usage tshark -r mycap.pcap -Xlua_script:myscript.lua > /dev/null

-- When a HTTPReq is found, a HTTP Post will clean IP. 
-- declare the tap
tap_tcp_rq = nil


-- declare max client output
WINNERS = 150

-- declare ip list array
IP = {}
VALUE = nil
COUNT = nil
CLIENT_IP = nil
NUM = 0
PORT = "0050"  -- 80 en Hexa

-- tap declaration, will create a event on each http.request, answer or TCP packet
TAP_PCKT = Listener.new()


function TAP_PCKT.packet(pinfo,buffer,tvb)
  NUM=NUM+1   -- Increment packet counter" 

  local PROTO = buffer(12,2)
	if tostring(buffer(12,3)) == "080045" then   -- if Ethernet and IPv4
		if tostring(buffer(0x17,1)) == "06" then  -- if TCP
			local D_PORT = tostring(buffer(0x22+2,2)) 
		  local S_PORT = tostring(buffer(0x22,2)) 
			if (S_PORT == PORT) or (D_PORT == PORT) then
		  	local FLAGS = tostring(buffer(0x2F,1))
				local S_IP = tostring(buffer(0x1A,4))
				local D_IP = tostring(buffer(0x1E,4))
				if buffer:len() > 0x42+12 then
			  	DATA = tostring(buffer(0x42,12)) -- Get first 12 Bytes from payload

					-- Here we are facing a HTTP Request : 
					if string.find(DATA,"47455420",1) or string.find(DATA,"434F4E4E45435420",1) or string.find(DATA,"4845414420",1) or string.find(DATA,"504F535420",1) then  -- "GET " or "POST " or "CONNECT " or "HEAD "  
						TUPLE = S_IP..S_PORT..D_IP..D_PORT
						IP[TUPLE] = (IP[TUPLE]  or 0) + 1  -- Increment Request Counter
						print (tostring(NUM) .. " " .. S_PORT .. " " ..  D_PORT .. " " .. S_IP .. " " .. D_IP .. " " .. FLAGS .." " .. DATA)
				  
					end

          -- Here we are facing a HTTP Response
					if (string.sub(DATA,1,14) == "485454502F312E" ) then -- if "^HTTP/1."
						print (tostring(NUM) .. " " .. S_PORT .. " " ..  D_PORT .. " " .. S_IP .. " " .. D_IP .. " " .. FLAGS .." " .. DATA)
						TUPLE = D_IP..D_PORT..S_IP..S_PORT
						IP[TUPLE] = (IP[TUPLE]  or 0) - 1  -- Decrement Request Counter
					end

					-- Here we are facing a TCP RESET
					RSET = math.floor(tonumber(FLAGS,16) / 2 ^ 2 ) % 2
					if RSET == 1 then
					  TUPLE = D_IP..D_PORT..S_IP..S_PORT
						if (( IP[TUPLE] or 0) ~= 0) then
							print(tostring(NUM) .. " RESET")
						end
					end
						
				end
			end
		end
  end
end


