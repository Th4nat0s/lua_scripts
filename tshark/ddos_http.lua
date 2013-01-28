-- Count http requests by clients
-- Usage tshark -r mycap.pcap -Xlua_script:ddos_http.lua > /dev/null

-- declare the tap
tap_http_rq = nil

-- declare max client output
WINNERS = 15

-- declare ip list array
IP = {} 
VALUE = nil
COUNT = nil
CLIENT_IP = nil

-- tap declaration, will create a event on each http.request
tap_http_rq = Listener.new(nil,"http.request")

-- will get the parsed header
client_f = Field.new("ip.src")

-- Print the most significants requests
function PRINT_MAX(TABLE)
	-- For numer of winners
	for I = 1,WINNERS do
    	local MAX = 0
        local MAXDATA = nil
        -- Find the query with the Max errors
        for DATA,COUNT in pairs(TABLE) do
            if COUNT > MAX then
                MAXDATA = DATA
				MAX = COUNT 
            end
        end
        -- If we can't find anything more
        if MAX == 0 then
            debug ( "No more winners" )
            break
        end
        -- Print out and remove this item
        debug ( MAX .. "," .. MAXDATA)
        TABLE[MAXDATA]=0
    end
end


-- this function is called at the end of the capture
function tap_http_rq.draw()
	debug("Request Http Stats: (Total Hits in cap) " )
	PRINT_MAX(IP)	
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

