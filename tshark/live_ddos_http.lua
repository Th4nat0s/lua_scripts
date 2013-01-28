-- Count http requests by clients and display it in realtime
-- Usage tshark -Xlua_script:live_ddos_http.lua > /dev/null

-- declare the tap
tap_http_rq = nil

-- declare max client output
WINNERS = 15
-- How many sec between updates
TIMER = 15

-- declare ip list array
IP = {} 
CLIENT_IP = nil
NX_TICK = os.time() + TIMER

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
		local COUNT = nil
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

-- theses function are called each time the filter of the tap matches
function tap_http_rq.packet()
	-- Print status on every TIMER
	if os.time() > NX_TICK  then
		debug  ('--- top request on ' .. os.date() .. '----------------' )
		PRINT_MAX(IP)
		IP = {}
		NX_TICK = os.time () + TIMER
	end
	
	CLIENT_IP = tostring(client_f())
	if IP[CLIENT_IP] == nil then
		IP[CLIENT_IP] = 1
	else
		IP[CLIENT_IP] = IP[CLIENT_IP] + 1
	end
end

