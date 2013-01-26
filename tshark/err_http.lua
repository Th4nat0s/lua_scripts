-- Print to request in http error
-- Sort and keep top 15 pages

-- (c) Thanat0s.trollprod.org 2013 

-- Usage: tshark -r mycap.pcap -Xlua_script:err_http.lua

-- How many winners
WINNERS = 5
-- Summarize per page or per First folder ?
FOLDER_CUT = true 

-- declare the tap on Request and Answers
TAP_HTTP_RQ = nil
TAP_HTTP_RP = nil

-- declare hashtables
TCP_STREAM = {}  -- Tcp flow
REQUEST_400 = {}  -- Error 400+
REQUEST_500 = {}  -- Error 500+

-- tap declaration, will create a event on each http.request and response
TAP_HTTP_RQ = Listener.new(nil,"http.request")
TAP_HTTP_RP = Listener.new(nil,"http.response")

-- will get the parsed header
code_f = Field.new("http.response.code")
stream_f = Field.new("tcp.stream")
request_f = Field.new("http.request.uri")
host_f = Field.new("http.host")

function PRINT_MAX(TABLE)
 -- For numer of winners
  for I = 1,WINNERS do
        local MAX = 0
        local MAXCOUNT = nil
        local MAXQUERY = nil
        -- Find the query with the Max 400 errors
        for QUERY,COUNT in pairs(TABLE) do
            if COUNT > MAX then
                MAXCOUNT = COUNT
                MAXQUERY = QUERY
            end
        end
        if MAXCOUNT == nil then
            debug ( "No more winners" )
            break
        end
        debug ( MAXCOUNT .. "," .. MAXQUERY)
        TABLE[MAXQUERY]=0
    end
end

-- this function is called at the end of the capture
function TAP_HTTP_RQ.draw()
	-- print access in error
	debug("Err 400 Winners: ")
	-- For numer of winners
	PRINT_MAX(REQUEST_400)
	debug("Err 500 Winners: ")
	PRINT_MAX(REQUEST_500)
end


-- theses function are called each time the filter of the tap matches
function TAP_HTTP_RQ.packet()
	-- Account the request in stream
	local STREAM = tonumber(tostring(stream_f()))
	local HOST = string.lower(tostring(host_f()))
	local REQUEST = string.lower(tostring(request_f()))
	-- they're always one request pending per tcp flow 
	-- we don't care about http pipelinning. it .never append ;)

	local SUB_REQUEST = nil 

	if FOLDER_CUT then
		SUB_REQUEST = string.find(REQUEST,'/',2)
		if SUB_REQUEST then
			if SUB_REQUEST < string.len(REQUEST) then
				SUB_REQUEST = SUB_REQUEST - 1
		 	end
			REQUEST = 	string.sub(REQUEST, 1  , SUB_REQUEST )
		 end
	end

	-- Si SUB_REQUEST is Nul here, find '?' 
	if not SUB_REQUEST then
		SUB_REQUEST = string.find(REQUEST,'?',2)
		if SUB_REQUEST then
			REQUEST = 	string.sub(REQUEST, 1  , SUB_REQUEST )
		end
	end

	TCP_STREAM[STREAM] = HOST .. REQUEST
	
end

function TAP_HTTP_RP.packet()
	-- if error code is > to 400 account it
	local code = tonumber(tostring(code_f()))

	-- error code is > 400 account it
	if (code >= 400 and code <= 499) then 
		local STREAM = tonumber(tostring(stream_f()))
		-- Get back the query 
		local QUERY = TCP_STREAM[STREAM]
		if REQUEST_400[QUERY] == nil then
			REQUEST_400[QUERY] = 1
		else
			REQUEST_400[QUERY] = REQUEST_400[QUERY]  + 1
		end
	end

	-- error code is > 500 account it
	if code >= 500 then 
		local STREAM = tonumber(tostring(stream_f()))
		-- Get back the query 
		local QUERY = TCP_STREAM[STREAM] 
		if REQUEST_500[QUERY] == nil then 
			REQUEST_500[QUERY] = 1 
		else
			REQUEST_500[QUERY] = REQUEST_500[QUERY]  + 1
		end
	end
end
