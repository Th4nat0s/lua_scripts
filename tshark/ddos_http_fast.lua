-- ACCOUNT GET/CONNECT/POST

-- Example get hit count 
-- Usage tshark -q -i eth5 -s 128 -a duration:15 -Xlua_script:myscript.lua 

-- declare max client output
WINNERS = 50

-- declare ip list array
IP = {}

-- on wich port does it hit ??
PORT = "0050"  -- 8012 en Hexa

-- tap declaration, will create a event on each http.request, answer or TCP packet
TAP_PCKT = Listener.new()

function hasbit(x, p)
          return x % (p + p) >= p
end

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
            print ( "No more winners" )
            break
        end
        -- Print out and remove this item
        print ( MAX .. "," .. MAXDATA)
        TABLE[MAXDATA]=0
    end
end


-- this function is called at the end of the capture
function TAP_PCKT.draw()
        print ("Request Http Stats: (Total Hits in cap) " )
        PRINT_MAX(IP)
end

function TAP_PCKT.packet(pinfo,buffer) --,tvb)
  if tostring(buffer(12,3)) == "080045" then   -- if Ethernet and IPv4
    if tostring(buffer(0x17,1)) == "06" then  -- if TCP
      local D_PORT = tostring(buffer(0x22+2,2))
      if D_PORT == PORT then
	  	  local S_IP = tostring(buffer(0x1E-4,4))
						
				-- Locate Data start
       	local TSIZE = tonumber(tostring(0x2E,1),16)
       	local DOFF = 0
       	if hasbit(TSIZE,4) then
          DOFF = DOFF + 1
        end
        if hasbit(TSIZE,5) then
          DOFF = DOFF +2
        end
        if hasbit(TSIZE,6) then
          DOFF = DOFF + 4
        end
        if hasbit(TSIZE,7) then
          DOFF = DOFF + 8
        end
        DOFF = DOFF * 4
        if buffer:len() > 0x2E+ DOFF + 8 then
				  DATA = tostring(buffer(0x2E+DOFF,8)) -- Get first 12 Bytes from payload
          -- Here we are facing a HTTP Request :
						if string.match(DATA,"47455420",1) or string.match(DATA,"434F4E4E45435420",1) or string.match(DATA,"4845414420",1) or string.match(DATA,"504F535420",1) then  -- "GET " or "POST " or "CONNECT " or "HEAD "
              TUPLE = S_IP
              IP[TUPLE] = (IP[TUPLE]  or 0) + 1  -- Increment Request Counter
            end

          end

        end
      end
  end
end
