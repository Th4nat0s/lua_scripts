-- SynSyn alone requests for a designated port

-- Usefull to find sick backends

-- Usage tshark -r mycap.pcap -Xlua_script:ddos_http.lua -q
-- need only capture with 96 byte and syn flag set

-- declare the tap
tap_tcp_rq = nil

-- declare max client output
WINNERS = 150

-- declare ip list array
IP = {}
VALUE = nil
COUNT = nil
CLIENT_IP = nil
MYCLIENTp = "8012"

-- tap declaration, will create a event on each http.request
tap_tcp_rq = Listener.new(nil,"tcp")

-- will get the parsed header
client_s = Field.new("ip.src")
client_d = Field.new("ip.dst")
Port_s = Field.new("tcp.srcport")
Port_d =  Field.new("tcp.dstport")
Syn = Field.new("tcp.flags.syn")
Ack = Field.new("tcp.flags.ack")

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
function tap_tcp_rq.draw()
  debug("Request Syn en trop: (Total Hits in cap) " )
  PRINT_MAX(IP)
end

-- theses function are called each time the filter of the tap matches
function tap_tcp_rq.packet()
if tostring(Syn()) == '1' then
-- debug ( 'Client ' .. tostring(client_s()) .. ' Syn'.. tostring(Syn() ) .. ' Ack'.. tostring(Ack()) .. " " ..  tostring(Port_s()) )
  if ((tostring(Ack()) == "0") and (tostring(Port_d()) == MYCLIENTp)) then
     Port = tostring(client_s()) ..':'.. tostring(Port_s()) .. '>' .. tostring(client_d()) .. ':' .. tostring(Port_d())
    if IP[Port] == nil then
      -- syn seen
      IP[Port] = 1
    else
      IP[Port] = IP[Port] + 1
  end
 end

 if ((tostring(Ack()) == "1") and (tostring(Port_s()) == MYCLIENTp)) then
--  # debug (Port .. "+++" ..tostring(Syn()) .. "++++" .. tostring(Ack()))
  Port =  tostring(client_d()) ..':'.. tostring(Port_d()) .. '>' .. tostring(client_s()) .. ':' .. tostring(Port_s())
if IP[Port] == nil then
      -- None to do... i see a ack without a syn
    else
       IP[Port] = IP[Port] - 1
    end
  end
end
end

