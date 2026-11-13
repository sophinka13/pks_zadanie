-- dissector protokolu fiit meteo v1, pripraveny s pomocou ai
local meteo = Proto("fiitmeteo", "FIIT Meteo v1")
local kinds = {[0]="REGISTER", "ACK", "REJECT", "DATA", "RETRANSMIT", "KEEPALIVE", "KEEPALIVE_ACK", "REGISTER_ACK"}
local sensors = {[0]="ThermoNode", "WindSense", "RainDetect", "AirQuality"}
local reasons = {[1]="Invalid session/token", [2]="Duplicate sensor ID", [3]="Invalid values", [4]="Unsupported message/version", [5]="Sequence conflict", [6]="Invalid sender address"}
local f = {
    version = ProtoField.uint8("fiitmeteo.version", "Version", base.DEC, nil, 0xc0),
    kind = ProtoField.uint8("fiitmeteo.type", "Message type", base.DEC, kinds, 0x38),
    sensor = ProtoField.uint8("fiitmeteo.sensor", "Sensor type", base.DEC, sensors, 0x06),
    reserved = ProtoField.uint8("fiitmeteo.reserved", "Reserved", base.DEC, nil, 1),
    seq = ProtoField.uint32("fiitmeteo.seq", "Sequence / acknowledged sequence", base.DEC),
    token = ProtoField.uint64("fiitmeteo.token", "Session token", base.HEX),
    id_length = ProtoField.uint8("fiitmeteo.id_length", "ID length (UTF-8 bytes)", base.DEC),
    id = ProtoField.string("fiitmeteo.id", "Sensor ID"),
    reason = ProtoField.uint8("fiitmeteo.reason", "Rejection reason", base.DEC, reasons),
    crc = ProtoField.uint32("fiitmeteo.crc", "CRC32", base.HEX),
    calculated = ProtoField.uint32("fiitmeteo.crc_calculated", "Calculated CRC32", base.HEX),
    crc_ok = ProtoField.bool("fiitmeteo.crc_ok", "CRC correct"),
    payload = ProtoField.bytes("fiitmeteo.payload", "Payload"),
}
-- kazdy parameter ma meno, sirku, minimum, maximalny kod, mierku a jednotku
local layouts = {
    [0]={{"temperature",11,-50,1100,10,"°C"},{"humidity",10,0,1000,10,"%"},{"dew_point",11,-50,1100,10,"°C"},{"pressure",15,800,30000,100,"hPa"}},
    [1]={{"wind_speed",9,0,500,10,"m/s"},{"wind_gust",10,0,700,10,"m/s"},{"wind_direction",9,0,359,1,"°"},{"turbulence",4,0,10,10,""}},
    [2]={{"rainfall",13,0,5000,10,"mm"},{"soil_moisture",10,0,1000,10,"%"},{"flood_risk",2,0,3,1,""},{"rain_duration",6,0,60,1,"min"}},
    [3]={{"co2",13,300,4700,1,"ppm"},{"ozone",13,0,5000,10,"µg/m³"},{"air_quality_index",9,0,500,1,""}},
}
for _, layout in pairs(layouts) do
    for _, field in ipairs(layout) do
        f[field[1]] = ProtoField.double("fiitmeteo." .. field[1], field[1] .. (field[6] ~= "" and " (" .. field[6] .. ")" or ""))
    end
end
meteo.fields = f
local malformed = ProtoExpert.new("fiitmeteo.malformed", "Invalid FIIT Meteo packet", expert.group.MALFORMED, expert.severity.ERROR)
local bad_crc = ProtoExpert.new("fiitmeteo.bad_crc", "CRC32 mismatch; decoded fields are untrusted", expert.group.CHECKSUM, expert.severity.WARN)
meteo.experts = {malformed, bad_crc}
meteo.prefs.port = Pref.uint("UDP server port", 9000, "Server port; use Decode As for additional ports")
local udp = DissectorTable.get("udp.port")
local current_port = 9000

-- vypocita xor bez zavislosti od konkretnej verzie lua bitovej kniznice
local function xor32(a, b)
    local result, weight = 0, 1
    for _=1,32 do
        if a % 2 ~= b % 2 then result = result + weight end
        a, b, weight = math.floor(a/2), math.floor(b/2), weight*2
    end
    return result
end
local crc_table = {}
for index=0,255 do
    local value = index
    for _=1,8 do
        local odd = value % 2
        value = math.floor(value / 2)
        if odd == 1 then value = xor32(value, 0xedb88320) end
    end
    crc_table[index] = value
end

-- vypocita standardne crc32 rovnake ako python zlib.crc32
local function crc32(buffer, length)
    local crc = 0xffffffff
    for offset=0,length-1 do
        local index = xor32(crc % 256, buffer(offset,1):uint())
        crc = xor32(math.floor(crc/256), crc_table[index])
    end
    return xor32(crc, 0xffffffff)
end

-- prida expertnu chybu a ponecha dostupne polia viditelne
local function invalid(tree, text)
    tree:add_proto_expert_info(malformed, text)
end

-- dekoduje jeden udp datagram a kontroluje dlzky pred pristupom k poliam
function meteo.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    pinfo.cols.protocol = "FIITMETEO"
    local root = tree:add(meteo, buffer())
    if length < 17 or buffer:reported_len() > length then
        pinfo.cols.info = "Truncated FIIT Meteo packet"
        invalid(root, "Truncated packet: expected at least 17 captured bytes")
        return
    end
    local control = buffer(0,1):uint()
    local version = math.floor(control/64)
    local kind = math.floor(control/8) % 8
    local sensor = math.floor(control/2) % 4
    local seq = buffer(1,4):uint()
    pinfo.cols.info = kinds[kind] .. " " .. sensors[sensor] .. " #" .. seq
    for _, name in ipairs({"version", "kind", "sensor", "reserved"}) do root:add(f[name], buffer(0,1)) end
    root:add(f.seq, buffer(1,4))
    root:add(f.token, buffer(5,8))
    local checksum = buffer(length-4,4):uint()
    local calculated = crc32(buffer, length-4)
    root:add(f.crc, buffer(length-4,4))
    root:add(f.calculated, calculated):set_generated()
    root:add(f.crc_ok, checksum == calculated):set_generated()
    if checksum ~= calculated then root:add_proto_expert_info(bad_crc) end
    if version ~= 1 or control % 2 ~= 0 then invalid(root, "Unsupported version or nonzero reserved bit") end
    if seq == 0 then invalid(root, "Sequence number must be positive") end
    local zero_token = buffer(5,4):uint() == 0 and buffer(9,4):uint() == 0
    if (kind == 0 and not zero_token) or (kind ~= 0 and kind ~= 2 and zero_token) then
        invalid(root, "Invalid token for message type")
    end
    local payload_length = length - 17
    if kind == 0 then
        if payload_length < 1 then invalid(root, "Missing ID length"); return end
        local id_length = buffer(13,1):uint()
        root:add(f.id_length, buffer(13,1))
        if id_length == 0 or payload_length ~= id_length+1 then invalid(root, "Invalid REGISTER length"); return end
        local identifier = buffer(14,id_length):string()
        root:add(f.id, buffer(14,id_length), buffer(14,id_length):string(ENC_UTF_8))
        if identifier:match("^%s*$") then invalid(root, "Empty sensor ID") end
        if utf8 and not utf8.len(identifier) then invalid(root, "Invalid UTF-8 sensor ID") end
    elseif kind == 2 then
        if payload_length ~= 1 then invalid(root, "REJECT requires one reason byte"); return end
        root:add(f.reason, buffer(13,1))
        if not reasons[buffer(13,1):uint()] then invalid(root, "Unknown rejection reason") end
    elseif kind == 3 then
        local layout, total_bits = layouts[sensor], 0
        for _, field in ipairs(layout) do total_bits = total_bits + field[2] end
        if payload_length ~= math.ceil(total_bits/8) then invalid(root, "Invalid DATA payload length"); return end
        local payload = buffer(13,payload_length)
        local values_tree = root:add(f.payload, payload)
        local bit_offset = 0
        for _, field in ipairs(layout) do
            local code = payload:bitfield(bit_offset, field[2])
            local value = field[3] + code/field[5]
            local first_byte = math.floor(bit_offset/8)
            local byte_count = math.ceil((bit_offset%8+field[2])/8)
            values_tree:add(f[field[1]], buffer(13+first_byte,byte_count), value)
            if code > field[4] then invalid(values_tree, "Out-of-range code for " .. field[1]) end
            bit_offset = bit_offset + field[2]
        end
        local padding = payload_length*8-total_bits
        if padding > 0 and payload:bitfield(total_bits,padding) ~= 0 then invalid(values_tree, "Nonzero DATA padding") end
    elseif payload_length ~= 0 then
        invalid(root, "Unexpected payload for control message")
    end
end

-- pri zmene nastaveni presunie registraciu na zvoleny udp port
function meteo.prefs_changed()
    udp:remove(current_port, meteo)
    current_port = meteo.prefs.port
    if current_port > 0 and current_port <= 65535 then udp:add(current_port, meteo) end
end
udp:add(current_port, meteo)
udp:add_for_decode_as(meteo)
