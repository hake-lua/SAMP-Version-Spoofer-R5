script_author("HAKE")
require "lib.moonloader"


function main()
    repeat wait(0) until isSampAvailable()

    R5Spoofer() -- ukljuceno ez

    while true do
        wait(0)
    end
end

function R5Spoofer()
    local ffi = require("ffi")
    local success, err = pcall(function()

        local RPC_CLIENT_JOIN   = 25
        local RPC_CLIENT_CHECK  = 103
        local R5_BITS = string.char(
            0x6c, 0xb0, 0xa2, 0x70, 0x6f, 0x64, 0x5c, 0x6d,
            0x65, 0x64, 0x69, 0x61, 0x5c, 0x74, 0x65, 0x5f,
            0x6c, 0x6f, 0x67, 0x6f, 0x2e, 0x70, 0x6e, 0x67,
            0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00
        )
        local _sendingResponse = false
        local R5Helper = nil

        local function initR5Helper()
            pcall(function()
                ffi.cdef[[
                    bool InitModules();
                    uint8_t ProcessClientCheck(uint8_t type, uint32_t addr, uint16_t offset, uint16_t count);
                    void ClearCache();
                ]]
            end)

            local dllPath = getWorkingDirectory() .. "\\R5Helper.dll"
            R5Helper = ffi.load(dllPath)
            if not R5Helper then
                print("[Nije moguce ucitati helper lib]")
                return false
            end

            if not R5Helper.InitModules() then
                print("[Nije moguce ucitati offsete iz lib-a]")
                return false
            end

            R5Helper.ClearCache()
            return true
        end

        local function sendClientCheckResponse(type, addr, result)
            _sendingResponse = true

            local bs = raknetNewBitStream()
            raknetBitStreamWriteInt8(bs, type)
            raknetBitStreamWriteInt32(bs, addr)
            raknetBitStreamWriteInt8(bs, result)

            raknetSendRpc(RPC_CLIENT_CHECK, bs)
            raknetDeleteBitStream(bs)

            _sendingResponse = false
        end

        local function onOutgoingRPC(id, bs)
            if id == RPC_CLIENT_CHECK and _sendingResponse then
                return true
            end

            if id == RPC_CLIENT_JOIN then
                local iVersion = raknetBitStreamReadInt32(bs)
                local byteMod = raknetBitStreamReadInt8(bs)
                local byteNameLen = raknetBitStreamReadInt8(bs)
                local szNickName = raknetBitStreamReadString(bs, byteNameLen)
                local uiChallengeResponse = raknetBitStreamReadInt32(bs)
                local byteAuthBSLen = raknetBitStreamReadInt8(bs)
                local pszAuthBullshit = raknetBitStreamReadString(bs, byteAuthBSLen)
                local cverlen = raknetBitStreamReadInt8(bs)
                local cver = raknetBitStreamReadString(bs, cverlen)

                raknetBitStreamResetWritePointer(bs)

                raknetBitStreamWriteInt32(bs, iVersion)
                raknetBitStreamWriteInt8(bs, byteMod)
                raknetBitStreamWriteInt8(bs, byteNameLen)
                for i = 1, byteNameLen do
                    raknetBitStreamWriteInt8(bs, string.byte(szNickName, i))
                end
                raknetBitStreamWriteInt32(bs, uiChallengeResponse)
                raknetBitStreamWriteInt8(bs, byteAuthBSLen)
                for i = 1, byteAuthBSLen do
                    raknetBitStreamWriteInt8(bs, string.byte(pszAuthBullshit, i))
                end

                local spoofedVer = "0.3.7-R5"
                raknetBitStreamWriteInt8(bs, #spoofedVer)
                for i = 1, #spoofedVer do
                    raknetBitStreamWriteInt8(bs, string.byte(spoofedVer, i))
                end

                for i = 1, #R5_BITS do
                    raknetBitStreamWriteInt8(bs, string.byte(R5_BITS, i))
                end

                print("[Client uspijesno spoofan na R5]")

                _sendingResponse = true
                raknetSendRpc(id, bs)
                _sendingResponse = false

                return false
            end

            return true
        end

        local function onIncomingRPC(id, bs)
            if id ~= RPC_CLIENT_CHECK then
                return true
            end

            local type  = raknetBitStreamReadInt8(bs)
            local addr  = raknetBitStreamReadInt32(bs)
            local offset = raknetBitStreamReadInt16(bs)
            local count = raknetBitStreamReadInt16(bs)

            if type == 0x05 and (addr == 0x520190 or addr == 0x5E8606) then
                local bsResp = raknetNewBitStream()
                raknetBitStreamWriteInt8(bsResp, 0x05)
                raknetBitStreamWriteInt32(bsResp, addr)
                raknetBitStreamWriteInt16(bsResp, 0xEF38)
                raknetBitStreamWriteInt16(bsResp, 0xC459)

                raknetSendRpc(RPC_CLIENT_CHECK, bsResp)
                raknetDeleteBitStream(bsResp)
                return false
            end

            if type == 0x02 then
                sendClientCheckResponse(type, 0x10000212, 0x01)
                return false
            end

            if not R5Helper then
                return true
            end

            local result = R5Helper.ProcessClientCheck(type, addr, offset, count)
            sendClientCheckResponse(type, addr, result)
            return false
        end

        if not initR5Helper() then
            print("[Neocekivana greska se dogodila, skripta se gasi]")
            return
        end

        addEventHandler("onReceiveRpc", onIncomingRPC)
        addEventHandler("onSendRpc", onOutgoingRPC)

        print("[Uspijesno ucitan R5Spoffer]")
    end)

    if not success then
        print(tostring(err))
    end
end
