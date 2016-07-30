local dns = require "dns"
local shortport = require "shortport"
local stdnse = require "stdnse"
local openssl = require "openssl"
local base64 = require "base64"

description = [[
  Checks DNSSEC configuration of a server.
  There are various parameters defined in RFCs for a DNSSEC configured server
  this script looks for most of the security parameters discussed
  in RFC 4033,4034,4035.
]]

---@usage
---@args
---@output

author = "Abhishek Singh"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

local function get_parameters()
  local input_table = {}

  input_table.zones = stdnse.get_script_args("dnssec-check-config.domains") or "unspecified"
  if input_table.zones == "unspecified" then
    stdnse.debug(1, "warning: domain not given, script will try few random string as domain name")
    local name = stdnse.get_hostname()
    if name and name ~= host.ip then
    end
  end
  if type(input_table.zones) == "string" then
    input_table.zones = {input_table.zones}
  end

  local default_list = {"SOA", "A", "AAAA"}
  input_table.records = stdnse.get_script_args("dnssec-check-config.records") or default_list
  return input_table
end

function print_r ( t )
    local print_r_cache={}
    local function sub_print_r(t,indent)
        if (print_r_cache[tostring(t)]) then
            print(indent.."*"..tostring(t))
        else
            print_r_cache[tostring(t)]=true
            if (type(t)=="table") then
                for pos,val in pairs(t) do
                    if (type(val)=="table") then
                        print(indent.."["..pos.."] => "..tostring(t).." {")
                        sub_print_r(val,indent..string.rep(" ",string.len(pos)+8))
                        print(indent..string.rep(" ",string.len(pos)+6).."}")
                    elseif (type(val)=="string") then
                        if pos ~= "data" then
                          print(indent.."["..pos..'] => "'..val..'"')
                        end
                    else
                        print(indent.."["..pos.."] => "..tostring(val))
                    end
                end
            else
                print(indent..tostring(t))
            end
        end
    end
    if (type(t)=="table") then
        print(tostring(t).." {")
        sub_print_r(t,"  ")
        print("}")
    else
        sub_print_r(t,"  ")
    end
    print()
end

Zone = {
  
  new = function (self, domain, host)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.options = {}
    o.options.domain = domain
    o.options.host = host
    o.options.dnskey = {}
    return o
  end,

  obtainkey = function (self)
    local status, result = dns.query(self.options.domain, {host = self.options.host.ip, dtype='DNSKEY', retAll=true, retPkt=true, dnssec=true})
    if result.answers then
      for num, reply in pairs(result.answers) do
        -- type for DNSKEY record is 48 and ZSK has flag value of 256 as per RFC 4034
        if reply['DNSKEY'] and reply.DNSKEY.flags == 256 then
          table.insert(self.options.dnskey, reply.DNSKEY)
        end
      end
    end
    --print_r(result)
    --os.exit()
  end,

  verifysig = function (self)
    --TODO handle multiple ZSK sent by server
    --self.opt  
  end,
 
  verifyRRset = function (self, recordtype)
    --TODO handle RRSET with more than two RRs
    print(recordtype)
    local status, result = dns.query(self.options.domain, {host = self.options.host.ip, dtype=recordtype, retAll=true, retPkt=true, dnssec=true})
    --print_r(result)
    --os.exit()
    if result.answers then
      for num, reply in pairs(result.answers) do
        if reply[recordtype] then
          for _, rrsig in pairs(result.answers) do
            if rrsig['RRSIG'] and rrsig.RRSIG.typecovered == reply.dtype then

              rrsig_rdata = string.unpack(">c" .. (rrsig.reslen - #rrsig.RRSIG.signature), rrsig.data, 1)
              local rr = string.pack(">zI2I2I4I2", reply.dname, reply.dtype, reply.class, reply.ttl, reply.reslen)
              local rr_data = string.pack(">zzI4I4I4I4I4", reply[recordtype].mname, reply[recordtype].rname, reply[recordtype].serial, reply[recordtype].refresh, reply[recordtype].retry, reply[recordtype].expire, reply[recordtype].minimum)
              rr = rr..rr_data
              signature = rrsig_rdata..rr
              local base = openssl.bignum_bin2bn(rrsig.RRSIG.signature)
              print(base64.enc(rrsig.RRSIG.signature))
              --print(openssl.bignum_bn2hex(openssl.bignum_bin2bn(signature)))
              --os.exit()
              --print_r(self.options.dnskey)
              for _, key_record in pairs(self.options.dnskey) do
                local exponent = openssl.bignum_bin2bn(key_record.publicKey.exponent)
                local modulus = openssl.bignum_bin2bn(key_record.publicKey.modulus)
                local result = openssl.bignum_mod_exp(base, exponent, modulus)
                result = openssl.bignum_bn2hex(result)
                print(result)
                --print(openssl.bignum_bn2hex(openssl.bignum_bin2bn(result)))
                os.exit()
                --print(#key_record.publicKey.modulus)
                --print(openssl.bignum_bn2hex(openssl.bignum_bin2bn(signature)))
                --print(openssl.bignum_bn2hex(openssl.bignum_bin2bn(openssl.sha1(signature))))
                --print(openssl.bignum_bn2hex(openssl.bignum_bin2bn(openssl.sha1("abcd"))))
                os.exit()
              end
            end
          end
        end
      end
    end
  end,   
}
portrule = shortport.port_or_service(53, "domain", {"tcp", "udp"})

action = function(host, port)
  local output, input = {}, {}
  input = get_parameters()
  --local keys = get_keys(input)
  for _, domain in pairs(input.zones) do
    local x = Zone:new(domain, host)
    x:obtainkey()
    for _, record_type in pairs(input.records) do
      x:verifyRRset(record_type)
    end
  end
  return stdnse.format_output(true, output)
end
