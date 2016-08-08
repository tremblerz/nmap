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

--table containing Algorithms supported in DNSSEC and their recommendation level
--TODO: Update this table
ALGO = {
  "RSAMD5 (Not Recommended)", --1
  "DH", --2
  "DSA (Optional)",  --3
  "RESERVED", --4
  "RSASHA1 (Mandatory)",  --5
  "DSA-NSEC3-SHA1", --6
  "RSASHA1-NSEC3-SHA1",  --7
  "RSASHA256",  --8
  "RESERVED",  --9
  "RSASHA512",  --10
  "RESERVED", --11
  "ECC-GOST",  --12
  "ECDSAP256SHA256",  --13
  "ECDSAP384SHA384",  --14
}

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
    o.output = {}
    o.rrset = {}
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
  end,

  verifyRRset = function (self)
    local verifyLabel = function(record)
      --print_r(rec_rrsig)
      local label_value = self.rrset.RRSIG.labels
      local owner_value = dns.num_labels(rrset[1].dname)
      return label_value <= owner_value
    end

    local verifyAlgo = function()
      return ALGO[rec_rrsig.RRSIG.algorithm]
    end

    local verifySignatureTime = function()
      return os.time() < rec_rrsig.RRSIG.sigexpire
    end

    local verifySignerName = function()
      return string.find(rec_rrsig.RRSIG.signee, self.options.domain, 1, true)
    end

    local verifyTypeCovered = function()
--      return rec_rrsig.RRSIG.typecovered == typecovered
    end

    local verifySignature = function()
      local rrs = ""
      local rrsig_rdata = string.unpack(">c" .. (rec_rrsig.RRSIG.reslen - #rr.RRSIG.signature), rec_rrsig.RRSIG.data, 1)
      for _, rr in ipairs(rrset) do
        local rr = string.pack(">zI2I2I4I2", rr.dname, rr.dtype, rr.class, rr.ttl, rr.reslen)
        local rdata = string.pack(">zzI4I4I4I4I4", rr.mname, rr.rname, rr.serial, rr.refresh, rr.retry, rr.expire, rr.minimum)
        rr = rr..rdata
        rrs = rrs .. rr
        --print(base64.enc(rrsig.RRSIG.signature))
        --print(openssl.bignum_bn2hex(openssl.bignum_bin2bn(signature)))
        --print_r(self.options.dnskey)
        --print(openssl.bignum_bn2hex(openssl.bignum_bin2bn(result)))
        --print(#key_record.publicKey.modulus)
        --print(openssl.bignum_bn2hex(openssl.bignum_bin2bn(signature)))
        --print(openssl.bignum_bn2hex(openssl.bignum_bin2bn(openssl.sha1(signature))))
        --print(openssl.bignum_bn2hex(openssl.bignum_bin2bn(openssl.sha1("abcd"))))
      end
      local signature = rrsig_rdata..rrs
      local base = openssl.bignum_bin2bn(rrsig.RRSIG.signature)
      for _, key_record in pairs(self.options.dnskey) do
        local exponent = openssl.bignum_bin2bn(key_record.publicKey.exponent)
        local modulus = openssl.bignum_bin2bn(key_record.publicKey.modulus)
        local result = openssl.bignum_mod_exp(base, exponent, modulus)
          result = openssl.bignum_bn2bin(result)
          print(result)
          if result == signature then
            return true
          end
      end
      --None of the keys verified the signature
      return false
    end,

    if not verifyLabel() then
      table.insert(output, "Label: verified")
      print("label verified")
    end
    if not verifySignatureTime() then
      print("signature time verified")
    end
    if not verifySignerName() then
      print("signer name verified")
    end
    if not verifySignature() then
    end
  end,

  getRecord = function(self, recordtype)
    --TODO handle RRSET with more than two RRs
    local status, result = dns.query(self.options.domain, {host = self.options.host.ip, dtype=recordtype, retAll=true, retPkt=true, dnssec=true})
    if result.answers then
      for _, record in ipairs(result.answers) do
        if record[recordtype] or record.RRSIG then
          table.insert(self.rrset, record)
        end  
      end
    end
  end,

  make_output = function(self)
    local output = {}
    table.insert(output, "Algorithm: " .. ALGO[rec_rrsig.RRSIG.algorithm])
    table.insert(output, "Signature Inception: " .. os.date("%x %X", rec_rrsig.RRSIG.sigincept, rec_rrsig.RRSIG.sigincept))
    table.insert(output, "Signature Expiration: " .. os.date("%x %X", rec_rrsig.RRSIG.sigexpire, rec_rrsig.RRSIG.sigexpire))
    table.insert(output, "Signer Name: " .. rec_rrsig.RRSIG.signee)
    table.insert(self.output[2], output)
  end,
}

portrule = shortport.port_or_service(53, "domain", {"tcp", "udp"})

action = function(host, port)
  local input = {}
  local x
  input = get_parameters()
  for _, domain in pairs(input.zones) do
    x = Zone:new(domain, host)
    x:obtainkey()
    for _, record_type in pairs(input.records) do
      print_r(x.output)
      x:getRecords(record_type)
      local status, reason = x:verifyzone()
      if status then
        table.insert(x.output, record_type .. ": verification successful")
      else
        table.insert(x.output, record_type .. ": verification unsuccessful (" .. reason .. ")")
      end
      local output={}
      table.insert(x.output, output)
      x:make_output()
    end
  end
  return stdnse.format_output(true, x.output)
end
