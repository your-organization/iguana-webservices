-- This example module shows how to make use of the crypto API to sign a Json Web Token (JWT).
-- You can expand on this module or use the crypto APIs directly.

local jwt = {}

jwt.SupportedAlgos = {
	HS256 = { func=crypto.hmac, digest="sha256" },
	HS384 = { func=crypto.hmac, digest="sha384" },
	HS512 = { func=crypto.hmac, digest="sha512" },
	RS256 = { func=crypto.sign, digest="sha256" },
	RS384 = { func=crypto.sign, digest="sha384" },
	RS512 = { func=crypto.sign, digest="sha512" },
}

-- **NOTE** that JWTs use Base64 URL encoding **which differs** from Base64
-- encoding in that trailing '=' are removed, '/' becomes '_', and '+' becomes '-'.
-- JWT signing will not work if you use regular Base64 encoding!

jwt.base64UrlEncode = function(Data)
   local Base64UrlEncoded = filter.base64.enc(Data):gsub("=", "" )
                                                   :gsub("/", "_")
                                                   :gsub("+", "-")
   return Base64UrlEncoded
end

-- Help documentation for jwt.base64UrlEncode
local EncodeHelp = {
   Title = "jwt.base64UrlEncode",
   Usage = "jwt.base64UrlEncode{data=&lt;value&gt;}",
   Desc  = [[Encodes a JWT using Base64 URL encoding **which differs** from Base64 encoding 
in that trailing "=" are removed, "/" becomes "_", and "+" becomes "-".<br><br>
<b>Note</b>: JWT signing will not work if you use regular Base64 encoding!]],
   ParameterTable = true,

   Parameters   = {
      { data  = { Desc = 'JWT data to encode <u>string</u>.'        }},
   },

   Examples = {[1]=[[<pre>
   -- encode two strings for JWT
   local HeaderB64  = jwt.base64UrlEncode(HeaderStr)
   local PayloadB64 = jwt.base64UrlEncode(PayloadStr)</pre>]]},

   Returns   = {
      { Desc = 'Encoded JWT data <u>string</u>' }
   }
}

help.set{input_function=jwt.base64UrlEncode, help_data=EncodeHelp}

-- This function performs the actual JWT signature and returns the JWT token.
jwt.sign = function(Params)
   local HeaderStr  = json.serialize{data=Params.header,  compact=true}
   local PayloadStr = json.serialize{data=Params.payload, compact=true}
   local HeaderB64  = jwt.base64UrlEncode(HeaderStr)
   local PayloadB64 = jwt.base64UrlEncode(PayloadStr)
   local BaseStr    = HeaderB64 .. "." .. PayloadB64
   trace("BaseStr: "..BaseStr)
   local RequestedAlgo = jwt.SupportedAlgos[Params.algo]

   if not RequestedAlgo then
      error("Do not recognize value " .. Params.algo .. " for parameter 'algo'")
	end

   local Signature = RequestedAlgo.func{
      data      = BaseStr,
      key       = Params.key,
      algorithm = RequestedAlgo.digest
   }

   local SignatureB64 = jwt.base64UrlEncode(Signature)
   local Token = BaseStr .. "." .. SignatureB64

   return Token
end

-- Help documentation for jwt.sign
local SignHelp = {
   Title = "jwt.sign",
   Usage = "jwt.sign{header=&lt;value&gt;, payload=&lt;value&gt;, algo=&lt;value&gt;, key=&lt;value&gt;}",
   Desc  = "Sign a JWT header and payload with the specified algorithm and compute the signature and return assembled token",
   ParameterTable = true,

   Parameters   = {
      { header  = { Desc = 'JWT header as Lua table <u>table</u>.'        }},
      { payload = { Desc = 'JWT payload as a Lua table <u>table</u>.'     }},
      { algo    = { Desc = 'Algorithm to sign with <u>string</u>.'        }},
      { key     = { Desc = 'HMAC secret or RSA private key <u>string</u>.'}},
   },
   
   Examples = {[1]=[[<pre>
   -- Generate a signature
   local Token = jwt.sign{header={alg="HS256", typ="JWT"}, payload=Payload,
                          algo="HS256", key=ClientSecret}</pre>]]},

   Returns   = {
      { Desc = 'JWT signature token <u>string</u>' }
   }
}

help.set{input_function=jwt.sign, help_data=SignHelp}

return jwt
