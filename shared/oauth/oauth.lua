-- Please see http://help.interfaceware.com/v6/oauth-1-0-with-twitter

local oauth = {}

-- Read in the whole file, close it and return its contents.
oauth.readCertificate = function(Path)
   local File = io.open(Path)
   local Data = File:read("*a")
   File:close()
   return Data
end

-- Help documentation for oauth.readCertificate
local CertHelp = {
   Title = "oauth.readCertificate",
   Usage = "oauth.readCertificate{path=&lt;value&gt;}",
   Desc  = [[Read in a specified certificate file, close it and return its total contents 
(the file name should include the full path)]],
   ParameterTable = false,

   Parameters   = {
      { path  = { Desc = 'Certificate file name and path <u>string</u>.'        }},
   },

   Returns   = {
      { Desc = 'Contents of certificate file <u>string</u>' }
   }
}

help.set{input_function=oauth.readCertificate, help_data=CertHelp}


-- Generate a nonce. See https://en.wikipedia.org/wiki/Cryptographic_nonce.
oauth.makeNonce = function(InputData)
   return filter.hex.enc(crypto.digest{data=tostring(InputData), algorithm='sha1'})
end

-- Help documentation for oauth.makeNonce
local NonceHelp = {
   Title = "oauth.makeNonce",
   Usage = "oauth.makeNonce{data=&lt;value&gt;}",
   Desc  = [[Generate a nonce. See <a href="https://en.wikipedia.org/wiki/Cryptographic_nonce">Wikipedia Cryptographic nonce</a>]],
   ParameterTable = false,

   Parameters   = {
      { data  = { Desc = 'Data to convert to a cryptographic nonce <u>string</u>.'        }},
   },

   Returns   = {
      { Desc = 'Generated cryptographic nonce <u>string</u>' }
   }
}

help.set{input_function=oauth.makeNonce, help_data=NonceHelp}


-- Using + instead of %20 is outdated and breaks OAuth. This ensures that
-- spaces are encoded as %20 and not +. The proper version is known as
-- percent encoding.
function oauth.percentEncode(Data)
   local StrictResultData = filter.uri.enc(Data)
   StrictResultData = StrictResultData:gsub("+", "%%20")
   return StrictResultData
end

-- Help documentation for oauth.percentEncode
local EncodeHelp = {
   Title = "oauth.percentEncode",
   Usage = "oauth.percentEncode{data=&lt;value&gt;}",
   Desc  = [[Ensures that spaces are correctly encoded as %20 and not +.                        
<br><br>Using + instead of %20 is outdated
and breaks OAuth. The proper version (using %20) is known as percent encoding]],
   ParameterTable = false,

   Parameters   = {
      { data  = { Desc = 'The string to be converted <u>string</u>.'        }},
   },

   Returns   = {
      { Desc = 'A percent encoded string <u>string</u>' }
   }
}

help.set{input_function=oauth.percentEncode, help_data=EncodeHelp}


-- The following steps are specified by the OAauth RFC for building
-- the parameter string to be used in the signature base.
-- See https://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
local function makeOAuthParamStr(Table)
   -- 1. URI encode the keys and values.
   local EncodedTable = {}
   for k,v in pairs(Table) do
      EncodedTable[oauth.percentEncode(k)] = oauth.percentEncode(tostring(v))
   end

   -- 2. Sort alphabetically by key. In Lua this requires building an
   --    array using the keys, sorting it, then using that array to 
   --    index the table.
   local SortedKeys = {}
   for Key in pairs(Table) do
      table.insert(SortedKeys, Key)
   end

   table.sort(SortedKeys)

   -- 3. Build the string into a standard GET query string.
   local Out = ""
   for i in ipairs(SortedKeys) do
      Out = Out .. SortedKeys[i] .. "=" .. EncodedTable[SortedKeys[i]] .. "&"
   end

   -- Remove the final ampersand.
   Out = Out:sub(1, -2)
   trace(Out)

   return Out
end

oauth.buildSignature = function(Params)
   -- 1. Build the sorted parameter string.
   -- 1.a Gather all the arguments.
   local OAuthParams = {
      oauth_nonce            = Params.nonce,
      oauth_consumer_key     = Params.consumer_key,
      oauth_signature_method = Params.signature_method,
      oauth_timestamp        = Params.timestamp,
      oauth_token            = Params.access_token,
      oauth_version          = "1.0",
   }
  
   if Params.additional_params then
      for k,v in pairs(Params.additional_params) do
	      OAuthParams[k] = v
      end
   end

   -- 1.b makeOauthParamStr handles the details of OAuth.
   --     See it's implementation if you're interested.
   local OAuthParamString = makeOAuthParamStr(OAuthParams)

   -- 2. Build the signature base string.
   local SignatureBase = string.format("%s&%s&%s",
      Params.method,                  -- 2.a Start with the HTTP method (uppercase).
      oauth.percentEncode(Params.url),      -- 2.b Append the percent encoded URL.
      oauth.percentEncode(OAuthParamString) -- 2.c Append the percent encoded argument string.
   )
   
   -- 3. Read the private key off disk.
   --local PrivateKey = h.readAll(self.private_key_path)
   
   -- 4. Generate the signature.
   local SignatureOperation
   if Params.signature_method:find("HMAC") then
      SignatureOperation = crypto.hmac
   else
      SignatureOperation = crypto.sign
   end

   local Sig = SignatureOperation{
      key       = Params.key,
      data      = SignatureBase,
      algorithm = Params.signature_algorithm
   }

   -- 4.a Base64 encode the binary signature.
   return filter.base64.enc(Sig)
end

-- Help documentation for oauth.buildSignature
local SignatureHelp = {
   Title = "oauth.buildSignature",
   Usage = "oauth.buildSignature{nonce=&lt;value&gt;, consumer_key=&lt;value&gt;, signature_method=&lt;value&gt;, timestamp=&lt;value&gt;, access_token=&lt;value&gt;}",
   Desc  = "Create an Oauth authorization signature used for signing (encoded as Base64)",
   ParameterTable = true,

   Parameters = {
      { nonce            = { Desc = 'Nonce <u>string</u>.'                        }},
      { consumer_key     = { Desc = 'Consumer key <u>table</u>.'                  }},
      { signature_method = { Desc = 'Signature method <u>string</u>.'             }},
      { timestamp        = { Desc = 'Timestamp as Unix Epoch time <u>integer</u>.'}},
      { access_token     = { Desc = 'Access token <u>date</u>.'                   }},
   },

   Returns   = {
      { Desc = 'Base64 encoded signature <u>string</u>' }
   }
}

help.set{input_function=oauth.buildSignature, help_data=SignatureHelp}


oauth.buildAuthHeader = function(Params)
   -- 5. Build the header string. Note that the header string contains
   --    oauth_signature but the sorted argument string does not.
   local AuthHeaderFormat    =  'OAuth '
                             .. 'oauth_consumer_key="%s", '
                             .. 'oauth_nonce="%s", '
                             .. 'oauth_signature="%s", '
                             .. 'oauth_token="%s", '
                             .. 'oauth_signature_method="%s", '
                             .. 'oauth_timestamp="%s", '
                             .. 'oauth_version="1.0"'
   -- 5.a Substitute the proper values.
   local AuthHeaderValue = string.format(AuthHeaderFormat,
      Params.consumer_key,
      Params.nonce,
      oauth.percentEncode(Params.signature),
      Params.access_token,
      Params.signature_method,
      Params.timestamp
   )
   
   return "Authorization: " .. AuthHeaderValue
end

-- Help documentation for oauth.buildAuthHeader
local AuthHeaderHelp = {
   Title = "oauth.buildAuthHeader",
   Usage = [[oauth.buildSignature{nonce=&lt;value&gt;, consumer_key=&lt;value&gt;, signature=&lt;value&gt;, 
                     signature_method=&lt;value&gt;, timestamp=&lt;value&gt;, access_token=&lt;value&gt;}]],
   Desc  = "Build an Oauth authorization header",
   ParameterTable = true,

   Parameters   = {
      { nonce            = { Desc = 'Nonce <u>string</u>.'                        }},
      { consumer_key     = { Desc = 'Consumer key <u>table</u>.'                  }},
      { signature        = { Desc = 'Signature <u>string</u>.'                    }},
      { signature_method = { Desc = 'Signature method <u>string</u>.'             }},
      { timestamp        = { Desc = 'Timestamp as Unix Epoch time <u>integer</u>.'}},
      { access_token     = { Desc = 'Access token <u>date</u>.'                   }},
   },

   Returns   = {
      { Desc = 'Oauth header <u>string</u>' }
   }
}

help.set{input_function=oauth.buildAuthHeader, help_data=AuthHeaderHelp}


return oauth
