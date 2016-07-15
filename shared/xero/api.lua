-- See http://help.interfaceware.com/v6/oauth-with-xero 

local oauth = require 'oauth.oauth'

-- Xero "class"
local xero = {
   urls = {
      users = 'https://api.xero.com/api.xro/2.0/Users',
      -- More API urls here ...
   },
   -- The algorithm to pass to Interfaceware's crypto API.
   signature_algorithm = 'sha1',
   -- The oauth signature method.
   signature_method = 'RSA-SHA1',
   access_token = "",
   private_key_path = iguana.project.files()["other/privatekey.pem"] or "upload your private certificate!",
}
xero.__index = xero

-- Constructor for Xero API objects.
function xero:connect(Params)
   local NewObj = Params or {}
   setmetatable(NewObj, self)
   -- Xero happens to use the same value for the OAuth
   -- access token and the consumer key.
   NewObj.access_token = NewObj.consumer_key
   return NewObj
end

-- Help documentation for xero:connect
local connectHelp = {
  Title = "xero:connect",
   Usage = "xero:connect{consumer_key=&lt;value&gt;, consumer_secret=&lt;}",
   Desc  = [[
Creates a Xero connection using OAuth 1.1 for authentication with RSA-SHA based signing. To get the parameters to put into this API object
you will need to set up a <a href="https://api.xero.com/" rel="nofollow">Xero App</a> 
and get the the API credentials. See <a href="http://help.interfaceware.com/v6/oauth-with-xero">OAuth 1.1 with Xero</a> 
for more information
   ]],
   ParameterTable = true,

   Parameters = {
      { consumer_key    = { Desc='Client key for the Xero API <u>string</u>.'   }},
      { consumer_secret = { Desc='Client secret for the Xero API <u>string</u>.'}},
   },
   
   Examples = {[1]=[[<pre>
   local C = Xero:connect{
      consumer_key    = 'Your consumer key',
      consumer_secret = 'Your consumer secret',
   }</pre>]]},

   Returns   = {
      { Desc = 'Connection object for the Xero API <u>table</u>' }
   },
      
   SeeAlso={{Title=" OAuth 1.1 with Xero", 
             Link="http://help.interfaceware.com/v6/oauth-with-xero"},
            {Title="Source code for the xero.api.lua module on github", 
             Link="https://github.com/interfaceware/iguana-webservices/blob/master/shared/xero/api.lua"},
            {Title="Xero website", 
             Link="https://www.xero.com/"},
            {Title="Xero API Documentation", 
             Link="https://developer.xero.com/documentation/"}},
}

help.set{input_function=xero.connect, help_data=connectHelp}


-- API calls
function xero:users()
   local AuthHeader = self:_signHeader(self.urls.users, "GET")
   
   local Result, Code = net.http.get{
      url = self.urls.users,
      live = true,
      headers = { AuthHeader }
   }
   
   if Code ~= 200 then
      -- Xero errors are percent encoded which conflicts with Lua patterns.
      error("Request failed. Result = " .. Result:gsub("%%20", "+"))
   end
   
   return xml.parse{data=Result}
end

-- Help documentation for xero:users
local usersHelp = {
   Title = "xero:users",
   Usage = "xero:users()",
   Desc  = [[Returns the users for the Xero organisation for your app. See 
<a href="https://developer.xero.com/documentation/api/users/">Users</a> in 
the Xero API docs for more information.]],
   ParameterTable = false,

   Parameters   = {},

   Examples = {[1]=[[<pre>
   -- Connect to Xero and query for a list of users
   local C = Xero:connect{
      consumer_key    = 'Your key',
      consumer_secret = 'Your secret',
   }
   -- Query for a list of users
   local UsersXml = C:users()]]},

   SeeAlso={{Title=" OAuth 1.1 with Xero", 
             Link="http://help.interfaceware.com/v6/oauth-with-xero"},
            {Title="Source code for the xero.api.lua module on github", 
             Link="https://github.com/interfaceware/iguana-webservices/blob/master/shared/xero/api.lua"},
            {Title="Xero API reference for the Users function", 
             Link="https://developer.xero.com/documentation/api/users"},
            {Title="Xero website", 
             Link="https://www.xero.com/"},
            {Title="Xero API Documentation", 
             Link="https://developer.xero.com/documentation/"}},

   Returns   = {
      { Desc = 'List of users <u>XML node tree</u>' }
   }
}

help.set{input_function=xero.users, help_data=usersHelp}


-- Private helpers (needs to use "self")
function xero:_signHeader(Url, Method)
   local Timestamp = os.ts.time()
   local Nonce = oauth.makeNonce(Timestamp)

   local Signature = oauth.buildSignature{
      url    = Url,
      key    = oauth.readCertificate(self.private_key_path),
      nonce  = Nonce,
      method = Method,
      timestamp     = Timestamp,
      consumer_key  = self.consumer_key,
      access_token  = self.access_token,
      signature_method    = self.signature_method,
      signature_algorithm = self.signature_algorithm,
   }

   local AuthHeader = oauth.buildAuthHeader{
      signature = Signature,
      nonce     = Nonce,
      timestamp = Timestamp,
      consumer_key = self.consumer_key,
      access_token = self.access_token,
      signature_method = self.signature_method,
   }
   
   return AuthHeader
end

-- Help documentation for xero:_signHeader
local signHeaderHelp = {
   Title = "xero:_signHeader",
   Usage = [[xero:_signHeader{Url=&lt;value&gt;, Method=&lt;value&gt;}]],
   Desc  = "Build a signed Xero authorization header.",
   ParameterTable = false,

   Parameters  = {
      { Url    = { Desc = 'URL for Xero API command <u>string</u>.'       }},
      { Method = { Desc = 'Command type either POST or GET <u>string</u>.'}},
   },

   SeeAlso={{Title=" OAuth 1.1 with Xero", 
             Link="http://help.interfaceware.com/v6/oauth-with-xero"},
            {Title="Source code for the xero.api.lua module on github", 
             Link="https://github.com/interfaceware/iguana-webservices/blob/master/shared/xero/api.lua"},
            {Title="Xero website", 
             Link="https://www.xero.com/"},
            {Title="Xero API Documentation", 
             Link="https://developer.xero.com/documentation/"}},

   Examples = {[1]=[[<pre>
   -- Build a signed Xero authorization header
   local AuthHeader = xero:_signHeader("https://api.xero.com/api.xro/2.0/Users", "GET")</pre>]]},

   Returns   = {
      { Desc = 'A Xero signed authorization header <u>string</u>' }
   }
}

help.set{input_function=xero._signHeader, help_data=signHeaderHelp}


return xero
