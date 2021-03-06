-- This example shows how to use the Twitter API using OAuth 1.0.

-- This example illustrates:
--   Fetching a list of users with the Xero API
--   Signing an OAuth 1 request

-- http://help.interfaceware.com/v6/oauth-with-xero 

local Xero = require 'xero.api'

local ArticleLink = "http://help.interfaceware.com/v6/oauth-with-xero"

local function work()
   local C = Xero:connect{
--      consumer_key    = 'Your consumer key',
--      consumer_secret = 'Your consumer secret',
      consumer_key    = '8VWYXTEFSJQME86YGSKPSPMVOKPYKB',
      consumer_secret = 'OWV1QBSMSVEZJH3XHDNYWB5FKTOQ5S',
   }
   -- Then we query a list of users
   local UsersXml = C:users() 

   -- Then we format a list of the users
   local Response = 'Example of Oauth 1.0 query to Xero users:\n--\n\n'
   Response = Response .. tostring(UsersXml)

   net.http.respond{body=Response, entity_type='text/plain'}
end   

function main(Data)
   local Success,Msg = pcall(work)
   if not Success then
      local Response = [[
      <p>
      To make this example work you will need to go to here:
      </p>   
      <a href="#LINK#">#LINK#</a>
      <p>   
      And follow these instructions.  The error raised was:
      </p>
      <pre>
      #ERROR#   
      </pre>
      ]]
      Response=Response:gsub("#LINK#", ArticleLink)
      Response=Response:gsub("#ERROR#", Msg)
      trace(Response)
      net.http.respond{body=Response}
   end
end
