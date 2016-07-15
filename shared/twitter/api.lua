-- Please see http://help.interfaceware.com/v6/oauth-1-0-with-twitter

local oauth = require "oauth.oauth"

local twitter = {
	urls = {
	   post_tweet = 'https://api.twitter.com/1.1/statuses/update.json',
   },
   -- The algorithm to pass to Interfaceware's crypto API.
   signature_algorithm = 'sha1',
   -- The oauth signature method.
   signature_method = 'HMAC-SHA1',
}
twitter.__index = twitter

function twitter:connect(Params)
   setmetatable(Params, self)
   return Params
end

-- Help documentation for twitter:connect
local connectHelp = {
  Title = "twitter:connect",
   Usage = "twitter:connect{consumer_key=&lt;value&gt;, consumer_secret=&lt;value&gt;, access_token=&lt;value&gt; , token_secret=&lt;value&gt;}",
   Desc  = [[
Creates a Twitter connection using OAuth 1.0 and HMAC signing. To get the parameters to put into this API object
you will need to set up a <a href="https://apps.twitter.com/" rel="nofollow">Twitter App</a> 
and get the the API credentials . See <a href="http://help.interfaceware.com/v6/oauth-1-0-with-twitter">OAuth 1.0 with Twitter</a> 
for more information.
   ]],
   ParameterTable = true,

   Parameters = {
      { consumer_key    = { Desc='Client key for iFormBuilder API <u>string</u>.'     }},
      { consumer_secret = { Desc='Client secret for iFormBuilder API <u>string</u>.'  }},
      { access_token    = { Desc='Profile id for API iFormBuilder API <u>string</u>.' }},
      { token_secret    = { Desc='Cache request token (default = true) <u>string</u>.'}},
   },
   
   Examples = {[1]=[[<pre>
   local C = twitter:connect{
      consumer_key    = 'Your consumer key',
      consumer_secret = 'Your consumer secret',
      access_token    = 'Your access token',
      token_secret    = 'Your token secret',
      }</pre>]]},

   Returns   = {
      { Desc = 'Connection object for the Twitter API <u>table</u>' }
   },
      
   SeeAlso={{Title="OAuth 1.0 with Twitter", 
             Link="http://help.interfaceware.com/v6/oauth-1-0-with-twitter"},
            {Title="Source code for the twitter.api.lua module on github", 
             Link="https://github.com/interfaceware/iguana-webservices/blob/master/shared/twitter/api.lua"},
            {Title="Twitter Apps", 
             Link="https://apps.twitter.com/"},
            {Title="Twitter API reference", 
             Link="https://dev.twitter.com/rest/public"}},
}

help.set{input_function=twitter.connect, help_data=connectHelp}


function twitter:tweet(Status)
   trace(self.urls.post_tweet)
   local AuthHeader = self:_buildHeader(self.urls.post_tweet, "POST", {status=Status})
   local Result = net.http.post{
      url        = self.urls.post_tweet,
      live       = true,
      headers    = {AuthHeader},
      parameters = {status=Status}
   }
   return json.parse{data=Result}
end

-- Help documentation for twitter:tweet
local TweetHelp = {
   Title = "twitter:tweet",
   Usage = "twitter:tweet{[Status=&lt;value&gt;]}",
   Desc  = [[Create a tweet, this updates the authenticating user’s current status, also known as Tweeting. 
A Status is required, you can pass it in the query string or as a parameter. See 
<a href="https://dev.twitter.com/rest/reference/post/statuses/update/" rel="nofollow">POST statuses/update</a> 
in the Twitter API docs for more information.]],
   ParameterTable = false,

   Parameters   = {
      { status  = { Desc = 'Tweet status (optional only if included in query string) <u>string</u>.', Opt=true}},
   },

   Examples = {[1]=[[<pre>
   -- Query for a list of users
   local TweetResult = C:tweet(Status)</pre>]]},

   SeeAlso={{Title="Twitter POST statuses/update API reference", 
             Link="https://dev.twitter.com/rest/reference/post/statuses/update"},
            {Title="Twitter API reference", 
             Link="https://dev.twitter.com/rest/public"}},

   Returns   = {
      { Desc = 'Tweet response/result <u>table</u>' }
   }
}

help.set{input_function=twitter.tweet, help_data=TweetHelp}


function twitter:_buildHeader(Url, Method, additional_params)
   local Timestamp = os.ts.time()
   local Nonce = oauth.makeNonce(Timestamp)

   local Key = string.format("%s&%s",
      oauth.percentEncode(self.consumer_secret),
      oauth.percentEncode(self.token_secret)
   )
   
   local Signature = oauth.buildSignature{
      url    = Url,
      key    = Key,
      nonce  = Nonce,
      method = Method,
      timestamp     = Timestamp,
      consumer_key  = self.consumer_key,
      access_token  = self.access_token,
      signature_method    = self.signature_method,
      signature_algorithm = self.signature_algorithm,
      additional_params   = additional_params
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

-- Help documentation for twitter:_buildHeader
local buildHeaderHelp = {
   Title = "twitter:_buildHeader",
   Usage = [[twitter:_buildHeader{Url=&lt;value&gt;, Method=&lt;value&gt;, additional_params=&lt;value&gt;}]],
   Desc  = "Build a Twitter authorization header (includes creating the signature)",
   ParameterTable = false,

   Parameters   = {
      { Url               = { Desc = 'URL for Twitter API command <u>string</u>.'                               }},
      { Method            = { Desc = 'Command type either POST or GET <u>string</u>.'                           }},
      { additional_params = { Desc = 'Additional parameters (appended to the signature) <u>table</u>.', Opt=true}},
   },

   Examples = {[1]=[[<pre>
   -- Build a Twitter authorization header
   local AuthHeader = twitter:_buildHeader("https://api.twitter.com/1.1/statuses/update.json", "POST", {status=Status})</pre>]]},

   SeeAlso={{Title="Twitter POST statuses/update API reference", 
             Link="https://dev.twitter.com/rest/reference/post/statuses/update"},
            {Title="Twitter API reference", 
             Link="https://dev.twitter.com/rest/public"}},

   Returns   = {
      { Desc = 'Twitter authorization header <u>string</u>' }
   }
}

help.set{input_function=twitter._buildHeader, help_data=buildHeaderHelp}


return twitter
