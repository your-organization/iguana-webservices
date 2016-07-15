local user = require 'iguana.user'

-- The iguana.user module can be helpful if for instance you have a web service for which you need
-- to authenticate. The module could be fleshed out more but it shows how one can query if a user
-- belongs to a given group and what their email address is.

-- http://help.interfaceware.com/v6/query-iguana-user-roleemail

function main()
   -- For efficiency you might want to put the user.open
   -- statement outside of the main function
   -- so it is only called once when the channel starts
   local Info = user.open()
   
   -- check if a user is in a group
   Info:userInGroup{user='admin', group='Administrators'}
   Info:userInGroup{user='admin', group='Users'}
   Info:userInGroup{user='somefella', group='Users'}
   
   -- Here we find out the email address of a user
   -- NOTE: If the result is nil it means email is not set for the "admin" user
   --       you can add an email address or query a different user
   local Info = Info:user{user='admin'}
   trace(Info.email)
end