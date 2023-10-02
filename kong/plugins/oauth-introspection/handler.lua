
local plugin = {
  PRIORITY = 1000, -- set the plugin priority, which determines plugin execution order
  VERSION = "0.1", -- version in X.Y.Z format. Check hybrid-mode compatibility requirements.
}

local utils = require "kong.plugins.oauth-introspection.utils"


-- runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)

  local errorMessage
  local errorDebug = ""
  local user_credentials
  local user_id_type
  local user_entitlements
  local valid_request


  for key, auth_methods in ipairs(plugin_conf.auth_methods) do 

    if auth_methods == "soap_headers_flow" then
      local errorDebugSoap
      user_credentials, errorMessage, errorDebugSoap = utils.get_credentials_soap(plugin_conf.token_location_xpath, plugin_conf.introspection_host, plugin_conf.cache_introspection)

      if user_credentials ~= nil then
        user_id_type = "userid"
      end

      if errorDebugSoap then
        kong.log.debug("AuthFlow: soap_headers - Error: ", errorDebugSoap)

        if plugin_conf.verbose then
          errorDebug = errorDebug .. "AuthFlow: soap_headers - Error: " .. errorDebugSoap
        end
      end
    end
  
    if auth_methods == "rest_headers_flow" then
      -- get jwt token from header 
      local jwtToken = kong.request.get_headers()[plugin_conf.token_location_header]
      if jwtToken ~= nil then
        jwtToken = string.match(jwtToken, " (.+)")
      end
  
      if jwtToken == nil then
        kong.log.debug("AuthFlow: rest_headers - Error: token not found or incorrect")

        if plugin_conf.verbose then
          errorDebug = errorDebug .. "AuthFlow: rest_headers - Error: token not found or incorrect"
        end
      end
  
      if jwtToken ~= nil then
        user_credentials, errorMessage = utils.introspect_token(plugin_conf.introspection_host, plugin_conf.cache_introspection, jwtToken)
      end

      if user_credentials ~= nil then
        user_id_type = "userid"
        kong.service.request.set_header("Authorization", user_credentials)
      end
    end

    if auth_methods == "user_id_flow" then

      local ipCheck, errorDebugUserid = utils.checkIpWhitelist(plugin_conf.iprange_whitelist)
      
      if ipCheck then
        user_credentials, errorDebugUserid = utils.get_userid(plugin_conf.userid_location_xpath)
      end

      if user_credentials ~= nil then
        user_id_type = "clientid"
      end

      if errorDebugUserid then
        kong.log.debug("AuthFlow: user_id - Error: ", errorDebugUserid)

        if plugin_conf.verbose then
          errorDebug = errorDebug .. "AuthFlow: user_id - Error: " .. errorDebugUserid
        end
      end
    end

    if errorMessage or user_credentials then
      break
    end

  end

  if errorMessage == nil then
    user_entitlements, errorMessage = utils.get_entitlements(plugin_conf.entitlement_host, plugin_conf.cache_entitlement, user_credentials, user_id_type)
  end

  if errorMessage == nil then
    valid_request, errorMessage= utils.check_entitlements(user_entitlements, plugin_conf.entitlement_required)
  end

  if not valid_request and errorMessage == nil then
    errorMessage = "double check activated, please check code!"
  end

  if errorMessage then
    if plugin_conf.verbose then
      errorMessage = "{\"timestamp\":\"" .. ngx.time() .. "\", \"message\":\"Issue with OauthToken plugin!\", \"error\":\"" .. errorMessage .. "\", \"debug\":\"" .. errorDebug .. "\"}"
    else
      errorMessage = "{\"timestamp\":\"" .. ngx.time() .. "\", \"message\":\"Issue with OauthToken plugin!\", \"error\":\"" .. errorMessage .. "\"}"
    end

    return kong.response.exit(401, errorMessage, {
      ["Content-Type"] = "application/problem+json"
    })
  end

  kong.service.request.set_header("APIGW-Identity", plugin_conf.shared_secret)

end


-- return our plugin object
return plugin
