-- local ffi             = require("ffi")
-- local libxml2         = require("xmlua.libxml2")
local resty_sha256    = require "resty.sha256"
local resty_str       = require "resty.string"
local http            = require "resty.http"
local xmlua           = require("xmlua")
local lrucache        = require "resty.lrucache"
local ipmatcher       = require "resty.ipmatcher"
local cjson           = require "cjson"

local cache = lrucache.new(512)

-- local loaded, xml2 = pcall(ffi.load, "xml2")

local _M = {}


-- Function to hash a given key using SHA256 and return it as a hexadecimal string.
local function hash_key(key)
  local sha256 = resty_sha256:new()
  sha256:update(key)
  return resty_str.to_hex(sha256:final())
end

local function make_request(endpoint, params)

  local params_request = {}
  params_request.method = params.method
  params_request.body = params.body
  params_request.headers = params.headers
  local timeout = params.timeout or 600

  local httpc = http.new()
  httpc:set_timeout(timeout)

  -- local proxyOpts = {
  --   http_proxy = params.proxy_url,
  --   https_proxy = params.proxy_url
  -- }
  -- httpc:set_proxy_options(proxyOpts)

  local res, err = httpc:request_uri(endpoint, params_request)

  -- return if error
  if err then
    kong.log.debug("antoine make_request error", err )
    return nil, err
  end

  -- always read response body, even if we discard it without using it on success
  local response_body = res.body
  local response_headers = res.headers
  local response_status = res.status
  local success = res.status < 400

  if not success then
    return nil, "status code: " .. tostring(res.status) .. " , body: " .. response_body
  end

  return response_body
end

local function call_introspection(endpoint, token)

  local response_body, err = make_request(endpoint, {
    method = "POST",
    body = token,
    headers = { 
      ["authorization"] = token
    },
    timeout = 20000
  })

  if err then
    return nil, "Error with make_request when retrieving introspection: " .. err
  end

  response_body = cjson.decode(response_body)

  if not response_body.active then
    return nil, "token is not active"
  end

  if not response_body.client_id then
    return nil, "no client_id"
  end

  return response_body.client_id
end

local function call_entitlements(endpoint, userid)

  local response_body, err = make_request(endpoint, {
    method = "POST",
    body = userid,
    headers = { 
      ["authorization"] = userid
    },
    timeout = 20000
  })

  if err then
    return nil, "Error with make_request when retrieving entitlements: " .. err
  end

  response_body = cjson.decode(response_body)

  if not response_body.entitlements then
    return nil, "no Entitlements"
  end

  return response_body.entitlements
end


function _M.check_entitlements(user_entitlements, plugin_entitlement)
  -- Iterate through the array and check if the string is present
  for i, v in ipairs(user_entitlements) do
    if v == plugin_entitlement then
      return true
    end
  end

  return nil, "user_entitlements are not authorized to access this service"
end

function _M.get_entitlements(endpoint, userid)
  -- Calculate a cache key based on the URL using the hash_key function.
  local token_cache_key = hash_key(userid)
  
  -- Try to retrieve the response_body from cache, with a TTL of 300 seconds, using the retrieveEntities function.
  local user_entitlements, err = kong.cache:get(token_cache_key, { ttl = 300 }, call_entitlements, endpoint, userid)

  if err then
    return nil, "Error while retrieving entitlements: " .. err
  end

  return user_entitlements
end

function _M.introspect_token(endpoint, token)

  -- Calculate a cache key based on the URL using the hash_key function.
  local token_cache_key = hash_key(token)

  -- Try to retrieve the response_body from cache, with a TTL of 300 seconds, using the retrieveEntities function.
  local client_id, err = kong.cache:get(token_cache_key, { ttl = 300 }, call_introspection, endpoint, token)

  if err then
    return nil, "Error while retrieving introspection: " .. err
  end

  return client_id
end


function _M.checkIpWhitelist(IpRange)
  local binary_remote_addr = ngx.var.binary_remote_addr
  
  if IpRange == nil then
    return nil, "IpRange is nil"
  end

  local matcher, err

  matcher = cache:get(IpRange)
  if not matcher then
    matcher, err = ipmatcher.new(IpRange)
    if err then
      return error("failed to create a new ipmatcher instance: " .. err)
    end

    cache:set(IpRange, matcher, 300)
  end

  local is_match
  is_match, err = matcher:match_bin(binary_remote_addr)
  if err then
    return error("invalid binary ip address: " .. err)
  end

  return is_match
end

function _M.get_userid(XPath)
  
-- Get SOAP envelope from the request
  local soapEnvelope = kong.request.get_raw_body()

  if soapEnvelope == nil then
    return nil, "body is nil"
  end
  
  -- Load the SOAP request XML into an XML document
  local success, document = pcall(xmlua.XML.parse, soapEnvelope)

  if success then
    -- Use XPath to select the desired element
    local selectedElement = document:search(XPath)

    -- Check if the element was found
    if #selectedElement > 0 then
        -- Extract the text content of the selected element
        local value = selectedElement[1]:text()
        return value
    else
        return nil, "Element not found"
    end
  else
    return nil, "Error when parsing: " .. document
  end

end


function _M.get_credentials_soap(XPath, endpoint)
  
  -- Get SOAP envelope from the request
    local soapEnvelope = kong.request.get_raw_body()
  
    if soapEnvelope == nil then
      return nil, "body is nil"
    end

    kong.log.debug("the soapEnvelope is:", soapEnvelope)

    -- Load the SOAP request XML into an XML document
    local success, document = pcall(xmlua.XML.parse, soapEnvelope)
  
    if success then

      kong.log.debug("antoine XPath is:", XPath)
      -- Use XPath to select the desired element
      local selectedElement = document:search(XPath)
      
      kong.log.debug("antoine after")

      -- Check if the element was found
      if #selectedElement > 0 then
        -- Extract the text content of the selected element
        local token = selectedElement[1]:text()

        if token == nil then
          kong.log.debug("method: soap_headers, token is nil")
          return nil
        end

        local user_credentials, errorMessage = _M.introspect_token(endpoint, token)

        if errorMessage then
          return nil, "Error while retrieving entities from cache for introspection: " .. errorMessage
        end

        selectedElement[1]:set_content(user_credentials)
        
        local options = {}
        options.include_declaration = false
        -- Serialize the updated XML document back to a string
        local updatedSoapRequest = document:to_xml(options)

        kong.log.debug("the updatedSoapRequest is:", updatedSoapRequest)

        kong.service.request.set_raw_body(updatedSoapRequest)

        return user_credentials
      else
        kong.log.debug("method: soap_headers, token not found")
        return nil
      end
    else
      kong.log.debug("Error when parsing: ", document)
      return nil
    end
    
  end


-- function find xpath
-- function _M.find_xpath(XMLtoSearch, XPath, XPathRegisterNs)
  
--   kong.log.debug("RouteByXPath, XMLtoSearch: " .. XMLtoSearch)

--   local context = libxml2.xmlNewParserCtxt()
--   local document = libxml2.xmlCtxtReadMemory(context, XMLtoSearch)
  
--   if not document then
--     return nil, "RouteByXPath, xmlCtxtReadMemory error, no document"
--   end
  
--   local context = libxml2.xmlXPathNewContext(document)
  
--   -- Register NameSpace(s)
--   kong.log.debug("XPathRegisterNs length: " .. #XPathRegisterNs)
  
--   -- Go on each NameSpace definition
--   for i = 1, #XPathRegisterNs do
--     local prefix, uri
--     local j = XPathRegisterNs[i]:find(',', 1)
--     if j then
--       prefix  = string.sub(XPathRegisterNs[i], 1, j - 1)
--       uri     = string.sub(XPathRegisterNs[i], j + 1, #XPathRegisterNs[i])
--     end
--     local rc = false
--     if prefix and uri then
--       -- Register NameSpace
--       rc = libxml2.xmlXPathRegisterNs(context, prefix, uri)
--     end
--     if rc then
--       kong.log.debug("RouteByXPath, successful registering NameSpace for '" .. XPathRegisterNs[i] .. "'")
--     else
--       kong.log.err("RouteByXPath, failure registering NameSpace for '" .. XPathRegisterNs[i] .. "'")
--     end
--   end

--   local object = libxml2.xmlXPathEvalExpression(XPath, context)
  
--   if object == ffi.NULL then
--     return nil, "RouteByXPath, object is null"
--   end

--   if object.nodesetval == ffi.NULL or object.nodesetval.nodeNr == 0 then        
--     return nil, "RouteByXPath, object.nodesetval is null"
--   end

--   local nodeContent = libxml2.xmlNodeGetContent(object.nodesetval.nodeTab[0])

--   return nodeContent

-- end

-- local function XSLTransform(soapEnvelope, user_credentials)
--   local errMessage  = ""
--   local err         = nil
--   local style       = nil
--   local xml_doc     = nil
--   local errDump     = 0
--   local xml_transformed_dump  = ""
--   local xmlNodePtrRoot        = nil
  
--   kong.log.debug("XSLT transformation, BEGIN: " .. XMLtoTransform)

--   local default_parse_options = bit.bor(ffi.C.XML_PARSE_NOERROR,
--                                       ffi.C.XML_PARSE_NOWARNING)

--   -- Load the XSLT document
--   local xslt_doc, errMessage = libxml2ex.xmlReadMemory(XSLT, nil, nil, default_parse_options, verbose)
  
--   if errMessage == nil then
--     -- Parse XSLT document
--     style = libxslt.xsltParseStylesheetDoc (xslt_doc)
--     if style ~= nil then
--       -- Load the complete XML document (with <soap:Envelope>)
--       xml_doc, errMessage = libxml2ex.xmlReadMemory(XMLtoTransform, nil, nil, default_parse_options, verbose)
--     else
--       errMessage = "error calling 'xsltParseStylesheetDoc'"
--     end
--   end

--   -- If the XSLT and the XML are correctly loaded and parsed
--   if errMessage == nil then
--     -- Transform the XML doc with XSLT transformation
--     local xml_transformed = libxslt.xsltApplyStylesheet (style, xml_doc)
    
--     if xml_transformed ~= nil then
--       -- Dump into a String the canonized image of the XML transformed by XSLT
--       xml_transformed_dump, errDump = libxml2ex.xmlC14NDocSaveTo (xml_transformed, nil)
--       if errDump == 0 then
--         -- If needed we append the xml declaration
--         -- Example: <?xml version="1.0" encoding="utf-8"?>
--         xml_transformed_dump = xmlgeneral.XSLT_Format_XMLDeclaration (
--                                             plugin_conf, 
--                                             style.version, 
--                                             style.encoding,
--                                             style.omitXmlDeclaration, 
--                                             style.standalone, 
--                                             style.indent) .. xml_transformed_dump

--         -- Remove empty Namespace (example: xmlns="") added by XSLT library or transformation 
--         xml_transformed_dump = xml_transformed_dump:gsub(' xmlns=""', '')
--         kong.log.debug ("XSLT transformation, END: " .. xml_transformed_dump)
--       else
--         errMessage = "error calling 'xmlC14NDocSaveTo'"
--       end
--     else
--       errMessage = "error calling 'xsltApplyStylesheet'"
--     end
--   end
  
--   if errMessage ~= nil then
--     kong.log.err ("XSLT transformation, errMessage: " .. errMessage)
--   end

--   -- xmlCleanupParser()
--   -- xmlMemoryDump()
  
--   return xml_transformed_dump, errMessage
  

-- end



-- function _M.replaceSoapHeaders (XPath, user_credentials)

--   -- Get SOAP envelope from the request
--   local soapEnvelope = kong.request.get_raw_body()

--   if soapEnvelope == nil then
--     return nil, "body is nil"
--   end
  
--   -- Load the SOAP request XML into an XML document
--   local success, document = pcall(xmlua.XML.parse, soapEnvelope)

--   if success then
--     -- Use XPath to select the desired element
--     local selectedElement = document:search(XPath)

--     -- Check if the element was found
--     if #selectedElement > 0 then
--         -- Extract the text content of the selected element
--         selectedElement[1]:set_text(user_credentials)
        
--         -- Serialize the updated XML document back to a string
--         local updatedSoapRequest = document:to_xml()

--         kong.service.request.set_raw_body(updatedSoapRequest)
--     else
--         return nil, "Element not found"
--     end
--   else
--     return nil, "Error when parsing: " .. document
--   end

-- end

-- return the lib
return _M
