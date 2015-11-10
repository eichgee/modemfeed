-- Copyright 2014-2015 Sandor Balazsi <sandor.balazsi@gmail.com>
-- Licensed to the public under the Apache License 2.0.

local ipairs, string, tostring, table = ipairs, string, tostring, table
local assert, type, unpack = assert, type, unpack

local xmlrpc = require "xmlrpc"
local scgi = require "xmlrpc.scgi"

local SCGI_ADDRESS = "localhost"
local SCGI_PORT = 5000

module "rtorrent"

function map(array, func)
	local new_array = {}
	for i, v in ipairs(array) do
		new_array[i] = func(v)
	end
	return new_array
end

function alter(prefix, methods, postfix)
	methods = map(methods, function(method)
		if method == 0 then return method end
		if prefix then method = prefix .. method end
		if postfix then method = method .. postfix end
		return method
	end)
	return methods
end

function format(method_type, res, methods)
	local formatted = {}
	for _, r in ipairs(res) do
		local item = {}
		for i, v in ipairs(r) do
			item[methods[method_type == "d." and i or i + 1]:gsub("%.", "_")] = v
		end
		table.insert(formatted, item)
	end
	return formatted
end

function call(method, ...)
	local ok, res = scgi.call(SCGI_ADDRESS, SCGI_PORT, method, ...)
	assert(ok, string.format("XML-RPC call failed on client: %s", tostring(res)))
	return res
end

function multicall(method_type, filter, ...)
	local res = (method_type == "d.")
		and call(method_type .. "multicall2", "", filter, unpack(alter(method_type, {...}, "=")))
		or call(method_type .. "multicall", filter, unpack(alter(method_type, {...}, "=")))
	return format(method_type, res, {...})
end

function batchcall(methods, params, prefix, postfix)
	local p = type(params) == "table" and params or { params }
	local methods_array = {}
	for _, m in ipairs(alter(prefix, methods, postfix)) do
		table.insert(methods_array, {
			["methodName"] = m,
			["params"] = xmlrpc.newTypedValue(p, "array")
		})
	end
	local res = {}
	for i, r in ipairs(call("system.multicall", xmlrpc.newTypedValue(methods_array, "array"))) do
		res[methods[i]] = r[1]
	end
	return res
end

