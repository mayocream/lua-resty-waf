local _M = {}

local base   = require "resty.waf.base"
local hdec   = require "resty.htmlentities"
local ffi    = require "ffi"
local logger = require "resty.waf.log"
local util   = require "resty.waf.util"

local ffi_cpy    = ffi.copy
local ffi_new    = ffi.new
local ffi_str    = ffi.string
local c_buf_type = ffi.typeof("char[?]")

local string_char   = string.char
local string_find   = string.find
local string_gmatch = string.gmatch
local string_gsub   = string.gsub
local string_len    = string.len
local string_lower  = string.lower
local string_match  = string.match
local string_sub    = string.sub

ffi.cdef[[
int js_decode(unsigned char *input, long int input_len);
int css_decode(unsigned char *input, long int input_len);
]]

_M.version = base.version

hdec.new() -- load the module on require

-- ffi 调用 libdecode
local loadlib = function()
	local so_name = 'libdecode.so'
	local cpath = package.cpath

    for k, v in string_gmatch(cpath, "[^;]+") do
        local so_path = string_match(k, "(.*/)")
        if so_path then
            -- "so_path" could be nil. e.g, the dir path component is "."
            so_path = so_path .. so_name

            -- Don't get me wrong, the only way to know if a file exist is
            -- trying to open it.
            local f = io.open(so_path)
            if f ~= nil then
                io.close(f)
                return ffi.load(so_path)
            end
        end
    end
end
local decode_lib = loadlib()

local function decode_buf_helper(value, len)
	local buf = ffi_new(c_buf_type, len)
	ffi_cpy(buf, value)
	return buf
end

_M.lookup = {
	base64_decode = function(waf, value)
		--_LOG_"Decoding from base64: " .. tostring(value)
		-- 使用 lua-resty-core 解码 base64
		local t_val = ngx.decode_base64(tostring(value))
		if t_val then
			--_LOG_"Decode successful, decoded value is " .. t_val
			return t_val
		else
			--_LOG_"Decode unsuccessful, returning original value " .. value
			return value
		end
	end,
	base64_encode = function(waf, value)
		--_LOG_"Encoding to base64: " .. tostring(value)
		local t_val = ngx.encode_base64(value)
		--_LOG_"Encoded value is " .. t_val
		return t_val
	end,
	-- [没有使用到]
	css_decode = function(waf, value)
		if not value then return end

		local len = #value
		local buf = decode_buf_helper(value, len)

		local n = decode_lib.css_decode(buf, len)

		return (ffi_str(buf, n))
	end,
	-- [没有使用到]
	cmd_line = function(waf, value)
		local str = tostring(value)
		str = ngx.re.gsub(str, [=[[\\'"^]]=], '',  waf._pcre_flags)
		str = ngx.re.gsub(str, [=[\s+/]=],    '/', waf._pcre_flags)
		str = ngx.re.gsub(str, [=[\s+[(]]=],  '(', waf._pcre_flags)
		str = ngx.re.gsub(str, [=[[,;]]=],    ' ', waf._pcre_flags)
		str = ngx.re.gsub(str, [=[\s+]=],     ' ', waf._pcre_flags)
		return string_lower(str)
	end,
	-- 替换空白字符, 正则匹配将多个空格字符 (空格/tab) 转换为单个空格
	compress_whitespace = function(waf, value)
		return ngx.re.gsub(value, [=[\s+]=], ' ', waf._pcre_flags)
	end,
	-- [没有使用到]
	hex_decode = function(waf, value)
		return util.hex_decode(value)
	end,
	-- [没有使用到]
	hex_encode = function(waf, value)
		return util.hex_encode(value)
	end,
	-- htmlentities 包, 针对 API 较多的情况应该避免解析 HTML
	html_decode = function(waf, value)
		local str = hdec.decode(value)
		--_LOG_"html decoded value is " .. str
		return str
	end,
	-- [没有使用到]
	js_decode = function(waf, value)
		if not value then return end

		local len = #value
		local buf = decode_buf_helper(value, len)

		local n = decode_lib.js_decode(buf, len)

		return (ffi_str(buf, n))
	end,
	-- [没有使用到]
	length = function(waf, value)
		return string_len(tostring(value))
	end,
	-- [经常使用]
	lowercase = function(waf, value)
		return string_lower(tostring(value))
	end,
	-- [没有使用到]
	md5 = function(waf, value)
		return ngx.md5_bin(value)
	end,
	-- [没有使用到]
	normalise_path = function(waf, value)
		while (ngx.re.match(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], waf._pcre_flags)) do
			value = ngx.re.gsub(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], '/', waf._pcre_flags)
		end
		return value
	end,
	-- [没有使用到]
	normalise_path_win = function(waf, value)
		value = string_gsub(value, [[\]], [[/]])
		return _M.lookup['normalise_path'](waf, value)
	end,
	-- [没有使用到]
	remove_comments = function(waf, value)
		return ngx.re.gsub(value, [=[\/\*(\*(?!\/)|[^\*])*\*\/]=], '', waf._pcre_flags)
	end,
	-- [没有使用到]
	remove_comments_char = function(waf, value)
		return ngx.re.gsub(value, [=[\/\*|\*\/|--|#]=], '', waf._pcre_flags)
	end,
	-- [没有使用到]
	remove_nulls = function(waf, value)
		return ngx.re.gsub(value, [[\0]], '', waf._pcre_flags)
	end,
	-- [没有使用到]
	remove_whitespace = function(waf, value)
		return ngx.re.gsub(value, [=[\s+]=], '', waf._pcre_flags)
	end,
	-- [没有使用到]
	replace_comments = function(waf, value)
		return ngx.re.gsub(value, [=[\/\*(\*(?!\/)|[^\*])*\*\/]=], ' ', waf._pcre_flags)
	end,
	-- [没有使用到]
	replace_nulls = function(waf, value)
		return ngx.re.gsub(value, [[\0]], ' ', waf._pcre_flags)
	end,
	-- [没有使用到]
	sha1 = function(waf, value)
		return ngx.sha1_bin(value)
	end,
	-- [没有使用到]
	sql_hex_decode = function(waf, value)
		if string_find(value, '0x', 1, true) then
			value = string_sub(value, 3)
			return util.hex_decode(value)
		else
			return value
		end
	end,
	-- [没有使用到]
	trim = function(waf, value)
		return ngx.re.gsub(value, [=[^\s*|\s+$]=], '')
	end,
	-- [没有使用到]
	trim_left = function(waf, value)
		return ngx.re.sub(value, [=[^\s+]=], '')
	end,
	-- [没有使用到]
	trim_right = function(waf, value)
		return ngx.re.sub(value, [=[\s+$]=], '')
	end,
	-- [经常使用]
	uri_decode = function(waf, value)
		return ngx.unescape_uri(value)
	end,
}

return _M
