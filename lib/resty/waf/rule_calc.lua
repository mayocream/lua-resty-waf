-- 规则编排
local _M = {}

local base = require "resty.waf.base"

local table_concat = table.concat
local table_insert = table.insert

_M.version = base.version

-- 生成 transform 的 KEY
local function _transform_collection_key(transform)
	if not transform then
		return nil
	end

	if type(transform) ~= 'table' then
		return tostring(transform)
	else
		return table_concat(transform, ',')
	end
end

local function _ignore_collection_key(ignore)
	local t = {}

	for i, j in ipairs(ignore) do
		table_insert(t, table_concat(j, ','))
	end

	return table_concat(t, ',')
end

-- 计算规则主键 (KEY)
local function _build_collection_key(var, transform)
	local key = {}
	-- TYPE 为规则查询的变量名
	key[1] = tostring(var.type)

	if var.parse ~= nil then
		table_insert(key, tostring(var.parse[1]))
		table_insert(key, tostring(var.parse[2]))
	end

	if var.ignore ~= nil then
		table_insert(key, tostring(_ignore_collection_key(var.ignore)))
	end

	table_insert(key, tostring(_transform_collection_key(transform)))

	return table_concat(key, "|")
end
_M.build_collection_key = _build_collection_key

-- 添加链规则 offset 
-- 接收参数  [规则链, 总规则数, 规则链起始 index]
local function _write_chain_offsets(chain, max, cur_offset)
	-- 规则链长度
	local chain_length = #chain
	-- 倒叙遍历 index
	local offset = chain_length

	-- 遍历规则
	for i = 1, chain_length do
		local rule = chain[i]

		-- 当前 chain 是否在最末尾
		if offset + cur_offset >= max then -- TODO 这个表达式可以简化
			rule.offset_nomatch = nil -- 默认, 没有下一条规则链了
			if rule.actions.disrupt == "CHAIN" then
				rule.offset_match = 1 -- 下次执行增加 1
			else
				rule.offset_match = nil -- 没有下一条规则链了
			end
		else
			rule.offset_nomatch = offset -- 跳过当前的剩余规则, 执行下一组规则
			rule.offset_match = 1
		end

		cur_offset = cur_offset + 1
		offset = offset - 1
	end
end

local function _write_skip_offset(rule, max, cur_offset)
	local offset = rule.skip + 1

	rule.offset_nomatch = 1

	if offset + cur_offset > max then
		rule.offset_match = nil
	else
		rule.offset_match = offset
	end
end

-- 规则集编排
function _M.calculate(ruleset, meta_lookup)
	-- 规则条目数
	local max = #ruleset
	-- 储存一条规则链
	local chain = {}

	-- 遍历规则集
	for i = 1, max do
		-- 单条规则
		local rule = ruleset[i]

		-- 是否有单独的配置项
		if not rule.opts then rule.opts = {} end

		-- 储存当前规则链
		chain[#chain + 1] = rule

		-- VAR 通常只有一个元素
		for i in ipairs(rule.vars) do
			local var = rule.vars[i]
			-- 计算规则主键
			var.collection_key = _build_collection_key(var, rule.opts.transform)
		end

		-- 规则的动作非 CHAIN, 可能是 [ACCEPT,DENY,DROP,IGNORE]
		if rule.actions.disrupt ~= "CHAIN" then
			-- 计算规则链增加的 step
			-- 传入参数 [规则链, 总规则数, 规则链起始 index]
			_write_chain_offsets(chain, max, i - #chain)

			if rule.skip then
				-- 跳过一组规则
				_write_skip_offset(rule, max, i)
			elseif rule.skip_after then
				local skip_after = rule.skip_after
				-- read ahead in the chain to look for our target
				-- when we find it, set the rule's skip value appropriately
				local j, ctr
				ctr = 0
				for j = i, max do
					ctr = ctr + 1
					local check_rule = ruleset[j]
					if check_rule.id == skip_after then
						break
					end
				end

				rule.skip = ctr - 1
				_write_skip_offset(rule, max, i)
			end

			-- 跳出当前规则链
			chain = {}
		end

		-- 根据 tags, msg 过滤
		if meta_lookup then
			if rule.msg then
				local msg = rule.msg

				if not meta_lookup.msgs[msg] then
					meta_lookup.msgs[msg] = { rule.id }
				else
					table_insert(meta_lookup.msgs[msg], rule.id)
				end
			end

			if rule.tag then
				for _, tag in ipairs(rule.tag) do
					if not meta_lookup.tags[tag] then
						meta_lookup.tags[tag] = { rule.id }
					else
						table_insert(meta_lookup.tags[tag], rule.id)
					end
				end
			end
		end
	end
end

return _M
