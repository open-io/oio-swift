-- Usage redis-cli --eval conversion_hierarchy_v2.lua [dry|run]
local get_key = function(key)
  local start = 0
  local index = 0
  for i=1,4 do
    index = string.find(key, ':',  start)
    if start == nil or start == index then
       return -1
     end
    start = index + 1
  end
  return start
end

local path = ''
local new_key = ''
local dry = true
if KEYS[1] == 'run' then
   dry = false
end
local keys = redis.call('KEYS', 'CS:*:*:*:*')
for _,k in pairs(keys) do
  local index = get_key(k)
  if index == -1 then
     redis.log(redis.LOG_WARNING, "Could not split key %s", k)
     break
  end
  new_key = string.sub(k, 0, index -2)
  path = string.sub(k, index)
  if dry then
     redis.log(redis.LOG_NOTICE, "HSET %s %s %d", new_key, path, 1)
     redis.log(redis.LOG_NOTICE, "DEL %s", k)
  else
    redis.call('HSET', new_key, path, 1)
    redis.call('DEL', k)
  end
end
