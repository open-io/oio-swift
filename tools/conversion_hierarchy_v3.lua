-- Usage redis-cli --eval conversion_hierarchy_v3.lua [dry|run]

local dry = true
if KEYS[1] == 'run' then
   dry = false
end

local keys = redis.call('KEYS', 'CS:*:*')
for _, k in pairs(keys) do
   local k_v2 = k .. ':v2'
   if dry then
      redis.log(redis.LOG_NOTICE, 'Rename ', k, ' to ', k_v2)
   else
      redis.call('RENAME', k, k_v2)
   end

   local hkeys = ""
   if dry then
      hkeys = redis.call('HGETALL', k)
   else
      hkeys = redis.call('HGETALL', k_v2)
   end

   for _, hk in pairs(hkeys) do
      if dry then
	 redis.log(redis.LOG_NOTICE, 'Add new zkey', k, ' ', hk)
      else
	 redis.call('ZADD', k, 1, hk)
      end
   end
   if dry then
      redis.log(redis.LOG_NOTICE, 'Delete key v2 ', k_v2)
   else
      redis.call('DEL', k_v2)
   end
end
