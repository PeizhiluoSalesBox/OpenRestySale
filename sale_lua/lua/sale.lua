#!/usr/local/openresty/luajit/bin/luajit-2.1.0-alpha

-----------------代码规范说明-----------------
--[[
所有程序基本框架都是类似的
说明1>对错误应答的处理
	在processmsg函数中会调用各个处理分支，如果分支函数成功则其内部返回http应答
	如果返回失败，由processmsg判断返回值统一应答
说明2>对鉴权等常规共性的动作做好可以统一到脚本中去执行
说明3>HTTP应答头统一都是OK，这样便于查找是应用错误，还是系统错误
]]


--[设定搜索路径]
--将自定义包路径加入package的搜索路径中。也可以加到环境变量LUA_PATH中
--放到init_lus_path.lua中，不然的话，每一个请求处理的时候都会对全局变量
--package.path进行设置，导致

--[包含公共的模块]
local tableutils = require("common_lua.tableutils")		--打印工具
local cjson = require("cjson.safe")
local wanip_iresty = require("common_lua.wanip_iresty")
local http_iresty = require ("resty.http")
local redis_iresty = require("common_lua.redis_iresty")
local script_utils = require("common_lua.script_utils")

--[基本变量参数]
local redis_ip = nil
local redis_port = 6379
local accessserver_addr = nil
local accessserver_port = 8000

--发送应答数据报
local function send_resp_table (status,resp)
	if not resp or type(resp) ~= "table" then
		ngx.log(ngx.ERR, "send_resp_table:type(resp) ~= table", type(resp))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	--HTTP应答头统一都是OK，这样便于查找是应用错误，还是系统错误
	--ngx.status = status
	local resp_str = cjson.encode(resp)
	--ngx.log(ngx.NOTICE, "send_resp_table:", resp_str)
	ngx.header.content_length = string.len(resp_str)
	ngx.say(resp_str)
end
local function send_resp_string(status,message_type,error_string)
	if not message_type or type(message_type) ~= "string" then
		ngx.log(ngx.ERR, "send_resp_string:type(message_type) ~= string", type(message_type))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	if not error_string or type(error_string) ~= "string" then
		ngx.log(ngx.ERR, "send_resp_string:type(error_string) ~= string", type(error_string))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	--HTTP应答头统一都是OK，这样便于查找是应用错误，还是系统错误
	--ngx.status = status
	local jrsp = {}
	jrsp["DDIP"] = {}
	jrsp["DDIP"]["Header"] = {}
	jrsp["DDIP"]["Header"]["Version"] = "1.0"
	jrsp["DDIP"]["Header"]["CSeq"] = "1"
	jrsp["DDIP"]["Header"]["MessageType"] = message_type
	jrsp["DDIP"]["Header"]["ErrorNum"] = string.format("%d",status)
	jrsp["DDIP"]["Header"]["ErrorString"] = error_string
	local resp_str = cjson.encode(jrsp)
	--ngx.log(ngx.NOTICE, "send_resp_string:", resp_str)
	ngx.header.content_length = string.len(resp_str)
	ngx.say(resp_str)
end

--对输入的参数做有效性检查，返回解码后的消息体对象json对象
local function get_request_param()
	--ngx.log(ngx.NOTICE, "get_request_param:",ngx.var.request_body)
    local req_body, err = cjson.decode(ngx.var.request_body)
	if not req_body then
		ngx.log(ngx.ERR, "get_request_param:req body is not a json")
		return nil, "req body is not a json"
    end
    if not req_body["DDIP"]
        or not req_body["DDIP"]["Header"]
        or not req_body["DDIP"]["Header"]["Version"]
        or not req_body["DDIP"]["Header"]["CSeq"]
        or not req_body["DDIP"]["Header"]["MessageType"]
        or not req_body["DDIP"]["Body"]
        or type(req_body["DDIP"]["Header"]["Version"]) ~= "string"
        or type(req_body["DDIP"]["Header"]["CSeq"]) ~= "string"
        or type(req_body["DDIP"]["Header"]["MessageType"]) ~= "string"
		then
        ngx.log(ngx.ERR, "invalid args")
        return nil, "invalid protocol format args"
    end
    return req_body, "success"
end

--向服务程序发送分析请求
local function send_to_accessserver(salebox,reqmsg,reqbody)
    --解释一下的域名
	local host_ip,err = wanip_iresty.getdomainip(accessserver_addr)
	if not host_ip then
        ngx.log(ngx.ERR,"getdomainip failed ",err,accessserver_addr)
        return false,"getdomainip failed"
    end
    --连接接入服务器
    local httpc = http_iresty.new()
    httpc:set_timeout(3000)
	local ok, err = httpc:connect(host_ip,accessserver_port)
	if not ok  then
		ngx.log(ngx.ERR,"httpc:connect failed ",host_ip,err)
		return false,"httpc:connect failed "..host_ip
	end
    
    --构造请求包
	local jreq = {}
	jreq["DDIP"] = {}
	jreq["DDIP"]["Header"] = {}
	jreq["DDIP"]["Header"]["Version"] = "1.0"
	jreq["DDIP"]["Header"]["CSeq"] = "1"
	jreq["DDIP"]["Header"]["MessageType"] = reqmsg
	jreq["DDIP"]["Body"] = reqbody
    --发送请求包
	local res, err = httpc:request{
		method = "POST",
		path = "/",
		headers = {
                ["Host"] = accessserver_addr,
                },
        body = cjson.encode(jreq),        
        }
	if res.status ~= ngx.HTTP_OK then
		ngx.log(ngx.ERR,"res.status is unexpected",res.status)
        return false,"res.status is unexpected"
	end
	--接收并解释接入服务器的应答包
	local body, err = res:read_body()
	if not body  then
		ngx.log(ngx.ERR,"httpc:read_body failed",err)
        return false,"httpc:read_body failed"
	end
	local jresbody, err = cjson.decode(body)
	if not jresbody then
		ngx.log(ngx.ERR, "res body is not a json", body)
		return false,"res body is not a json"
	end

	if not jresbody["DDIP"]["Header"]["ErrorNum"]
		or not jresbody["DDIP"]["Header"]["ErrorString"]
		then
		ngx.log(ngx.ERR, "res body is invalid protocol format args")
        return false,"res body is invalid protocol format args"
   	end
	if jresbody["DDIP"]["Header"]["ErrorNum"] ~= "200"
        then
		ngx.log(ngx.ERR, "res body is not include need info")
        return false,"res body is not include need info"
   	end
	return true
end

--创建一个流水号[docker容器中，本地时区设置]
local function get_recordid()
    return os.date("%Y%m%d-%H%M%S")  
end

--获取salebox配置
local function get_salebox_config(salebox)
	--
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --
    local salebox_key = "salesbox:"..salebox..":config"
    local salebox_config, err = red_handler:hmget(salebox_key,"LayerNum","LayerCameraNum")
    if not salebox_config then
	    ngx.log(ngx.ERR, "get salebox_config failed : ", salebox_key,err,redis_ip)
		return false,"get salebox_config failed"
	end
    local layernum = tonumber(salebox_config[1])
    local layercameranum = tonumber(salebox_config[2])
    if(layernum <= 0) or (layercameranum <= 0) then
        ngx.log(ngx.ERR, "check salebox config failed:",layernum,layercameranum)
		return false,"check salebox config failed"
    end
    return layernum,layercameranum
end
--获取salebox状态
local function get_salebox_status(salebox)
	--
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --
    local saleboxstatus_key = "salesbox:"..salebox..":status"
    local salebox_status, err = red_handler:hmget(saleboxstatus_key,"Operator","RecordID")
    if not salebox_status then
	    --ngx.log(ngx.ERR, "get salebox_status failed : ", saleboxstatus_key,err,redis_ip)
		return "000","000"
	end
    local operator = salebox_status[1]
    local recordid = salebox_status[2]
    return operator,recordid
end
--设置salebox状态
local function set_salebox_status(salebox,operator,recordid)
	--
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --
    local saleboxstatus_key = "salesbox:"..salebox..":status"
    local ok, err = red_handler:hmset(saleboxstatus_key,
                                        "Operator",operator,
                                        "RecordID",recordid)
    if not ok then
        ngx.log(ngx.ERR, "hmset Salebox Status to redis failed", err)
        return false,"hmset Salebox Status to redis failed"
    end
    return true
end

local function check_salebox_camera_close(salebox,layernum,layercameranum)
	--
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --
    local close_camera_count = 0
    local total_carama_count = layernum * layercameranum
    for index=0,total_carama_count-1 do
        local aaa = math.floor(index/layercameranum)
        local bbb = (index%layercameranum)
        local salebox_camera_key = "salesbox:"..salebox..":camera:"..tostring(1+aaa)..tostring(1+bbb)..":status"
        print(salebox_camera_key)
        local doorStatus, err = red_handler:hget(salebox_camera_key,"DoorStatus")
        print(doorStatus)
        if (not doorStatus) or (doorStatus ~= "Close") then
            break
        end
        close_camera_count = close_camera_count + 1
    end
    print(close_camera_count,total_carama_count)
    if (total_carama_count == close_camera_count) then
        return true
    end
    return false
end
    
--记录一条异常支付
local function unpay_record_salebox(salebox,operator,recordid)
	--
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --
    local salebox_unpay_key = "salesbox:"..salebox..":unpay:"..operator
    local ok, err = red_handler:set(salebox_unpay_key,recordid)
    if not ok then
        ngx.log(ngx.ERR, "set unpay record to free failed : ", salebox_unpay_key,err)
    end
    return true
end

--处理小程序发来的开门请求
function do_opendoor(jreq)
	--判断命令格式的有效性
	if not jreq["DDIP"]["Body"]["SalesBox"]
        or not jreq["DDIP"]["Body"]["Operator"]
		or type(jreq["DDIP"]["Body"]["SalesBox"]) ~= "string"
        or type(jreq["DDIP"]["Body"]["Operator"]) ~= "string"
		then
	    ngx.log(ngx.ERR, "do_opendoor,invalid args")
	    return false,"do_opendoor,invalid args"
	end
    local salebox = jreq["DDIP"]["Body"]["SalesBox"]
    
    --创建redis操作句柄
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end

    --获取配置(验证一下,项目是否存在，并且已经配置)
    local layernum,layercameranum = get_salebox_config(salebox)
    if layernum == false then
        ngx.log(ngx.ERR, "check salebox config failed:",layernum,layercameranum)
		return false,"check salebox config failed"
    end

    -->[异常恢复:开门之后，直接退出小程序，马上闭门，此时一直卡住购物状态]
    local ret = check_salebox_camera_close(salebox,layernum,layercameranum)
    if ret == true then
        local ok, err = set_salebox_status(salebox,"000","000")
        if not ok then
            ngx.log(ngx.ERR, "set_salebox_status to free failed : ", salebox_key,err)
            return false,"hmset salebox status 000 to redis failed"
        end
    end

    --获取状态
    local operator,recordid = get_salebox_status(salebox)
    if (operator ~= "000") or (recordid ~= "000") then
        --前面的人还没有完成，后面的人又开始扫码了
        ngx.log(ngx.ERR, "Salebox is using by ",operator)
        return false,"Salebox is using by"..operator
    end

    --根据[购物流程梳理2]
    --<1>分配流水号,记录操作者
    --<2>创建流水记录，流水状态为[正在开门]
    --<3>给接入服务器发送识别请求
    --<4>等待所有camera的初始识别完成。
    --<5>给接入服务器发送开门请求
    --<6>流水状态为[正在拿物]
    --<7>给小程序应答
    
    --<1>分配流水号,记录操作者
    local operator = jreq["DDIP"]["Body"]["Operator"]
    local recordid = get_recordid()
    local ok, err = set_salebox_status(salebox,operator,recordid)
    if not ok then
        ngx.log(ngx.ERR, "hmset Salebox Status to redis failed", err)
        return false,"hmset Salebox Status to redis failed"
    end
    
    --<2>创建流水记录，流水状态为[正在开门]
    local record_key = "salesbox:"..salebox..":record:"..recordid
    local ok, err = red_handler:hmset(record_key,
                                        "Status","Opening",
                                        "Operator",operator,
                                        "OpenDoorTime",ngx.localtime())
    if not ok then
        ngx.log(ngx.ERR, "hmset Record to redis failed", err)
        return false,"hmset Record to redis failed"
    end
    
    --<3>给接入服务器发送识别请求
    local reqbody = {}
    reqbody["SalesBox"] = jreq["DDIP"]["Body"]["SalesBox"]
	reqbody["RecordID"] = recordid
    local ok = send_to_accessserver(jreq["DDIP"]["Body"]["SalesBox"],"MSG_RECOGNIZE_REQ",reqbody)
    if ok ~= true then
        --退出开门状态
        set_salebox_status(salebox,"000","000")
        ngx.log(ngx.ERR, "send_to_accessserver MSG_RECOGNIZE_REQ failed")
        return false,"send_to_accessserver MSG_RECOGNIZE_REQ failed"
    end

    --<4>等待所有camera的初始识别完成
    local wait_succ = false
    for i=1,15 do
        local get_camera_count = 0
        local total_carama_count = layernum * layercameranum
        for index=0,total_carama_count-1 do
            local aaa = math.floor(index/layercameranum)
            local bbb = (index%layercameranum)
            local camera_key = "Begin:"..tostring(1+aaa)..tostring(1+bbb)..":ThingsName"
            local exist, err = red_handler:hexists(record_key,camera_key)
            --不存在返回0，存在返回1
            if (not exist) or (exist==0) then
                break
            end
            get_camera_count = get_camera_count + 1
        end
        print(total_carama_count,get_camera_count)
        if(get_camera_count == total_carama_count) then
            wait_succ = true
            break
        end   
        ngx.sleep(1)
    end
    if(wait_succ ~= true) then
        --退出开门状态
        set_salebox_status(salebox,"000","000")
        ngx.log(ngx.ERR, "wait for camera ready timeout")
        return false,"wait for camera ready timeout"
    end

    --<5>给接入服务器发送开门请求
    local reqbody = {}
    reqbody["SalesBox"] = jreq["DDIP"]["Body"]["SalesBox"]
    local ok = send_to_accessserver(jreq["DDIP"]["Body"]["SalesBox"],"MSG_OPENDOOR_REQ",reqbody)
    if ok ~= true then
        --退出开门状态
        set_salebox_status(salebox,"000","000")    
        ngx.log(ngx.ERR, "send_to_accessserver MSG_RECOGNIZE_REQ failed")
        return false,"send_to_accessserver MSG_RECOGNIZE_REQ failed"
    end

    --<6>流水状态为[正在拿物]
    local ok, err = red_handler:hset(record_key,"Status","Selecting")
    if not ok then
        --退出开门状态
        set_salebox_status(salebox,"000","000")    
        ngx.log(ngx.ERR, "hmset Record Status to Selecting failed", err)
        return false,"hmset Record Status to Selecting  failed"
    end
    
    --<7>给小程序应答
	local jrsp = {}
	jrsp["DDIP"] = {}
	jrsp["DDIP"]["Header"] = {}
	jrsp["DDIP"]["Header"]["Version"] = "1.0"
	jrsp["DDIP"]["Header"]["CSeq"] = "1"
	jrsp["DDIP"]["Header"]["MessageType"] = "MSG_OPENDOOR_RSP"
	jrsp["DDIP"]["Header"]["ErrorNum"] = "200"
	jrsp["DDIP"]["Header"]["ErrorString"] = "Success OK"
	send_resp_table(ngx.HTTP_OK,jrsp)
	return true, "OK"
end

--处理识别消息
function do_recognize(jreq)
	--判断命令格式的有效性
	if not jreq["DDIP"]["Body"]["SalesBox"]
        or not jreq["DDIP"]["Body"]["Camera"]
        or not jreq["DDIP"]["Body"]["DoorStatus"]
        or not jreq["DDIP"]["Body"]["Objects"]
		or type(jreq["DDIP"]["Body"]["SalesBox"]) ~= "string"
        or type(jreq["DDIP"]["Body"]["Camera"]) ~= "string"
        or type(jreq["DDIP"]["Body"]["DoorStatus"]) ~= "string"
    then
	    ngx.log(ngx.ERR, "do_recognize,invalid args")
	    return false,"do_recognize,invalid args"
	end
    local salebox = jreq["DDIP"]["Body"]["SalesBox"]
    
    --创建redis操作句柄
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    
    --分解消息,用起来方便一点
    local things_name = {}
    local things_boxs_inview = {}
    local things_boxs_inlayer = {}
    for k, v in pairs(jreq["DDIP"]["Body"]["Objects"]) do
        things_name[k] = v["Name"]
        things_boxs_inview[k] = v["BoxInView"]
        things_boxs_inlayer[k] = v["BoxInLayer"]
    end
    local doorstatus = jreq["DDIP"]["Body"]["DoorStatus"]
    local camera = jreq["DDIP"]["Body"]["Camera"]

    --获取状态: 确认当前属于购物态(空闲态是不要识别的)
    local operator,recordid = get_salebox_status(salebox)
    if(operator == "000") or (recordid == "000") then
        ngx.log(ngx.ERR, "Salebox is free")
        return false,"Salebox is free"
    end
   
    --根据[购物流程梳理2]
    --记录并更新流水状态
    --1>[正在开门]==当前状态
    --  检测(门状态==关闭),否则出错。
    --  将识别结果记录到Begin:下
    --2>[正在拿物]==当前状态
    --  if(门状态==开门)
    --      将识别结果记录到Mid:下
    --  if(门状态==关门)
    --      将识别结果记录到End:下
    local record_key = "salesbox:"..jreq["DDIP"]["Body"]["SalesBox"]..":record:"..recordid
    local record_status, err = red_handler:hget(record_key,"Status")
    if not record_status then
        ngx.log(ngx.ERR, "hget record_status failed", err)
        return false,"hget record_status failed"
    end
    local prefix = "Mid:"
    if record_status == "Opening" then
        if doorstatus ~= "Close" then
            ngx.log(ngx.ERR, "check doorstatus==Close failed ", doorstatus)
            return false,"check doorstatus==Close failed"
        end
        prefix = "Begin:"
    elseif record_status == "Selecting" then
        if doorstatus == "Open" then
            prefix = "Mid:"
        else
            prefix = "End:"
        end
    end
    local camera_key1 = prefix..camera..":ThingsName"
    local camera_key2 = prefix..camera..":ThingsBoxInView"
    local camera_key3 = prefix..camera..":ThingsBoxInLayer"
    local camera_value1 = cjson.encode(things_name)
    local camera_value2 = cjson.encode(things_boxs_inview)
    local camera_value3 = cjson.encode(things_boxs_inlayer)
    local ok, err = red_handler:hmset(record_key,camera_key1,camera_value1,
                                        camera_key2,camera_value2,camera_key3,camera_value3)
    if not ok then
        ngx.log(ngx.ERR, "hmset camera status failed", err)
        return false,"hmset camera status failed"
    end

    --返回应答数据
	local jrsp = {}
	jrsp["DDIP"] = {}
	jrsp["DDIP"]["Header"] = {}
	jrsp["DDIP"]["Header"]["Version"] = "1.0"
	jrsp["DDIP"]["Header"]["CSeq"] = "1"
	jrsp["DDIP"]["Header"]["MessageType"] = "MSG_RECOGNIZE_ACK"
	jrsp["DDIP"]["Header"]["ErrorNum"] = "200"
	jrsp["DDIP"]["Header"]["ErrorString"] = "Success OK"
	send_resp_table(ngx.HTTP_OK,jrsp)
	return true, "OK"
end

function table_link_together(a,b)
    for i,v in pairs(b) do
        table.insert(a,v)
    end
end

--超时处理
function  pay_timeout_process(premature,salebox)
    print("----------pay_timeout_process-----------",salebox)
    --获取状态
    local operator,recordid = get_salebox_status(salebox)
    if(operator == "000") and (recordid == "000") then
        return true
    end
    ngx.log(ngx.ERR, "Salebox Pay timeout by ",operator,recordid)
    --1>把售货机状态切换为空闲态
    local ok, err = set_salebox_status(salebox,"000","000")
    if not ok then
        ngx.log(ngx.ERR, "set_salebox_status to free failed : ", salebox_key,err)
    end
    --2>产生一条异常流水记录
    local ok, err = unpay_record_salebox(salebox,operator,recordid)
    if not ok then
        ngx.log(ngx.ERR, "unpay_record_salebox failed : ", salebox_key,err)
    end
end

function do_buyinfo(jreq)
	--判断命令格式的有效性
	if not jreq["DDIP"]["Body"]["SalesBox"]
		or type(jreq["DDIP"]["Body"]["SalesBox"]) ~= "string"
		then
	    ngx.log(ngx.ERR, "do_opendoor,invalid args")
	    return false,"do_opendoor,invalid args"
	end
    local salebox = jreq["DDIP"]["Body"]["SalesBox"]
    
    --创建redis操作句柄
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    
    --获取配置
    local layernum,layercameranum = get_salebox_config(salebox)
    if layernum == false then
        ngx.log(ngx.ERR, "check salebox config failed:",layernum,layercameranum)
		return false,"check salebox config failed"
    end

    --获取状态
    local operator,recordid = get_salebox_status(salebox)
    if(operator == "000") or (recordid == "000") then
        ngx.log(ngx.ERR, "Salebox is free")
        return false,"Salebox is free"
    end
    
    --必须处于[正在拿物]
    local record_key = "salesbox:"..jreq["DDIP"]["Body"]["SalesBox"]..":record:"..recordid
    local record_status, err = red_handler:hget(record_key,"Status")
    if not record_status then
        ngx.log(ngx.ERR, "hget record_status failed", err)
        return false,"hget record_status failed"
    end
    if record_status ~= "Selecting" then
        ngx.log(ngx.ERR, "record_status not Selecting", record_status)
        return false,"record_status not Selecting"
    end
    
    --根据[购物流程梳理2]
    --1>判断所有camera的结束识别是否完成。
    --2>获取购物清单
    --3>如果已经完成,并且切换到[正在支付]
    --4>并且启动定时器，要求30秒内支付完成。
    --  如果支付失败或者超时，则产生一条未付款记录。
    local get_camera_count = 0
    local total_carama_count = layernum * layercameranum
    for index=0,total_carama_count-1 do
        local aaa = math.floor(index/layercameranum)
        local bbb = (index%layercameranum)
        local camera_key = "End:"..tostring(1+aaa)..tostring(1+bbb)..":ThingsName"
        local exist, err = red_handler:hexists(record_key,camera_key)
        --不存在返回0，存在返回1
        if (not exist) or (exist==0) then
            break
        end
        get_camera_count = get_camera_count + 1
    end

    --
    print(total_carama_count,get_camera_count)
    local prefix = "Mid:"
    if(get_camera_count == total_carama_count) then
        prefix = "End:"
        record_status = "Paying"
    end
    
    --获取购物清单列表
    local cost_things_name = {}
    local cost_things_value = {}
    local cost_total = 0.0
    for index=0,total_carama_count-1 do
        local aaa = math.floor(index/layercameranum)
        local bbb = (index%layercameranum)
        local camera_key = prefix..tostring(1+aaa)..tostring(1+bbb)..":ThingsName"
        local thingsname,err = red_handler:hget(record_key,camera_key)
        if not thingsname then
            ngx.log(ngx.ERR, "hget thingsname failed", err)
            return false,"hget thingsname failed"
        end
        local thingsnameJson, err = cjson.decode(thingsname)
        if not thingsnameJson then
            ngx.log(ngx.ERR, "thingsname is not a json",thingsname)
            return false,"thingsname is not a json"
        end
        table_link_together(cost_things_name,thingsnameJson)
    end
    for i=1,#cost_things_name do
        cost_things_value[i] = 0.0  --从数据库中查到
        cost_total = cost_total + cost_things_value[i]
    end

    --切换到[正在支付]
    if record_status == "Paying" then
        local ok, err = red_handler:hmset(record_key,
                                        "Status","Paying",
                                        "CloseDoorTime",ngx.localtime(),
                                        "CostNames",cjson.encode(cost_things_name),
                                        "CostValues",cjson.encode(cost_things_value),
                                        "CostTotal",cost_total)
        if not ok then
            ngx.log(ngx.ERR, "hmset Record to redis failed", err)
            return false,"hmset Record to redis failed"
        end
        
        --启动一个定时器,超时时间60秒
        local ok, err = ngx.timer.at(60,pay_timeout_process,salebox)
        if not ok then
            ngx.log(ngx.ERR, "failed to start pay timeout timer: ", err)
            return
        end
    end 
    
    --返回应答数据
	local jrsp = {}
	jrsp["DDIP"] = {}
	jrsp["DDIP"]["Header"] = {}
	jrsp["DDIP"]["Header"]["Version"] = "1.0"
	jrsp["DDIP"]["Header"]["CSeq"] = "1"
	jrsp["DDIP"]["Header"]["MessageType"] = "MSG_BUY_INFO_RSP"
	jrsp["DDIP"]["Header"]["ErrorNum"] = "200"
	jrsp["DDIP"]["Header"]["ErrorString"] = "Success OK"
    jrsp["DDIP"]["Body"] = {}
    jrsp["DDIP"]["Body"]["Status"] = record_status
    jrsp["DDIP"]["Body"]["ThingsName"] = cost_things_name
    jrsp["DDIP"]["Body"]["ThingsCost"] = cost_things_value
    jrsp["DDIP"]["Body"]["TotalCost"] = cost_total
	send_resp_table(ngx.HTTP_OK,jrsp)
	return true, "OK"
end

function do_payresult(jreq)
    --判断命令格式的有效性
	if not jreq["DDIP"]["Body"]["SalesBox"]
        or not jreq["DDIP"]["Body"]["Result"]
		or type(jreq["DDIP"]["Body"]["SalesBox"]) ~= "string"
        or type(jreq["DDIP"]["Body"]["Result"]) ~= "string"
		then
	    ngx.log(ngx.ERR, "do_opendoor,invalid args")
	    return false,"do_opendoor,invalid args"
	end
    local salebox = jreq["DDIP"]["Body"]["SalesBox"]
    
    --创建redis操作句柄
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    
    --获取状态
    local operator,recordid = get_salebox_status(salebox)
    if(operator == "000") or (recordid == "000") then
        ngx.log(ngx.ERR, "Salebox is free")
        return false,"Salebox is free"
    end

    --必须处于[正在支付]
    local record_key = "salesbox:"..salebox..":record:"..recordid
    local record_status, err = red_handler:hget(record_key,"Status")
    if not record_status then
        ngx.log(ngx.ERR, "hget record_status failed", err)
        return false,"hget record_status failed"
    end
    if record_status ~= "Paying" then
        ngx.log(ngx.ERR, "record_status not Paying,but in", record_status)
        return false,"record_status not Paying,but in"..record_status
    end

    --根据[购物流程梳理2]
    --1>判断支付是否成功，如果成功，则切换到[支付完成]
    if(jreq["DDIP"]["Body"]["Result"] == "OK") then
        local ok, err = red_handler:hmset(record_key,
                                        "Status","Payed",
                                        "PayTime",ngx.localtime())
        if not ok then
            ngx.log(ngx.ERR, "hmset Record to redis failed", err)
            return false,"hmset Record to redis failed"
        end
        --把售货机恢复到空闲态
        local ok, err = set_salebox_status(salebox,"000","000")
        if not ok then
            ngx.log(ngx.ERR, "set_salebox_status to free failed : ", salebox_key,err)
            return false,"hmset salebox status 000 to redis failed"
        end
    else
        --1>把售货机状态切换为空闲态
        local ok, err = set_salebox_status(salebox,"000","000")
        if not ok then
            ngx.log(ngx.ERR, "set_salebox_status to free failed : ", salebox_key,err)
        end
        --2>产生一条异常流水记录
        local ok, err = unpay_record_salebox(salebox,operator,recordid)
        if not ok then
            ngx.log(ngx.ERR, "unpay_record_salebox failed : ", salebox_key,err)
        end
        ngx.log(ngx.ERR, "Pay Result Failed")
        return false,"Pay Result Failed" 
    end

    --返回应答数据
	local jrsp = {}
	jrsp["DDIP"] = {}
	jrsp["DDIP"]["Header"] = {}
	jrsp["DDIP"]["Header"]["Version"] = "1.0"
	jrsp["DDIP"]["Header"]["CSeq"] = "1"
	jrsp["DDIP"]["Header"]["MessageType"] = "MSG_PAY_RESULT_NOTICE"
	jrsp["DDIP"]["Header"]["ErrorNum"] = "200"
	jrsp["DDIP"]["Header"]["ErrorString"] = "Success OK"
	send_resp_table(ngx.HTTP_OK,jrsp)
	return true, "OK"
end

--消息处理函数入库
function process_msg()
	--获取请求对象
	local jreq, err = get_request_param()
	if not jreq then
		send_resp_string(ngx.HTTP_BAD_REQUEST,"any",err);
	    return
	end

	--分命令处理
	if (jreq["DDIP"]["Header"]["MessageType"] == "MSG_RECOGNIZE_NOTICE") then
		local ok, err = do_recognize(jreq);
		if not ok then
			send_resp_string(ngx.HTTP_BAD_REQUEST,"MSG_RECOGNIZE_ACK",err);
		end
	elseif (jreq["DDIP"]["Header"]["MessageType"] == "MSG_OPENDOOR_REQ") then
		local ok, err = do_opendoor(jreq);
		if not ok then
			send_resp_string(ngx.HTTP_BAD_REQUEST,"MSG_OPENDOOR_RSP",err);
		end
	elseif (jreq["DDIP"]["Header"]["MessageType"] == "MSG_BUY_INFO_REQ") then
		local ok, err = do_buyinfo(jreq);
		if not ok then
			send_resp_string(ngx.HTTP_BAD_REQUEST,"MSG_BUY_INFO_RSP",err);
		end
	elseif (jreq["DDIP"]["Header"]["MessageType"] == "MSG_PAY_RESULT_NOTICE") then
		local ok, err = do_payresult(jreq);
		if not ok then
			send_resp_string(ngx.HTTP_BAD_REQUEST,"MSG_PAY_RESULT_ACK",err);
		end
	else
		ngx.log(ngx.ERR, "invalid MessageType",jreq["DDIP"]["Header"]["MessageType"])
		send_resp_string(ngx.HTTP_BAD_REQUEST,"any","Invalid MessageType");
	end
end

--加载配置信息(环境变量中配置)
local function load_ip_addr()
	redis_ip = ngx.shared.shared_data:get("RedisIP")
	if redis_ip == nil  then
		ngx.log(ngx.ERR,"get RedisIP failed ")
        return false
	end
    redis_port = ngx.shared.shared_data:get("RedisPort")
	if redis_port == nil  then
		ngx.log(ngx.ERR,"get RedisPort failed ")
        return false
	end
    accessserver_addr = ngx.shared.shared_data:get("AccessServerAddr")
	if accessserver_addr == nil  then
		ngx.log(ngx.ERR,"get AccessServerAddr failed ")
        return false
	end
    accessserver_port = ngx.shared.shared_data:get("AccessServerPort")
	if accessserver_port == nil  then
		ngx.log(ngx.ERR,"get AccessServerPort failed ")
        return false
	end
	return true
end

--程序入口
--print("get request_body:"..ngx.var.request_body)
--print("=====================new request=======================\n")
--print("get server_port::::",ngx.var.server_port,type(ngx.var.server_port))

--可以通过端口号用来区分https和http
--ngx.var.server_port

local ok = load_ip_addr()
if not ok then
    ngx.log(ngx.ERR,"load_ip_addr failed ")
    return false
end
process_msg()

