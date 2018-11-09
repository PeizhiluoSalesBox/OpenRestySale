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

-----------------设计思路-----------------
--[[状态机驱动:"Free|Selecting|Paying"]]
--[[
Free:【稳态】
    a>开门请求->[序列操作成功]->Selecting
    a>其他请求->无效应答
Opening:【瞬态，超时10秒】
    a>识别请求->[写入数据库]
    a>其他请求->无效应答
Selecting:【稳态】
    a>购物信息请求->[判断所有识别结束]->Paying
    a>识别请求->[写入数据库]->[判断所有识别结束]->Paying
    a>其他请求->无效应答
Paying:【瞬态，超时30秒】
    a>支付成功信息->Free
    a>超时判断->Free
    a>其他请求->无效应答
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

--获取salebox的接入服务的地址信息
local function get_salebox_accessserver(salebox)
	--
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --
    local carame11_key = "salesbox:"..salebox..":carame:11:status"
    local carame11_status, err = red_handler:hmget(carame11_key,"AccessServerAddr","AccessServerPort")
    if not carame11_status then
	    ngx.log(ngx.ERR, "get carame11_status failed : ", carame11_key,err,redis_ip)
		return false,"get carame11_status failed"
	end
    return carame11_status[1],tonumber(carame11_status[2])
end

--向服务程序发送分析请求
local function send_to_accessserver(salebox,reqmsg,reqbody)
    
    --从Redis中获取AccessServer的地址信息
    local server_addr,server_port = get_salebox_accessserver(salebox)
    if not server_addr then
        ngx.log(ngx.ERR,"get_salebox_accessserver failed ",err,server_addr)
        return false,"get_salebox_accessserver failed"
    end

    --连接接入服务器
    local httpc = http_iresty.new()
    httpc:set_timeout(3000)
	local ok, err = httpc:connect(server_addr,server_port)
	if not ok  then
		ngx.log(ngx.ERR,"httpc:connect failed ",server_addr,err)
		return false,"httpc:connect failed "..server_addr
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

--
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
    local salebox_status, err = red_handler:hmget(saleboxstatus_key,"Status","StatusTime","Operator","RecordID")
    if not salebox_status then
	    --ngx.log(ngx.ERR, "get salebox_status failed : ", saleboxstatus_key,err,redis_ip)
		return "Free",0,"000","000"
	end
    return salebox_status[1],tonumber(salebox_status[2]),salebox_status[3],salebox_status[4]
end

--设置salebox状态
local function set_salebox_status(salebox,status,statustime,operator,recordid)
	--
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --
    local saleboxstatus_key = "salesbox:"..salebox..":status"
    if operator == nil or recordid == nil then
        local ok, err = red_handler:hmset(saleboxstatus_key,
                                            "Status",status,
                                            "StatusTime",tostring(statustime))
        if not ok then
            ngx.log(ngx.ERR, "hmset Salebox Status to redis failed", err)
            return false,"hmset Salebox Status to redis failed"
        end
    else
        local ok, err = red_handler:hmset(saleboxstatus_key,
                                            "Status",status,
                                            "StatusTime",tostring(statustime),
                                            "Operator",operator,
                                            "RecordID",recordid)
        if not ok then
            ngx.log(ngx.ERR, "hmset Salebox Status to redis failed", err)
            return false,"hmset Salebox Status to redis failed"
        end
    end
    return true
end
local function is_salebox_status_exist(salebox)
	--
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --
    local saleboxstatus_key = "salesbox:"..salebox..":status"
    local exist, err = red_handler:exists(saleboxstatus_key)
    return exist
end

--判断所有camera的都关门了
local function check_salebox_camera_close(salebox)
	--
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --
    local layernum,layercameranum = get_salebox_config(salebox)
    if layernum == false then
        ngx.log(ngx.ERR, "get_salebox_config failed:",layernum,layercameranum)
		return false,"get_salebox_config failed"
    end
    --
    local close_camera_count = 0
    local total_carama_count = layernum * layercameranum
    for index=0,total_carama_count-1 do
        local aaa = math.floor(index/layercameranum)
        local bbb = (index%layercameranum)
        local salebox_camera_key = "salesbox:"..salebox..":camera:"..tostring(1+aaa)..tostring(1+bbb)..":status"
        local doorStatus, err = red_handler:hget(salebox_camera_key,"DoorStatus")
        --print(salebox_camera_key,doorStatus)
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

--判断某一条记录下的camera的识别结果都已经到位
local function check_salebox_camera_recognize(salebox,prefex,waittime)
	--
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --
    local layernum,layercameranum = get_salebox_config(salebox)
    if layernum == false then
        ngx.log(ngx.ERR, "get_salebox_config failed:",layernum,layercameranum)
		return false,"get_salebox_config failed"
    end
    --获取状态
    local _,_,_,recordid = get_salebox_status(salebox)
    if recordid == nil or recordid=="000" then
        ngx.log(ngx.ERR, "get_salebox_status failed:recordid",recordid)
		return false,"get_salebox_status failed"
    end
    --
    local wait_succ = false
    repeat
        --
        local get_camera_count = 0
        local total_carama_count = layernum * layercameranum
        for index=0,total_carama_count-1 do
            local aaa = math.floor(index/layercameranum)
            local bbb = (index%layercameranum)
            local record_key = "salesbox:"..salebox..":record:"..recordid
            local camera_key = prefex..tostring(1+aaa)..tostring(1+bbb)..":ThingsName"
            local exist, err = red_handler:hexists(record_key,camera_key)
            --不存在返回0，存在返回1
            if (not exist) or (exist==0) then
                break
            end
            get_camera_count = get_camera_count + 1
        end
        --print("get_camera_count=",get_camera_count," total_carama_count=",total_carama_count)
        if(get_camera_count == total_carama_count) then
            wait_succ = true
            break
        end 
        --
        waittime = waittime-1
        if(waittime > 0) then
            ngx.sleep(1)
        end
    until (waittime<=0)
    return wait_succ
end

--记录一条异常支付
local function unpay_record_salebox(salebox)
	--
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --
    local status,statustime,operator,recordid = get_salebox_status(salebox)
    if not status then
        ngx.log(ngx.ERR, "get_salebox_status failed!")
        return false,"get_salebox_status failed!"
    end
    --
    local salebox_unpay_key = "salesbox:"..salebox..":unpay:"..operator
    local ok, err = red_handler:set(salebox_unpay_key,recordid)
    if not ok then
        ngx.log(ngx.ERR, "set unpay record to failed : ", salebox_unpay_key,err)
    end
    return true
end

--状态校验和恢复
function do_status_check(salebox,request_type)
    --获取状态
    local status,statustime,operator,recordid = get_salebox_status(salebox)
    
    --异常状态恢复
    if (status == "Opening") and (ngx.now() >= statustime+15) then 
        ngx.log(ngx.ERR, "Opening Timeout,Reset to Free;salebox=", salebox)
        set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        status = "Free"
    end
    if (status == "Paying") and (ngx.now() >= statustime+30) then 
        -->产生一条异常流水记录
        local ok, err = unpay_record_salebox(salebox)
        if not ok then
            ngx.log(ngx.ERR, "unpay_record_salebox failed : ", salebox_key,err)
        end
        ngx.log(ngx.ERR, "Paying Timeout,Reset to Free;salebox=", salebox)
        set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        status = "Free"
    end
    if (status == "Selecting") and (ngx.now() >= statustime+30) then 
        --在购物状态下,有30秒没有收到设备的识别消息(此时设备关门了)
        local ret = check_salebox_camera_close(salebox)
        if ret == true then
            ngx.log(ngx.ERR, "Selecting Timeout,Reset to Free;salebox=", salebox)
            set_salebox_status(salebox,"Free",ngx.now(),"000","000")
            status = "Free"
        end
    end
    
    --状态和命令的匹配
    if (status == "Free") then
        if(request_type ~= "MSG_OPENDOOR_REQ") then
            ngx.log(ngx.ERR, "Unmatch Status:",status," with Request:",request_type)
            return false,"Unmatch Status:"..status.." with Request:"..request_type
        end
    elseif (status == "Opening") then
        if(request_type ~= "MSG_RECOGNIZE_NOTICE") then
            ngx.log(ngx.ERR, "Unmatch Status:",status," with Request:",request_type)
            return false,"Unmatch Status:"..status.." with Request:"..request_type
        end    
    elseif (status == "Selecting") then
        if(request_type ~= "MSG_BUY_INFO_REQ") 
        and (request_type ~= "MSG_RECOGNIZE_NOTICE") then
            ngx.log(ngx.ERR, "Unmatch Status:",status," with Request:",request_type)
            return false,"Unmatch Status:"..status.." with Request:"..request_type
        end
    elseif (status == "Paying") then
        if(request_type ~= "MSG_PAY_RESULT_NOTICE") then
            ngx.log(ngx.ERR, "Unmatch Status:",status," with Request:",request_type)
            return false,"Unmatch Status:"..status.." with Request:"..request_type
        end
    else
        local isexist = is_salebox_status_exist(salebox)
        if not isexist then
            set_salebox_status(salebox,"Free",ngx.now(),"000","000")
            return true
        else
            ngx.log(ngx.ERR, "Unexpected Status ",status)
            return false,"Unexpected Status "
        end
    end
    return true
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
    local doorstatus = jreq["DDIP"]["Body"]["DoorStatus"]
    local camera = jreq["DDIP"]["Body"]["Camera"]
    
    --分解消息,用起来方便一点
    local things_name = {}
    local things_boxs_inview = {}
    local things_boxs_inlayer = {}
    for k, v in pairs(jreq["DDIP"]["Body"]["Objects"]) do
        things_name[k] = v["Name"]
        things_boxs_inview[k] = v["BoxInView"]
        things_boxs_inlayer[k] = v["BoxInLayer"]
    end
    --tableutils.printTable(jreq["DDIP"]["Body"])
    --tableutils.printTable(things_name)
    --tableutils.printTable(things_boxs_inview)
    --tableutils.printTable(things_boxs_inlayer)

    --创建redis操作句柄
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end

    --获取状态,更新数据库
    local status,statustime,operator,recordid = get_salebox_status(salebox)
    local prefix = "Mid:"
    if status == "Opening" then
        if doorstatus ~= "Close" then   --正在开门的时候 ，摄像机端肯定是关闭状态的
            ngx.log(ngx.ERR, "check doorstatus==Close failed ", doorstatus)
            return false,"check doorstatus==Close failed"
        end
        prefix = "Begin:"
    elseif status == "Selecting" then
        if doorstatus == "Open" then
            prefix = "Mid:"
            --刷新购物态下的时间戳()
            set_salebox_status(salebox,"Selecting",ngx.now(),nil,nil)
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
    local record_key = "salesbox:"..salebox..":record:"..recordid
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

    --根据[购物流程梳理2]
    --<1>设置对应的状态
    local operator = jreq["DDIP"]["Body"]["Operator"]
    local recordid = get_recordid()
    local ok, err = set_salebox_status(salebox,"Opening",ngx.now(),operator,recordid)
    if not ok then
        ngx.log(ngx.ERR, "hmset Salebox Status to redis failed", err)
        return false,"hmset Salebox Status to redis failed"
    end
    
    --<2>创建流水记录
    local record_key = "salesbox:"..salebox..":record:"..recordid
    local ok, err = red_handler:hmset(record_key,"Operator",operator,"OpenDoorTime",ngx.localtime())
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
        --恢复状态
        set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        ngx.log(ngx.ERR, "send_to_accessserver MSG_RECOGNIZE_REQ failed")
        return false,"send_to_accessserver MSG_RECOGNIZE_REQ failed"
    end
    
    --<4>等待所有camera的初始识别完成
    local ok,err = check_salebox_camera_recognize(salebox,"Begin:",15)
    if(ok ~= true) then
        --恢复状态
        set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        ngx.log(ngx.ERR, "wait for camera ready timeout")
        return false,"wait for camera ready timeout"
    end

    --<5>给接入服务器发送开门请求
    local reqbody = {}
    reqbody["SalesBox"] = jreq["DDIP"]["Body"]["SalesBox"]
    local ok = send_to_accessserver(jreq["DDIP"]["Body"]["SalesBox"],"MSG_OPENDOOR_REQ",reqbody)
    if ok ~= true then
        --恢复状态
        set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        ngx.log(ngx.ERR, "send_to_accessserver MSG_RECOGNIZE_REQ failed")
        return false,"send_to_accessserver MSG_RECOGNIZE_REQ failed"
    end

    --<6>流水状态为[正在拿物]
    local ok, err = set_salebox_status(salebox,"Selecting",ngx.now(),operator,recordid)
    if not ok then
        --恢复状态
        set_salebox_status(salebox,"Free",ngx.now(),"000","000") 
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

--从数据库中查找商品的单价
function get_thingprice(name)
    return 1.00
end
function add_to_thingmap(thingmap,thinglist)
    for i,v in pairs(thinglist) do
        if thingmap[v] ~= nil then 
            thingmap[v] = thingmap[v]+1
        else
            thingmap[v] = 1
        end
    end
end
function sub_thingmap(mapA,mapB)
    sub_map = {}   --mapA减去mapB
    for k,v in pairs(mapA) do
        if mapB[k] ~= nil then 
            sub_map[k] = mapA[k]-mapB[k]
        else
            sub_map[k] = mapA[k]
        end
    end
    return sub_map
end

--获取购物列表
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
    
    --根据[购物流程梳理2]
    --1>判断所有camera的结束识别是否完成。
    local prefix = "Mid:"    
    local camera_end_ok,_ = check_salebox_camera_recognize(salebox,"End:",0)
    if(camera_end_ok) then
        prefix = "End:"
    else
        --如果连中间态也没有好的话，暂时无法产生购物列表
        local camera_mid_ok,_ = check_salebox_camera_recognize(salebox,"Mid:",0)
        if(not camera_mid_ok) then 
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
            jrsp["DDIP"]["Body"]["Status"] = "Selecting"
            jrsp["DDIP"]["Body"]["CostThings"] = {}
            jrsp["DDIP"]["Body"]["CostTotal"] = 0.00
            send_resp_table(ngx.HTTP_OK,jrsp)
            return true, "OK"
        end
    end
    
    --2>计算购物清单------
    --获取设备配置
    local layernum,layercameranum = get_salebox_config(salebox)
    if layernum == false then
        ngx.log(ngx.ERR, "get_salebox_config failed:",layernum,layercameranum)
		return false,"get_salebox_config failed"
    end
    local total_carama_count = layernum*layercameranum
    --获取设备状态
    local status,_,_,recordid = get_salebox_status(salebox)
    if not status then
        ngx.log(ngx.ERR, "get_salebox_status failed!")
        return false,"get_salebox_status failed!"
    end
    local record_key = "salesbox:"..salebox..":record:"..recordid
    
    --获取列表:初始时刻
    local begin_things_map = {}
    local cur_things_map = {}    
    for index=0,total_carama_count-1 do
        local aaa = math.floor(index/layercameranum)
        local bbb = (index%layercameranum)
        local camera_key = "Begin:"..tostring(1+aaa)..tostring(1+bbb)..":ThingsName"
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
        add_to_thingmap(begin_things_map,thingsnameJson)
    end
    --获取列表:当前时刻
    for index=0,total_carama_count-1 do
        local aaa = math.floor(index/layercameranum)
        local bbb = (index%layercameranum)
        local camera_key = prefix..tostring(1+aaa)..tostring(1+bbb)..":ThingsName"
        local thingsname,err = red_handler:hget(record_key,camera_key)
        if not thingsname then
            ngx.log(ngx.ERR, "hget failed:",err)
            return false,"hget thingsname failed"
        end
        local thingsnameJson, err = cjson.decode(thingsname)
        if not thingsnameJson then
            ngx.log(ngx.ERR, "thingsname is not a json",thingsname)
            return false,"thingsname is not a json"
        end
        add_to_thingmap(cur_things_map,thingsnameJson)
    end
    --计算购物清单
    local cost_things_map = {}     
    local cost_total = 0.00
    local decrease_map = sub_thingmap(begin_things_map,cur_things_map)
    --tableutils.printTable(decrease_map)
    local index = 1
    for k,v in pairs(decrease_map) do
        if v > 0 then
            info = {}
            info["name"] = k
            info["price"] = get_thingprice(k)    --从数据库中查找单价
            info["count"] = v
            info["cost"] = info["count"]*info["price"]
            cost_things_map[index] = info
            index = index + 1
            cost_total = cost_total + info["cost"]  --计算总价
        end
    end
    tableutils.printTable(cost_things_map)
    
    --3>更新操作状态[正在拿物]
    if prefix == "End:" then
        local ok, err = set_salebox_status(salebox,"Paying",ngx.now(),nil,nil)
        if not ok then
            ngx.log(ngx.ERR, "hmset Record Status to Selecting failed", err)
            return false,"hmset Record Status to Selecting  failed"
        end
        --更新流水记录
        local ok, err = red_handler:hmset(record_key,"CloseDoorTime",ngx.localtime(),
                                        "CostThings",cjson.encode(cost_things_map),
                                        "CostTotal",cost_total)
        if not ok then
            ngx.log(ngx.ERR, "hmset Record to redis failed", err)
            return false,"hmset Record to redis failed"
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
    if prefix == "End:" then
        jrsp["DDIP"]["Body"]["Status"] = "Paying"
    else
        jrsp["DDIP"]["Body"]["Status"] = "Selecting"
    end    
    jrsp["DDIP"]["Body"]["CostThings"] = cost_things_map
    jrsp["DDIP"]["Body"]["CostTotal"] = cost_total
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
    --获取设备状态
    local status,_,_,recordid = get_salebox_status(salebox)
    if not status then
        ngx.log(ngx.ERR, "get_salebox_status failed!")
        return false,"get_salebox_status failed!"
    end
    local record_key = "salesbox:"..salebox..":record:"..recordid
    
    --创建redis操作句柄
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    
    --根据[购物流程梳理2]
    --1>判断支付是否成功，如果成功，则切换到[支付完成]
    if(jreq["DDIP"]["Body"]["Result"] == "OK") then
        --更新流水记录
        local ok, err = red_handler:hmset(record_key,"PayTime",ngx.localtime())
        if not ok then
            ngx.log(ngx.ERR, "hmset Record to redis failed", err)
            return false,"hmset Record to redis failed"
        end
        --更新售货机状态为空闲态
        local ok, err = set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        if not ok then
            ngx.log(ngx.ERR, "hmset Record Status to Free failed", err)
            return false,"hmset Record Status to Free failed"
        end
    else
        -->产生一条异常流水记录
        local ok, err = unpay_record_salebox(salebox)
        if not ok then
            ngx.log(ngx.ERR, "unpay_record_salebox failed : ", salebox_key,err)
        end
        --更新售货机状态为空闲态
        local ok, err = set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        if not ok then
            ngx.log(ngx.ERR, "hmset Record Status to Free failed", err)
            return false,"hmset Record Status to Free failed"
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
	jrsp["DDIP"]["Header"]["MessageType"] = "MSG_PAY_RESULT_ACK"
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
    
    --状态校验
    if not jreq["DDIP"]
        or not jreq["DDIP"]["Header"]
        or not jreq["DDIP"]["Body"]
        or not jreq["DDIP"]["Header"]["MessageType"]
        or not jreq["DDIP"]["Body"]["SalesBox"] 
    then
        send_resp_string(ngx.HTTP_BAD_REQUEST,"any","invalid message format");
	    return
	end
    local salebox = jreq["DDIP"]["Body"]["SalesBox"]
    local request_type = jreq["DDIP"]["Header"]["MessageType"]
    local ok,err = do_status_check(salebox,request_type)
    if not ok then
		send_resp_string(ngx.HTTP_BAD_REQUEST,"any",err);
	    return
	end

	--分命令处理
	if (request_type == "MSG_RECOGNIZE_NOTICE") then
		local ok, err = do_recognize(jreq);
		if not ok then
			send_resp_string(ngx.HTTP_BAD_REQUEST,"MSG_RECOGNIZE_ACK",err);
		end
	elseif (request_type == "MSG_OPENDOOR_REQ") then
		local ok, err = do_opendoor(jreq);
		if not ok then
			send_resp_string(ngx.HTTP_BAD_REQUEST,"MSG_OPENDOOR_RSP",err);
		end
	elseif (request_type == "MSG_BUY_INFO_REQ") then
		local ok, err = do_buyinfo(jreq);
		if not ok then
			send_resp_string(ngx.HTTP_BAD_REQUEST,"MSG_BUY_INFO_RSP",err);
		end
	elseif (request_type == "MSG_PAY_RESULT_NOTICE") then
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

