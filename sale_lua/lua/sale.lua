#!/usr/local/openresty/luajit/bin/luajit-2.1.0-alpha

-----------------����淶˵��-----------------
--[[
���г��������ܶ������Ƶ�
˵��1>�Դ���Ӧ��Ĵ���
	��processmsg�����л���ø��������֧�������֧�����ɹ������ڲ�����httpӦ��
	�������ʧ�ܣ���processmsg�жϷ���ֵͳһӦ��
˵��2>�Լ�Ȩ�ȳ��湲�ԵĶ������ÿ���ͳһ���ű���ȥִ��
˵��3>HTTPӦ��ͷͳһ����OK���������ڲ�����Ӧ�ô��󣬻���ϵͳ����
]]

-----------------���˼·-----------------
--[[״̬������:"Free|Selecting|Paying"]]
--[[
Free:����̬��
    a>��������->[���в����ɹ�]->Selecting
    a>��������->��ЧӦ��
Opening:��˲̬����ʱ10�롿
    a>ʶ������->[д�����ݿ�]
    a>��������->��ЧӦ��
Selecting:����̬��
    a>������Ϣ����->[�ж�����ʶ�����]->Paying
    a>ʶ������->[д�����ݿ�]->[�ж�����ʶ�����]->Paying
    a>��������->��ЧӦ��
Paying:��˲̬����ʱ30�롿
    a>֧���ɹ���Ϣ->Free
    a>��ʱ�ж�->Free
    a>��������->��ЧӦ��
]]

--[�趨����·��]
--���Զ����·������package������·���С�Ҳ���Լӵ���������LUA_PATH��
--�ŵ�init_lus_path.lua�У���Ȼ�Ļ���ÿһ���������ʱ�򶼻��ȫ�ֱ���
--package.path�������ã�����

--[����������ģ��]
local tableutils = require("common_lua.tableutils")		--��ӡ����
local cjson = require("cjson.safe")
local wanip_iresty = require("common_lua.wanip_iresty")
local http_iresty = require ("resty.http")
local redis_iresty = require("common_lua.redis_iresty")
local script_utils = require("common_lua.script_utils")

--[������������]
local redis_ip = nil
local redis_port = 6379

--����Ӧ�����ݱ�
local function send_resp_table (status,resp)
	if not resp or type(resp) ~= "table" then
		ngx.log(ngx.ERR, "send_resp_table:type(resp) ~= table", type(resp))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	--HTTPӦ��ͷͳһ����OK���������ڲ�����Ӧ�ô��󣬻���ϵͳ����
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
	--HTTPӦ��ͷͳһ����OK���������ڲ�����Ӧ�ô��󣬻���ϵͳ����
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

--������Ĳ�������Ч�Լ�飬���ؽ�������Ϣ�����json����
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

--��ȡsalebox�Ľ������ĵ�ַ��Ϣ
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

--���������ͷ�������
local function send_to_accessserver(salebox,reqmsg,reqbody)
    
    --��Redis�л�ȡAccessServer�ĵ�ַ��Ϣ
    local server_addr,server_port = get_salebox_accessserver(salebox)
    if not server_addr then
        ngx.log(ngx.ERR,"get_salebox_accessserver failed ",err,server_addr)
        return false,"get_salebox_accessserver failed"
    end

    --���ӽ��������
    local httpc = http_iresty.new()
    httpc:set_timeout(3000)
	local ok, err = httpc:connect(server_addr,server_port)
	if not ok  then
		ngx.log(ngx.ERR,"httpc:connect failed ",server_addr,err)
		return false,"httpc:connect failed "..server_addr
	end

    --���������
	local jreq = {}
	jreq["DDIP"] = {}
	jreq["DDIP"]["Header"] = {}
	jreq["DDIP"]["Header"]["Version"] = "1.0"
	jreq["DDIP"]["Header"]["CSeq"] = "1"
	jreq["DDIP"]["Header"]["MessageType"] = reqmsg
	jreq["DDIP"]["Body"] = reqbody
    --���������
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
	--���ղ����ͽ����������Ӧ���
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
--����һ����ˮ��[docker�����У�����ʱ������]
local function get_recordid()
    return os.date("%Y%m%d-%H%M%S")  
end

--��ȡsalebox����
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

--��ȡsalebox״̬
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

--����salebox״̬
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

--�ж�����camera�Ķ�������
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

--�ж�ĳһ����¼�µ�camera��ʶ�������Ѿ���λ
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
    --��ȡ״̬
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
            --�����ڷ���0�����ڷ���1
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

--��¼һ���쳣֧��
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

--״̬У��ͻָ�
function do_status_check(salebox,request_type)
    --��ȡ״̬
    local status,statustime,operator,recordid = get_salebox_status(salebox)
    
    --�쳣״̬�ָ�
    if (status == "Opening") and (ngx.now() >= statustime+15) then 
        ngx.log(ngx.ERR, "Opening Timeout,Reset to Free;salebox=", salebox)
        set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        status = "Free"
    end
    if (status == "Paying") and (ngx.now() >= statustime+30) then 
        -->����һ���쳣��ˮ��¼
        local ok, err = unpay_record_salebox(salebox)
        if not ok then
            ngx.log(ngx.ERR, "unpay_record_salebox failed : ", salebox_key,err)
        end
        ngx.log(ngx.ERR, "Paying Timeout,Reset to Free;salebox=", salebox)
        set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        status = "Free"
    end
    if (status == "Selecting") and (ngx.now() >= statustime+30) then 
        --�ڹ���״̬��,��30��û���յ��豸��ʶ����Ϣ(��ʱ�豸������)
        local ret = check_salebox_camera_close(salebox)
        if ret == true then
            ngx.log(ngx.ERR, "Selecting Timeout,Reset to Free;salebox=", salebox)
            set_salebox_status(salebox,"Free",ngx.now(),"000","000")
            status = "Free"
        end
    end
    
    --״̬�������ƥ��
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

--����ʶ����Ϣ
function do_recognize(jreq)
	--�ж������ʽ����Ч��
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
    
    --�ֽ���Ϣ,����������һ��
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

    --����redis�������
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end

    --��ȡ״̬,�������ݿ�
    local status,statustime,operator,recordid = get_salebox_status(salebox)
    local prefix = "Mid:"
    if status == "Opening" then
        if doorstatus ~= "Close" then   --���ڿ��ŵ�ʱ�� ��������˿϶��ǹر�״̬��
            ngx.log(ngx.ERR, "check doorstatus==Close failed ", doorstatus)
            return false,"check doorstatus==Close failed"
        end
        prefix = "Begin:"
    elseif status == "Selecting" then
        if doorstatus == "Open" then
            prefix = "Mid:"
            --ˢ�¹���̬�µ�ʱ���()
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

    --����Ӧ������
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

--����С�������Ŀ�������
function do_opendoor(jreq)
	--�ж������ʽ����Ч��
	if not jreq["DDIP"]["Body"]["SalesBox"]
        or not jreq["DDIP"]["Body"]["Operator"]
		or type(jreq["DDIP"]["Body"]["SalesBox"]) ~= "string"
        or type(jreq["DDIP"]["Body"]["Operator"]) ~= "string"
		then
	    ngx.log(ngx.ERR, "do_opendoor,invalid args")
	    return false,"do_opendoor,invalid args"
	end
    local salebox = jreq["DDIP"]["Body"]["SalesBox"]
          
    --����redis�������
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end

    --����[������������2]
    --<1>���ö�Ӧ��״̬
    local operator = jreq["DDIP"]["Body"]["Operator"]
    local recordid = get_recordid()
    local ok, err = set_salebox_status(salebox,"Opening",ngx.now(),operator,recordid)
    if not ok then
        ngx.log(ngx.ERR, "hmset Salebox Status to redis failed", err)
        return false,"hmset Salebox Status to redis failed"
    end
    
    --<2>������ˮ��¼
    local record_key = "salesbox:"..salebox..":record:"..recordid
    local ok, err = red_handler:hmset(record_key,"Operator",operator,"OpenDoorTime",ngx.localtime())
    if not ok then
        ngx.log(ngx.ERR, "hmset Record to redis failed", err)
        return false,"hmset Record to redis failed"
    end
    
    --<3>���������������ʶ������
    local reqbody = {}
    reqbody["SalesBox"] = jreq["DDIP"]["Body"]["SalesBox"]
	reqbody["RecordID"] = recordid
    local ok = send_to_accessserver(jreq["DDIP"]["Body"]["SalesBox"],"MSG_RECOGNIZE_REQ",reqbody)
    if ok ~= true then
        --�ָ�״̬
        set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        ngx.log(ngx.ERR, "send_to_accessserver MSG_RECOGNIZE_REQ failed")
        return false,"send_to_accessserver MSG_RECOGNIZE_REQ failed"
    end
    
    --<4>�ȴ�����camera�ĳ�ʼʶ�����
    local ok,err = check_salebox_camera_recognize(salebox,"Begin:",15)
    if(ok ~= true) then
        --�ָ�״̬
        set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        ngx.log(ngx.ERR, "wait for camera ready timeout")
        return false,"wait for camera ready timeout"
    end

    --<5>��������������Ϳ�������
    local reqbody = {}
    reqbody["SalesBox"] = jreq["DDIP"]["Body"]["SalesBox"]
    local ok = send_to_accessserver(jreq["DDIP"]["Body"]["SalesBox"],"MSG_OPENDOOR_REQ",reqbody)
    if ok ~= true then
        --�ָ�״̬
        set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        ngx.log(ngx.ERR, "send_to_accessserver MSG_RECOGNIZE_REQ failed")
        return false,"send_to_accessserver MSG_RECOGNIZE_REQ failed"
    end

    --<6>��ˮ״̬Ϊ[��������]
    local ok, err = set_salebox_status(salebox,"Selecting",ngx.now(),operator,recordid)
    if not ok then
        --�ָ�״̬
        set_salebox_status(salebox,"Free",ngx.now(),"000","000") 
        ngx.log(ngx.ERR, "hmset Record Status to Selecting failed", err)
        return false,"hmset Record Status to Selecting  failed"
    end
    
    --<7>��С����Ӧ��
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

--�����ݿ��в�����Ʒ�ĵ���
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
    sub_map = {}   --mapA��ȥmapB
    for k,v in pairs(mapA) do
        if mapB[k] ~= nil then 
            sub_map[k] = mapA[k]-mapB[k]
        else
            sub_map[k] = mapA[k]
        end
    end
    return sub_map
end

--��ȡ�����б�
function do_buyinfo(jreq)
	--�ж������ʽ����Ч��
	if not jreq["DDIP"]["Body"]["SalesBox"]
		or type(jreq["DDIP"]["Body"]["SalesBox"]) ~= "string"
		then
	    ngx.log(ngx.ERR, "do_opendoor,invalid args")
	    return false,"do_opendoor,invalid args"
	end
    local salebox = jreq["DDIP"]["Body"]["SalesBox"]
    
    --����redis�������
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    
    --����[������������2]
    --1>�ж�����camera�Ľ���ʶ���Ƿ���ɡ�
    local prefix = "Mid:"    
    local camera_end_ok,_ = check_salebox_camera_recognize(salebox,"End:",0)
    if(camera_end_ok) then
        prefix = "End:"
    else
        --������м�̬Ҳû�кõĻ�����ʱ�޷����������б�
        local camera_mid_ok,_ = check_salebox_camera_recognize(salebox,"Mid:",0)
        if(not camera_mid_ok) then 
            --����Ӧ������
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
    
    --2>���㹺���嵥------
    --��ȡ�豸����
    local layernum,layercameranum = get_salebox_config(salebox)
    if layernum == false then
        ngx.log(ngx.ERR, "get_salebox_config failed:",layernum,layercameranum)
		return false,"get_salebox_config failed"
    end
    local total_carama_count = layernum*layercameranum
    --��ȡ�豸״̬
    local status,_,_,recordid = get_salebox_status(salebox)
    if not status then
        ngx.log(ngx.ERR, "get_salebox_status failed!")
        return false,"get_salebox_status failed!"
    end
    local record_key = "salesbox:"..salebox..":record:"..recordid
    
    --��ȡ�б�:��ʼʱ��
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
    --��ȡ�б�:��ǰʱ��
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
    --���㹺���嵥
    local cost_things_map = {}     
    local cost_total = 0.00
    local decrease_map = sub_thingmap(begin_things_map,cur_things_map)
    --tableutils.printTable(decrease_map)
    local index = 1
    for k,v in pairs(decrease_map) do
        if v > 0 then
            info = {}
            info["name"] = k
            info["price"] = get_thingprice(k)    --�����ݿ��в��ҵ���
            info["count"] = v
            info["cost"] = info["count"]*info["price"]
            cost_things_map[index] = info
            index = index + 1
            cost_total = cost_total + info["cost"]  --�����ܼ�
        end
    end
    tableutils.printTable(cost_things_map)
    
    --3>���²���״̬[��������]
    if prefix == "End:" then
        local ok, err = set_salebox_status(salebox,"Paying",ngx.now(),nil,nil)
        if not ok then
            ngx.log(ngx.ERR, "hmset Record Status to Selecting failed", err)
            return false,"hmset Record Status to Selecting  failed"
        end
        --������ˮ��¼
        local ok, err = red_handler:hmset(record_key,"CloseDoorTime",ngx.localtime(),
                                        "CostThings",cjson.encode(cost_things_map),
                                        "CostTotal",cost_total)
        if not ok then
            ngx.log(ngx.ERR, "hmset Record to redis failed", err)
            return false,"hmset Record to redis failed"
        end
    end
    
    --����Ӧ������
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
    --�ж������ʽ����Ч��
	if not jreq["DDIP"]["Body"]["SalesBox"]
        or not jreq["DDIP"]["Body"]["Result"]
		or type(jreq["DDIP"]["Body"]["SalesBox"]) ~= "string"
        or type(jreq["DDIP"]["Body"]["Result"]) ~= "string"
		then
	    ngx.log(ngx.ERR, "do_opendoor,invalid args")
	    return false,"do_opendoor,invalid args"
	end
    local salebox = jreq["DDIP"]["Body"]["SalesBox"]
    --��ȡ�豸״̬
    local status,_,_,recordid = get_salebox_status(salebox)
    if not status then
        ngx.log(ngx.ERR, "get_salebox_status failed!")
        return false,"get_salebox_status failed!"
    end
    local record_key = "salesbox:"..salebox..":record:"..recordid
    
    --����redis�������
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    
    --����[������������2]
    --1>�ж�֧���Ƿ�ɹ�������ɹ������л���[֧�����]
    if(jreq["DDIP"]["Body"]["Result"] == "OK") then
        --������ˮ��¼
        local ok, err = red_handler:hmset(record_key,"PayTime",ngx.localtime())
        if not ok then
            ngx.log(ngx.ERR, "hmset Record to redis failed", err)
            return false,"hmset Record to redis failed"
        end
        --�����ۻ���״̬Ϊ����̬
        local ok, err = set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        if not ok then
            ngx.log(ngx.ERR, "hmset Record Status to Free failed", err)
            return false,"hmset Record Status to Free failed"
        end
    else
        -->����һ���쳣��ˮ��¼
        local ok, err = unpay_record_salebox(salebox)
        if not ok then
            ngx.log(ngx.ERR, "unpay_record_salebox failed : ", salebox_key,err)
        end
        --�����ۻ���״̬Ϊ����̬
        local ok, err = set_salebox_status(salebox,"Free",ngx.now(),"000","000")
        if not ok then
            ngx.log(ngx.ERR, "hmset Record Status to Free failed", err)
            return false,"hmset Record Status to Free failed"
        end
        ngx.log(ngx.ERR, "Pay Result Failed")
        return false,"Pay Result Failed" 
    end

    --����Ӧ������
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

--��Ϣ���������
function process_msg()
	--��ȡ�������
	local jreq, err = get_request_param()
	if not jreq then
		send_resp_string(ngx.HTTP_BAD_REQUEST,"any",err);
	    return
	end
    
    --״̬У��
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

	--�������
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

--����������Ϣ(��������������)
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

--�������
--print("get request_body:"..ngx.var.request_body)
--print("=====================new request=======================\n")
--print("get server_port::::",ngx.var.server_port,type(ngx.var.server_port))

--����ͨ���˿ں���������https��http
--ngx.var.server_port

local ok = load_ip_addr()
if not ok then
    ngx.log(ngx.ERR,"load_ip_addr failed ")
    return false
end
process_msg()

