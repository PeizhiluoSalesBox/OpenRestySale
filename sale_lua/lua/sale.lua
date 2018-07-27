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
local accessserver_addr = nil
local accessserver_port = 8000

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

--���������ͷ�������
local function send_to_accessserver(salebox,reqmsg,reqbody)
    --����һ�µ�����
	local host_ip,err = wanip_iresty.getdomainip(accessserver_addr)
	if not host_ip then
        ngx.log(ngx.ERR,"getdomainip failed ",err,accessserver_addr)
        return false,"getdomainip failed"
    end
    --���ӽ��������
    local httpc = http_iresty.new()
    httpc:set_timeout(3000)
	local ok, err = httpc:connect(host_ip,accessserver_port)
	if not ok  then
		ngx.log(ngx.ERR,"httpc:connect failed ",host_ip,err)
		return false,"httpc:connect failed "..host_ip
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
    local salebox_status, err = red_handler:hmget(saleboxstatus_key,"Operator","RecordID")
    if not salebox_status then
	    --ngx.log(ngx.ERR, "get salebox_status failed : ", saleboxstatus_key,err,redis_ip)
		return "000","000"
	end
    local operator = salebox_status[1]
    local recordid = salebox_status[2]
    return operator,recordid
end
--����salebox״̬
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
    
--��¼һ���쳣֧��
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

    --��ȡ����(��֤һ��,��Ŀ�Ƿ���ڣ������Ѿ�����)
    local layernum,layercameranum = get_salebox_config(salebox)
    if layernum == false then
        ngx.log(ngx.ERR, "check salebox config failed:",layernum,layercameranum)
		return false,"check salebox config failed"
    end

    -->[�쳣�ָ�:����֮��ֱ���˳�С�������ϱ��ţ���ʱһֱ��ס����״̬]
    local ret = check_salebox_camera_close(salebox,layernum,layercameranum)
    if ret == true then
        local ok, err = set_salebox_status(salebox,"000","000")
        if not ok then
            ngx.log(ngx.ERR, "set_salebox_status to free failed : ", salebox_key,err)
            return false,"hmset salebox status 000 to redis failed"
        end
    end

    --��ȡ״̬
    local operator,recordid = get_salebox_status(salebox)
    if (operator ~= "000") or (recordid ~= "000") then
        --ǰ����˻�û����ɣ���������ֿ�ʼɨ����
        ngx.log(ngx.ERR, "Salebox is using by ",operator)
        return false,"Salebox is using by"..operator
    end

    --����[������������2]
    --<1>������ˮ��,��¼������
    --<2>������ˮ��¼����ˮ״̬Ϊ[���ڿ���]
    --<3>���������������ʶ������
    --<4>�ȴ�����camera�ĳ�ʼʶ����ɡ�
    --<5>��������������Ϳ�������
    --<6>��ˮ״̬Ϊ[��������]
    --<7>��С����Ӧ��
    
    --<1>������ˮ��,��¼������
    local operator = jreq["DDIP"]["Body"]["Operator"]
    local recordid = get_recordid()
    local ok, err = set_salebox_status(salebox,operator,recordid)
    if not ok then
        ngx.log(ngx.ERR, "hmset Salebox Status to redis failed", err)
        return false,"hmset Salebox Status to redis failed"
    end
    
    --<2>������ˮ��¼����ˮ״̬Ϊ[���ڿ���]
    local record_key = "salesbox:"..salebox..":record:"..recordid
    local ok, err = red_handler:hmset(record_key,
                                        "Status","Opening",
                                        "Operator",operator,
                                        "OpenDoorTime",ngx.localtime())
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
        --�˳�����״̬
        set_salebox_status(salebox,"000","000")
        ngx.log(ngx.ERR, "send_to_accessserver MSG_RECOGNIZE_REQ failed")
        return false,"send_to_accessserver MSG_RECOGNIZE_REQ failed"
    end

    --<4>�ȴ�����camera�ĳ�ʼʶ�����
    local wait_succ = false
    for i=1,15 do
        local get_camera_count = 0
        local total_carama_count = layernum * layercameranum
        for index=0,total_carama_count-1 do
            local aaa = math.floor(index/layercameranum)
            local bbb = (index%layercameranum)
            local camera_key = "Begin:"..tostring(1+aaa)..tostring(1+bbb)..":ThingsName"
            local exist, err = red_handler:hexists(record_key,camera_key)
            --�����ڷ���0�����ڷ���1
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
        --�˳�����״̬
        set_salebox_status(salebox,"000","000")
        ngx.log(ngx.ERR, "wait for camera ready timeout")
        return false,"wait for camera ready timeout"
    end

    --<5>��������������Ϳ�������
    local reqbody = {}
    reqbody["SalesBox"] = jreq["DDIP"]["Body"]["SalesBox"]
    local ok = send_to_accessserver(jreq["DDIP"]["Body"]["SalesBox"],"MSG_OPENDOOR_REQ",reqbody)
    if ok ~= true then
        --�˳�����״̬
        set_salebox_status(salebox,"000","000")    
        ngx.log(ngx.ERR, "send_to_accessserver MSG_RECOGNIZE_REQ failed")
        return false,"send_to_accessserver MSG_RECOGNIZE_REQ failed"
    end

    --<6>��ˮ״̬Ϊ[��������]
    local ok, err = red_handler:hset(record_key,"Status","Selecting")
    if not ok then
        --�˳�����״̬
        set_salebox_status(salebox,"000","000")    
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
    
    --����redis�������
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    
    --�ֽ���Ϣ,����������һ��
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

    --��ȡ״̬: ȷ�ϵ�ǰ���ڹ���̬(����̬�ǲ�Ҫʶ���)
    local operator,recordid = get_salebox_status(salebox)
    if(operator == "000") or (recordid == "000") then
        ngx.log(ngx.ERR, "Salebox is free")
        return false,"Salebox is free"
    end
   
    --����[������������2]
    --��¼��������ˮ״̬
    --1>[���ڿ���]==��ǰ״̬
    --  ���(��״̬==�ر�),�������
    --  ��ʶ������¼��Begin:��
    --2>[��������]==��ǰ״̬
    --  if(��״̬==����)
    --      ��ʶ������¼��Mid:��
    --  if(��״̬==����)
    --      ��ʶ������¼��End:��
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

function table_link_together(a,b)
    for i,v in pairs(b) do
        table.insert(a,v)
    end
end

--��ʱ����
function  pay_timeout_process(premature,salebox)
    print("----------pay_timeout_process-----------",salebox)
    --��ȡ״̬
    local operator,recordid = get_salebox_status(salebox)
    if(operator == "000") and (recordid == "000") then
        return true
    end
    ngx.log(ngx.ERR, "Salebox Pay timeout by ",operator,recordid)
    --1>���ۻ���״̬�л�Ϊ����̬
    local ok, err = set_salebox_status(salebox,"000","000")
    if not ok then
        ngx.log(ngx.ERR, "set_salebox_status to free failed : ", salebox_key,err)
    end
    --2>����һ���쳣��ˮ��¼
    local ok, err = unpay_record_salebox(salebox,operator,recordid)
    if not ok then
        ngx.log(ngx.ERR, "unpay_record_salebox failed : ", salebox_key,err)
    end
end

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
    
    --��ȡ����
    local layernum,layercameranum = get_salebox_config(salebox)
    if layernum == false then
        ngx.log(ngx.ERR, "check salebox config failed:",layernum,layercameranum)
		return false,"check salebox config failed"
    end

    --��ȡ״̬
    local operator,recordid = get_salebox_status(salebox)
    if(operator == "000") or (recordid == "000") then
        ngx.log(ngx.ERR, "Salebox is free")
        return false,"Salebox is free"
    end
    
    --���봦��[��������]
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
    
    --����[������������2]
    --1>�ж�����camera�Ľ���ʶ���Ƿ���ɡ�
    --2>��ȡ�����嵥
    --3>����Ѿ����,�����л���[����֧��]
    --4>����������ʱ����Ҫ��30����֧����ɡ�
    --  ���֧��ʧ�ܻ��߳�ʱ�������һ��δ�����¼��
    local get_camera_count = 0
    local total_carama_count = layernum * layercameranum
    for index=0,total_carama_count-1 do
        local aaa = math.floor(index/layercameranum)
        local bbb = (index%layercameranum)
        local camera_key = "End:"..tostring(1+aaa)..tostring(1+bbb)..":ThingsName"
        local exist, err = red_handler:hexists(record_key,camera_key)
        --�����ڷ���0�����ڷ���1
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
    
    --��ȡ�����嵥�б�
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
        cost_things_value[i] = 0.0  --�����ݿ��в鵽
        cost_total = cost_total + cost_things_value[i]
    end

    --�л���[����֧��]
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
        
        --����һ����ʱ��,��ʱʱ��60��
        local ok, err = ngx.timer.at(60,pay_timeout_process,salebox)
        if not ok then
            ngx.log(ngx.ERR, "failed to start pay timeout timer: ", err)
            return
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
    jrsp["DDIP"]["Body"]["Status"] = record_status
    jrsp["DDIP"]["Body"]["ThingsName"] = cost_things_name
    jrsp["DDIP"]["Body"]["ThingsCost"] = cost_things_value
    jrsp["DDIP"]["Body"]["TotalCost"] = cost_total
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
    
    --����redis�������
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    
    --��ȡ״̬
    local operator,recordid = get_salebox_status(salebox)
    if(operator == "000") or (recordid == "000") then
        ngx.log(ngx.ERR, "Salebox is free")
        return false,"Salebox is free"
    end

    --���봦��[����֧��]
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

    --����[������������2]
    --1>�ж�֧���Ƿ�ɹ�������ɹ������л���[֧�����]
    if(jreq["DDIP"]["Body"]["Result"] == "OK") then
        local ok, err = red_handler:hmset(record_key,
                                        "Status","Payed",
                                        "PayTime",ngx.localtime())
        if not ok then
            ngx.log(ngx.ERR, "hmset Record to redis failed", err)
            return false,"hmset Record to redis failed"
        end
        --���ۻ����ָ�������̬
        local ok, err = set_salebox_status(salebox,"000","000")
        if not ok then
            ngx.log(ngx.ERR, "set_salebox_status to free failed : ", salebox_key,err)
            return false,"hmset salebox status 000 to redis failed"
        end
    else
        --1>���ۻ���״̬�л�Ϊ����̬
        local ok, err = set_salebox_status(salebox,"000","000")
        if not ok then
            ngx.log(ngx.ERR, "set_salebox_status to free failed : ", salebox_key,err)
        end
        --2>����һ���쳣��ˮ��¼
        local ok, err = unpay_record_salebox(salebox,operator,recordid)
        if not ok then
            ngx.log(ngx.ERR, "unpay_record_salebox failed : ", salebox_key,err)
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
	jrsp["DDIP"]["Header"]["MessageType"] = "MSG_PAY_RESULT_NOTICE"
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

	--�������
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

