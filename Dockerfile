#Dockerfile
FROM salesbox/openrestybase:v0.01
#FROM daocloud.io/peizhiluo007/openresty:latest
MAINTAINER peizhiluo007<25159673@qq.com>

#采用supervisor来管理多任务
#配置文件的路径变化了(since Supervisor 3.3.0)
COPY supervisord.conf /etc/supervisor/supervisord.conf
COPY sale_lua/ /xm_workspace/xmcloud3.0/sale_lua/
COPY https_cert/ /xm_workspace/xmcloud3.0/https_cert/
RUN	chmod 777 /xm_workspace/xmcloud3.0/sale_lua/*

EXPOSE 9000
WORKDIR /xm_workspace/xmcloud3.0/sale_lua/
CMD ["supervisord"]
