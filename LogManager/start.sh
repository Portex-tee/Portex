# 切换到 LogManager 的目录
cd /root/Portex-gitee/LogManager/

\cp log.txt log.txt.bkp

# 在指定目录下重新启动 LogManager 并重定向输出到 log.txt
./build/LogManager > log.txt
