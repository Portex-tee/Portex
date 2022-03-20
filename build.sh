#！/usr/bin/bash

source /opt/intel/sgxsdk/environment

cd client
make clean
make SGX_MODE=SIM

cd ..
cd server
make clean
make SGX_MODE=SIM

cd ..