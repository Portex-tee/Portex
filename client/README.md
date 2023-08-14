------------------------------------
How to Build/Execute the Client Code
------------------------------------
1. Install Drogon:
    - Follows https://github.com/drogonframework/drogon/wiki/ENG-02-Installation
2. Install GMP:
    - `sudo apt-get install libgmp-dev`
3. Install PBC:
    - Downloads pbc in https://crypto.stanford.edu/pbc/download.html
    - `./configure`\
      `make`\
      `make install`
4. Build the client code:
    - `cd client`\
      `mkdir build`\
      `cd build`\
      `cmake ..`\
      `cmake --build .`\
      `cd ..`
5. Execute the client code:
    - `cd client`
    - `build/Client`
    - Open the browser and access `0.0.0.0:18080`
    - Encrypt message and copy the ciphertext
    - Paste the ciphertext in the input box and click the Decrypt
    - Access the log manager in `[2001:da8:201d:1107::c622]:18081`