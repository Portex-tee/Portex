# Portex
Feel free to explore the [Portex Demo](https://ac-dec.com/service.html) for a practical demonstration of the project's capabilities.

## Building and Executing Portex

To install and run Portex, follow these steps:

### Install Drogon
- Follow the [Drogon Installation Guide](https://github.com/drogonframework/drogon/wiki/ENG-02-Installation).

### Install GMP
- Execute `sudo apt-get install libgmp-dev`.

### Install PBC
- Download PBC from [PBC Official Website](https://crypto.stanford.edu/pbc/download.html).
- Install using the commands:
  ```
  ./configure
  make
  make install
  ```

### Build the Client
```
cd client
mkdir build
cd build
cmake ..
make
cd ..
```

### Build the LogManager
```
cd LogManager
mkdir build
cd build
cmake ..
make
cd ..
```

### Build the PKG
```
cd pkg
make
```

### Execute the Client, LogManager, and PKG
```
# Client
cd client
build/Client
# LogManager
cd LogManager
build/LogManager
# PKG
cd pkg
./app
```

### Accessing the Service
- Visit `0.0.0.0:80` in your web browser.




