## How to build the project
This project utilize VS code Dev Container to ease up the environment setup. 
![alt text](Doc/remote-dev-arch.png)
### Set-up Dev Environment
Please refer to official tutorial tutorial for how to setup the environment
### Compile the Project
Execute the following command in terminal of VS code, please note the command is actually executed on the dev container.
```shell
cd ECIES
mkdir build
cd build
cmake ..
make
```
### Run the executable
Execute the following command in terminal of VS code, please note the command is actually executed on the dev container.
```shell
./ECIES
```
