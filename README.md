# m2m2_test
A basic cpp program to receive lidar data from the m2m2 mapper lidar


# Getting started
build the single file with:

```
g++ -std=c++17 lidar_client.cpp -o lidar_client  -lssl -lcrypto
```

Then if the m2m2 is wired to your ethernet at 192.168.1.243 the command would be:
```
./lidar_client 192.168.1.243 1445
```



