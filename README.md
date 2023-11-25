Available sensor type:
Device:
temperature,light,humidity,radiation,co2,co,motion,smoke
Washing Machine
washer,lock,load,electricity_usage,water_usage,rpm,temperature,duration

Command type:
heater on/off, light on/off, washer on/off

Example interactions

```markdown
Node /house3/room3/phone - Enter command (interest/data/exit/add_fit): data
Enter destination node for data packet: /house1/room2/washine_machine
Enter sensor name: motor
Enter data content: command/on
```

Start devices separately in different terminals

1. Start devices for House1:
Run each of the following scripts in different terminals
```shell
chmod +x ./device1 ./device2 ./device3 ./device4 ./washing_machine ./phone
./device1 
./device2 
./device3 
./device4 
./washing_machine
./phone
```

2. Start devices for House2:
Run each of the following scripts in different terminals
```shell
chmod +x ./device5 ./device6
./device5
./device6 
```

3. Start devices for House3:
Run each of the following scripts in different terminals
```shell
chmod +x ./device7 ./device8 ./device9
./device7
./device8 
./device9 
```

4. Start auto sender sending encrypted data

```shell
python send_data.py
```

5. Start auto sender sending unencrypted data

```shell
python send_unsecured_data.py
```
