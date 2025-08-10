# HOTEL NETWORK PROJECT

## DESCRIPTION

You are required to design and implementa a Vic Modern Hotel network. The hotel has three floors; in the first floor there are three departments(Reception, store and Logistics), in the second floor there are three departments(Finance, HR and Sales/Marketing), while the third floor hosts the IT and Admin. Therefore, the following are part of the considerations during the design and implementation.

1. There should be three routers connecting each floor(all placed in the server room in IT department).
2. All routers should be connected to each other using serial DCE cable.
3. The network between the routers should be 10.10.10.0/30, 10.10.10.4/30, 10.10.10.9/30
4. Each floor is expected to have one switch (placed in the respective floor).
5. Each floor is expected to have WIFI networks connected to laptops and phones.
6. Each departmente is expected to have a printer.
7. Each department is expected to be in different VLAN with the following details:

        1st Floor;
        • Reception - VLAN 80, Network of 192.168.8.0/24
        • Store - VLAN 70, Network of 192.168.7.0/24
        • Logistics - VLAN 60, Network of 192.168.6.0/24
    
        2nd Floor;
        • Finance - VLAN 50, Network of 192.168.5.0/24
        • HR - VLAN 40, Network of 192.168.4.0/24
        • Sales - VLAN 30, Network of 192.168.3.0/24
    
        3rd Floor;
        • Admin - VLAN 20, Network of 192.168.2.0/24
        • IT - VLAN 10, Network of 192.168.1.0/24

9. Use OSPF as the routing protocol to advertise routes.
10. All devices in the network are expected to obtain IP address dynamically with their respective router configured as the DHCP server.
11. All the devices in the network are expected to communicate with each other.
12. Configure SSH in all the routers for remote login.
13. In IT department, add PC called Test-PC to port fa0/1 and use it to test remote login.
<br>

## SOLUTION

The following image presents the whole hotel network design grouped in different floors, in a Cisco Packet Tracer schema.

![Alt text](Total_Network_Diagram.png)

Since requirements 1-3 refer to the 3rd floor and specifically the IT department, I will start the configuration from there.

### 3RD FLOOR

<p align="center"> <img src="3rd_Floor_Diagram.png" alt="Diagram" width="600"> </p>

The 3rd Floor is consisted of the IT and the Admin departments.
In the IT department I will add 3 Cisco ISR 4321 routers connected with serial DCE cables to meet the requirements 1 and 2. On the 3rd requirement I am given 3 networks to use between the routers.

The first network is 10.10.10.0/30, which corresponds to the address range 10.10.10.0 - 10.10.10.3. 
However, 10.10.10.0 and 10.10.10.3 need to be reserved as network and broadcast addresses respectively. So,
- Router1 - Router3:<br>
10.10.10.0 -> Network <br>
10.10.10.1 -> R1 <br>
10.10.10.2 -> R3 <br>
10.10.10.3 -> Broadcast

The second network is 10.10.10.4/30, so that leaves us with address range 10.10.10.4 - 10.10.10.7. So, in the same way:
- Router2 - Router3:<br>
10.10.10.4 -> Network <br>
10.10.10.5 -> R3 <br>
10.10.10.6 -> R2 <br>
10.10.10.7 -> Broadcast

The third network is 10.10.10.8/30, so the available address range is 10.10.10.8 - 10.10.10.11 and once again:
- Router1 - Router2:<br>
10.10.10.8 -> Network <br>
10.10.10.9 -> R1 <br>
10.10.10.10 -> R2 <br>
10.10.10.11 -> Broadcast


