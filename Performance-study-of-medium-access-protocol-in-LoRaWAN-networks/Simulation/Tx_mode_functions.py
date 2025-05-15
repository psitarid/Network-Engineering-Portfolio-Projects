import numpy as np


def select_nodes_to_transmit(time, lambd, ToA, node_list, nodes_transmitting, nodes_to_retransmit):
    num_to_transmit = 0  # Number of nodes to transmit
    new_nodes_to_retransmit = []  # Nodes attempting to retransmit
    nodes_attempted_to_retransmit = 0  # Number of nodes attempting to retransmit
    total_nodes_selected = 0  # Total number of nodes selected to transmit
    # unable_to_transmit_because_of_duty_cycle = 0  # Number of nodes unable to transmit due to duty cycle
    
    #find the number of nodes that can transmit in this msec in terms of duty cycle
    duty_cycle_verified = []
    for node in node_list:
        # if(node.Toff >= ToA/node.duty_cycle - ToA):
        if node.time_transmitted <= 36000 - ToA:    
            duty_cycle_verified.append(node)

    # Choose the number of nodes to transmit using Poisson distribution
        num_to_transmit = min(abs(np.random.poisson(lambd * len(node_list))), len(duty_cycle_verified))#  0<= num_to_transmit <= len(duty_cycle_verified)
    for i in range(num_to_transmit):
        i = np.random.choice(duty_cycle_verified)
        i.time_transmitted += ToA
        nodes_transmitting.append(i)
        node_list.remove(i)
        duty_cycle_verified.remove(i)

    # Check if any nodes want to retransmit
    if(len(nodes_to_retransmit) > 0):
        for j in nodes_to_retransmit:
            if time == j.retransmission_time:
            # if(time == (j.retransmission_time) and j.time_transmitted <= 36000 - ToA):  # Wait long enough until the next transmission to comply with duty cycle policy):
                    j.time_transmitted += ToA
                    nodes_transmitting.append(j)
                    nodes_attempted_to_retransmit += 1
            else:
                # j.retransmission_time = time + np.random.randint(1, 80000)
                new_nodes_to_retransmit.append(j)
        nodes_to_retransmit.clear()
        for i in new_nodes_to_retransmit:
            nodes_to_retransmit.append(i)
    
    total_nodes_selected = num_to_transmit + nodes_attempted_to_retransmit    
    return total_nodes_selected


def check_collisions(gateway, nodes_transmitting):
    if((len(nodes_transmitting) >= 1 and gateway.get_state() == 'busy') or len(nodes_transmitting) > 1 and gateway.get_state() == 'idle'):
        if(gateway.get_state() == 'busy'):
            gateway.ack_collided = True
        for node in nodes_transmitting:
            if(node.collided == False):
                node.collided = True




def check_uplink_finished(time, nodes_transmitting, RX_delay1, max_timeout_for_ack, waiting_for_ack):
    new_nodes_transmitting = []
    if(len(nodes_transmitting) > 0):
        for node in nodes_transmitting:
            if(node.time_left == 0):  # Check if nodes finished transmitting
                waiting_for_ack.append(node)  # Transfer the finished nodes to waiting_for_ack list
                node.RX_delay1_ends = time + RX_delay1
                node.timeout_ends = time + RX_delay1 + max_timeout_for_ack
            else:
                new_nodes_transmitting.append(node)
        nodes_transmitting.clear()
        for node in new_nodes_transmitting:
            node.time_left -= 1
            nodes_transmitting.append(node)



def update_Toff(time, node_list, nodes_to_retransmit):
    lists = [node_list, nodes_to_retransmit]
    if(time % 3600000 == 1):
        for nodes in lists:
            for node in nodes:
                node.Toff +=1
                node.time_transmitted = 0
    else:
        for nodes in lists:
            for node in nodes:
                node.Toff +=1