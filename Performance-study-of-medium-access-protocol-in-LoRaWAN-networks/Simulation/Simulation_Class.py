import numpy as np
from Node_Class import Node


class Simulation:
    node_num = 0
    num_to_transmit = 0
    successful_transmissions = 0
    collisions = 0
    total_num_to_transmit = 0
    total_successful_transmissions = 0
    total_collisions = 0

    def __init__(self):
        self.node_num = 0
        self.num_to_transmit = 0
        self.successful_transmissions = 0
        self.collisions = 0
        self.total_successful_transmissions = 0
        self.total_num_to_transmit = 0
        self.total_collisions = 0
    

    def update_metrics_per_cycle(self, Tx_results, gateway):
        if(Tx_results > 0):
            self.successful_transmissions += Tx_results
            gateway.successful_acks += 1 
        elif(Tx_results < 0 ):
            self.collisions += Tx_results/(-1)

    
    
    def update_metrics_per_node_step(self, node_step, gateway, ToA, G, S, node_list, nodes_to_retransmit, nodes_transmitting, waiting_for_ack, collision_rate, len_node_list, len_nodes_transmitting, len_waiting_for_ack, len_nodes_to_retransmit, nodes_selected, ack_duration):
            collided_acks = gateway.ack_attempts - gateway.successful_acks
            # self.num_to_transmit = self.collisions + self.successful_transmissions
            nodes_selected.append(self.collisions + self.successful_transmissions)
            # G.append((self.num_to_transmit * ToA + gateway.ack_attempts * ack_duration)/node_step)
            G.append((self.collisions + self.successful_transmissions) * ToA/node_step)
            # S.append((ToA * self.successful_transmissions + ack_duration * gateway.successful_acks)/node_step)
            S.append(ToA * self.successful_transmissions/node_step)
            
            if(self.num_to_transmit > 0):
                collision_rate.append(self.collisions / self.num_to_transmit)
                # collision_rate.append(self.collisions * ToA / node_step)
            else:
                collision_rate.append(0)

            len_node_list.append(len(node_list))
            len_nodes_transmitting.append(len(nodes_transmitting))
            len_waiting_for_ack.append(len(waiting_for_ack))
            len_nodes_to_retransmit.append(len(nodes_to_retransmit))                                                

    
    def reset_metrics(self, gateway):
        self.num_to_transmit = 0
        self.successful_transmissions = 0
        self.collisions = 0
        gateway.ack_attempts = 0
        gateway.successful_acks = 0
    
    
    def update_total_metrics(self):
        self.total_successful_transmissions += self.successful_transmissions
        self.total_collisions += self.collisions
        self.total_num_to_transmit += self.num_to_transmit