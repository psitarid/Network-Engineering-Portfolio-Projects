from Node_Class import Node
import numpy as np

def check_transmission_success(time, node_list, nodes_to_retransmit, waiting_for_ack, gateway, ToA, ack_duration, max_backoff):
    #search in waiting_for_ack for any new node that has finished transmitting without collision.
    #Then include it to the nodes_to_respond list.
    success_num = 0
    new_waiting_for_ack = []

    if(len(waiting_for_ack)>0):
        for node in waiting_for_ack:                    
            if(time == node.RX_delay1_ends):                                    
                if(node.collided == False and gateway.get_state() == 'idle'):
                    gateway.node_to_send_ack = node.id
                    gateway.ack_attempts +=1
                new_waiting_for_ack.append(node)
            elif(node.ack_received == True):
                    success_num +=1
                    node.set_initial_state(ToA)
                    node_list.append(node)
            elif(time == node.timeout_ends and node.ack_received == False):
                success_num -=1      #make success_num = -1 for this cycle if collision occurs
                if(node.retransmission_num < 40):
                    node.set_retransmitting_state(time, ToA, max_backoff)      
                    nodes_to_retransmit.append(node)
                elif(node.retransmission_num >= 40):
                    node.set_initial_state(ToA)
                    node_list.append(node)
            else:
                new_waiting_for_ack.append(node)            
        
        waiting_for_ack.clear()
        for node in new_waiting_for_ack:
            waiting_for_ack.append(node)

        gateway.ack_handler(ack_duration, waiting_for_ack)
        

                
    return success_num