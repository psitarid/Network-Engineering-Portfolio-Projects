class Gateway:
    ack_time_left = 0
    state = 'idle'
    node_to_send_ack = 0
    ack_collided = False
    ack_attempts = 0
    successful_acks = 0
    
    def __init__(self, ack_duration):
        self.ack = False
        self.ack_time_left = ack_duration
        self.state = 'idle'
        self.node_to_send_ack = 0
        self.ack_collided = False
        self.ack_attempts = 0
        self.successful_acks = 0
        

    def get_state(self):
        if(self.node_to_send_ack != 0):
            return 'busy'
        else:
            return 'idle'

    def change_node(self, ack_duration):
        self.ack_time_left = ack_duration
        self.node_to_send_ack = 0
        self.ack_collided = False

    def ack_handler(self, ack_duration, waiting_for_ack):
        if(self.node_to_send_ack != 0):
            self.ack_time_left -=1
        if(self.ack_time_left == 0):
            for node in waiting_for_ack:
                if(node.id == self.node_to_send_ack and self.ack_collided == False):
                    node.ack_received = True
            self.change_node(ack_duration)