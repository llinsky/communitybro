
refine flow MQTT_Flow += {
    function proc_mqtt_message(msg: MQTT_PDU): bool
    %{
        vector<MQTT_message*>* messages = ${msg.mqtt_messages};
        vector<MQTT_message*>::const_iterator messages_ptr;

        for ( messages_ptr = messages->begin(); messages_ptr != messages->end(); ++messages_ptr ) {

            switch((*messages_ptr)->msg_type()) {
                case MQTT_CONNECT: {
                    MQTT_connect* ptr = (*messages_ptr)->connect_packet();
                    
                    RecordVal* hdr = new RecordVal(BifType::Record::MQTT::HEADER);	
                    
                    hdr->Assign(0, new Val(ptr->hdrlen(), TYPE_COUNT));
                    hdr->Assign(1, new Val(ptr->QoS(), 	  TYPE_COUNT));
                    hdr->Assign(2, new Val(ptr->dup(), 	  TYPE_COUNT));
                    hdr->Assign(3, new Val(ptr->retain(), TYPE_COUNT));

                    RecordVal* conn_msg = new RecordVal(BifType::Record::MQTT::CONNECT);					
                    
                    conn_msg->Assign(0, hdr);

                    conn_msg->Assign(1, new StringVal(ptr->protocol_name().length(), (const char*)ptr->protocol_name().begin()));
                    conn_msg->Assign(2, new Val((int)ptr->protocol_version(), TYPE_COUNT));
                    conn_msg->Assign(3, new Val((int)ptr->connect_flags(), TYPE_COUNT));
                    conn_msg->Assign(4, new Val((int)ptr->keep_alive(), TYPE_COUNT));
                    conn_msg->Assign(5, new StringVal(ptr->client_id().length(), (const char*) ptr->client_id().begin())); 
                    conn_msg->Assign(6, new Val((int)ptr->clean_session(), TYPE_COUNT));
                                        
                    if (ptr->will()){
                        conn_msg->Assign(7, new StringVal(std_str(ptr->will_objs()->will_topic()).c_str())); 
                        conn_msg->Assign(8, new StringVal(std_str(ptr->will_objs()->will_msg()).c_str())); 
                    }

                    if (ptr->username()){
                        conn_msg->Assign(9, new StringVal(std_str(ptr->uname_objs()->uname()).c_str())); 
                    }

                    if (ptr->password()){
                        conn_msg->Assign(10, new StringVal(std_str(ptr->pass_objs()->pass()).c_str())); 
                    }

                    BifEvent::generate_mqtt_conn(connection()->bro_analyzer(), 
                                                connection()->bro_analyzer()->Conn(), 
                                                (*messages_ptr)->msg_type(),
                                                conn_msg);
                }   
                    break;

                case MQTT_CONNACK: {
                        MQTT_connectack* ptr = (*messages_ptr)->connectack_packet();           
                        
                        RecordVal* hdr = new RecordVal(BifType::Record::MQTT::HEADER);	
                        
                        hdr->Assign(0, new Val(ptr->hdrlen(), TYPE_COUNT));
                        hdr->Assign(1, new Val(ptr->QoS(), 	  TYPE_COUNT));
                        hdr->Assign(2, new Val(ptr->dup(), 	  TYPE_COUNT));
                        hdr->Assign(3, new Val(ptr->retain(), TYPE_COUNT));
        
                        RecordVal* connack = new RecordVal(BifType::Record::MQTT::CONNACK);					
                        
                        connack->Assign(0, hdr);
                        connack->Assign(1, new Val((int)ptr->return_code(), TYPE_COUNT));
                    
                        BifEvent::generate_mqtt_connack(connection()->bro_analyzer(), 
                                                        connection()->bro_analyzer()->Conn(), 
                                                        (*messages_ptr)->msg_type(), 
                                                        connack);
                }
                    break; 

                case MQTT_PUBLISH: {
                    MQTT_publish* ptr = (*messages_ptr)->publish_packet();
                
                    RecordVal* hdr = new RecordVal(BifType::Record::MQTT::HEADER);	

                    hdr->Assign(0, new Val(ptr->hdrlen(), TYPE_COUNT));
                    hdr->Assign(1, new Val(ptr->QoS(), 	  TYPE_COUNT));
                    hdr->Assign(2, new Val(ptr->dup(), 	  TYPE_COUNT));
                    hdr->Assign(3, new Val(ptr->retain(), TYPE_COUNT));

                    RecordVal* pub_msg = new RecordVal(BifType::Record::MQTT::PUBLISH);
                    
                    pub_msg->Assign(0, hdr);
                    pub_msg->Assign(1, new StringVal(ptr->topic().length(), (const char*)ptr->topic().begin()));
                    
                    switch(ptr->QoS()) {
                        case 1:
                            pub_msg->Assign(2, new Val(ptr->confirm_req(), TYPE_COUNT));
                            pub_msg->Assign(3, new StringVal(ptr->publish_with_qos_1().length(),
                                                            (const char*) ptr->publish_with_qos_1().begin()));
                            break;
                        case 2:
                            pub_msg->Assign(2, new Val(ptr->four_step_hs(), TYPE_COUNT));
                            pub_msg->Assign(3, new StringVal(ptr->publish_with_qos_2().length(),
                                                            (const char*) ptr->publish_with_qos_2().begin()));
                            break;
                        default:
                            pub_msg->Assign(2, new Val(0, TYPE_COUNT));
                            pub_msg->Assign(3, new StringVal(ptr->public_with_qos_def().length(),
                                                            (const char*) ptr->public_with_qos_def().begin()));
                            break;
                    }

                    BifEvent::generate_mqtt_pub(connection()->bro_analyzer(), 
                                                connection()->bro_analyzer()->Conn(),
                                                (*messages_ptr)->msg_type(),
                                                pub_msg);
                }
                    break;

                case MQTT_PUBACK: {
                    MQTT_puback* ptr = (*messages_ptr)->puback_packet();
                    
                    RecordVal* hdr = new RecordVal(BifType::Record::MQTT::HEADER);	
                    
                    hdr->Assign(0, new Val(ptr->hdrlen(), TYPE_COUNT));
                    hdr->Assign(1, new Val(ptr->QoS(), 	 TYPE_COUNT));
                    hdr->Assign(2, new Val(ptr->dup(), 	 TYPE_COUNT));
                    hdr->Assign(3, new Val(ptr->retain(), TYPE_COUNT));
    
                    RecordVal* pub_ack = new RecordVal(BifType::Record::MQTT::PUBACK);	
                    
                    pub_ack->Assign(0, hdr);
                    pub_ack->Assign(1, new Val(ptr->msg_id(), TYPE_COUNT));
                    
                    BifEvent::generate_mqtt_puback(connection()->bro_analyzer(), 
                                                    connection()->bro_analyzer()->Conn(),
                                                    (*messages_ptr)->msg_type(),
                                                    pub_ack);
                }
                    break;

                case MQTT_SUBSCRIBE: {
                    MQTT_subscribe* ptr = (*messages_ptr)->subscribe_packet();
                            
                    RecordVal* hdr = new RecordVal(BifType::Record::MQTT::HEADER);	
                    
                    hdr->Assign(0, new Val(ptr->hdrlen(), TYPE_COUNT));
                    hdr->Assign(1, new Val(ptr->QoS(), 	  TYPE_COUNT));
                    hdr->Assign(2, new Val(ptr->dup(), 	  TYPE_COUNT));
                    hdr->Assign(3, new Val(ptr->retain(), TYPE_COUNT));
    
                    RecordVal* sub_msg = new RecordVal(BifType::Record::MQTT::SUBSCRIBE);	
                    
                    sub_msg->Assign(0, hdr);
                    sub_msg->Assign(1, new Val(ptr->msg_id(), TYPE_COUNT));
        
                    vector<MQTT_subscribe_topic*>* sub_options = ptr->topics();
                    vector<MQTT_subscribe_topic*>::const_iterator topic_ptr;
    
                    for ( topic_ptr = sub_options->begin(); topic_ptr != sub_options->end(); ++topic_ptr ) {
                        sub_msg->Assign(2, new StringVal((*topic_ptr)->subscribe_topic().length(), 
                                                         (const char*)(*topic_ptr)->subscribe_topic().begin()));
                        sub_msg->Assign(3, new Val((int)(*topic_ptr)->requested_QoS(), TYPE_COUNT));
    
                        BifEvent::generate_mqtt_sub(connection()->bro_analyzer(), 
                                                    connection()->bro_analyzer()->Conn(), 
                                                    (*messages_ptr)->msg_type(),
                                                    sub_msg);
                    }
                }
                    break;

                case MQTT_SUBACK: {
                    MQTT_suback* ptr = (*messages_ptr)->suback_packet();
            
                    RecordVal* hdr = new RecordVal(BifType::Record::MQTT::HEADER);	
                    
                    hdr->Assign(0, new Val(ptr->hdrlen(), TYPE_COUNT));
                    hdr->Assign(1, new Val(ptr->QoS(), 	 TYPE_COUNT));
                    hdr->Assign(2, new Val(ptr->dup(), 	 TYPE_COUNT));
                    hdr->Assign(3, new Val(ptr->retain(), TYPE_COUNT));
    
                    RecordVal* sub_ack = new RecordVal(BifType::Record::MQTT::SUBACK);	
    
                    sub_ack->Assign(0, hdr);
                    sub_ack->Assign(1, new Val(ptr->msg_id(), TYPE_COUNT));
                    sub_ack->Assign(2, new Val(ptr->granted_QoS(), TYPE_COUNT));
    
                    BifEvent::generate_mqtt_suback(connection()->bro_analyzer(), 
                                                   connection()->bro_analyzer()->Conn(),
                                                   (*messages_ptr)->msg_type(),
                                                   sub_ack);
                }
                    break;
                     
                case MQTT_UNSUBSCRIBE: {
                    MQTT_unsubscribe* ptr = (*messages_ptr)->unsubscribe_packet();
                   
                    RecordVal* hdr = new RecordVal(BifType::Record::MQTT::HEADER);	
                    
                    hdr->Assign(0, new Val(ptr->hdrlen(), TYPE_COUNT));
                    hdr->Assign(1, new Val(ptr->QoS(), 	 TYPE_COUNT));
                    hdr->Assign(2, new Val(ptr->dup(), 	 TYPE_COUNT));
                    hdr->Assign(3, new Val(ptr->retain(), TYPE_COUNT));
    
                    RecordVal* unsub = new RecordVal(BifType::Record::MQTT::UNSUBSCRIBE);	
    
                    unsub->Assign(0, hdr);
                    unsub->Assign(1, new Val(ptr->msg_id(), TYPE_COUNT));
    
                    vector<MQTT_unsubscribe_topic*>* unsub_options = ptr->topics();
                    vector<MQTT_unsubscribe_topic*>::const_iterator unsub_ptr;
                
                    for ( unsub_ptr = unsub_options->begin(); unsub_ptr != unsub_options->end(); ++unsub_ptr ) {
                        unsub->Assign(2, new StringVal((*unsub_ptr)->unsub_topic().length(), 
                                                       (const char*) (*unsub_ptr)->unsub_topic().begin()));
    
                        BifEvent::generate_mqtt_unsub(connection()->bro_analyzer(), 
                                                      connection()->bro_analyzer()->Conn(), 
                                                      (*messages_ptr)->msg_type(),
                                                      unsub);
                    }
                }
                    break;
        
                case MQTT_UNSUBACK: {
                    MQTT_unsuback* ptr = (*messages_ptr)->unsuback_packet();
                  
                    RecordVal* hdr = new RecordVal(BifType::Record::MQTT::HEADER);	
                    
                    hdr->Assign(0, new Val(ptr->hdrlen(), TYPE_COUNT));
                    hdr->Assign(1, new Val(ptr->QoS(), 	 TYPE_COUNT));
                    hdr->Assign(2, new Val(ptr->dup(), 	 TYPE_COUNT));
                    hdr->Assign(3, new Val(ptr->retain(), TYPE_COUNT));
    
                    RecordVal* unsuback = new RecordVal(BifType::Record::MQTT::UNSUBACK);	
    
                    unsuback->Assign(0, hdr);
                    unsuback->Assign(1, new Val(ptr->msg_id(), TYPE_COUNT));
    
                    BifEvent::generate_mqtt_unsuback(connection()->bro_analyzer(), 
                                                     connection()->bro_analyzer()->Conn(), 
                                                     (*messages_ptr)->msg_type(),
                                                     unsuback);
                    
                }
                    break;

                case MQTT_PINGREQ: {
                    BifEvent::generate_mqtt_pingreq(connection()->bro_analyzer(), 
                                                    connection()->bro_analyzer()->Conn(), 
                                                    (*messages_ptr)->msg_type());
                }
                    break;
            
                case MQTT_PINGRESP: {
                    BifEvent::generate_mqtt_pingres(connection()->bro_analyzer(), 
                                                    connection()->bro_analyzer()->Conn(), 
                                                    (*messages_ptr)->msg_type());
                }
                    break;
        
                case MQTT_DISCONNECT: {
                    BifEvent::generate_mqtt_disconnect(connection()->bro_analyzer(), 
                                                        connection()->bro_analyzer()->Conn(), 
                                                        (*messages_ptr)->msg_type());
                }
                    break;

                default:
                    // std::cout << " Unknown Message = " << (int)(*messages_ptr)->msg_type() << std::endl;
                    
                    break;
            }
        }

        return true;
    %}
};

refine typeattr MQTT_PDU += &let {
    proc: bool = $context.flow.proc_mqtt_message(this);
};
