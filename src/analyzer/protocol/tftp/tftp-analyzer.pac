# Developed by Leo Linsky for Packetsled. Copyright 2016.

refine flow TFTP_Flow += {
	function proc_tftp_message(msg: TFTP_PDU): bool
		%{		
		if (${msg.opcode} == TFTP_RRQ)
		{
			RecordVal *conn = connection()->bro_analyzer()->Conn()->BuildConnVal();
			Val *service = conn->Lookup("service");
			Val *tftp_string = new StringVal("tftp_req");
			((TableVal*)service)->Assign(tftp_string, NULL);
			Unref(conn);

			BifEvent::generate_tftp_read_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), new StringVal(std::string(${msg.rreq.filename}->begin(),(${msg.rreq.filename}->end())).c_str()), new StringVal(std::string(${msg.rreq.mode}->begin(),(${msg.rreq.mode}->end())).c_str()));
			return true;
		}
		else if (${msg.opcode} == TFTP_WRQ)
		{
			RecordVal *conn = connection()->bro_analyzer()->Conn()->BuildConnVal();
			Val *service = conn->Lookup("service");
			Val *tftp_string = new StringVal("tftp_req");
			((TableVal*)service)->Assign(tftp_string, NULL);
			Unref(conn);

			BifEvent::generate_tftp_write_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), new StringVal(std::string(${msg.wreq.filename}->begin(),(${msg.wreq.filename}->end())).c_str()), new StringVal(std::string(${msg.wreq.mode}->begin(),(${msg.wreq.mode}->end())).c_str()));
			return true;
		}
		else if (${msg.opcode} == TFTP_ACK)
		{
			if (${msg.ack.block} == 0)
			{
				RecordVal *conn = connection()->bro_analyzer()->Conn()->BuildConnVal();
				Val *service = conn->Lookup("service");
				Val *tftp_string = new StringVal("tftp");
				((TableVal*)service)->Assign(tftp_string, NULL);
				Unref(conn);

				connection()->bro_analyzer()->Conn()->FlipRoles();

				BifEvent::generate_tftp_reply(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());
			}
			return true;
		}
		else if (${msg.opcode} == TFTP_ERROR)
		{
			BifEvent::generate_tftp_error(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), new StringVal(std::string(${msg.error.errmsg}->begin(),(${msg.error.errmsg}->end())).c_str()));
			return true;
		}
		else if (${msg.opcode} == TFTP_DATA)
		{
			if (${msg.data.block} == 1)
			{
				//RRQ doesn't get an ack of block zero, the data just starts getting sent, so we
				// differentiate with the service field
				RecordVal *conn = connection()->bro_analyzer()->Conn()->BuildConnVal();
				Val *service = conn->Lookup("service");
				Val *tftp_string = new StringVal("tftp");

				if (((TableVal*)service)->Lookup(tftp_string))
				{
					//reporter->Info("TFTP present, this must not be a reply (wrq)");
				}
				else
				{
					connection()->bro_analyzer()->Conn()->FlipRoles();

					BifEvent::generate_tftp_reply(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());
				}
				Unref(tftp_string);
				Unref(conn);
			}

			//TODO: If tftp block length < 512 (UDP length < 516), it signals the end of a flow
			//For now we just use connection_state_remove
			//if (${msg.datalen} < 512)
			//{
			//	BifEvent::generate_tftp_flow_done(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), ${msg.datalen});
			//}
		
			return true;
		}
		

		connection()->bro_analyzer()->ProtocolViolation("Invalid TFTP opcode");
		connection()->bro_analyzer()->Weird("Invalid TFTP opcode");

		return false;
		%}
};

refine typeattr TFTP_PDU += &let {
	proc: bool = $context.flow.proc_tftp_message(this);
};