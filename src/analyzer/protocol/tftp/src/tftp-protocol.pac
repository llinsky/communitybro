# Developed by Leo Linsky for Packetsled. Copyright 2016.

# ## TODO: Add your protocol structures in here.
# ## some examples:

# Types are your basic building blocks.
# There are some builtins, or you can define your own.
# Here's a definition for a regular expression:
# type TFTP_WHITESPACE = RE/[ \t]*/;


enum Tftp_Opcode
{
	TFTP_RRQ	= 1,
	TFTP_WRQ	= 2,
	TFTP_DATA	= 3,
	TFTP_ACK	= 4,
	TFTP_ERROR	= 5,
};

type tftp_request = record {
	filename	: uint8[] &until($element == 0);
	mode		: uint8[] &until($element == 0);
};

type tftp_data = record {
	block		: uint16;
	data		: bytestring &restofdata;
};

type tftp_ack = record {
	block		: uint16;
};

type tftp_error = record {
	errcode		: uint16;
	errmsg		: uint8[] &until($element == 0);
	pad1		: padding[1];
};

type TFTP_PDU(is_orig: bool) = record {
	opcode		: uint16;
	message		: case (opcode) of {
		TFTP_RRQ	->	rreq		: tftp_request;
		TFTP_WRQ	->	wreq		: tftp_request;
		TFTP_DATA	->	data		: tftp_data;
		TFTP_ACK	->	ack			: tftp_ack;
		TFTP_ERROR	->	error		: tftp_error;
	};
} &byteorder=bigendian;



