@load base/frameworks/files
@load base/files/hash

module X509;

export {
	redef enum Log::ID += { LOG };

	## The record type which contains the fields of the X.509 log.
	type Info: record {
		## Current timestamp.
		ts: time &log;

		## File id of this certificate.
		id: string &log;

		## Basic information about the certificate.
		certificate: X509::Certificate &log;

		## The opaque wrapping the certificate. Mainly used
		## for the verify operations.
		handle: opaque of x509;

		## All extensions that were encountered in the certificate.
		extensions: vector of X509::Extension &default=vector();

		## Subject alternative name extension of the certificate.
		san: X509::SubjectAlternativeName &optional &log;

		## Basic constraints extension of the certificate.
		basic_constraints: X509::BasicConstraints &optional &log;
	};

	## Event for accessing logged records.
	global log_x509: event(rec: Info);
}

event bro_init() &priority=5
	{
	Log::create_stream(X509::LOG, [$columns=Info, $ev=log_x509, $path="x509"]);

	Files::register_for_mime_type(Files::ANALYZER_X509, "application/x-x509-user-cert");
	Files::register_for_mime_type(Files::ANALYZER_X509, "application/x-x509-ca-cert");
	# Always calculate hashes. They are not necessary for base scripts
	# but very useful for identification, and required for policy scripts
	Files::register_for_mime_type(Files::ANALYZER_MD5, "application/x-x509-user-cert");
	Files::register_for_mime_type(Files::ANALYZER_MD5, "application/x-x509-ca-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA1, "application/x-x509-user-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA1, "application/x-x509-ca-cert");
	}

redef record Files::Info += {
	## Information about X509 certificates. This is used to keep
	## certificate information until all events have been received.
	x509: X509::Info &optional;
};

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=5
	{
	if ( ! f$info?$mime_type )
		f$info$mime_type = "application/pkix-cert";

	f$info$x509 = [$ts=f$info$ts, $id=f$id, $certificate=cert, $handle=cert_ref];
	}

event x509_extension(f: fa_file, ext: X509::Extension) &priority=5
	{
	if ( f$info?$x509 )
		f$info$x509$extensions[|f$info$x509$extensions|] = ext;
	}

event x509_ext_basic_constraints(f: fa_file, ext: X509::BasicConstraints) &priority=5
	{
	if ( f$info?$x509 )
		f$info$x509$basic_constraints = ext;
	}

event x509_ext_subject_alternative_name(f: fa_file, ext: X509::SubjectAlternativeName) &priority=5
	{
	if ( f$info?$x509 )
		f$info$x509$san = ext;
	}

event file_state_remove(f: fa_file) &priority=5
	{
	if ( ! f$info?$x509 )
		return;

	Log::write(LOG, f$info$x509);
	}
