// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <algorithm>
#include <iterator>
#include <iostream>
#include <iomanip>

#include "EXIF.h"
#include "util.h"
#include "Event.h"
#include "file_analysis/Manager.h"

#include "events.bif.h"
#include "types.bif.h"

using namespace std;
using namespace file_analysis;
using namespace BifType::Record::EXIF_FILE_ANALYZER;

void print_bytes(std::ostream& out, const char *title, const unsigned char *data, size_t dataLen, bool format = true) {
    out << title << std::endl;
    out << std::setfill('0');
    for(size_t i = 0; i < dataLen; ++i) {
        out << std::hex << std::setw(2) << (int)data[i];
        if (format) {
            out << (((i + 1) % 16 == 0) ? "\n" : " ");
        }
    }
    out << std::endl;
}

EXIF::EXIF(RecordVal* args, File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("EXIF"), args, file)
{
	fed = false;
	total_len = 0;
}

EXIF::~EXIF()
{
	total_len = 0;
	
	if ( bufv.size() > 0 ) {
		bufv.clear();
	}
}

file_analysis::Analyzer* EXIF::Instantiate(RecordVal* args, File* file)
{
	return new EXIF(args, file);
}

bool EXIF::DeliverStream(const u_char* data, uint64 len)
{
	if ( ! fed ) {
		fed = len > 0;
	}

	if ( total_len < EXIF_MAX_BUFFER) {
		bufv.insert(bufv.end(), data, data+len);		
		total_len += len;
	}

	return true;
}

bool EXIF::EndOfFile()
{
	Finalize();
	return false;
}

bool EXIF::Undelivered(uint64 offset, uint64 len)
{
	return false;
}

void EXIF::Finalize()
{
	if ( ! fed ) {
		return;
	}

#ifdef DEBUG_EXIF
	print_bytes(std::cout, "BUFFER", (const u_char *)&bufv[0], total_len);
#endif // DEBUG_EXIF

	easyexif::EXIFInfo result;
	int code = result.parseFrom((const u_char *)&bufv[0], total_len, false);

	if ( code ) {
		return;
    }

	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());

	RecordVal* gps = new RecordVal(BifType::Record::EXIF_FILE_ANALYZER::GPS);
	
	RecordVal* latitude = new RecordVal(BifType::Record::EXIF_FILE_ANALYZER::Latitude);	
	latitude->Assign(0, new Val(result.GeoLocation.LatComponents.degrees, TYPE_DOUBLE));
	latitude->Assign(1, new Val(result.GeoLocation.LatComponents.minutes, TYPE_DOUBLE));
	latitude->Assign(2, new Val(result.GeoLocation.LatComponents.seconds, TYPE_DOUBLE));
	latitude->Assign(3, new StringVal(std::string(1, result.GeoLocation.LatComponents.direction)));

	RecordVal* longitude = new RecordVal(BifType::Record::EXIF_FILE_ANALYZER::Longitude);	
	longitude->Assign(0, new Val(result.GeoLocation.LonComponents.degrees, TYPE_DOUBLE));
	longitude->Assign(1, new Val(result.GeoLocation.LonComponents.minutes, TYPE_DOUBLE));
	longitude->Assign(2, new Val(result.GeoLocation.LonComponents.seconds, TYPE_DOUBLE));
	longitude->Assign(3, new StringVal(std::string(1, result.GeoLocation.LonComponents.direction)));

	gps->Assign(0, latitude);
	gps->Assign(1, longitude);
	gps->Assign(2, new Val(result.GeoLocation.DOP, 	 TYPE_DOUBLE));
	gps->Assign(3, new Val(result.GeoLocation.Altitude, TYPE_DOUBLE));

	RecordVal* image = new RecordVal(BifType::Record::EXIF_FILE_ANALYZER::Image);
	image->Assign(0, new Val(result.ImageWidth,  TYPE_COUNT));
	image->Assign(1, new Val(result.ImageHeight, TYPE_COUNT));

	if ( result.Copyright.length() > 0 ) {
		image->Assign(2, new StringVal(result.Copyright));
	}

	image->Assign(3, new Val(result.Orientation, TYPE_COUNT));

	if ( result.ImageDescription.length() > 0 ) {
		image->Assign(4, new StringVal(result.ImageDescription));
	}

	if ( result.DateTimeOriginal.length() > 0 ) {
		image->Assign(5, new StringVal(result.DateTimeOriginal));
	}

	RecordVal* camera = new RecordVal(BifType::Record::EXIF_FILE_ANALYZER::Camera);
	if ( result.Make.length() > 0 ) {
		camera->Assign(0, new StringVal(result.Make));
	}

	if ( result.Model.length() > 0 ) {
		camera->Assign(1, new StringVal(result.Model));
	}

	if ( result.Software.length() > 0 ) {
		camera->Assign(2, new StringVal(result.Software));
	}

	RecordVal* lens = new RecordVal(BifType::Record::EXIF_FILE_ANALYZER::Lens);
	if ( result.LensInfo.Make.length() > 0 ) {
		lens->Assign(0, new StringVal(result.LensInfo.Make));
	}

	if ( result.LensInfo.Model .length() > 0 ) {
		lens->Assign(1, new StringVal(result.LensInfo.Model));
	}

	RecordVal* results = new RecordVal(BifType::Record::EXIF_FILE_ANALYZER::Results);
	results->Assign(0, gps);
	results->Assign(1, image);
	results->Assign(2, camera);
	results->Assign(3, lens);

	vl->append(results);
	mgr.QueueEvent(file_exif, vl);
}
