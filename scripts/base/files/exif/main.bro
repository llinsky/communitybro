# EXIF File Analyzer
# Copyright 2017 Packetsled
#
# Aaron Eppert (aaron.eppert@packetsled.com)
#

export {
    redef record Files::Info += {
        ## EXIF Metadata if Present in an Image
        exif: EXIF_FILE_ANALYZER::Results &log &optional;
    };
}

const exif_mime_types = { "image/jpeg" };

event bro_init() &priority=5
{
    Files::register_for_mime_types(Files::ANALYZER_EXIF, exif_mime_types);
}

event file_exif(f: fa_file, exif_results: EXIF_FILE_ANALYZER::Results)
{    
    f$info$exif = exif_results;
}