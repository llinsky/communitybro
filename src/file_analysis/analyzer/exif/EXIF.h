#include <string>
#include <vector>

#include "Val.h"
#include "OpaqueVal.h"
#include "File.h"
#include "file_analysis/Analyzer.h"
#include "easy_exif.h"

#define EXIF_MAX_BUFFER (16 * 1024)

namespace file_analysis {
    class EXIF : public file_analysis::Analyzer {
    public:
        virtual ~EXIF();
        static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);
        virtual bool DeliverStream(const u_char* data, uint64 len);
        virtual bool EndOfFile();
        virtual bool Undelivered(uint64 offset, uint64 len);

    protected:
        EXIF(RecordVal* args, File* file);
        void Finalize();

    private:
        bool fed;
        int total_len;
        std::vector<u_char> bufv;
    };
} // namespace file_analysis
