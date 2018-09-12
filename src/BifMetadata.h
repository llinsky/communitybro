
#include <stdio.h>
#include <map>
#include <string>
#include <vector>

#include "Type.h"

// This assumes no legitimate BIF's or events have 135490 arguments
#define VA_ARGS 135490

#ifdef ENABLE_LUAJIT

struct cmp_std_str
{
   bool operator()(std::string a, std::string b) const
   {
      return strcmp(a.c_str(), b.c_str()) < 0;
   }
};

typedef std::map<std::string, std::vector<std::string>, cmp_std_str> BifArgMap;


class BifMeta
{
public:

	BifMeta();

	~BifMeta();

	void PrintBifs(BifArgMap &bif_args);

	int LoadBifsFromFile(const char *file_name, const char* search_string, BifArgMap &bif_args_map);

	// Returns the number of arguments for a given BIF name (including scope)
	int BIFArgCount(std::string bif);
	int EventArgCount(std::string event);

	// Returns the argument type at a given index, or NULL for an invalid index
	TypeTag BIFArgType(std::string bif, int arg_index);
	TypeTag EventArgType(std::string event, int arg_index);

private:
	BifArgMap bifs_map;
	BifArgMap events_map;
};

extern BifMeta *bifmeta_mgr;

#endif










