//Developed by Leo Linsky for Packetsled. Copyright 2016-2017.

#include "bro-config.h"

#include "LuajitMgr.h"
#include "Reporter.h"
#include "EventRegistry.h"
#include "List.h"
#include "Type.h"
#include "NetVar.h"
#include "Attr.h"
#include "LuajitFunctions.h"
#include "File.h"
#include "EventHandler.h"
#include "RE.h"

#ifdef ENABLE_LUAJIT

#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>
#include <unistd.h>
#include <fstream>
#include <sys/inotify.h> 


LuajitManager::LuajitManager(const char *lua_script_dir)
{
	if (strlen(lua_script_dir) > LUA_MAX_PATH_SIZE)
	{
		reporter->FatalError(fmt("Lua: Script path name is too long:  %s\n", lua_script_dir));
		return;
	}

	if (pthread_mutex_init(&lua_lock, NULL) != 0)
    {
        reporter->FatalError("Unable to initialize lua_lock");
        return;
    }

    script_dir = lua_script_dir;

	//TODO: Add sig handler for seg faults that can be caused by Lua BIF's, or use a sig_handler
	//	exception library:  http://stackoverflow.com/questions/2350489/how-to-catch-segmentation-fault-in-linux
	//	We would try dangerous operations, such as BIF's, and catch the exception, removing the
	//	faulty script and continue on.
}


int LuajitManager::Load()
{
#ifdef LUA_DEBUG
    reporter->Info("Loading Lua scripts");
#endif

	if (!TraverseLuaScriptTree(script_dir, 0))
	{
		reporter->FatalError(fmt("Lua: Can't open scripts directory:  %s\n", script_dir));
		return LUA_FAILURE;
	}

	ifd = inotify_init();
	if (ifd < 0)
	{
		reporter->Error("Unable to instantiate inotify for dynamic Lua script loading.");
		return LUA_FAILURE;
	}
	fcntl(ifd, F_SETFL, fcntl(ifd, F_GETFL, 0) | O_NONBLOCK);

	wfd = inotify_add_watch(ifd, script_dir, IN_MODIFY | IN_CREATE | IN_DELETE);

	keepalive = true;
	int err = pthread_create(&(tid_inotify), NULL, CheckINotifyEvents, NULL);
	if (err != 0)
	{
		reporter->Error("Unable to create inotify thread, error:  %s", strerror(err));
		return LUA_FAILURE;
	}

	return LUA_SUCCESS;
}


int LuajitManager::TraverseLuaScriptTree(const char *name, int level)
{
	DIR *dir;
    struct dirent *entry;

    if (level >= LUA_MAX_DEPTH)
    {
    	reporter->Warning("Too many directories in the Lua script tree");
    	return LUA_FAILURE;
    }

    if (!(dir = opendir(name)))
    {
        return LUA_FAILURE;
    }

    if (!(entry = readdir(dir)))
    {
        return LUA_FAILURE;
    }

    do {
        if (entry->d_type == DT_DIR) {
            char path[1024];
            int len = snprintf(path, sizeof(path)-1, "%s/%s", name, entry->d_name);
            path[len] = '\0';
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            if (len > LUA_MAX_PATH_SIZE)
			{
				reporter->Warning(fmt("Lua: Full script name+path is too long:  %s\n", path));
				return LUA_FAILURE;
			}
            if (TraverseLuaScriptTree(path, level+1) != LUA_SUCCESS)
            {
            	return LUA_FAILURE;
            }
        }
        else if (HasLuaExtension(entry->d_name))
		{
			char path[1024];
            int len = snprintf(path, sizeof(path)-1, "%s/%s", name, entry->d_name);
            path[len] = '\0';

			int status = LoadLuaScript(path);
		}
		else
		{
#ifdef LUA_DEBUG
			reporter->Info("Found non- .lua files in the Lua script directory:  %s \n", name);
#endif
		}
    } while ((entry = readdir(dir)));
    closedir(dir);

	return LUA_SUCCESS;
}


void *LuajitManager::CheckINotifyEvents(void *self)
{
	char sys_buf[SYS_BUF_SIZE];
	int length, i;
	char full_name[1024];
    int len;

	while (lua_mgr->keepalive)
	{
		sleep(2);

#ifdef LUA_DEBUG
		reporter->Info("Looping through inotify events . . .");
#endif

		i = 0;
        length = read(lua_mgr->ifd, sys_buf, SYS_BUF_SIZE);

        while (i < length) 
        {
	        struct inotify_event *event = (struct inotify_event *) &sys_buf[i];     
	        if (event->len) {
	        	len = snprintf(full_name, sizeof(full_name)-1, "%s/%s", lua_mgr->script_dir, \
	        		event->name);
            	full_name[len] = '\0';

				if (event->mask & IN_CREATE) 
				{
					//TODO: Support recursive directories... http://stackoverflow.com/questions/14215912/inotify-get-directory
					if (event->mask & IN_ISDIR)
					{
#ifdef LUA_DEBUG
						reporter->Info("New directory %s created.", full_name);
#endif
					}
					else
					{
#ifdef LUA_DEBUG
						reporter->Info( "New file %s created.", full_name);
#endif
						if (likely(HasLuaExtension(event->name)))
						{
#ifdef LUA_DEBUG
							reporter->Info("Loading newly added Lua file: %s.", full_name);
#endif
							if (unlikely(lua_mgr->DynamicallyAddScript(full_name) != LUA_SUCCESS))
							{
								reporter->Error("Error loading new script: %s", full_name);
							}
						}
					}
				}
				else if ( event->mask & IN_DELETE )
				{
					if ( event->mask & IN_ISDIR )
					{
#ifdef LUA_DEBUG
						reporter->Info( "Directory %s deleted.", full_name);
#endif
					}
					else
					{
#ifdef LUA_DEBUG
						reporter->Info( "File %s deleted.", full_name);
#endif
						if (likely(HasLuaExtension(event->name)))
						{
#ifdef LUA_DEBUG
							reporter->Info("Attempting to unload deleted Lua file: %s.", \
								full_name);
#endif
							lua_mgr->DynamicallyRemoveScript(full_name);
						}
					}
				}
				else if ( event->mask & IN_MODIFY ) 
				{
					if ( event->mask & IN_ISDIR ) {
#ifdef LUA_DEBUG
						reporter->Info( "Directory %s modified.", full_name );
#endif
					}
					else
					{
#ifdef LUA_DEBUG
						reporter->Info( "File %s modified.", full_name );
#endif
						if (likely(HasLuaExtension(event->name)))
						{
#ifdef LUA_DEBUG
							reporter->Info("Attempting to reload modified Lua file: %s.", \
								full_name);
#endif
							if (lua_mgr->DynamicallyRemoveScript(full_name) != LUA_SCRIPT_REMOVED)
							{
#ifdef LUA_DEBUG
								reporter->Info("Failed to remove modified Lua file: %s.", \
									full_name);
#endif
							}
							if (unlikely(lua_mgr->DynamicallyAddScript(full_name) != LUA_SUCCESS))
							{
								reporter->Error("Error loading modified script: %s", full_name);
							}
#ifdef LUA_DEBUG
							else
							{
								reporter->Info("Successfully reloaded Lua file: %s.", full_name);
							}
#endif
						}
					}
				}
			}
			i += sizeof(struct inotify_event) + event->len;
		}
        
	}

#ifdef LUA_DEBUG
	reporter->Info("Dynamic loading thread exiting . . . ");
#endif

	return NULL;
}


int LuajitManager::DynamicallyRemoveScript(const char *filename, bool force)
{
#ifdef LUA_DEBUG
	//reporter->Info("Locking Lua (DynamicallyRemoveScript)");
#endif
	pthread_mutex_lock(&lua_lock);

	bool found = false;
	LuaActiveMap::iterator s = active_states.begin();

	while (s != active_states.end())
	{
#ifdef LUA_DEBUG
		reporter->Info("active_states script: %s", s->second);
#endif
		if (strcmp(filename, s->second) == 0)
		{
			//Match found
			if (force || (active_hashes[static_cast<void *>(s->first)] != FileHash(filename)))
			{
				found = true;
				lua_close(static_cast<lua_State *>(s->first));

				active_hashes.erase(static_cast<void *>(s->first));
				active_states.erase(s);
				

#ifdef LUA_DEBUG
				reporter->Info("Script deleted");
#endif

#ifdef LUA_DEBUG
				//reporter->Info("Unlocking Lua (DynamicallyRemoveScript)");
#endif
				pthread_mutex_unlock(&lua_lock);
				return LUA_SCRIPT_REMOVED;
			}
#ifdef LUA_DEBUG
			else
			{
				found = true;
				reporter->Info("Attempted to remove script, but hashes were the same");
			}
#endif
		}
		++s;
	}

#ifdef LUA_DEBUG
	if (!found)
	{
		reporter->Info("Attempted to remove script, but it was not found in active_states");
	}
#endif

#ifdef LUA_DEBUG
	//reporter->Info("Unlocking Lua (DynamicallyRemoveScript)");
#endif
	pthread_mutex_unlock(&lua_lock);

	return LUA_NOT_REMOVED;
}


int LuajitManager::DynamicallyAddScript(const char *filename)
{
#ifdef LUA_DEBUG
	//reporter->Info("Locking Lua (DynamicallyAddScript)");
#endif
	pthread_mutex_lock(&lua_lock);

	//Ensure that script is not already loaded (shouldn't be possible here?)
	bool found = false;
	lua_State *L = NULL;
	const char *name = "bro_init";

	for (LuaActiveMap::iterator s = active_states.begin(); s != active_states.end(); ++s)
	{
		if (strcmp(s->second, filename) == 0)
		{
			found = true;
			break;
		}
	}

#ifdef LUA_DEBUG
	reporter->Info("Just searched active states.");
#endif

	if (found)
	{
#ifdef LUA_DEBUG
		//reporter->Info("Unlocking Lua (DynamicallyAddScript)");
#endif
		pthread_mutex_unlock(&lua_lock);
		reporter->Error("Will not add Lua script: already loaded");
		return LUA_FAILURE;
	}

#ifdef LUA_DEBUG
	reporter->Info("Did not find script in active_states.");
#endif

	//Load script in the normal way
	if (!LoadLuaScript(filename))
	{
#ifdef LUA_DEBUG
		//reporter->Info("Unlocking Lua (DynamicallyAddScript)");
#endif
		pthread_mutex_unlock(&lua_lock);
		reporter->Error("Will not add Lua script: error loading");
		return LUA_FAILURE;
	}

	found = false;

	//Generate bro_init for this script only
	for (LuaActiveMap::iterator s = active_states.begin(); s != active_states.end(); ++s)
	{
		if (strcmp(s->second, filename) == 0)
		{
			found = true;
			L = static_cast<lua_State *>(s->first);
			break;
		}
	}

#ifdef LUA_DEBUG
	reporter->Info("Generating bro_init.");
#endif

	if (!found)
	{
#ifdef LUA_DEBUG
		//reporter->Info("Unlocking Lua (DynamicallyAddScript)");
#endif
		pthread_mutex_unlock(&lua_lock);
#ifdef LUA_DEBUG
		reporter->Info("Unable to find script after Loading it, yet LoadLuaScript didn't \
			return failure");
#endif
		reporter->Error("Internal error: unable to add new Lua script to active_states");
		return LUA_FAILURE;
	}

	lua_getglobal(L, name);

	//TODO: pcall should be replaced with pcallk everywhere to handle Lua yields (coroutines)
	// for now, see lua_isyieldable
	if (unlikely(lua_pcall(L, 0, 0, 0) != 0))
	{
    	reporter->Error("Lua error running function `%s' in script %s: %s", name, filename, \
    		lua_tostring(L, -1));
	}

#ifdef LUA_DEBUG
	reporter->Info("Added file successfully.");
#endif

#ifdef LUA_DEBUG
	//reporter->Info("Unlocking Lua (DynamicallyAddScript)");
#endif
	pthread_mutex_unlock(&lua_lock);
	return LUA_SUCCESS;
}


//Lock needs to be already held whenever this function is called
void LuajitManager::RemoveFaultyScript(lua_State *L)
{
	if (active_states.find(static_cast<void *>(L)) != active_states.end())
	{
		reporter->Warning("Removed faulty script:  %s", active_states[static_cast<void *>(L)]);
		active_states.erase(static_cast<void *>(L));
		active_hashes.erase(static_cast<void *>(L));

		lua_close(L);
	}
	else
	{
		reporter->Error("Unable to remove faulty script");
	}
}

void LuajitManager::SetFaultyScript(lua_State *L)
{
	lua_mgr->bad_context_list.push_back(static_cast<void *>(L));
}


int LuajitManager::LoadLuaScript(const char *name)
{
	if (!name)
	{
		reporter->Warning("Luajit unable to identify script: bad filename\n");
		return LUA_FAILURE;
	}

	lua_State *L = luaL_newstate();
	if (L == NULL)
	{
		reporter->Warning(fmt("Luajit unable to allocate state for script:  %s\n", name));
		return LUA_FAILURE;
	}

	//Load Lua libraries and custom Bro libraries for each script
    luaL_openlibs(L);

    lua_reg_bro_libs(L);

    //Note: May need to replace with luaL_dofile for other Luajit versions
	int status = luaL_loadfile(L, name);
	switch( status )
	{
	    case LUA_ERRFILE:
	        reporter->Error(fmt("Cannot find / open lua script file: %s\n", name));
	        break;
	    case LUA_ERRSYNTAX:
	        reporter->Error(fmt("Syntax error during pre-compilation of script file: %s\n", name));
	        break;
	    case LUA_ERRMEM:
	        reporter->Error(fmt("Fatal memory allocation error during processing of \
	        	script file: %s\n", name));
	}

	if (status != 0)
	{
		reporter->Error(fmt("Luajit unable to load script:  %s\n", name));
		return LUA_FAILURE;
	}

	status = lua_pcall(L, 0, 0, 0);
	switch( status )
	{
	    case LUA_ERRRUN:
	        reporter->Error(fmt("Runtime error, script file: %s\n", name));
	        break;
	    case LUA_ERRMEM:
	        reporter->Error(fmt("Memory allocation error, script file: %s\n", name));
	        break;
	    case LUA_ERRERR:
	        reporter->Error(fmt("Error while running the error handler function, \
	        	script file: %s\n", name));
	}

	if (status != 0)
	{
		reporter->Error(fmt("Luajit unable to prime script:  %s\n", name));
		return LUA_FAILURE;
	}

	//Parse script for events, do all pre-processing and add applicable hooks to unordered_map.
	EventRegistry::string_list *all_handlers = event_registry->AllHandlers(); 
	if (!all_handlers)
	{
		reporter->Error(fmt("Error loading event registry during script load:  %s\n", name));
		lua_close(L);
		return LUA_FAILURE;
	}
	
	const char *handler_name = NULL;

	while (handler_name = all_handlers->get(), handler_name)
	{
		lua_getglobal(L, handler_name);
		if ((!lua_isnil(L, -1)) && lua_isfunction(L, -1))
		{
			if (likely(LuaEventSupported(handler_name) ))
			{
				//Add Lua state to every event handler it registers
				bool found = false;
				for (std::list<void *>::iterator s = responders[handler_name].begin(); \
					s != responders[handler_name].end(); ++s)
				{
					if (static_cast<void *>(L) == *s)
					{
						found = true;
						break;
					}
				}
#ifdef LUA_DEBUG
				if (found)
				{
					reporter->Info("Skipped adding duplicate context during LoadLuaScript");
				}
#endif
				if (!found)
				{
					responders[handler_name].push_back(static_cast<void *> (L));
				}
				char *script_name = new char[strlen(name) + 8];
				strcpy(script_name, name);

				//set to active so we only delete it once
				active_states[static_cast<void *> (L)] = script_name; 
				active_hashes[static_cast<void *> (L)] = FileHash(script_name);

				//Register event with registry
				EventHandler* h = event_registry->Lookup(handler_name);
				if ( ! h )
				{
					h = new EventHandler(handler_name);
					event_registry->Register(h);
				}
			}
			else
			{
				reporter->Warning("Lua script %s called unsupported event %s  -- event not \
					registered", name, handler_name);
			}
		}
		handler_name = NULL;
	}

	if ((active_states.find(static_cast<void *>(L)) == active_states.end()))
	{
		reporter->Info(fmt("No events registered from script:  %s\n", name));
		lua_close(L);
	}

	return LUA_SUCCESS;
}



void LuajitManager::LuajitTryEvent(const char *name, val_list *args, bool need_lock)
{
#ifdef LUA_DEBUG
	//reporter->Info("About to lock Lua if needed (LuajitTryEvent)");
#endif
	if (need_lock)
	{
#ifdef LUA_DEBUG
		//reporter->Info("Locking Lua (LuajitTryEvent): %s", name);
#endif
		pthread_mutex_lock(&lua_lock);
	}

	int num_args = args->length();
	int num_returns = 0;

	lua_State *L;
	
	std::list<void *> *scripts = &(responders[name]);
	if ((*scripts).size() > 0)
	{

#ifdef LUA_DEBUG
		reporter->Info("Number of args seen from event %s :  %d", name, num_args);
#endif

		std::list<void *>::iterator s = (*scripts).begin();

		while ( s != (*scripts).end())
		{
			if ((active_states.find(static_cast<void *>(*s)) == active_states.end()))
			{
				(*scripts).erase(s++);
#ifdef LUA_DEBUG
				reporter->Info("Cleared out an old context from event responders list for \
					event %s", name);
#endif
				continue;
			}
			L = static_cast<lua_State *>(*s);
			lua_getglobal(L, name);

			//Any errors here will be self-reported. This could include failure to rectify 
			//	situations such as 'optional' type fields that could not be defaulted 
			//	(they should probably be set to nil)
			int pushed_args = 0;
			if (num_args > 0)
			{
				pushed_args = PushLuaArgs(L, args);
			}

			if (unlikely( pushed_args < 0 ))
			{
				reporter->Warning("Unable to push args, skipping script:  %s  for event:  %s", \
					active_states[*s], name);
				continue; 
			}

#ifdef LUA_DEBUG			
			if (unlikely(pushed_args != num_args))
			{
				reporter->Info("That's weird, Lua pushed:  %d  args, but we expected:  %d", \
					pushed_args, num_args);
			}
#endif

			// pcall (or maybe the C function call) automatically pops num_args, so we aren't worried about stack leaks
			if (unlikely((lua_pcall(L, num_args, num_returns, 0) != 0) || bad_context_list.size()))
			{
	        	reporter->Warning("Lua error running function `%s' in script %s: %s", name, \
	        		active_states[*s], lua_tostring(L, -1));

#ifdef LUA_DEBUG
	        	//Debug dump of event arguments (val_list)
	        	BroFile* f;
				int offset = 0;

				f = new BroFile(stdout);

				desc_style style = f->IsRawOutput() ? RAW_STYLE : STANDARD_STYLE;
	        	ODesc d(DESC_READABLE);
				d.SetFlush(0);
				d.SetStyle(style);

	        	if ( f->IsRawOutput() )
				{
					ODesc d(DESC_READABLE);
					d.SetFlush(0);
					d.SetStyle(style);

					describe_vals(args, &d, offset);
					f->Write(d.Description(), d.Len());
				}
				else
				{
					ODesc d(DESC_READABLE, f);
					d.SetFlush(0);
					d.SetStyle(style);

					describe_vals(args, &d, offset);
					f->Write("\n", 1);
				}

				delete f;
#endif

				if (unlikely(bad_context_list.size()))
				{
					lua_State *bad = static_cast<lua_State *>(bad_context_list.back());
					bad_context_list.pop_back();
					RemoveFaultyScript(bad);
				}
				else
				{
					//Remove current script for a Lua error not seen by Bro. 
					//	For example, indexing a value that is nil will not show up in pre-parsing
					//	of the script, and yet it is a Lua error (not relevant to Bro objects).
					RemoveFaultyScript(L);
				}

#ifdef LUA_DEBUG
				if (unlikely(bad_context_list.size()))
				{
					reporter->FatalError("Bad contexts list could not be properly emptied");
				}
#endif
			}

			++s;
		}
	}

#ifdef LUA_DEBUG
	//reporter->Info("About to unlock Lua if needed (LuajitTryEvent)");
#endif
	if (need_lock)
	{
#ifdef LUA_DEBUG
		//reporter->Info("Unlocking Lua (LuajitTryEvent)");
#endif
		pthread_mutex_unlock(&lua_lock);
	}
}


//Push a list of arguments accompanying an Event to Lua's virtual stack prior to calling the 
//	Lua function
int LuajitManager::PushLuaArgs(lua_State *L, val_list *args)
{
	int args_pushed = 0;
	int i;
	for ( i = 0; i < (args)->length(); ++i )
	{
		Val *arg = (*args)[i];

#ifdef LUA_DEBUG
		reporter->Info("Pushing userdata argument");
#endif

		if (unlikely(PushLuaVal(L, arg)) == LUA_FAILURE)
		{
			return LUA_FAILURE;
		}
		else
		{
			args_pushed++;
		}
	}

	return args_pushed;
}



//This will push complex types as userdata (references) and convert simple types to Lua types 
//	(immutable values) 
int LuajitManager::PushLuaVal(lua_State *L, Val* arg, bool ref)
{
	TypeTag arg_type;
	Val **v;
	int refcnt=0;

	if (arg)
	{
		arg_type = arg->Type()->Tag();
	}
	else
	{
		arg_type = TYPE_VOID;
	}

	switch (arg_type)
	{
		/* Container types -- represented as userdata of the meta-type bro.val */
		case TYPE_RECORD:
		case TYPE_TABLE:
		case TYPE_VECTOR:
		case TYPE_LIST:

		case TYPE_ADDR:
		case TYPE_SUBNET:
		case TYPE_PORT:
		case TYPE_TIME:
		case TYPE_INTERVAL:
		case TYPE_PATTERN:
		case TYPE_ENUM: 
		case TYPE_FILE: 
		case TYPE_UNION: 
		case TYPE_TIMER:
		case TYPE_ANY:
		case TYPE_FUNC:
		case TYPE_OPAQUE:

			v = (Val **) lua_newuserdata(L, sizeof(Val *));
			*v = arg;

			luaL_getmetatable(L, "bro.val");
			lua_setmetatable(L, -2);

			refcnt = (*v)->RefCnt();
			LuaRef(*v);
			if (!ref)
			{
				(*v)->LuaRefReset(refcnt);
			}


#ifdef LUA_DEBUG
			reporter->Info("Pushed userdata");
#endif
			break;


		/* Basic types -- represented as basic Lua equivalents */
		case TYPE_BOOL:
			lua_pushboolean(L, (arg->CoerceToInt() ? 1 : 0) );
#ifdef LUA_DEBUG
			reporter->Info("Pushed Boolean");
#endif
			break;

		case TYPE_INT:
		case TYPE_COUNT:
		case TYPE_COUNTER:
		case TYPE_DOUBLE:
			lua_pushnumber(L, arg->CoerceToDouble() );

#ifdef LUA_DEBUG
			reporter->Info("Pushed Number");
#endif
			break;


		case TYPE_STRING:
			lua_pushlstring(L, arg->CoerceToCString(), strlen(arg->CoerceToCString()) );

#ifdef LUA_DEBUG
			reporter->Info("Pushed StringVal:  %s", arg->CoerceToCString() );
#endif
			break;


		//Will always treat these values as nil
		case TYPE_TYPE:
		case TYPE_ERROR:
		case TYPE_VOID:
		default:
			//Weird
			//TODO: How to differentiate valid Bro values of nil? There is no way, nil = false
			reporter->Error("Lua: nil value pushed to stack for unsupported arg type \
				or uninitialized arg");
			lua_pushnil(L);
			return LUA_FAILURE;
	}

	return LUA_SUCCESS;
}



//Push Bro Val recursively as a native Lua table onto the Lua stack
int LuajitManager::PushLuaValAsTableRecursive(lua_State *L, Val *arg, int first_call)
{
	int args_pushed = 0;

	int i;
	int size;
	int sz;
	val_list *table_indices;
	RecordType *sub_type;
	val_list *vl;
	int n;
	IPPrefix subnet;
	const char *addr;
	const char *type;
	const PDict(TableEntryVal)* tbl;
	IterCookie* c;
	HashKey* k;
	ListVal *lv;
	TableVal *tv;
	ODesc d(DESC_READABLE);
	Val *temp;

	//validate each Val arg for compatibility (like optional args)
	TypeTag arg_type;

	if (arg)
	{
		arg_type = arg->Type()->Tag();
	}
	else
	{
		arg_type = TYPE_ERROR;
	}

	// Note: ignoring attributes in table representations of Vals

	switch (arg_type)
	{
		case TYPE_BOOL:
			//lua boolean
			lua_pushboolean(L, (arg->CoerceToInt() ? 1 : 0) );
			args_pushed++;

#ifdef LUA_DEBUG
			reporter->Info("Pushed Boolean");
#endif
			break;


		case TYPE_INT:
		case TYPE_COUNT:
		case TYPE_COUNTER:
		case TYPE_DOUBLE:
			//lua number
			lua_pushnumber(L, arg->CoerceToDouble() );
			args_pushed++;

#ifdef LUA_DEBUG
			reporter->Info("PushedNumber");
#endif

			break;


		case TYPE_STRING:
			//lua string

			//Note: C strings cannot contain embedded 0's when converting to Lua, use pushlstring
			lua_pushlstring(L, arg->CoerceToCString(), strlen(arg->CoerceToCString()) );
			args_pushed++;

#ifdef LUA_DEBUG
			reporter->Info("Pushed StringVal:  %s", arg->CoerceToCString() );
#endif
			break;


		/* Dynamic length objects (list, vector, record, table) */
		case TYPE_TABLE:

			size = 2*static_cast<int>( ((TableVal *)arg)->Size() );
			if (unlikely(size == 0))
			{
#ifdef LUA_DEBUG
				reporter->Warning("Failed to call event: arg of table type of size zero. \
					Pushed nil");
#endif
				lua_pushnil(L);
				args_pushed++;
				break;
			}
			if (unlikely(!lua_checkstack (L, (first_call ? size : size - 1) )))
			{
				reporter->Warning("Unable to pass arg to Lua script, not enough room on stack");
				return STACK_ERROR;
			}


#ifdef LUA_DEBUG
			reporter->Info("Pushing TableVal -- Total args: %d", ((TableVal *)arg)->Size() );
#endif

			tv = ((TableVal *)arg);
			lv = ((TableVal *)arg)->ConvertToList();

			lua_newtable(L);

			if (tv->Type()->IsSet())
			{
				lua_pushlstring(L, "Set", sizeof("Set"));
			}
			else
			{
				lua_pushlstring(L, "Table", sizeof("Table"));
			}
			lua_setfield(L, -2, "__brotype");


			for (i = 0; i < ((TableVal *)arg)->Size(); ++i)
			{
#ifdef LUA_DEBUG
				reporter->Info("Pushing table arg");
#endif

				if (tv->Type()->IsSet())
				{
					//index as list
#ifdef LUA_DEBUG
					reporter->Info("Pushing table arg as set");
#endif
					args_pushed += 1;
					lua_pushnumber(L, i );
					args_pushed += PushLuaValAsTableRecursive(L, lv->Index(i), 0);
				}
				else
				{
#ifdef LUA_DEBUG
					reporter->Info("Pushing table arg NOT as set");
#endif
					temp = tv->Lookup( lv->Index(i) );
					args_pushed += PushLuaValAsTableRecursive(L, lv->Index(i), 0);
					if (unlikely(!temp || temp == (Val*)tv))
					{
						lua_pushnil(L);
					}
					else
					{
						args_pushed += PushLuaValAsTableRecursive(L, temp, 0);
					}
				}
				lua_settable(L, -3);
			}

			delete lv;
			break;

		case TYPE_LIST:
			//Used by TableVals (2 dimensionally) when calling ConvertToList

#ifdef LUA_DEBUG
			reporter->Info("Pushing ListVal");
#endif

			size = 2*static_cast<int>( ((ListVal *)arg)->Length() );
			if (unlikely(size == 0))
			{

#ifdef LUA_DEBUG
				reporter->Warning("Failed to call event: arg of table type of size zero");
#endif
				lua_pushnil(L);
				args_pushed++;
				break;
			}
			if (unlikely(!lua_checkstack (L, (first_call ? size : size - 1) )))
			{
				reporter->Warning("Unable to pass arg to Lua script, not enough room on stack");
				return STACK_ERROR;
			}

			lua_newtable(L);
			lua_pushlstring(L, "List", sizeof("List"));
			lua_setfield(L, -2, "__brotype");

#ifdef LUA_DEBUG
			reporter->Info("Total ListVal Args to push: %d", ((ListVal *)arg)->Length() );
#endif

			sz = static_cast<int>( ((ListVal *)arg)->Length() );
			for(i=0 ; i < sz; ++i )
			{
#ifdef LUA_DEBUG
				reporter->Info("Pushing ListVal Arg");
#endif
				args_pushed += 1;
				lua_pushnumber(L, i );
				args_pushed += PushLuaValAsTableRecursive(L, ((ListVal *)arg)->Index(i), 0);
				lua_settable(L, -3);
			}
			break;

		case TYPE_VECTOR:
			////indices will be integers (0,1,2...)

#ifdef LUA_DEBUG
			reporter->Info("Pushing VectorVal");
#endif

			// Dynamic sizes multiplied by 2 to account for 1 key per val with table implementation
			//	or is this already considered?
			size = 2*static_cast<int>( ((VectorVal *)arg)->Size() );
			if (unlikely(size == 0))
			{
#ifdef LUA_DEBUG
				reporter->Warning("Failed to call event: arg of table type of size zero");
#endif
				lua_pushnil(L);
				args_pushed++;
				break;
			}
			if (unlikely(!lua_checkstack (L, (first_call ? size : size - 1) )))
			{
				reporter->Warning("Unable to pass arg to Lua script, not enough room on stack");
				return STACK_ERROR;
			}

			lua_newtable(L);

			lua_pushlstring(L, "Vector", sizeof("Vector"));
			lua_setfield(L, -2, "__brotype");

			sz = static_cast<int>( ((VectorVal *)arg)->Size() );
			for(i=0 ; i < sz; i++ )
			{
				args_pushed += 1;
				lua_pushnumber(L, i );
				args_pushed += PushLuaValAsTableRecursive(L, ((VectorVal *)arg)->Lookup(i), 0);
				lua_settable(L, -3);
			}

			break;

		case TYPE_RECORD:

#ifdef LUA_DEBUG
			reporter->Info("Pushing RecordVal");
#endif

			//record size multiplied by 2 to account for 1 key per val with table implementation
			size = 2*static_cast<int>( ((RecordVal*) arg)->SizeVal()->CoerceToInt() );
			if (unlikely(size == 0))
			{
#ifdef LUA_DEBUG
				reporter->Warning("Failed to call event: arg of type Record of size zero");
#endif
				lua_pushnil(L);
				args_pushed++;
				break;
			}
			if (unlikely(!lua_checkstack (L, (first_call ? size : size - 1) )))
			{
				reporter->Warning("Unable to pass arg to Lua script, not enough room on stack");
				return STACK_ERROR;
			}

			lua_newtable(L);

			lua_pushlstring(L, "Record", sizeof("Record"));
			lua_setfield(L, -2, "__brotype");

			sub_type = ((RecordVal*) arg)->LuaRecordType();


#ifdef LUA_DEBUG
			vl = ((RecordVal*) arg)->LuaRecordVals();
#endif

			n = sub_type->NumFields();
#ifdef LUA_DEBUG
			if (unlikely(vl->length() != n))
			{
				reporter->Warning("Val length and num fields don't match in \
					PushLuaValAsTableRecursive");
			}
#endif

			for ( i = 0; i < n; ++i )
			{
				if (sub_type->FieldDecl(i)->FindAttr(ATTR_OPTIONAL) ) {
#ifdef LUA_DEBUG
				 	reporter->Info("Optional arg incoming:");
#endif
				}

#ifdef LUA_DEBUG
				reporter->Info("Event pushing field name:  %s ", (sub_type->FieldName(i)));
#endif

				args_pushed += 1;
				args_pushed += PushLuaValAsTableRecursive(L, \
				((RecordVal *)arg)->Lookup(sub_type->FieldName(i), 0, true), 0); //push value
				lua_setfield(L, -2, (sub_type->FieldName(i)) );			
			}
			break;

		case TYPE_PORT:
			size = 6;

#ifdef LUA_DEBUG
			reporter->Info("Pushing PortVal");
#endif
			
			if (unlikely(!lua_checkstack (L, (first_call ? size : size - 1) )))
			{
				reporter->Warning("Unable to pass arg to Lua script, not enough room on stack");
				return STACK_ERROR;
			}

			lua_newtable(L);

			lua_pushlstring(L, "Port", sizeof("Port"));
			lua_setfield(L, -2, "__brotype");

			lua_pushnumber(L,  ((PortVal *) arg)->Port() );
			lua_setfield(L, -2, "port");

			type = TransportProtoToString(((PortVal *) arg)->PortType());

			lua_pushstring(L,  type );
			lua_setfield(L, -2, "proto");


			args_pushed += size;
			break;

		case TYPE_SUBNET:
			size = 4;

#ifdef LUA_DEBUG
			reporter->Info("Pushing SubNetVal");
#endif
			
			if (unlikely(!lua_checkstack (L, (first_call ? size : size - 1) )))
			{
				reporter->Warning("Unable to pass arg to Lua script, not enough room on stack");
				return STACK_ERROR;
			}

			lua_newtable(L);

			lua_pushlstring(L, "Subnet", sizeof("Subnet"));
			lua_setfield(L, -2, "__brotype");

			subnet = arg->AsSubNet();
			lua_pushlstring(L, subnet.AsString().c_str(), strlen(subnet.AsString().c_str()) );
			lua_setfield(L, -2, "mask");

			args_pushed += size;
			break;

		case TYPE_ADDR:
			size = 6;

#ifdef LUA_DEBUG
			reporter->Info("Pushing AddrVal");
#endif
			
			if (unlikely(!lua_checkstack (L, (first_call ? size : size - 1) )))
			{
				reporter->Warning("Unable to pass arg to Lua script, not enough room on stack");
				return STACK_ERROR;
			}

			addr = arg->AsAddr().AsString().c_str(); 

			lua_newtable(L);

			lua_pushlstring(L, "Addr", sizeof("Addr"));
			lua_setfield(L, -2, "__brotype");

			lua_pushlstring(L, addr, strlen(addr));
			lua_setfield(L, -2, "address");

			if (arg->AsAddr().GetFamily() == IPv4)
			{
				lua_pushstring(L, "ipv4");
			} else {
				lua_pushstring(L, "ipv6");
			}
			lua_setfield(L, -2, "version");

			args_pushed += size;
			break;

		case TYPE_TIME:
			//we will use a double table val and parse this via metatable (another 
			//	example where we should have a metatable?)
			size = 2;

#ifdef LUA_DEBUG
			reporter->Info("Pushing TimeVal");
#endif
			
			if (unlikely(!lua_checkstack (L, (first_call ? size : size - 1) )))
			{
				reporter->Warning("Unable to pass arg to Lua script, not enough room on stack");
				return STACK_ERROR;
			}

			lua_newtable(L);

			lua_pushlstring(L, "Time", sizeof("Time"));
			lua_setfield(L, -2, "__brotype");

			lua_pushnumber(L, arg->ForceAsDouble());
			lua_setfield(L, -2, "time");

			args_pushed += size;
			break;

		case TYPE_INTERVAL:
			//treating this the same as a time value essentially... just a double
			size = 4;

#ifdef LUA_DEBUG
			reporter->Info("Pushing IntervalVal");
#endif
			
			if (unlikely(!lua_checkstack (L, (first_call ? size : size - 1) )))
			{
				reporter->Warning("Unable to pass arg to Lua script, not enough room on stack");
				return STACK_ERROR;
			}

			lua_newtable(L);

			lua_pushlstring(L, "Interval", sizeof("Interval"));
			lua_setfield(L, -2, "__brotype");

			lua_pushnumber(L, arg->ForceAsDouble());
			lua_setfield(L, -2, "interval");

			args_pushed += size;

			break;

		case TYPE_PATTERN:
			size = 4;

#ifdef LUA_DEBUG
			reporter->Info("Pushing PatternVal");
#endif
			
			if (unlikely(!lua_checkstack (L, (first_call ? size : size - 1) )))
			{
				reporter->Warning("Unable to pass arg to Lua script, not enough room on stack");
				return STACK_ERROR;
			}

			lua_newtable(L);

			lua_pushlstring(L, "Pattern", sizeof("Pattern"));
			lua_setfield(L, -2, "__brotype");

			((PatternVal *)arg)->AsLuaPattern(&d);
			lua_pushlstring(L, d.Description(), sizeof(d.Description()));
			lua_setfield(L, -2, "regex");

			args_pushed += size;
			break;


		case TYPE_ENUM: 
		case TYPE_FILE: 
		case TYPE_UNION: 
		case TYPE_TIMER:
		case TYPE_ANY:
		case TYPE_VOID:
		case TYPE_FUNC:
		case TYPE_OPAQUE:
		case TYPE_TYPE:
		case TYPE_ERROR:
			// We will not support table conversions for these types

		default:
			reporter->Warning("Lua: Tried pushing unsupported arg type as table, pushed \
				nil to stack."); 
			lua_pushnil(L);
			//TODO: should we still have a field assigned to nil? Should we always pass nil?
			args_pushed++;

			break;
			
	}

	return args_pushed;
}


Val* LuajitManager::PullLuaValFromGenericArg(lua_State *L, int index, bool *userdata, \
	TypeTag desired_type)
{
	const char *field;
	bool bool_index;
	double in;
	Val *result;

#ifdef LUA_DEBUG
	reporter->Info("Pulling generic Val arg . . . ");
#endif

	*userdata = false;

	//Now we need to get the field type and make sure whatever Val we are assigning is safe
	if (lua_type(L, index) == LUA_TSTRING)
	{
		field = luaL_checkstring(L, index);
		if (unlikely(!field))
		{
			reporter->Error("Fail in PullLuaValFromGenericArg -- invalid string as second \
				argument");
			return NULL;
		}
		result = new StringVal(field);
	}
	else if (lua_isboolean(L, index))
	{
		bool_index = lua_toboolean(L, index);
		result = new Val( bool_index, TYPE_BOOL);
	}
	//Here is a guess at what type of Bro number this needs to be
	else if (lua_isnumber(L, index))
	{
		in = lua_tonumber(L, index);

		if (desired_type == TYPE_COUNT)
		{
			result = new Val( (int) in, TYPE_COUNT);
		}
		else if (desired_type == TYPE_INT)
		{
			result = new Val( (int) in, TYPE_INT);
		}
		else if (desired_type == TYPE_DOUBLE)
		{
			result = new Val( (double) in, TYPE_DOUBLE);
		}
		else if (desired_type == TYPE_PORT)
		{
			result = (Val*) ( new PortVal( (uint32_t) in) );
		}
		else if (desired_type == TYPE_INTERVAL)
		{
			result = new Val( (double) in, TYPE_INTERVAL);
		}
		else
		{
			if (in == (unsigned int)in) {
				//call it a count
				result = new Val( (int) in, TYPE_COUNT);
			}
			else if (in == (int)in) {
				//call it an int
				result = new Val( (int) in, TYPE_INT);
			}
			else {
				//call it a double
				result = new Val( in, TYPE_DOUBLE);
			}
		}
	}
	else if (lua_isuserdata(L, index))
	{
		result = CheckLuaUserdata(L, index); 
		if (unlikely(!result))
		{
			reporter->Error("Not a valid userdata table argument");
			return NULL;
		}
		*userdata = true;
		Ref(result);
	}
	else if (lua_istable(L, index))
	{
		result = LuajitManager::PullLuaValFromTableRecursive(L, index);
		if (unlikely(!result))
		{
			reporter->Error("Unable to create Val from table");
			SetFaultyScript(L);
			return NULL;
		}
	}
	else
	{
		if (likely(lua_isnil(L, index)))
		{
#ifdef LUA_DEBUG
			reporter->Warning("Pulling nil as Val arg... ");
#endif
			//bool_index = lua_toboolean(L, index);
			//result = new Val( bool_index, TYPE_BOOL);

			//Note: returning NULL. May want an actual false boolean to represent nil.
			return NULL;
		}
		else
		{
			reporter->Error("Not a valid Val argument type");
			SetFaultyScript(L);
			*userdata = true; //to notify caller that it is not nil
			return NULL;
		}
	}

	return result;
}


//TODO: Now here is where we need to check the brotype and recordtype of the table to see if we can 
//	make the conversion. THEN, we create a new Val and perform the assignment. Note:
//	When we pushAsTable (and we previously had reffed it) we should unref. But first we need
//	to load the whole thing. Do all this in PullLuaAsTableRecursive
Val* LuajitManager::PullLuaValFromTableRecursive(lua_State *L, int index)
{
	//make sure __brotype is correct, fields are correct types, create new Val
	//	 and populate, and init empty fields to nil

	//This MAY be implemented for Ports, Addrs, and Subnets, but that would be it. It's best to use
	//methods instead

	//this will be exceptionally tricky because we don't know what order the metadata will appear on the stack,
	//	so we need to buffer this table info in a custom C object Lua table representation that can be queried 
	//	using Lua table access syntax (to get __brotype and __recordtype, __tabletype, etc.)

	// discard any extra arguments passed in
	if (unlikely(lua_gettop(L)) != 1)
	{
		reporter->Error("Lua function called PullLuaValFromTableRecursive with incorrect \
			number of arguments");
		lua_mgr->SetFaultyScript(L);
		return NULL;
	}
	
	if (unlikely(lua_type(L, 1) != LUA_TTABLE))
	{
		reporter->Error("Lua function called PullLuaValFromTableRecursive with incorrect \
		 number of arguments");
		lua_mgr->SetFaultyScript(L);
		return NULL;
	}

	luaL_checktype(L, 1, LUA_TTABLE);

	// Now to get the data out of the table
	// 'unpack' the table by putting the values onto
	// the stack first. Then convert those stack values
	// into an appropriate C type.

	Val *v = NULL;

	lua_getfield(L, 1, "__brotype");
	const char *type = luaL_checkstring(L, -1);
	if (strcmp(type, "Port") == 0)
	{
		lua_getfield(L, 1, "port");
		lua_getfield(L, 1, "proto");

		int port = luaL_checkint(L, -3);
		TransportProto proto = StringToTransportProto(luaL_checkstring(L, -2));

		v = (Val *) (new PortVal(port, proto));

		lua_pop(L, 3);
	}
	else if (strcmp(type, "Addr") == 0)
	{
		//TODO
	}
	else if (strcmp(type, "Subnet") == 0)
	{
		//TODO
	}
	else
	{
		reporter->Error("Lua function called PullLuaValFromTableRecursive on unsupported type");
		lua_mgr->SetFaultyScript(L);
		return NULL;
	}

	//Currently not supported, return null
	return v;
}


//Setter for userdata with bro.val metatables. Called in the form val["field"] = newval, where 
//	field and newval can be any valid types (interpreted appropriately when possible). 
//	val.field = newval is also a valid syntax
int LuajitManager::function_SetLuaVal(lua_State *L)
{
	//Expected args: Val userdata object, 'any' field, 'any' value (we support string, boolean,
	//	number, table, and userdata objects.)
	if (unlikely(lua_gettop(L) != 3))
	{
		reporter->Error("Lua function called setter with incorrect number of arguments");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	Val* v = lua_mgr->CheckLuaUserdata(L, 1); 
	if (unlikely(!v))
	{
		reporter->Error("In setter -- not a valid userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}


	TypeTag arg_type = v->Type()->Tag();
	Val *result;

	//unref and delete this Val if we create it
	Val *table_index = NULL;
	Val *oldVal;

	bool userdataIndex = false;
	bool userdataResult = false;

	RecordVal *rv;
	TableVal *tv;
	ListVal *lv;
	VectorVal *vv;

	RecordType *record_type;

	const char *field = NULL;

	const char *string_index = NULL;
	int field_index = 0;
	int vector_index = 0;
	bool bool_index = false;
	double number_index = 0;

	switch (arg_type)
	{
		case TYPE_RECORD:
			rv = (RecordVal *)v;

#ifdef LUA_DEBUG
			reporter->Info("Setting Lua RecordVal");
#endif

			field = luaL_checkstring(L, 2);
			if (unlikely(!field))
			{
				reporter->Error("Fail in setter -- bad string as second argument");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

			record_type = rv->LuaRecordType();
			field_index = record_type->FieldOffset(field);
			if (unlikely(field_index < 0))
			{
				reporter->Error("Invalid field access in setter: `  %s  ` not recognized", \
					field );
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

			if ( (record_type->FieldType(field)->Tag() == TYPE_INT) || \
					(record_type->FieldType(field)->Tag() == TYPE_COUNT) || \
					(record_type->FieldType(field)->Tag() == TYPE_DOUBLE) || \
					(record_type->FieldType(field)->Tag() == TYPE_PORT) || \
					(record_type->FieldType(field)->Tag() == TYPE_INTERVAL) )
			{
				//Force numeric type, if possible
				result = lua_mgr->PullLuaValFromGenericArg(L, 3, &userdataResult, \
					record_type->FieldType(field)->Tag());
			}
			else
			{
				result = lua_mgr->PullLuaValFromGenericArg(L, 3, &userdataResult);
			}

			if (unlikely(!result))
			{
				if (unlikely(userdataResult))
				{
					reporter->Error("Invalid type in setter");
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
#ifdef LUA_DEBUG
				reporter->Warning("Trying to assign userdata value to RecordVal");
#endif


				//TODO: Assigning null to RecordVal field. Is this legal? Should we limit
				//	to optional/default attribute fields?
				rv->Assign(field_index, result);
				return 0;
			}
			
			if (record_type->FieldType(field)->Tag() != result->Type()->Tag() )
			{
				char s1[100];
				char s2[100];
				memset(s1, '\0', sizeof(s1));
				memset(s2, '\0', sizeof(s2));
				TypeTagToString(record_type->FieldType(field)->Tag(), s1);
				TypeTagToString(result->Type()->Tag(), s2);
				reporter->Error("Record Value type mismatch, unable to make assignment, \
					expected %s, received %s", s1, s2);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			
			rv->Assign(field_index, result);
			///Note: Assuming Assign automatically Unref's old value, and does not Ref
			//	the new value apparently (but we already did by pulling it)

			break;

		case TYPE_TABLE:
			tv = (TableVal *)v;

#ifdef LUA_DEBUG
			reporter->Info("Setting Lua TableVal");
#endif

			if (tv->Type()->IsSet())
			{
				reporter->Error("Assigned value to set index, use add and remove instead");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			
			table_index = lua_mgr->PullLuaValFromGenericArg(L, 2, &userdataIndex, \
				tv->Type()->YieldType()->Tag());

			//Note: Nil is not valid for an index
			if (unlikely(!table_index))
			{
				reporter->Error("In setter -- unable to create valid index Val from \
					argument for TableVal");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

			//Note: Index needs to be a ListVal
			lv = new ListVal(table_index->Type()->Tag());
			lv->Append(table_index);

			//Note: Use desired type whenever possible in PullLuaValFromGenericArg

			//Now get the Val for the new value
			result = lua_mgr->PullLuaValFromGenericArg(L, 3, &userdataResult, \
				tv->Type()->YieldType()->Tag());

			if (unlikely(!result))
			{
				if (userdataResult)
				{
					reporter->Error("Invalid type in setter");
					Unref(table_index);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}

				//Intentional nil value
			}
			else
			{
				if (unlikely(result->Type()->Tag() != tv->Type()->YieldType()->Tag()))
				{
					reporter->Error("Bad type assigned to TableVal in SetLuaVal");
					Unref(table_index);
					Unref(result);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}

			//TODO: Check that Table INDEX is of correct type
			//if (same_type(tv->GetTableType(), table_index->Type()))


			if (unlikely(!result))
			{
#ifdef LUA_DEBUG
				reporter->Info("Deleting tableval index in setter (var[x] = nil)");
#endif
				//Note: Delete returns the value (or the table), and we should unref it. 

				oldVal = tv->Delete(lv);
				if (unlikely(!oldVal || (oldVal==(Val*)tv)))
				{
					if (oldVal == tv)
					{
						//If it returns itself, it Unrefs it
						Unref(tv);
					}
#ifdef LUA_DEBUG
					reporter->Info("In setter -- unable to delete index \
						from TableVal because there was no entry");
#endif
				}
				Unref(oldVal);
				Unref(lv);
			}
			else
			{
				if (unlikely(!tv->Assign(lv, result)))
				{
					reporter->Error("In setter -- unable to assign result to TableVal");
					Unref(result);
					Unref(table_index);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
				//Note: We can't Unref index! It's held by the Table
			}

			break;

		case TYPE_LIST:
			reporter->Error("Setter called on Lua ListVal -- newList and add instead, \
				although you probably shouldn't be manipulating lists directly anyway.");
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;

		case TYPE_VECTOR:
			vv = (VectorVal *)v;

#ifdef LUA_DEBUG
			reporter->Info("Setting Lua VectorVal");
#endif
			
			if (lua_isnumber(L, 2))
			{
				vector_index = (int) lua_tonumber(L, 2);
			}
			else
			{
				reporter->Warning("Invalid non-numeric non-self argument for VectorVal index");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

			if (unlikely(vector_index < 0 || vector_index > (int)vv->Size()))
			{
				reporter->Error("Invalid number VectorVal index: %d", vector_index);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

			result = lua_mgr->PullLuaValFromGenericArg(L, 3, &userdataResult, \
				vv->Type()->YieldType()->Tag());

			if (unlikely(!result))
			{
				//not going to push null to a VectorVals either, this would most likely be 
				//	bad practice
				reporter->Error("Unable to create valid Val to push to VectorVal");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

			if (unlikely(result->Type()->Tag() != vv->Type()->YieldType()->Tag()))
			{
				//Check for an intentional nil value
				if (result->Type()->Tag() == TYPE_BOOL && result->AsNumber() == 0)
				{
					Unref(result);
					result = NULL;
				}
			}


			if (unlikely(!vv->Assign(number_index, result)))
			{
				reporter->Error("Unable to create valid Val to push to VectorVal");
				return LUA_FAILURE;
			}

			break;

		//Note: these types are const
		case TYPE_PORT:
		case TYPE_ADDR:
		case TYPE_SUBNET:

		default:
			char typestringarray[100];
			reporter->Error("Cannot set invalid userdata type: %d", \
				TypeTagToString(arg_type, typestringarray));
			return LUA_FAILURE;
	}

	return 0;
}



//Getter for userdata with bro.val metatables. Called in the form val = val["field"], where 
//	field can be any valid index type or string field. val = val.field is also valid syntax.
int LuajitManager::function_GetLuaVal(lua_State *L)
{
	//Expected args: Val userdata object, string field
	if (lua_gettop(L) != 2)
	{
		reporter->Error("Lua function called getter with incorrect number of arguments: %d", \
			lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	Val *v = CheckLuaUserdata(L, 1);
	if (!v)
	{
		reporter->Error("Fail in getter -- not a valid userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	TypeTag self_type = v->Type()->Tag();
	Val *result;

	RecordVal *rv;
	TableVal *tv;
	ListVal *lv;
	VectorVal *vv;
	
	Val *table_index = NULL;
	bool userdataIndex = false;

	const char *field = NULL;
	bool alreadyGotString = false;
	int vector_index = 0;
	bool bool_index = false;
	double number_index = 0;

	const char *type;
	
	//This handles methods that are caught as arguments by the __index metamethod
	luaL_getmetatable(L, "bro.val");
	lua_pushvalue(L, 2);
	lua_rawget(L, -2);

	if ( lua_isnil(L, -1) ) {
		lua_pop(L, 1);
	}
	else
	{
		return 1;
	}
	

	switch (self_type)
	{
		case TYPE_RECORD:
			rv = (RecordVal *)v;

#ifdef LUA_DEBUG
			reporter->Info("Getting Lua field from RecordVal object");
#endif
			if (!alreadyGotString)
			{
				field = luaL_checkstring(L, 2);
				if (unlikely(!field))
				{
					reporter->Error("Fail in getter -- bad string as field argument for \
						RecordVal");
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}

			result = rv->Lookup(field, true, true);
			if (unlikely(!result))
			{
				if (unlikely(rv->LuaRecordType()->FieldOffset(field) < 0))
				{
					reporter->Error("Invalid field access in getter (illegal field:  %s)", field);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
				else
				{
#ifdef LUA_DEBUG
					reporter->Info("RecordVal field uninitialized in getter");
#endif
					lua_pushnil(L);
					return 1;
				}
			}

			//Note: PushLuaVal will LuaRef this, and Lookup Refs it IF DEFAULT IS SET? But
			//	doesn't return it so this will cause a seg fault
			//Unref(result);

			break;

		case TYPE_TABLE:
			tv = (TableVal *)v;

			if (tv->Type()->IsSet())
			{
				reporter->Error("Bad syntax -- Can't index a set");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

#ifdef LUA_DEBUG
			reporter->Info("Getting Lua field from TableVal object");
#endif
			
			table_index = lua_mgr->PullLuaValFromGenericArg(L, 2, &userdataIndex, \
				tv->Type()->YieldType()->Tag());

			//Nil is not a valid table index
			if (unlikely(!table_index))
			{
				reporter->Error("In getter -- unable to create valid index Val from argument");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

			//TODO: Check that Table INDEX is of correct type
			//if (same_type(tv->GetTableType(), table_index->Type()))

			//Note: Index needs to be a ListVal
			lv = new ListVal(table_index->Type()->Tag());
			lv->Append(table_index);

			//Note: TableVal quirk is that if the lookup fails, they return the whole table...
			result = tv->Lookup(lv, false);
			if (unlikely(!result || (result==tv)))
			{
				lua_pushnil(L);
				Unref(lv);
				return 1;
			}

			Unref(lv);
			break;

		case TYPE_LIST:
			lv = (ListVal *)v;

#ifdef LUA_DEBUG
			reporter->Info("Getting Lua field from ListVal object");
#endif

			if (unlikely(!lua_isnumber(L, 2)))
			{
				reporter->Error("Invalid non-numeric argument for ListVal index");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			
			vector_index = (int) lua_tonumber(L, 2);
			if (unlikely(vector_index < 0 || vector_index >= lv->Length()))
			{
				reporter->Error("Invalid number ListVal index");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			result = lv->Index(vector_index);

			if (unlikely(!result))
			{
				lua_pushnil(L);
				return 1;
			}

			break;

		case TYPE_VECTOR:
			vv = (VectorVal *)v;

#ifdef LUA_DEBUG
			reporter->Info("Getting Lua field from VectorVal object");
#endif

			if (unlikely(!lua_isnumber(L, 2)))
			{
				reporter->Error("Invalid non-numeric argument for Vectorval index");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

			vector_index = (int) lua_tonumber(L, 2);
			if (unlikely(vector_index < 0 || vector_index >= (int)vv->Size()))
			{
				reporter->Error("Invalid VectorVal index: %d", vector_index);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			result = vv->Lookup(vector_index);

			if (unlikely(!result))
			{
				lua_pushnil(L);
				return 1;
			}

			break;

		//Note: These are const, but we allow table access
		case TYPE_PORT:

			if (!alreadyGotString)
			{
				field = luaL_checkstring(L, 2);
				if (unlikely(!field))
				{
					reporter->Error("Fail in getter -- bad string as field argument for PortVal");
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}
			if (strcmp(field, "port") == 0)
			{
				lua_pushnumber(L, ((PortVal *)v)->Port() );
				return 1;
			}
			else if (strcmp(field, "type") == 0)
			{
				type = TransportProtoToString(((PortVal *)v)->PortType());
				lua_pushlstring(L, type, strlen(type));
				return 1;
			}
			
			reporter->Error("Illegal field access for PortVal:  %s", field);
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;

		case TYPE_ADDR:
			//allow ip addr to be obtained as string
			if (!alreadyGotString)
			{
				field = luaL_checkstring(L, 2);
				if (unlikely(!field))
				{
					reporter->Error("Fail in getter -- bad string as field argument for PortVal");
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}

			if (strcmp(field, "addr") == 0)
			{
				type = ((AddrVal *)v)->AsAddr().AsString().c_str();
				lua_pushlstring(L, type, strlen(type));
				return 1;
			}
			else if (strcmp(field, "type") == 0)
			{
				lua_pushnumber(L, (((AddrVal *)v)->AsAddr().GetFamily() == IPv4) ? 4 : 6 );
				return 1;
			}
			
			reporter->Error("Illegal field access for AddrVal:  %s", field);
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;

		case TYPE_SUBNET:
			//allow mask, prefix to be retreived as strings
			if (!alreadyGotString)
			{
				field = luaL_checkstring(L, 2);
				if (unlikely(!field))
				{
					reporter->Error("Fail in getter -- bad string as field argument for PortVal");
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}

			if (strcmp(field, "mask") == 0)
			{
				type = ((SubNetVal*)v)->Mask().AsString().c_str();
				lua_pushlstring(L, type, strlen(type));
				return 1;
			}
			else if (strcmp(field, "prefix") == 0)
			{
				type = ((SubNetVal *)v)->Prefix().AsString().c_str();
				lua_pushlstring(L, type, strlen(type));
				return 1;
			}

			reporter->Error("Illegal field access for SubnetVal:  %s", field);
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;


		default:
			reporter->Error("Userdata should be accessed as container that is not a container \
				or supported complex type!!!");
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;
	}

	if (unlikely(lua_mgr->PushLuaVal(L, result) != LUA_SUCCESS))
	{
		reporter->Error("Failed to push result val in getter");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	return 1;
}



//Registered to Lua descriptor AsTable(), calls PushLuaValAsTableRecursive
int LuajitManager::function_PushLuaTable(lua_State *L)
{
	//Expected args: Val userdata object
	if (unlikely(lua_gettop(L) != 1))
	{
		reporter->Error("Lua function called method asTable() with incorrect number of arguments");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	Val* v = CheckLuaUserdata(L, 1);
	if (unlikely(!v))
	{
		reporter->Error("In function_PushLuaTable() -- not a valid userdata");
		return LUA_FAILURE;
	}

	lua_mgr->PushLuaValAsTableRecursive(L, v, 1);

#ifdef LUA_DEBUG
	reporter->Info("Called asTable, pushed Bro Val as Lua table");
#endif
	return 1;
}



//Converts a userdata to string -- if used on a table, converts to Val first and then describes
int LuajitManager::function_ValToString(lua_State *L)
{
	if (unlikely(lua_gettop(L) != 1))
	{
		reporter->Error("Lua function called method function_ValToString() with incorrect \
			number of arguments: %d", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	Val* v = CheckLuaUserdata(L, 1);
	if (unlikely(!v))
	{
		reporter->Error("In function_ValToString() -- not a valid userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	std::string s = ValAsString(v);
	if (!s.empty())
	{
		const char *as_string = s.c_str();
		lua_pushlstring(L, as_string, strlen(as_string));
	}
	else
	{
		reporter->Error("In function_ValToString() -- not a valid string");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	return 1;
}


//Garbage collection method for Lua userdata (this ensures no memory leaks on Vals)
int LuajitManager::function_GarbageCollectVal(lua_State *L)
{
	//Expected args: Val userdata object
	if (unlikely(lua_gettop(L) != 1))
	{
		reporter->Error("Error calling Lua garbage collection");
		lua_mgr->SetFaultyScript(L);
		return 0;
		//Note: It appears returning failure from a Lua event will kill all execution, 
		//	let's just set faulty for now. This can cause problems if it isn't called 
		//	within LuajitTryEvent
	}

	Val* v = CheckLuaUserdata(L, 1);
	if (unlikely(!v))
	{
		reporter->Error("In function_GarbageCollectVal() -- not a valid userdata");
		lua_mgr->SetFaultyScript(L);
		return 0;
		//Note: It appears returning failure from Lua garbage collection will kill all execution....
		//TODO: is this specific to __gc or specific to being called outside of LuajitTryEvent?
	}

#ifdef LUA_DEBUG

	char type[32];
	std::string s = ValAsString(v, type);
	if (s.size())
	{
		const char *string = s.c_str();
		reporter->Info("About to garbage collect this Val: %s ", type);//:  %s", type, string);
	}
	else
	{
		reporter->Error("In function_GarbageCollectVal() -- unable to obtain a string");
	}

	val_list *vl = new val_list(1);
	vl->append(v);
	BroFile* f;
	int offset = 0;

	f = new BroFile(stdout);

	desc_style style = f->IsRawOutput() ? RAW_STYLE : STANDARD_STYLE;
	ODesc d(DESC_READABLE);
	d.SetFlush(0);
	d.SetStyle(style);

	if ( f->IsRawOutput() )
	{
		ODesc d(DESC_READABLE);
		d.SetFlush(0);
		d.SetStyle(style);

		describe_vals(vl, &d, offset);
		f->Write(d.Description(), d.Len());
	}
	else
	{
		ODesc d(DESC_READABLE, f);
		d.SetFlush(0);
		d.SetStyle(style);

		describe_vals(vl, &d, offset);
		f->Write("\n", 1);
	}
	delete f;
	delete vl; // ANE

#endif

	LuaUnref(v);

#ifdef LUA_DEBUG
	reporter->Info("Garbage collected");
#endif

	return 0;
}


//Creates a copy of a Val for Lua assignment. Any time a Val/userdata is copied, it is Ref'd. 
//	Once the variable is no longer needed, it's garbage collected. 
int LuajitManager::function_CopyLuaVal(lua_State *L)
{
	//Expected args: Val userdata object
	if (unlikely(lua_gettop(L) != 1))
	{
		lua_mgr->SetFaultyScript(L);
		reporter->Warning("Lua function called method asCopy() with incorrect number of arguments");

		return LUA_FAILURE;
	}

	Val* v = CheckLuaUserdata(L, 1);
	if (unlikely(!v))
	{
		reporter->Warning("In function_CopyLuaVal() -- not a valid userdata");
		return LUA_FAILURE;
	}

	//TODO: Does clone also clone sub-values of a container? This is essential. Not sure
	//However it raises the question of how they will be UnRef'd? Special clone flag in Val
	//that activates Unref of all its elements when it's deleted. Need to look into this TODO
	//We would want to set the Ref count of all of the deep copied objects to 1

	//Note: it most likely is not a fully deep copy for deep containers, but this only matters
	// if it shares mutable objects. In general this will not be an issue that shows up, but we 
	// will eventually want to address it (TODO)
	Val *clone = v->Clone();
	if (!clone)
	{
		reporter->Error("Unable to clone value");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}
	//clone->LuaRefReset(1);

	if (unlikely(lua_mgr->PushLuaVal(L, clone) != LUA_SUCCESS))
	{
		reporter->Error("Unable to push copied Val to Lua stack");
		lua_mgr->SetFaultyScript(L);

		delete clone; //Unref(clone); //Note: this should delete it
		return LUA_FAILURE;
	}

	return 1;
}


int LuajitManager::function_HideMetaTable(lua_State *L)
{
	reporter->Error("Illegal: Lua script attempted to access userdata metatable.");
	lua_mgr->SetFaultyScript(L);
	return LUA_FAILURE;
}


//Called when Lua calls a userdata like a function.
int LuajitManager::function_CallLuaVal(lua_State *L)
{
	reporter->Warning("Lua script attempted to access userdata metatable as function: Ignored");
	return 0;
}


//Adds two Lua userdata together, if the underlying Vals support addition, and returns a third Val to represent the sum
int LuajitManager::function_AddLuaVals(lua_State *L)
{
	//All of these checks are an attempt to prevent any Lua script from breaking Bro
	if (unlikely(lua_gettop(L) != 2))
	{
		reporter->Error("Lua called function_AddLuaVal with %d arguments; I was only \
			prepared for 2!", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool arg1_userdata = false;
	Val *arg1 = lua_mgr->PullLuaValFromGenericArg(L, 1, &arg1_userdata);
	if (unlikely(!arg1))
	{
		reporter->Error("Fail in function_AddLuaVal -- argument 1 cannot be resolved to a \
			userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool arg2_userdata = false;
	Val *arg2 = lua_mgr->PullLuaValFromGenericArg(L, 2, &arg2_userdata, \
		(arg1->Type()->YieldType() ? arg1->Type()->YieldType()->Tag() : TYPE_VOID));
	if (unlikely(!arg2))
	{
		reporter->Error("Fail in function_AddLuaVal -- argument 2 cannot be resolved to a \
			userdata");
		Unref(arg1);
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	//This implies that order matters for some operations
	//Q: whose __add gets called if you add two userdatas? Both? 
	//		Answer: first (shouldn't matter)
	//Q: Does __add still get called with userdata first if you do "2 + userdata" instead of 
	//	"userdata + 2"
	//		Answer: no, order is arbitrary
	//Q: What if we add "A + B + C + 3 + D + nonuserdata + E" ? Will __add be called two at 
	//	a time, PEMDAS style, or will we handle all at once?
	//		Answer: Two at a time, doesn't matter whether it's left to right or right to left

	//For some operations, order doesn't matter and we need to standardize. For others, it may 
	//	matter asvit determines which object is modified.
	//Currently the only example of order mattering is adding something to file, which only 
	//	matters if there are two files and you need to add to one, but we won't support that 
	//	for now anyway

	//TODO: Should adding always create a new object? There is no += in Lua so probably.
	//So create a clone and add the new values into it, and then push the clone as userdata


	TypeTag arg1_type = arg1->Type()->Tag();
	TypeTag arg2_type = arg2->Type()->Tag();

	//Whether or not Arg1 is our base object for adding to
	bool usingArg1First = false;

	if (arg1_userdata)
	{
		usingArg1First = true;
	}
	else if (unlikely(!arg2_userdata))
	{
		reporter->FatalError("Illegal: internal error, __add called on non-userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	TypeTag base_type = usingArg1First ? arg1_type : arg2_type;
	TypeTag added_type = usingArg1First ? arg2_type : arg1_type;

	Val *base_arg = usingArg1First ? arg1 : arg2;
	Val *added_arg = usingArg1First ? arg2 : arg1;

	Val *result;
	Val *tempval;

	PatternVal *string_pat;
	RE_Matcher *matcher;
	TransportProto ptype;

	int temp_size;
	unsigned int it;
	int start;
	int ret = 0;
	std::string s1, s2;

	bool ref = true;

	switch (base_type)
	{		
		case TYPE_VECTOR:
			//vector + vector, vector + const (of appropriate type!!!) 
			//combine elements into new vector

			//Note: assuming this is not a deep copy
			result = base_arg->Clone();
			//result->LuaRefReset(1);
			
			if (added_type == TYPE_VECTOR)
			{
				//Then do vector combining
				temp_size = ((VectorVal *)base_arg)->Size() + ((VectorVal *)added_arg)->Size();
				start = ((VectorVal *)base_arg)->Size();
				((VectorVal *)result)->Resize(temp_size);

				it = start;
				while (it < ((VectorVal *)added_arg)->Size())
				{
					if (unlikely(!((VectorVal *)result)->Assign(it, \
						((VectorVal *)added_arg)->Lookup(it-start) )))
					{
						reporter->Error("Unable to merge vectors in __add: probably due to \
							type mismatch");
						delete result; //Unref(result); //should delete it
						Unref(arg1);
						Unref(arg2);
						lua_mgr->SetFaultyScript(L);
						return LUA_FAILURE;
					}
					it++;
				}
			}
			else
			{
				temp_size = ((VectorVal *)base_arg)->Size();
				((VectorVal *)result)->Resize(temp_size + 1);

				//Append valid type to vector (will fail if there's a type mismatch)
				if (unlikely(!((VectorVal *)result)->Assign(temp_size, added_arg) ))
				{
					reporter->Error("Unable to add to vector in __add: probably due to \
						type mismatch");
					delete result; //Unref(result); //should delete it
					Unref(arg1);
					Unref(arg2);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}

			break;

		case TYPE_TABLE:
			
			if (((TableVal *)base_arg)->Type()->IsSet())
			{
				//set: set + set, combine sets; set + table, not supported
				// set + const (of correct type, if sets have types?): put const in set if 
				//	possible

				//Note: assuming this is not a deep copy
				result = base_arg->Clone();
				//result->LuaRefReset(1);

				if ((added_arg)->Type()->IsSet())
				{
					//check types, try merging sets
					if (unlikely(!((TableVal *)added_arg)->AddTo(result, 0)))
					{
						reporter->Error("Unable to add to set in __add: probably due to \
							type mismatch");
						delete result; //Unref(result); //should delete it
						Unref(arg1);
						Unref(arg2);
						lua_mgr->SetFaultyScript(L);
						return LUA_FAILURE;
					}
				}
				else if (added_type == TYPE_TABLE)
				{
					reporter->Error("Unable to add table to set: type mismatch!");
					delete result; //Unref(result); //should delete it
					Unref(arg1);
					Unref(arg2);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
				else
				{
					tempval = (Val *) ((TableVal *)result)->ConvertToList();
					((ListVal *)tempval)->Append(added_arg);
					result = (Val *)(((ListVal *)tempval)->ConvertToSet());

					Unref(tempval);
				}

			}
			else
			{
				//table: table + table, add elements into one table, if duplicates, use value 
				//	from first arg
				//table + set, not supported
				//table + LUA TABLE.... not supported, why don't you just use the SETTER

				//Note: assuming this is not a deep copy
				//TODO: This might be a deep copy. In any case, as assume it deep copies for 
				//	some uses and assume otherwise for others, which could be a big problem
				result = base_arg->Clone();
				//result->LuaRefReset(1);

				if (added_type != TYPE_TABLE)
				{
					reporter->Error("Unable to add base element to table in __add: probably due to type mismatch");
					delete result; //Unref(result); //should delete it
					Unref(arg1);
					Unref(arg2);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}

				if (unlikely(!((TableVal *)added_arg)->AddTo(result, 0)))
				{
					reporter->Error("Unable to add to set in __add: probably due to type mismatch");
					delete result; //Unref(result); //should delete it
					Unref(arg1);
					Unref(arg2);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}

			}
			break;

		case TYPE_PORT:
			//add const to port number
			if ((added_type == TYPE_INT) || (added_type == TYPE_COUNT))
			{
				//Note: trusting that PullGenericLuaVal provides type_double if there was floating point precision
				result = (Val *)(new PortVal(added_arg->CoerceToInt() + \
					((PortVal *)base_arg)->Port(), ((PortVal *)base_arg)->PortType()) );
				if (unlikely(!result))
				{
					reporter->Error("Unable to add to PortVal");
					delete result; // ANE
					Unref(arg1);
					Unref(arg2);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}
			else if (added_type == TYPE_PORT)
			{
				if (((PortVal *)base_arg)->PortType() == TRANSPORT_UNKNOWN)
				{
					ptype = ((PortVal *)added_arg)->PortType();
				}
				else if (((PortVal *)added_arg)->PortType() == TRANSPORT_UNKNOWN)
				{
					ptype = ((PortVal *)base_arg)->PortType();
				}
				else
				{
					if (unlikely(!(((PortVal *)added_arg)->PortType() == \
						((PortVal *)base_arg)->PortType())))
					{
						reporter->Error("Unable to add PortVals -- incompatible port types");
						Unref(arg1);
						Unref(arg2);
						lua_mgr->SetFaultyScript(L);
						return LUA_FAILURE;
					}
					ptype = ((PortVal *)base_arg)->PortType();
				}
				
				result = (Val *)(new PortVal(((PortVal *)base_arg)->Port() + \
					((PortVal *)added_arg)->Port(), ptype) );
				if (unlikely(!result))
				{
					reporter->Error("Unable to add to PortVal");
					delete result; // ANE
					Unref(arg1);
					Unref(arg2);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}
			else
			{
				reporter->Error("Unable to add unsupported type to PortVal");
				Unref(arg1);
				Unref(arg2);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			break;

		case TYPE_INTERVAL:
			//add const, interval
			if ((added_type == TYPE_INT) || (added_type == TYPE_COUNT) || \
				(added_type == TYPE_DOUBLE))
			{
				//Note: trusting that PullGenericLuaVal provides type_double if there was 
				//	floating point precision
				result = (Val *)(new IntervalVal( added_arg->CoerceToDouble(), 1) );
				if (unlikely(!result))
				{
					reporter->Error("Unable to add to IntervalVal");
					Unref(arg1);
					Unref(arg2);
					delete result; // ANE
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}
			else if (added_type == TYPE_INTERVAL)
			{
				result = (Val *)(new IntervalVal( added_arg->CoerceToDouble(), 1) );
				if (unlikely(!result))
				{
					reporter->Error("Unable to add IntervalVals");
					Unref(arg1);
					Unref(arg2);
					delete result; // ANE
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}
			else
			{
				reporter->Error("Unable to add unsupported type to IntervalVal");
				Unref(arg1);
				Unref(arg2);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

			break;


		case TYPE_PATTERN:
			//calls add_to
			//same with concat ...
			result = base_arg->Clone();
			//result->LuaRefReset(1);

			if (added_type == TYPE_PATTERN)
			{
				ret = ((PatternVal *) result)->AddTo( ((PatternVal *)added_arg), 0);
			} 
			else if (added_type == TYPE_STRING)
			{
				matcher = new RE_Matcher(added_arg->CoerceToCString()); 
				string_pat = new PatternVal(matcher);
				ret = string_pat->AddTo((PatternVal *)result, 0);
				delete matcher;
				delete string_pat;
			}
			else
			{
				reporter->Error("Fail in __add -- expecting PatternVal or compatible StringVal");
				ret = 0;
			}

			if (unlikely(!ret))
			{
				reporter->Error("Fail in __add -- Unable to add patterns");
				Unref(arg1);
				Unref(arg2);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

			break;

		case TYPE_VOID:
		case TYPE_ERROR:
		case TYPE_FILE: 
		case TYPE_UNION: 
		case TYPE_TIMER:
		case TYPE_ANY:
		case TYPE_FUNC:
		case TYPE_OPAQUE:
		case TYPE_RECORD:
			reporter->Error("Illegal: unsupported userdata type for addition or concatenation.");
			Unref(arg1);
			Unref(arg2);
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;

		default:
			reporter->Error("Illegal: unsupported userdata type for addition.");
			Unref(arg1);
			Unref(arg2);
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;
	}


	Unref(arg1);
	Unref(arg2);

	if (unlikely(!arg1_userdata && !arg2_userdata))
	{
		reporter->FatalError("Internal error, this should never happen (both args allocated \
			in __add");
	}

	if (unlikely(lua_mgr->PushLuaVal(L, result, ref) != LUA_SUCCESS))
	{
		reporter->Error("Unable to push added Val to Lua stack");
		lua_mgr->SetFaultyScript(L);
		Unref(result); 
		return LUA_FAILURE;
	}

	return 1;
}



//Adds the second value to a Lua userdata, if the underlying Vals support addition
int LuajitManager::function_AddElementToLuaVal(lua_State *L)
{
	//All of these checks are an attempt to prevent any Lua script from breaking Bro
	if (unlikely(lua_gettop(L) != 2))
	{
		reporter->Error("Lua called function_AddToLuaVal with %d arguments; I was only \
			prepared for 2!", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool arg1_userdata = false;
	Val *base_arg = lua_mgr->PullLuaValFromGenericArg(L, 1, &arg1_userdata);
	if (unlikely(!base_arg))
	{
		reporter->Error("Fail in function_AddToLuaVal -- argument 1 cannot be resolved to \
			a userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool arg2_userdata = false;
	Val *added_arg = lua_mgr->PullLuaValFromGenericArg(L, 2, &arg2_userdata, \
		(base_arg->Type()->YieldType() ? base_arg->Type()->YieldType()->Tag() : TYPE_VOID));
	if (unlikely(!added_arg))
	{
		reporter->Error("Fail in function_AddToLuaVal -- argument 2 cannot be resolved to \
			a userdata");
		Unref(base_arg);
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	TypeTag base_type = base_arg->Type()->Tag();
	TypeTag added_type = added_arg->Type()->Tag();

	//Whether or not Arg1 is our base object for adding to, which it always must be
	if (unlikely(!arg1_userdata))
	{
		reporter->Error("Internal error in AddToVal -- called on non-userdata");
		Unref(base_arg);
		Unref(added_arg);
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	Val *tempval;
	ListVal *lv;

	int temp_size;
	unsigned int it;
	int start;
	int ret = 0;
	std::string s1, s2;

	switch (base_type)
	{		
		case TYPE_VECTOR:
			//vector + vector, vector + const (of appropriate type!!!) 
			//combine elements into new vector

			if (added_type == TYPE_VECTOR)
			{
				//Then do vector combining
				temp_size = ((VectorVal *)base_arg)->Size() + ((VectorVal *)added_arg)->Size();
				start = ((VectorVal *)base_arg)->Size();
				((VectorVal *)base_arg)->Resize(temp_size);

				it = start;
				while (it < ((VectorVal *)added_arg)->Size())
				{
					if (unlikely(!((VectorVal *)base_arg)->Assign(it, \
						((VectorVal *)added_arg)->Lookup(it-start) )))
					{
						//Probably failed due to type mismatch
						reporter->Error("Unable to merge vectors in addTo: probably due \
							to type mismatch");
						Unref(base_arg);
						Unref(added_arg);
						lua_mgr->SetFaultyScript(L);
						return LUA_FAILURE;
					}
					it++;
				}
			}
			else
			{
				temp_size = ((VectorVal *)base_arg)->Size();
				((VectorVal *)base_arg)->Resize(temp_size + 1);

				//Append valid type to vector (will fail if there's a type mismatch)
				if (unlikely(!((VectorVal *)base_arg)->Assign(temp_size, added_arg) ))
				{
					reporter->Error("Unable to add to vector in addTo: probably due \
						to type mismatch");
					Unref(base_arg);
					Unref(added_arg);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}

			break;

		case TYPE_TABLE:
			
			if (((TableVal *)base_arg)->Type()->IsSet())
			{
				//set: set + set, combine sets; set + table, not supported
				//set + const (of correct type, if sets have types?): put const in set 
				//	if possible

				if ((added_arg)->Type()->IsSet())
				{
					//check types, try merging sets
					if (unlikely(!((TableVal *)added_arg)->AddTo(base_arg, 0)))
					{
						reporter->Error("Unable to add to set in addTo: probably due to \
							type mismatch");
						Unref(base_arg);
						Unref(added_arg);
						lua_mgr->SetFaultyScript(L);
						return LUA_FAILURE;
					}
				}
				else if (added_type == TYPE_TABLE)
				{
					reporter->Error("Unable to add table to set: type mismatch!");
					Unref(base_arg);
					Unref(added_arg);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
				else
				{
					lv = new ListVal(added_arg->Type()->Tag());
					lv->Append(added_arg);

					Ref(added_arg);
					if (unlikely(!((TableVal *)base_arg)->Assign(lv, NULL)))
					{
						reporter->Error("Unable to add argument to set: probable type mismatch!");
						Unref(base_arg);
						Unref(added_arg);
						Unref(lv);
						lua_mgr->SetFaultyScript(L);
						return LUA_FAILURE;
					}
					Unref(lv);
				}
			}
			else
			{
				//table: table + table, add elements into one table, if duplicates, use value from first arg
				//table + set, not supported
				//table + LUA TABLE.... not supported, why don't you just use the SETTER

				if (added_type == TYPE_TABLE)
				{
					if (unlikely(!((TableVal *)added_arg)->AddTo(base_arg, 0)))
					{
						reporter->Error("Unable to add to table in addTo: probably due to \
							type mismatch");
						Unref(base_arg);
						Unref(added_arg);
						lua_mgr->SetFaultyScript(L);
						return LUA_FAILURE;
					}
				}
				else
				{
					reporter->Error("Unable to add to table in addTo: probably due to \
						type mismatch");
					Unref(base_arg);
					Unref(added_arg);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}

			}
			
			break;

		case TYPE_RECORD:
#ifdef LUA_DEBUG
			reporter->Info("Attempting to interpret addition to record instance as \
				extension of record type");
#endif
			Unref(base_arg);
			Unref(added_arg);
			return function_RedefRecord(L);

		case TYPE_LIST:
#ifdef LUA_DEBUG
			reporter->Info("Attempting to append to a ListVal");
#endif
			((ListVal *)base_arg)->Append(added_arg);
			break;

		default:
			char s[100];
			TypeTagToString(base_type, s);
			reporter->Error("Illegal: unsupported userdata type for addition in addTo: %s", s);
			Unref(base_arg);
			Unref(added_arg);
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;
	}

	Unref(base_arg);
	Unref(added_arg);

	if (unlikely(!arg1_userdata && !arg2_userdata))
	{
		reporter->FatalError("Internal error, both args allocated in addTo");
	}
	return 0;
}


//Removes one value from a Lua userdata and modifies the base object, if the types support 
//	subtraction 
//	Supported types include: Set, Table, 
int LuajitManager::function_RemoveFromLuaVal(lua_State *L)
{
	if (unlikely(lua_gettop(L) != 2))
	{
		reporter->Error("Lua called function_RemoveFromLuaVal with %d arguments; \
			expected 2!", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool arg1_userdata = false;
	Val *base_arg = lua_mgr->PullLuaValFromGenericArg(L, 1, &arg1_userdata);
	if (unlikely(!base_arg))
	{
		reporter->Error("Fail in function_RemoveFromLuaVal -- argument 1 cannot be \
			resolved to a userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool arg2_userdata = false;
	Val *removed_arg = lua_mgr->PullLuaValFromGenericArg(L, 2, &arg2_userdata, 
		(base_arg->Type()->YieldType() ? base_arg->Type()->YieldType()->Tag() : TYPE_VOID));
	if (unlikely(!removed_arg))
	{
		reporter->Error("Fail in function_RemoveFromLuaVal -- argument 2 cannot be \
			resolved to a userdata");
		Unref(removed_arg);
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	TypeTag base_type = base_arg->Type()->Tag();
	TypeTag removed_type = removed_arg->Type()->Tag();

	//Whether or not Arg1 is our base object for removing from, which it always must be
	if (unlikely(!arg1_userdata))
	{
		reporter->FatalError("Internal error in function_RemoveFromLuaVal -- called on \
			non-userdata");
		Unref(base_arg);
		Unref(removed_arg);
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	Val *tempval;

	PatternVal *string_pat;
	RE_Matcher *matcher;

	int temp_size;
	unsigned int it;
	int start;
	int ret = 0;
	std::string s1, s2;

	switch (base_type)
	{
		//Note: Currently only supports tables and sets.
		case TYPE_TABLE:
			
			//Note:vbetter to just do tableval[index] = null
			//remove value from set, if present
			tempval = ((TableVal *)base_arg)->Delete(removed_arg); 
			if (!tempval)
			{
#ifdef LUA_DEBUG
				reporter->Info("Index not present in remove");
#endif
				lua_pushboolean(L, false);
			}
			//Another TableVal quirk: delete returns the table itself (Ref'd) if it fails
			else if (tempval == base_arg)
			{
#ifdef LUA_DEBUG
				reporter->Info("Index not present and valid in remove");
#endif
				Unref(base_arg);
				lua_pushboolean(L, false);
			}
			else
			{
				lua_pushboolean(L, true);
			}
			break;

		//Note: for now, vectors and enums are not supported
		case TYPE_VECTOR:
		case TYPE_ENUM:

		default:
			reporter->Error("Illegal: unsupported userdata type for addition in removeFrom.");
			Unref(base_arg);
			Unref(removed_arg);
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;
	}

	Unref(base_arg);
	Unref(removed_arg);

	if (unlikely(!arg1_userdata && !arg2_userdata))
	{
		reporter->FatalError("Internal error, this should never happen (both args allocated \
			in removeFrom");
	}

	return 1;
}


//Concatenates two Lua userdata together, if the underlying Vals support concatenation. If
//	not, returns concatenated __tostring() representation
int LuajitManager::function_ConcatLuaVals(lua_State *L)
{
	//All of these checks are an attempt to prevent any Lua script from breaking Bro
	if (unlikely(lua_gettop(L) != 2))
	{
		reporter->Error("Lua called function_AddLuaVal with %d arguments; I was only \
			prepared for 2!", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool arg1_userdata = false;
	Val *arg1 = lua_mgr->PullLuaValFromGenericArg(L, 1, &arg1_userdata);
	if (unlikely(!arg1))
	{
		reporter->Error("Fail in function_AddLuaVal -- argument 1 cannot be resolved \
			to a userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool arg2_userdata = false;
	Val *arg2 = lua_mgr->PullLuaValFromGenericArg(L, 2, &arg2_userdata, \
		(arg1->Type()->YieldType() ? arg1->Type()->YieldType()->Tag() : TYPE_VOID));
	if (unlikely(!arg2))
	{
		reporter->Error("Fail in function_AddLuaVal -- argument 2 cannot be resolved \
			to a userdata");
		Unref(arg1);
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	//Same order considerations as __add

	TypeTag arg1_type = arg1->Type()->Tag();
	TypeTag arg2_type = arg2->Type()->Tag();

	//Whether or not Arg1 is our base object for adding to
	bool usingArg1First = false;

	if (arg1_userdata)
	{
		usingArg1First = true;
	}
	else if (unlikely(!arg2_userdata))
	{
		reporter->FatalError("Illegal: internal error, __concat called on non-userdata");
		Unref(arg1);
		Unref(arg2);
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	TypeTag base_type = usingArg1First ? arg1_type : arg2_type;
	TypeTag added_type = usingArg1First ? arg2_type : arg1_type;

	Val *base_arg = usingArg1First ? arg1 : arg2;
	Val *added_arg = usingArg1First ? arg2 : arg1;

	Val *result;
	Val *tempval;

	PatternVal *string_pat;
	RE_Matcher *matcher;

	int temp_size;
	unsigned int it;
	int start;
	int ret = 0;
	std::string s1, s2;

	switch (base_type)
	{	
		case TYPE_VECTOR:
			//vector + vector, vector + const (of appropriate type!!!) 
			//combine elements into new vector

			//Note: assuming this is not a deep copy
			result = base_arg->Clone();
			//result->LuaRefReset(1);
			
			if (added_type == TYPE_VECTOR)
			{
				//Then do vector combining
				temp_size = ((VectorVal *)base_arg)->Size() + ((VectorVal *)added_arg)->Size();
				start = ((VectorVal *)base_arg)->Size();
				((VectorVal *)result)->Resize(temp_size);

				it = start;
				while (it < ((VectorVal *)added_arg)->Size())
				{
					if (unlikely(!((VectorVal *)result)->Assign(it, \
						((VectorVal *)added_arg)->Lookup(it-start) )))
					{
						reporter->Error("Unable to merge vectors in __concat: probably \
							due to type mismatch");
						delete result; //Unref(result); //should delete it
						Unref(arg1);
						Unref(arg2);
						lua_mgr->SetFaultyScript(L);
						return LUA_FAILURE;
					}
					it++;
				}
			}
			else
			{
				temp_size = ((VectorVal *)base_arg)->Size();
				((VectorVal *)result)->Resize(temp_size + 1);

				//Append valid type to vector (will fail if there's a type mismatch)
				if (unlikely(!((VectorVal *)result)->Assign(temp_size, added_arg) ))
				{
					reporter->Error("Unable to add to vector in __concat: probably \
						due to type mismatch");
					delete result; //Unref(result); //should delete it
					Unref(arg1);
					Unref(arg2);
					lua_mgr->SetFaultyScript(L);
					return LUA_FAILURE;
				}
			}
			break;

		case TYPE_RECORD:
		case TYPE_ENUM:
		case TYPE_VOID:
		case TYPE_ERROR:
		case TYPE_FILE: 
		case TYPE_UNION: 
		case TYPE_TIMER:
		case TYPE_ANY:
		case TYPE_FUNC:
		case TYPE_OPAQUE:
			reporter->Error("Illegal: unsupported userdata type for addition or concatenation.");
			Unref(arg1);
			Unref(arg2);
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;

		default:
			s1 = ValAsString(arg1);
			s2 = ValAsString(arg2);
			if ((s1.empty()) || (s2.empty()))
			{
				reporter->Error("Unable to concatenate types as strings");
				Unref(arg1);
				Unref(arg2);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			result = (Val *)(new StringVal(s1 + s2));
	}

	Unref(arg1);
	Unref(arg2);

	if (unlikely(!arg1_userdata && !arg2_userdata))
	{
		reporter->FatalError("Internal error, this should never happen (both args \
			allocated in __add");
	}

	if (unlikely(lua_mgr->PushLuaVal(L, result) != LUA_SUCCESS))
	{
		reporter->Error("Unable to push added Val to Lua stack");
		lua_mgr->SetFaultyScript(L);
		Unref(result); 
		return LUA_FAILURE;
	}

	return 1;
}


//Compares two Lua Vals for equality
int LuajitManager::function_CompareEqLuaVal(lua_State *L)
{
	//All of these checks are an attempt to prevent any Lua script from breaking Bro
	if (unlikely(lua_gettop(L) != 2))
	{
		reporter->Error("Lua called function_AddLuaVal with %d arguments; I was only \
			prepared for 2!", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool arg1_userdata = false;
	Val *arg1 = lua_mgr->PullLuaValFromGenericArg(L, 1, &arg1_userdata);
	if (unlikely(!arg1))
	{
		reporter->Error("Fail in function_AddLuaVal -- argument 1 cannot be resolved \
			to a userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool arg2_userdata = false;
	Val *arg2 = lua_mgr->PullLuaValFromGenericArg(L, 2, &arg2_userdata);
	if (unlikely(!arg2))
	{
		reporter->Error("Fail in function_AddLuaVal -- argument 2 cannot be resolved \
			to a userdata");
		Unref(arg1);
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	TypeTag arg1_type = arg1->Type()->Tag();
	TypeTag arg2_type = arg2->Type()->Tag();

	//Whether or not Arg1 is our base object for adding to
	bool usingArg1First = false;

	if (arg1_userdata)
	{
		usingArg1First = true;
	}
	else if (unlikely(!arg2_userdata))
	{
		reporter->Error("Illegal: internal error, __add called on non-userdata");
		Unref(arg1);
		Unref(arg2);
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	TypeTag base_type = usingArg1First ? arg1_type : arg2_type;
	TypeTag added_type = usingArg1First ? arg2_type : arg1_type;

	Val *base_arg = usingArg1First ? arg1 : arg2;
	Val *added_arg = usingArg1First ? arg2 : arg1;

	Val *result;
	Val *tempval;

	int temp_size;
	int it;
	int start;

	BroFile *f = new BroFile(stdout);
	desc_style style = f->IsRawOutput() ? RAW_STYLE : STANDARD_STYLE;

	ODesc des1(DESC_READABLE);
	des1.SetFlush(0);
	des1.SetStyle(style);

	ODesc des2(DESC_READABLE);
	des2.SetFlush(0);
	des2.SetStyle(style);

	bool eq = false;

	if (unlikely(base_arg == added_arg))
	{
#ifdef LUA_DEBUG
		reporter->Info("Comparison with self");
#endif
		lua_pushboolean(L, true);
		return 1;
	}

	switch(base_type)
	{
		case TYPE_RECORD:
		case TYPE_VECTOR:
		case TYPE_TABLE:
			if (likely(base_type == added_type))
			{
				//describe, see if descriptions match
				base_arg->Describe(&des1);
				added_arg->Describe(&des2);
				if (strcmp(des1.Description(), des2.Description()) == 0)
				{
					eq = true;
				}
			}
			else
			{
				reporter->Error("Can't compare incompatible container types in __eq");
				Unref(arg1);
				Unref(arg2);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			break;
		

		case TYPE_ADDR:
			//check elements, or compare against ip address string
			if (added_type == TYPE_ADDR)
			{
				if ( strcmp( added_arg->AsAddr().AsString().c_str(), \
					base_arg->AsAddr().AsString().c_str()) == 0)
				{
					eq = true;
				}
			}
			else if (added_type == TYPE_STRING)
			{
				if ( strcmp( reinterpret_cast<const char*>(added_arg->AsString()->Bytes()), \
					base_arg->AsAddr().AsString().c_str()) == 0)
				{
					eq = true;
				}
			}
			else
			{
				reporter->Error("Can't compare incompatible container types in __eq");
				Unref(arg1);
				Unref(arg2);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			break;

		case TYPE_SUBNET:
			//check elements, or compare against prefix/mask string
			if (added_type == TYPE_ADDR)
			{
				if ( strcmp( added_arg->AsAddr().AsString().c_str(), \
					base_arg->AsAddr().AsString().c_str()) == 0)
				{
					eq = true;
				}
			}
			else if (added_type == TYPE_STRING)
			{
				if ( strcmp( reinterpret_cast<const char*>(added_arg->AsString()->Bytes()), \
					base_arg->AsAddr().AsString().c_str()) == 0)
				{
					eq = true;
				}
			}
			else
			{
				reporter->Error("Can't compare incompatible Addr comparison type in __eq");
				Unref(arg1);
				Unref(arg2);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			break;

		case TYPE_PORT:
			//check elements, or compare against number (port)
			if (added_type == TYPE_PORT)
			{
				if (( ((PortVal *)base_arg)->Port() == ((PortVal *)added_arg)->Port() ) && \
					( ((PortVal *)base_arg)->PortType() == ((PortVal *)added_arg)->PortType() ))
				{
					eq = true;
				}
			}
			else if ((added_type == TYPE_INT) || (added_type == TYPE_COUNT))
			{
				if ( ((PortVal *)base_arg)->Port() == added_arg->CoerceToInt() )
				{
					eq = true;
				}
			}
			else
			{
				reporter->Error("Can't compare incompatible Port comparison type in __eq");
				Unref(arg1);
				Unref(arg2);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			break;


		case TYPE_INTERVAL:
			//check elements, or compare against number (time in seconds)
			if ( added_arg->CoerceToDouble() == base_arg->CoerceToDouble() )
			{
				eq = true;
			}

		case TYPE_PATTERN:
			//check pattern, or compare against pattern string
			if (added_type == TYPE_PATTERN)
			{
				((PatternVal*)base_arg)->AsLuaPattern(&des1);
				((PatternVal*)added_arg)->AsLuaPattern(&des2);
				if (strcmp(des1.Description(), des2.Description()) == 0)
				{
					eq = true;
				}
			}
			else if (added_type == TYPE_STRING)
			{
				eq = (bool) ((PatternVal *)base_arg)->MatchExactly(added_arg->CoerceToCString());
			}
			else
			{
				reporter->Error("Can't compare incompatible Pattern comparison type in __eq");
				Unref(arg1);
				Unref(arg2);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

		case TYPE_ENUM: 
			//check int, or compare against ENUM string name
			if (added_type == TYPE_ENUM)
			{
				if ( ((EnumVal *)base_arg)->ToNumber() == ((EnumVal *)added_arg)->ToNumber() )
				{
					eq = true;
				}
			}
			else if ((added_type == TYPE_INT) || (added_type == TYPE_COUNT))
			{
				if ( ((EnumVal *)base_arg)->ToNumber() == added_arg->CoerceToInt() )
				{
					eq = true;
				}
			}
			else if (added_type == TYPE_STRING)
			{
				if ( strcmp(((EnumVal *)base_arg)->ToString(), \
					added_arg->CoerceToCString()) == 0 )
				{
					eq = true;
				}
			}
			else
			{
				reporter->Error("Can't compare incompatible Enum comparison type in __eq");
				Unref(arg1);
				Unref(arg2);
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

		//For now, file types are not supported userdata for any Lua BIF's
		case TYPE_FILE:

		default:
			reporter->Error("Non-supported userdata type in function_CompareEqLuaVal");
			Unref(arg1);
			Unref(arg2);
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;
	}

	Unref(arg1);
	Unref(arg2);

	if (unlikely(!arg1_userdata && !arg2_userdata))
	{
		reporter->FatalError("Internal error, both args allocated in __eq");
	}

	lua_pushboolean(L, eq);
	return 1;
}


int LuajitManager::function_GetBroType(lua_State *L)
{
	//TODO: flatten type for complex types
	Val *v = GetValOfType(L, TYPE_VOID, 1, 1);

	const char *type;

	std::string typestring = v->Type()->GetName();
	type = typestring.c_str();

	//or return Tag type?
	/*
	if (v->Type()->IsSet())
	{
		lua_pushlstring(L, "set", sizeof("set"));
		return 1;
	}
	*/
	
	lua_pushlstring(L, type, strlen(type));
	return 1;
}


int LuajitManager::function_IsVector(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_VECTOR, 1, 1, true);
	
	lua_pushboolean(L, (v ? true : false) );
	return 1;
}


int LuajitManager::function_IsRecord(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_RECORD, 1, 1, true);
	
	lua_pushboolean(L, (v ? true : false) );
	return 1;
}


int LuajitManager::function_IsTable(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_TABLE, 1, 1, true);

	lua_pushboolean(L, (v ? (v->Type()->IsTable()) : false) );
	return 1;
}


int LuajitManager::function_IsSet(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_TABLE, 1, 1, true);

	lua_pushboolean(L, (v ? (v->Type()->IsSet()) : false) );
	return 1;
}


int LuajitManager::function_IsPort(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_PORT, 1, 1, true);
	
	lua_pushboolean(L, (v ? true : false) );
	return 1;
}


int LuajitManager::function_IsAddr(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_ADDR, 1, 1, true);
	
	lua_pushboolean(L, (v ? true : false) );
	return 1;
}


int LuajitManager::function_IsSubnet(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_SUBNET, 1, 1, true);

	lua_pushboolean(L, (v ? true : false) );
	return 1;
}


int LuajitManager::function_IsInterval(lua_State *L)
{
	if (unlikely(lua_gettop(L) != 1))
	{
		reporter->Error("Lua called function_IsInterval with more than one argument: %d", \
			lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool userdata = false;
	Val *v = lua_mgr->PullLuaValFromGenericArg(L, 1, &userdata, TYPE_INTERVAL);

	if (unlikely(!v))
	{
		reporter->Error("Unable to pull Val in function_IsInterval");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	lua_pushboolean(L, ( (v->Type()->Tag()==TYPE_INTERVAL) ? true : false) );

	Unref(v);
	return 1;
}


int LuajitManager::function_Size(lua_State *L)
{
	Val *v;
	double size;

	if (unlikely(lua_gettop(L) != 1))
	{
		reporter->Error("Lua called function_Size -- expected 1 argument (the userdata), \
			received: %d", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	v = CheckLuaUserdata(L, 1);
	if (unlikely(!v))
	{
		reporter->Error("Fail in function_Size -- not a valid userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (unlikely(lua_mgr->PushLuaVal(L, v->SizeVal()) == LUA_FAILURE)) {
		reporter->Error("Fail in function_Size -- unable to push Lua Val");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}
	return 1;
}


int LuajitManager::function_ToNumber(lua_State *L)
{
	//This is for port, time, interval and enum values
	Val *v;
	double number;

	if (unlikely(lua_gettop(L) != 1))
	{
		reporter->Error("Lua called function_ToNumber with incorrect number of \
			arguments: %d", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	v = CheckLuaUserdata(L, 1);
	if (unlikely(!v))
	{
		reporter->Error("Fail in function_ToNumber -- not a valid userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	TypeTag self_type = v->Type()->Tag();

	switch (self_type)
	{
		case TYPE_COUNT:
		case TYPE_COUNTER:
		case TYPE_DOUBLE:
		case TYPE_INT:
			number = (double) v->AsNumber();
			break;
		case TYPE_PORT:
			number = (double)((PortVal *)v)->Port();
			break;
		case TYPE_ENUM:
			number = ((EnumVal *)v)->ToNumber();
			break;
		case TYPE_INTERVAL:
			number = v->CoerceToDouble();
			break;
		case TYPE_TIME:
			number = v->CoerceToDouble();
			break;
		default:
			reporter->Error("Fail in function_ToNumber -- not a valid numeric type");
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;
	}

	lua_pushnumber(L, number);
	return 1;
}


int LuajitManager::function_IsTCP(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_PORT, 1, 1);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_IsTCP");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	lua_pushboolean(L, (bool) ((PortVal *)v)->IsTCP() );
	return 1;
}


int LuajitManager::function_IsUDP(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_PORT, 1, 1);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_IsUDP");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	lua_pushboolean(L, (bool) ((PortVal *)v)->IsUDP() );
	return 1;
}


int LuajitManager::function_IsICMP(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_PORT, 1, 1);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_IsICMP");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	lua_pushboolean(L, (bool) ((PortVal *)v)->IsICMP() );
	return 1;
}


int LuajitManager::function_PortNumber(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_PORT, 1, 1);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_PortNumber");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	lua_pushnumber(L, ((PortVal *)v)->Port() );
	return 1;
}


int LuajitManager::function_IPVersion(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_ADDR, 1, 1);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_IPVersion");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (v->AsAddr().GetFamily() == IPv4)
	{
		lua_pushnumber(L, 4);
	} else {
		lua_pushnumber(L, 6);
	}
	return 1;
}


int LuajitManager::function_IPByteArray(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_ADDR, 1, 1);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_IPByteArray");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	//TODO: create byte array somehow -- options: new userdata for raw lua/bro 
	//	bytearray operations -- or use a table

	//IPAddr addr = v->AsAddr();
	//TODO: could also use IPAddr's built in types like AsHexString, AsString, etc.

	return 0;
}


// Push key vals for a table as a Bro vector, so that tables can be iterable. 
int LuajitManager::function_GetTableIndicesVector(lua_State *L)
{
	if (unlikely(lua_gettop(L) != 1))
	{
		reporter->Error("Lua called function_GetTableIndicesVector with incorrect number of \
			arguments: %d", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool userdata = false;
	Val *base = lua_mgr->PullLuaValFromGenericArg(L, 1, &userdata);
	if (unlikely(!base || !userdata))
	{
		reporter->Error("Fail in function_GetTableIndicesVector");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (unlikely((base->Type()->Tag() != TYPE_TABLE) || base->Type()->IsSet()))
	{
		reporter->Error("Fail in function_GetTableIndicesVector: Invalid type -- not a table");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	ListVal *list = ((TableVal*)base)->ConvertToList();

	BroType *containerType = (base->Type()->AsTableType()->Indices()->IsPure() ? \
		base->Type()->AsSetType()->Indices()->PureType() : \
		base->Type()->AsSetType()->Indices());

	VectorVal *newVector = new VectorVal(new VectorType(containerType));

	loop_over_list(*(list->Vals()), iter_base)
	{
		Val *element = ((ListVal*)(list->Index(iter_base)))->Index(0);
		bool success = newVector->Assign(iter_base, element);
		if (unlikely(!success))
		{
			reporter->Error("Fail in function_GetTableIndicesVector: assigning to vector");
			lua_mgr->SetFaultyScript(L);
			Unref(newVector);
			return LUA_FAILURE;
		}
	}

	if (unlikely(lua_mgr->PushLuaVal(L, ((Val *)newVector)) != LUA_SUCCESS))
	{
		reporter->Error("Fail in function_GetTableIndicesVector: pushing result");
		lua_mgr->SetFaultyScript(L);
		Unref(newVector);
		return LUA_FAILURE;
	}
	Unref(newVector);
	return 1;
}


// Push elements of a set as a Bro vector, so that sets can be iterable
int LuajitManager::function_GetSetElementsVector(lua_State *L)
{
	if (unlikely(lua_gettop(L) != 1))
	{
		reporter->Error("Lua called function_GetSetElementsVector with incorrect number of \
			arguments: %d", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool userdata = false;
	Val *base = lua_mgr->PullLuaValFromGenericArg(L, 1, &userdata);
	if (unlikely(!base || !userdata))
	{
		reporter->Error("Fail in function_GetSetElementsVector");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (unlikely(!base->Type()->IsSet()))
	{
		reporter->Error("Fail in function_GetSetElementsVector: Invalid type -- not a set");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	ListVal *list = ((TableVal*)base)->ConvertToList();

	BroType *containerType = (base->Type()->AsSetType()->Indices()->IsPure() ? \
		base->Type()->AsSetType()->Indices()->PureType() : \
		base->Type()->AsSetType()->Indices());

	VectorVal *newVector = new VectorVal(new VectorType(containerType));

	loop_over_list(*(list->Vals()), iter_base)
	{
		Val *element = ((ListVal*)(list->Index(iter_base)))->Index(0);
		bool success = newVector->Assign(iter_base, element);
		if (unlikely(!success))
		{
			reporter->Error("Fail in function_GetSetElementsVector: assigning to vector");
			lua_mgr->SetFaultyScript(L);
			Unref(newVector);
			return LUA_FAILURE;
		}
	}

	if (unlikely(lua_mgr->PushLuaVal(L, ((Val *)newVector)) != LUA_SUCCESS))
	{
		reporter->Error("Fail in function_GetSetElementsVector: pushing result");
		lua_mgr->SetFaultyScript(L);
		Unref(newVector);
		return LUA_FAILURE;
	}
	Unref(newVector);
	return 1;
}


//Test membership (applies broadly to Subnets (and Addr's), Sets, Tables, 
// Vectors (and their respective elements, NOT recursively), Patterns, 
// Strings (and Strings) )
int LuajitManager::function_ValContains(lua_State *L)
{
	bool userdata = false;
	bool contains = true;
	Val *base;
	Val *arg;

	if (unlikely(lua_gettop(L) != 2))
	{
		reporter->Error("Lua called function_ValContains with incorrect number of \
			arguments: %d", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	base = lua_mgr->PullLuaValFromGenericArg(L, 1, &userdata);
	if (unlikely(!base || !userdata))
	{
		reporter->Error("Fail in function_ValContains");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	arg = lua_mgr->PullLuaValFromGenericArg(L, 2, &userdata);
	if (unlikely(!arg))
	{
		reporter->Error("Fail in function_ValContains -- arg is not a valid userdata");
		Unref(base);
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}


	/*
	// In progress- derived from InExpr::InExpr (this does type checks on the args)
	*/

	if ( base->Type()->Tag() == TYPE_PATTERN )
	{
		if ( arg->Type()->Tag() != TYPE_STRING )
		{
			Unref(base);
			Unref(arg);
			reporter->Error("Fail in function_ValContains: pattern requires string index");
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;
		}
	}

	else if ( base->Type()->Tag() == TYPE_RECORD )
	{
		if ( arg->Type()->Tag() != TYPE_TABLE )
		{
			Unref(base);
			Unref(arg);
			reporter->Error("Fail in function_ValContains: for arg2, table/set required");
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;
		}

		// This checks whether a TableVal is the equivalent representation of a RecordVal
		// Don't see why we would ever use this
		const BroType* t1 = base->Type();
		const TypeList* it =
			arg->Type()->AsTableType()->Indices();

		if ( ! same_type(t1, it) )
		{
			Unref(base);
			Unref(arg);
			reporter->Error("Fail in function_ValContains: indexing mismatch");
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;
		}
	}
	// Check for:
		//		<addr> in <subnet>
		//		<addr> in set[subnet]
		//		<addr> in table[subnet] of ...
	else if ( 
		((arg->Type()->Tag() == TYPE_ADDR ) && \
		((base->Type()->Tag() == TYPE_SUBNET ) || \
		( arg->Type()->Tag() == TYPE_TABLE && \
		  arg->Type()->AsTableType()->IsSubNetIndex() ))) )
	{
		//noop, it's fine. These are all supported by the native InExpr::Fold
	}
	else
	{
		// The below are not handled by eval/fold so we have a custom implementation
		// This enables index type matches
		// It also enables containers with the same index type to be compared
		// Giving up on recursive container comparisons though of base index type elements, 
		// that's overkill

		if (base->Type()->Tag() == TYPE_VECTOR)
		{
			//vector element in vector (basically a vector search)
			if (same_type(base->Type()->AsVectorType()->YieldType(), arg->Type()))
			{
				unsigned int iter;
				for (iter = 0; iter < base->AsVectorVal()->Size(); iter++) {
					Val *equal = EqExprFold(base->AsVectorVal()->Lookup(iter), arg);
					if (unlikely(!equal)) {
						Unref(base);
						Unref(arg);
						reporter->Error("Fail in function_ValContains: bad EqExprFold \
							(vector element in vector)");
						lua_mgr->SetFaultyScript(L);
						return LUA_FAILURE;
					}

					bool equality = equal->AsBool();
					if (equality) {
						contains = true;
						break;
					}
				}
			}
			//vector in vector
			else if ((arg->Type()->Tag() == TYPE_VECTOR) && \
				(same_type(base->Type()->AsVectorType()->YieldType(), \
					arg->Type()->AsVectorType()->YieldType())))
			{
				//double for loop to see if arg is completely contained in base
				unsigned int iter_arg;
				for (iter_arg = 0; iter_arg < base->AsVectorVal()->Size(); iter_arg++) {
					Val *arg_element = arg->AsVectorVal()->Lookup(iter_arg);
					unsigned int iter_base;
					bool found = false;
					for (iter_base = 0; iter_base < base->AsVectorVal()->Size(); iter_base++) {
						Val *equal = EqExprFold(base->AsVectorVal()->Lookup(iter_base), arg_element);
						if (unlikely(!equal)) {
							Unref(base);
							Unref(arg);
							reporter->Error("Fail in function_ValContains: bad EqExprFold \
								(vector in vector)");
							lua_mgr->SetFaultyScript(L);
							return LUA_FAILURE;
						}

						bool equality = equal->AsBool();
						if (equality) {
							found = true;
							break;
						}
					}
					if (!found) {
						contains = false;
						break;
					} else {
						contains = true;
					}
				}
			}
			//set in vector
			else if ((arg->Type()->IsSet()) && \
				(same_type(base->Type()->AsVectorType()->YieldType(), \
					arg->Type()->AsSetType()->Indices() ) ))
			{
				//same as above (vector in vector) except outer loop is iterating over 
				// the Set (as a ListVal)
				ListVal *list = ((TableVal*)arg)->ConvertToList();

				loop_over_list(*(list->Vals()), iter_arg) {
					Val *arg_element = ((ListVal*)(list->Index(iter_arg)))->Index(0);
					unsigned int iter_base;
					bool found = false;
					for (iter_base = 0; iter_base < base->AsVectorVal()->Size(); iter_base++) {
						Val *equal = EqExprFold(base->AsVectorVal()->Lookup(iter_base), arg_element);
						if (unlikely(!equal)) {
							Unref(base);
							Unref(arg);
							reporter->Error("Fail in function_ValContains: bad EqExprFold \
								(set in vector)");
							lua_mgr->SetFaultyScript(L);
							Unref(list); // ANE
							return LUA_FAILURE;
						}

						bool equality = equal->AsBool();
						if (equality) {
							found = true;
							break;
						}
					}
					if (!found) {
						contains = false;
						break;
					} else {
						contains = true;
					}
				}

				Unref(list); // ANE
			}
			else
			{
				Unref(base);
				Unref(arg);
				reporter->Error("Fail in function_ValContains: incompatible types (vector base)");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}

		}
		else if (base->Type()->IsSet())
		{
			//set in set
			if ((arg->Type()->IsSet()) && \
				(same_type(base->Type()->AsSetType()->Indices(), \
					arg->Type()->AsSetType()->Indices()) ))
			{
				//convert arg/base to lists, check that every element in arg is in base
				ListVal *list = ((TableVal*)arg)->ConvertToList();
				ListVal *baseList = ((TableVal*)base)->ConvertToList();

				//TODO: CHECK EVERYWHERE -- ConvertToList returns a list of listVals
				// for non listTypes, the desired Val is at Index 0. We'll always assume that
				// use case for simplicity

				loop_over_list(*(list->Vals()), iter_arg) {
					Val *arg_element = ((ListVal*)(list->Index(iter_arg)))->Index(0);
					bool found = false;

					loop_over_list(*(baseList->Vals()), iter_base) {
						Val *equal = EqExprFold(((ListVal*)baseList->Index(iter_base))->Index(0), arg_element);
						if (unlikely(!equal)) {
							Unref(base);
							Unref(arg);
							reporter->Error("Fail in function_ValContains: bad EqExprFold \
								(set in vector)");
							lua_mgr->SetFaultyScript(L);
							Unref(list); // ANE
							Unref(baseList);
							return LUA_FAILURE;
						}

						bool equality = equal->AsBool();
						if (equality) {
							found = true;
							break;
						}
					}
					if (!found) {
						contains = false;
						break;
					} else {
						contains = true;
					}
				}

				Unref(list);	 // ANE
				Unref(baseList);
			}
			//vector in set
			else if ((arg->Type()->Tag() == TYPE_VECTOR) && \
				(same_type( base->Type()->AsSetType()->Indices(), \
					arg->Type()->AsVectorType()->YieldType()) ))
			{
				//convert base to list, check that every element in arg vector is in base
				ListVal *baseList = ((TableVal*)base)->ConvertToList();

				unsigned int iter_arg;
				for (iter_arg = 0; iter_arg < arg->AsVectorVal()->Size(); iter_arg++) {
					Val *arg_element = arg->AsVectorVal()->Lookup(iter_arg);
					bool found = false;

					loop_over_list(*(baseList->Vals()), iter_base) {
						Val *equal = EqExprFold(((ListVal*)baseList->Index(iter_base))->Index(0), arg_element);
						if (unlikely(!equal)) {
							Unref(base);
							Unref(arg);
							reporter->Error("Fail in function_ValContains: bad EqExprFold \
								(set in vector)");
							lua_mgr->SetFaultyScript(L);
							Unref(baseList); // ANE
							return LUA_FAILURE;
						}

						bool equality = equal->AsBool();
						if (equality) {
							found = true;
							break;
						}
					}
					if (!found) {
						contains = false;
						break;
					} else {
						contains = true;
					}
				}

				Unref(baseList); // ANE
			}
			// non-container ELEMENT in set
			else if (same_type( base->Type()->AsSetType()->Indices() , arg->Type())) 
			{
				
				ListVal *baseList = ((TableVal*)base)->ConvertToList();
				contains = false;
				loop_over_list(*(baseList->Vals()), iter_base) {
					Val *base_element = ((ListVal*)(baseList->Index(iter_base)))->Index(0);
					
					Val *equal = EqExprFold(base_element, arg);

					if (unlikely(!equal)) {
						Unref(base);
						Unref(arg);
						reporter->Error("Fail in function_ValContains: bad EqExprFold \
							(set element in set)");
						lua_mgr->SetFaultyScript(L);
						Unref(baseList); // ANE
						Unref(equal);
						return LUA_FAILURE;
					}

					bool equality = equal->AsBool();
					if (equality) {
						contains = true;
						break;
					}
				}

				Unref(baseList); // ANE
			}
			else
			{
				Unref(base);
				Unref(arg);
				reporter->Error("Fail in function_ValContains: incompatible types (set base)");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
		}
		else if (base->Type()->Tag() == TYPE_TABLE)
		{
			//val (value) in table
			Val *returnVal = NULL;
			if (unlikely(!base->Type()->AsTableType()->YieldType())) {
				Unref(base);
				Unref(arg);
				reporter->Error("Fail in function_ValContains: no yield type for table");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
			if (same_type(arg->Type(), base->Type()->AsTableType()->YieldType()))
			{
				//see if there is an entry for the value, return true/false
				ListVal *list = ((TableVal*)base)->ConvertToList();

				contains = false;
				loop_over_list(*(list->Vals()), iter_base) {
					Val *base_element = ((ListVal*)(list->Index(iter_base)))->Index(0);
					
					Val *equal = EqExprFold(base->AsTableVal()->Lookup(base_element), arg);

					if (unlikely(!equal)) {
						Unref(base);
						Unref(arg);
						reporter->Error("Fail in function_ValContains: bad EqExprFold \
							(table value in table)");
						lua_mgr->SetFaultyScript(L);
						Unref(list); // ANE
						return LUA_FAILURE;
					}

					bool equality = equal->AsBool();
					if (equality) {
						contains = true;
						break;
					}
				}

				Unref(list); // ANE
			}
			else
			{
				Unref(base);
				Unref(arg);
				reporter->Error("Fail in function_ValContains: incompatible value type (table base)");
				lua_mgr->SetFaultyScript(L);
				return LUA_FAILURE;
			}
		}
		else 
		{
			reporter->Error("Fail in function_ValContains: not an index type");
			Unref(base);
			Unref(arg);
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;
		}

		Unref(base);
		Unref(arg);
		lua_pushboolean(L, contains);
		return 1;
	}

	// BinaryExpr::Eval

	Val* v1 = base;
	Val* v2 = arg;

	Val* result = NULL;

	//Removed the vector comparison, that's handled separately

	// Fold for scalars which are not handled in the above element comparisons
	result = InExprFold(v1, v2);

	if (unlikely(!result)) {
		reporter->Error("Invalid result from InExprFold");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	Unref(v1);
	Unref(v2);
	lua_pushboolean(L, result->AsBool());
	Unref(result);
	return 1;
}

//TODO: This would probably be more useful if it returned an AddrVal
int LuajitManager::function_SubnetMask(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_SUBNET, 1, 1);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_SubnetMaskPrefix");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	const char *subnetmask = ((SubNetVal*)v)->Mask().AsString().c_str();
	lua_pushlstring(L, subnetmask, strlen(subnetmask));
	return 1;
}


int LuajitManager::function_SubnetMaskWidth(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_SUBNET, 1, 1);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_SubnetMaskWidth");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	lua_pushnumber(L, ((SubNetVal*)v)->Width() );
	return 1;
}

//TODO: This would probably be more useful if it returned an AddrVal
int LuajitManager::function_SubnetPrefix(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_SUBNET, 1, 1);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_SubnetMaskPrefix");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	const char *prefix = ((SubNetVal*)v)->Prefix().AsString().c_str();
	lua_pushlstring(L, prefix, strlen(prefix));
	return 1;
}


int LuajitManager::function_AddPattern(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_PATTERN, 1, 2);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_AddPattern");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool userdata = false;
	//TODO: should be able to take a pattern from a table as well (will get PatternVal) 
	//	OR StringVal
	Val *pattern2 = lua_mgr->PullLuaValFromGenericArg(L, 2, &userdata);
	if (unlikely(!pattern2))
	{
		reporter->Error("Fail in function_AddPattern -- expected pattern is not a valid userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	TypeTag arg_type = pattern2->Type()->Tag();

	int ret = 0;
	if (arg_type == TYPE_PATTERN)
	{
		ret = ((PatternVal *) v)->AddTo(pattern2, 0);
	} 
	else if (arg_type == TYPE_STRING)
	{
		RE_Matcher matcher(pattern2->CoerceToCString()); 
		PatternVal string_pat = PatternVal(&matcher);
		ret = ((PatternVal *) v)->AddTo(&string_pat, 0);
	}
	else
	{
		reporter->Error("Fail in function_AddPattern -- expecting PatternVal or compatible StringVal");
		Unref(pattern2);
		lua_mgr->SetFaultyScript(L);
		ret = 0;
	}

	if (unlikely(!ret))
	{
		reporter->Error("Fail in function_AddPattern -- Unable to add patterns");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	Unref(pattern2);

	return 0;
}


int LuajitManager::function_SearchPattern(lua_State *L)
{
	int index = 0;

	Val *pattern = GetValOfType(L, TYPE_PATTERN, 1, 2);

	if (unlikely(!pattern))
	{
		reporter->Error("Fail in function_SearchPattern");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bool userdata = false;
	Val *string = lua_mgr->PullLuaValFromGenericArg(L, 2, &userdata);

	if (unlikely((!string) || (string->Type()->Tag() != TYPE_STRING)))
	{
		reporter->Error("Fail in function_SearchPattern -- unable to resolve string as userdata");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	index = ((PatternVal*)pattern)->MatchAnywhere(string->CoerceToCString());

	Unref(string);

	lua_pushnumber(L, index);
	return 1;
}


int LuajitManager::function_FileIsOpen(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_FILE, 1, 1);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_FileIsOpen");
		return LUA_FAILURE;
	}

	BroFile *file = v->AsFile();
	if (!file)
	{
		reporter->Error("Unable to resolve Val as File");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	lua_pushboolean(L, file->IsOpen());
	return 1;
}

int LuajitManager::function_WriteFile(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_FILE, 1, 2);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_WriteFile");
		return LUA_FAILURE;
	}

	BroFile *file = v->AsFile();
	if (!file)
	{
		reporter->Error("Unable to resolve Val as File");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	const char *field;

	//For now, we can write a string to file
	if (likely(lua_type(L, 2) == LUA_TSTRING))
	{
		field = luaL_checkstring(L, 2);
		if (!file->Write(field, strlen(field)))
		{
			reporter->Error("Fail in function_WriteFile -- unable to write to file");
			lua_mgr->SetFaultyScript(L);
			return LUA_FAILURE;
		}
	}
	else
	{
		reporter->Error("Fail in function_WriteFile -- expecting string as second argument");
		lua_mgr->SetFaultyScript(L);
		return LUA_FAILURE;
	}

	return 0;
}

int LuajitManager::function_CloseFile(lua_State *L)
{
	Val *v = GetValOfType(L, TYPE_FILE, 1, 1);

	if (unlikely(!v))
	{
		reporter->Error("Fail in function_CloseFile");
		return LUA_FAILURE;
	}

	BroFile *file = v->AsFile();
	file->Close();

	return 0;
}


//Checks and returns Val from userdata
Val * LuajitManager::CheckLuaUserdata(lua_State *L, int index)
{
	void **ud = (void **)luaL_checkudata(L, index, "bro.val");
	luaL_argcheck(L, ud != NULL, 1, "'Val' expected");
	if (unlikely(ud==NULL))
	{
		return NULL;
	}

	Val *realObject = static_cast<Val*>(*ud);

#ifdef LUA_DEBUG
	//Some random Val operations that will cause a segfault if something has gone wrong
	//	TODO: This shouldn't be necessary, and if it should, this needs to handle seg fault
	//	signals
	realObject->Ref();
	Unref(realObject);
#endif

	return realObject;
}

//Note that this function does not Ref userdata. It's meant for quick and temporary operations
//	on a Val within a single scope.
Val* LuajitManager::GetValOfType(lua_State *L, TypeTag type, int index, int argc, bool type_check)
{
	//All of these checks are an attempt to prevent any Lua script from breaking Bro
	Val *v;

	if (unlikely(lua_gettop(L) != argc))
	{
		reporter->Error("Lua called GetValOfType with incorrect number of arguments: %d", lua_gettop(L));
		lua_mgr->SetFaultyScript(L);
		return NULL;
	}

	v = CheckLuaUserdata(L, index);
	if (unlikely(!v))
	{
		reporter->Error("Fail in GetValOfType -- not a valid userdata");
		return NULL;
	}

	TypeTag self_type = v->Type()->Tag();
	
	if ((self_type != type) && (type != TYPE_VOID))
	{
		if (unlikely(!type_check))
		{
			reporter->Error("Fail in GetValOfType -- type conflict");
			lua_mgr->SetFaultyScript(L);
		}
		return NULL;
	}

	return v;
}


std::string LuajitManager::ValAsString(Val *v, char *print_type)
{
	val_list* vals = new val_list(1);

	vals->append(v);
	ODesc d(DESC_READABLE);
	d.SetFlush(0);

	TypeTag tag = v->Type()->Tag();

	//Note: unlikely because it's only used for debug
	if (unlikely(print_type))
	{
		char typestring[32];
		if (TypeTagToString(tag, typestring))
		{
			snprintf(print_type, 32, "Type: %s", typestring);
		}
		else
		{
			snprintf(print_type, 32, "Type: %d", tag);
		}
	}

	switch (tag)
	{
		case TYPE_ENUM:
			 delete vals; // ANE
			return std::string(((EnumVal *)v)->ToString());

		case TYPE_PATTERN:
		case TYPE_SUBNET:
		case TYPE_ADDR:
		case TYPE_PORT:
		case TYPE_FILE:
		case TYPE_INTERVAL:
		case TYPE_TIME:
			// ^TODO above types


		case TYPE_RECORD:
		case TYPE_TABLE:
		case TYPE_VECTOR:
			describe_vals(vals, &d, 0);
			break;

		default:
			char tstring[32];
			if (TypeTagToString(tag, tstring))
			{
				reporter->Error("In ValAsString() -- not a valid type: %s", tstring);
			}
			else
			{
				reporter->Error("In ValAsString() -- not a valid type: %d", tag);
			}
			delete vals; //  ANE
			return std::string();
	}

	delete vals;
	return std::string(d.Description());
}


int LuajitManager::HasLuaExtension(char const *name)
{
	size_t len = strlen(name);
	return (len > 4 && strcmp(name + len - 4, ".lua") == 0);
}


int LuajitManager::FileHash(char const *name)
{
	struct stat attr;
	long int size = 0;
	long int hash = 0;

    stat(name, &attr);

    hash = (long int) attr.st_size + (long int) attr.st_mtime;
    return (int) hash%MAX_INT;
}


bool LuajitManager::LuaEventSupported(const char *handler)
{
	//TODO -- any explicitly unsupported events go here

	//this may include events that use unsupported types, if any (multi-dimensional ListDecls like
	//	TableVal of Set of Addr may cause problems, for example), or events that for other reasons 
	//	are too closely intertwined with the Bro core/ bifs/ analyzers/ frameworks to be reliably 
	//	communicated to Lua

	//For now, everything is supported
	//The best way to blacklist would be by scanning the arguments for unsupported types

	return true;
}


LuajitManager::~LuajitManager()
{
#ifdef LUA_DEBUG
	reporter->Info("Destroying LuajitMgr");
#endif
	keepalive = false;

	pthread_join(tid_inotify, NULL);
    pthread_mutex_destroy(&lua_lock);

    if (ifd)
    {
    	inotify_rm_watch(ifd, wfd);
    	close(ifd);
    }

	LuaActiveMap::iterator s = active_states.begin();
	while ( s != active_states.end())
	{
		lua_close(static_cast<lua_State *>(s->first));
		++s;
	}

	responders.clear();
	active_states.clear();
	active_hashes.clear();
}

// TODO
bool inline passed_safety_checks(lua_State *L, long int lua_index, const char *c_function)
{
	return false;
}

#endif /* ENABLE_LUAJIT */
