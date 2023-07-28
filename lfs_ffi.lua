local bit = require "bit"
local ffi = require "ffi"

local lib = ffi.C

local has_table_new, new_tab = pcall(require, "table.new")
if not has_table_new or type(new_tab) ~= "function" then
	new_tab = function() return {} end
end


local _M = {
	_VERSION = "0.1",
}

-- common utils/constants
local IS_64_BIT = ffi.abi('64bit')

-- Linux:
-- sys/types.h has ssize_t
-- in Windows it's missing, so I wedged it in
require 'ffi.c.sys.types'

require 'ffi.c.string'	-- strerror
local errnolib = require 'ffi.c.errno'

local function errnostr()
	return ffi.string(lib.strerror(ffi.errno()))
end

-- Windows and Linux:
-- FILENAME_MAX, SEEK_SET, SEEK_END
-- Windows:
-- _fileno, fseek, ftell
-- ... and fileno alias
-- Linux:
-- fileno
local stdiolib = require 'ffi.c.stdio'

-- sys/syslimits.h
local MAXPATH_UNC = 32760
local HAVE_WFINDFIRST = true

-- misc
-- Windows-only:
local wchar_t, win_utf8_to_unicode
if ffi.os == "Windows" then
   	-- in Windows:
	-- wchar.h -> corecrt_wio.h
	-- mbrtowc, _wfindfirst, _wfindnext, _wfinddata_t, _wfinddata_i64_t
	local wiolib = require 'ffi.c.wchar'

	-- corecrt_io.h
	-- _findfirst, _findnext, _finddata_t, _finddata_i64_t
	-- _setmode, _locking
	local iolib = require 'ffi.c.io'

	function wchar_t(s)
		local mbstate = ffi.new('mbstate_t[1]')
		local wcs = ffi.new('wchar_t[?]', #s + 1)
		local i = 0
		local offset = 0
		local len = #s
		while true do
			local processed = wiolib.mbrtowc(
				wcs + i, ffi.cast('const char *', s) + offset, len, mbstate)
			if processed <= 0 then break end
			i = i + 1
			offset = offset + processed
			len = len - processed
		end
		return wcs
	end

	-- getcwd in POSIX is in unistd.h
	-- _getcwd in Windows is in direct.h
	-- for compat's sake I have a lua binding in ffi.c.unistd to _getcwd
	-- _wgetcwd in Windows is in direct.h or wchar.h

	-- Windows:
	-- _getcwd, _wgetcwd, _chdir, _wchdir, _rmdir, _wrmdir, _mkdir, _wmkdir
	require 'ffi.c.direct'

	ffi.cdef([[
typedef wchar_t* LPTSTR;
typedef unsigned char BOOLEAN;
typedef unsigned long DWORD;
BOOLEAN CreateSymbolicLinkW(
	LPTSTR lpSymlinkFileName,
	LPTSTR lpTargetFileName,
	DWORD dwFlags
);

// where?
int WideCharToMultiByte(
	unsigned int	 CodePage,
	DWORD	dwFlags,
	const wchar_t*  lpWideCharStr,
	int	  cchWideChar,
	char*	lpMultiByteStr,
	int	  cbMultiByte,
	const char*   lpDefaultChar,
	int*   lpUsedDefaultChar);

// where?
int MultiByteToWideChar(
	unsigned int	 CodePage,
	DWORD	dwFlags,
	const char*   lpMultiByteStr,
	int	  cbMultiByte,
	wchar_t*   lpWideCharStr,
	int	  cchWideChar);

// where?
uint32_t GetLastError();

// where?
uint32_t FormatMessageA(
	uint32_t dwFlags,
	const void* lpSource,
	uint32_t dwMessageId,
	uint32_t dwLanguageId,
	char* lpBuffer,
	uint32_t nSize,
	va_list *Arguments
);
	]]
	-- Some helper functions
	local function error_win(lvl)
		local errcode = ffi.C.GetLastError()
		local str = ffi.new("char[?]",1024)
		local FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
		local FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
		local numout = ffi.C.FormatMessageA(bit.bor(FORMAT_MESSAGE_FROM_SYSTEM,
			FORMAT_MESSAGE_IGNORE_INSERTS), nil, errcode, 0, str, 1023, nil)
		if numout == 0 then
			error("Windows Error: (Error calling FormatMessage)", lvl)
		else
			error("Windows Error: "..ffi.string(str, numout), lvl)
		end
	end
	local CP_UTF8 = 65001
	local WC_ERR_INVALID_CHARS = 0x00000080
	local MB_ERR_INVALID_CHARS  = 0x00000008
	function win_utf8_to_unicode(szUtf8)
		local dwFlags = _M.unicode_errors and MB_ERR_INVALID_CHARS or 0
		local nLenWchar = lib.MultiByteToWideChar(CP_UTF8, dwFlags, szUtf8, -1, nil, 0 );
		if nLenWchar ==0 then error_win(2) end
		local szUnicode = ffi.new("wchar_t[?]",nLenWchar)
		nLenWchar = lib.MultiByteToWideChar(CP_UTF8, dwFlags, szUtf8, -1, szUnicode, nLenWchar);
		if nLenWchar ==0 then error_win(2) end
		return szUnicode, nLenWchar
	end
	_M.win_utf8_to_unicode = win_utf8_to_unicode
	local function win_unicode_to_utf8( szUnicode)
		local dwFlags = _M.unicode_errors and WC_ERR_INVALID_CHARS or 0
		local nLen = lib.WideCharToMultiByte(CP_UTF8, dwFlags, szUnicode, -1, nil, 0, nil, nil);
		if nLen ==0 then error_win(2) end
		local str = ffi.new("char[?]",nLen)
		nLen = lib.WideCharToMultiByte(CP_UTF8, dwFlags, szUnicode, -1, str, nLen, nil, nil);
		if nLen ==0 then error_win(2) end
		return str
	end
	_M.win_unicode_to_utf8 = win_unicode_to_utf8
	local CP_ACP = 0
	function _M.win_utf8_to_acp(utf)
		local szUnicode = win_utf8_to_unicode(utf)
		local dwFlags = _M.unicode_errors and WC_ERR_INVALID_CHARS or 0
		local nLen = lib.WideCharToMultiByte(CP_ACP, dwFlags, szUnicode, -1, nil, 0, nil, nil);
		if nLen ==0 then error_win(2) end
		local str = ffi.new("char[?]",nLen)
		nLen = lib.WideCharToMultiByte(CP_ACP, dwFlags, szUnicode, -1, str, nLen, nil, nil);
		if nLen ==0 then error_win(2) end
		return ffi.string(str)
	end
	function _M.chdir(path)
		if _M.unicode then
			local uncstr = win_utf8_to_unicode(path)
			if lib._wchdir(uncstr) == 0 then return true end
		else
			if type(path) ~= 'string' then
				error('path should be a string')
			end
			if lib._chdir(path) == 0 then
				return true
			end
		end
		return nil, errnostr()
	end

	function _M.currentdir()
		if _M.unicode then
			local buf = ffi.new("wchar_t[?]",MAXPATH_UNC)
			if lib._wgetcwd(buf, MAXPATH_UNC) ~= nil then
				local buf_utf = win_unicode_to_utf8(buf)
				return ffi.string(buf_utf)
			end
			error("error in currentdir")
		else
		local size = stdiolib.FILENAME_MAX
		while true do
			local buf = ffi.new("char[?]", size)
			if lib._getcwd(buf, size) ~= nil then
				return ffi.string(buf)
			end
			if ffi.errno() ~= errnolib.ERANGE then
				return nil, errnostr()
			end
			size = size * 2
		end
		end
	end

	function _M.mkdir(path)
		if _M.unicode then
			local unc_str = win_utf8_to_unicode(path)
			if lib._wmkdir(unc_str) == 0 then
				return true
			end
		else
			if type(path) ~= 'string' then
				error('path should be a string')
			end
			if lib._mkdir(path) == 0 then
				return true
			end
		end
		return nil, errnostr()
	end

	function _M.rmdir(path)
		if _M.unicode then
			local unc_str = win_utf8_to_unicode(path)
			if lib._wrmdir(unc_str) == 0 then
				return true
			end
		else
			if type(path) ~= 'string' then
				error('path should be a string')
			end
			if lib._rmdir(path) == 0 then
				return true
			end
		end
		return nil, errnostr()
	end

	function _M.setmode(file, mode)
		if io.type(file) ~= 'file' then
			error("setmode: invalid file")
		end
		if mode ~= nil and (mode ~= 'text' and mode ~= 'binary') then
			error('setmode: invalid mode')
		end
		mode = (mode == 'text') and 0x4000 or 0x8000
		local prev_mode = iolib._setmode(stdiolib.fileno(file), mode)
		if prev_mode == -1 then
			return nil, errnostr()
		end
		return true, (prev_mode == 0x4000) and 'text' or 'binary'
	end

	local function check_is_dir(path)
		return _M.attributes(path, 'mode') == 'directory' and 1 or 0
	end

	function _M.link(old, new)
		local is_dir = check_is_dir(old)
		if lib.CreateSymbolicLinkW(
				wchar_t(new),
				wchar_t(old), is_dir) ~= 0 then
			return true
		end
		return nil, errnostr()
	end

	local function findclose(dentry)
		if dentry and dentry.handle ~= -1 then
			iolib._findclose(dentry.handle)
			dentry.handle = -1
		end
	end

	local dir_type = ffi.metatype("struct {intptr_t handle;}", {
		__gc = findclose
	})

	local function close(dir)
		findclose(dir._dentry)
		dir.closed = true
	end

	local function iterator(dir)
		if dir.closed ~= false then error("closed directory") end
		local entry = ffi.new("_finddata_t")
		if not dir._dentry then
			dir._dentry = ffi.new(dir_type)
			dir._dentry.handle = iolib._findfirst(dir._pattern, entry)
			if dir._dentry.handle == -1 then
				dir.closed = true
				return nil, errnostr()
			end
			return ffi.string(entry.name)
		end

		if iolib._findnext(dir._dentry.handle, entry) == 0 then
			return ffi.string(entry.name)
		end
		close(dir)
		return nil
	end

	local function witerator(dir)
		if dir.closed ~= false then error("closed directory") end
		local entry = ffi.new("_wfinddata_t")
		if not dir._dentry then
			dir._dentry = ffi.new(dir_type)
			local szPattern = win_utf8_to_unicode(dir._pattern);
			dir._dentry.handle = wiolib._wfindfirst(szPattern, entry)
			if dir._dentry.handle == -1 then
				dir.closed = true
				return nil, errnostr()
			end
			local szName = win_unicode_to_utf8(entry.name)--, -1, szName, 512);
			return ffi.string(szName)
		end

		if wiolib._wfindnext(dir._dentry.handle, entry) == 0 then
			local szName = win_unicode_to_utf8(entry.name)--, -1, szName, 512);
			return ffi.string(szName)
		end
		close(dir)
		return nil
	end

	local dirmeta = {__index = {
		next = iterator,
		close = close,
	}}

	function _M.sdir(path)
		if #path > stdiolib.FILENAME_MAX - 2 then
			error('path too long: ' .. path)
		end
		local dir_obj = setmetatable({
			_pattern = path..'/*',
			closed  = false,
		}, dirmeta)
		return iterator, dir_obj
	end

	local wdirmeta = {__index = {
		next = witerator,
		close = close,
	}}

	function _M.wdir(path)
		if #path > stdiolib.FILENAME_MAX - 2 then
			error('path too long: ' .. path)
		end
		local dir_obj = setmetatable({
			_pattern = path..'/*',
			closed  = false,
		}, wdirmeta)
		return witerator, dir_obj
	end

	function _M.dir(path)
		if _M.unicode then
			return _M.wdir(path)
		else
			return _M.sdir(path)
		end
	end

	local mode_ltype_map = {
		r = 2, -- LK_NBLCK
		w = 2, -- LK_NBLCK
		u = 0, -- LK_UNLCK
	}

	local function lock(fh, mode, start, len)
		local lkmode = mode_ltype_map[mode]
		if not len or len <= 0 then
			if lib.fseek(fh, 0, stdiolib.SEEK_END) ~= 0 then
				return nil, errnostr()
			end
			len = lib.ftell(fh)
		end
		if not start or start <= 0 then
			start = 0
		end
		if lib.fseek(fh, start, stdiolib.SEEK_SET) ~= 0 then
			return nil, errnostr()
		end
		local fd = stdiolib.fileno(fh)
		if lib._locking(fd, lkmode, len) == -1 then
			return nil, errnostr()
		end
		return true
	end

	function _M.lock(filehandle, mode, start, length)
		if mode ~= 'r' and mode ~= 'w' then
			error("lock: invalid mode")
		end
		if io.type(filehandle) ~= 'file' then
			error("lock: invalid file")
		end
		local ok, err = lock(filehandle, mode, start, length)
		if not ok then
			return nil, err
		end
		return true
	end

	function _M.unlock(filehandle, start, length)
		if io.type(filehandle) ~= 'file' then
			error("unlock: invalid file")
		end
		local ok, err = lock(filehandle, 'u', start, length)
		if not ok then
			return nil, err
		end
		return true
	end
else
	-- Linux:
	-- getcwd, chdir, rmdir, link, symlink, unlink, syscall, readlink
	require 'ffi.c.unistd'
	-- mkdir
	require 'ffi.c.sys.stat'

	function _M.chdir(path)
		if lib.chdir(path) == 0 then
			return true
		end
		return nil, errnostr()
	end

	function _M.currentdir()
		local size = stdiolib.FILENAME_MAX
		while true do
			local buf = ffi.new("char[?]", size)
			if lib.getcwd(buf, size) ~= nil then
				return ffi.string(buf)
			end
			if ffi.errno() ~= errnolib.ERANGE then
				return nil, errnostr()
			end
			size = size * 2
		end
	end

	function _M.mkdir(path, mode)
		if lib.mkdir(path, mode or 509) == 0 then
			return true
		end
		return nil, errnostr()
	end

	function _M.rmdir(path)
		if lib.rmdir(path) == 0 then
			return true
		end
		return nil, errnostr()
	end

	function _M.setmode()
		return true, "binary"
	end

	function _M.link(old, new, symlink)
		local f = symlink and lib.symlink or lib.link
		if f(old, new) == 0 then
			return true
		end
		return nil, errnostr()
	end

	-- Linux:
	-- struct dirent, DIR, opendir, readdir, closedir
	require 'ffi.c.dirent'

	local function close(dir)
		if dir._dentry ~= nil then
			lib.closedir(dir._dentry)
			dir._dentry = nil
			dir.closed = true
		end
	end

	local function iterator(dir)
		if dir.closed ~= false then error("closed directory") end

		local entry = lib.readdir(dir._dentry)
		if entry ~= nil then
			return ffi.string(entry.d_name)
		else
			close(dir)
			return nil
		end
	end

	local dir_obj_type = ffi.metatype([[
		struct {
			DIR *_dentry;
			bool closed;
		}
	]],
	{__index = {
		next = iterator,
		close = close,
	}, __gc = close
	})

	function _M.dir(path)
		local dentry = lib.opendir(path)
		if dentry == nil then
			error("cannot open "..path.." : "..errnostr())
		end
		local dir_obj = ffi.new(dir_obj_type)
		dir_obj._dentry = dentry
		dir_obj.closed = false;
		return iterator, dir_obj
	end

	local F_SETLK = (ffi.os == 'Linux') and 6 or 8
	local mode_ltype_map
	local flock_def
	if ffi.os == 'Linux' then
		flock_def = [[
			struct flock {
				short int l_type;
				short int l_whence;
				int64_t l_start;
				int64_t l_len;
				int l_pid;
			};
		]]
		mode_ltype_map = {
			r = 0, -- F_RDLCK
			w = 1, -- F_WRLCK
			u = 2, -- F_UNLCK
		}
	else
		flock_def = [[
			struct flock {
				int64_t l_start;
				int64_t l_len;
				int32_t l_pid;
				short   l_type;
				short   l_whence;
			};
		]]
		mode_ltype_map = {
			r = 1, -- F_RDLCK
			u = 2, -- F_UNLCK
			w = 3, -- F_WRLCK
		}
	end

	ffi.cdef(flock_def..[[
		// Where?
		int fcntl(int fd, int cmd, ... /* arg */ );
	]])

	local function lock(fd, mode, start, len)
		local flock = ffi.new('struct flock')
		flock.l_type = mode_ltype_map[mode]
		flock.l_whence = stdiolib.SEEK_SET
		flock.l_start = start or 0
		flock.l_len = len or 0
		if lib.fcntl(fd, F_SETLK, flock) == -1 then
			return nil, errnostr()
		end
		return true
	end

	function _M.lock(filehandle, mode, start, length)
		if mode ~= 'r' and mode ~= 'w' then
			error("lock: invalid mode")
		end
		if io.type(filehandle) ~= 'file' then
			error("lock: invalid file")
		end
		local fd = stdiolib.fileno(filehandle)
		local ok, err = lock(fd, mode, start, length)
		if not ok then
			return nil, err
		end
		return true
	end

	function _M.unlock(filehandle, start, length)
		if io.type(filehandle) ~= 'file' then
			error("unlock: invalid file")
		end
		local fd = stdiolib.fileno(filehandle)
		local ok, err = lock(fd, 'u', start, length)
		if not ok then
			return nil, err
		end
		return true
	end
end

-- Windows
-- sys/utime.h:
-- _utime64 / _utime32 is in sys/utime.h
-- _wutime is in sys/utime.h or wchar.h
-- struct __utimbuf32, _utime32
-- struct __utimbuf64, _utime64
--
-- Linux:
-- utime.h:
-- struct utimbuf, utime
local utimelib = require 'ffi.c.sys.utime'
function _M.touch(path, actime, modtime)
	local buf

	if type(actime) == "number" then
		modtime = modtime or actime
		buf = ffi.new(utimelib.struct_utimbuf)
		buf.actime  = actime
		buf.modtime = modtime
	end

	local p = ffi.new("unsigned char[?]", #path + 1)
	ffi.copy(p, path)

	if utimelib.utime(p, buf) == 0 then
		return true
	end
	return nil, errnostr()
end

-- lock related
local dir_lock_struct
local create_lockfile
local delete_lockfile

if ffi.os == 'Windows' then
	ffi.cdef([[
		typedef const wchar_t* LPCWSTR;
		typedef struct _SECURITY_ATTRIBUTES {
			DWORD nLength;
			void *lpSecurityDescriptor;
			int bInheritHandle;
		} SECURITY_ATTRIBUTES;
		typedef SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;
		void *CreateFileW(
			LPCWSTR lpFileName,
			DWORD dwDesiredAccess,
			DWORD dwShareMode,
			LPSECURITY_ATTRIBUTES lpSecurityAttributes,
			DWORD dwCreationDisposition,
			DWORD dwFlagsAndAttributes,
			void *hTemplateFile
		);

		int CloseHandle(void *hObject);
	]])

	local GENERIC_WRITE = 0x40000000
	local CREATE_NEW = 1
	local FILE_NORMAL_DELETE_ON_CLOSE = 0x04000080

	dir_lock_struct = 'struct {void *lockname;}'

	function create_lockfile(dir_lock, _, lockname)
		lockname = wchar_t(lockname)
		dir_lock.lockname = lib.CreateFileW(lockname, GENERIC_WRITE, 0, nil, CREATE_NEW,
				FILE_NORMAL_DELETE_ON_CLOSE, nil)
		return dir_lock.lockname ~= ffi.cast('void*', -1)
	end

	function delete_lockfile(dir_lock)
		return lib.CloseHandle(dir_lock.lockname)
	end
else
	dir_lock_struct = 'struct {char *lockname;}'
	function create_lockfile(dir_lock, path, lockname)
		dir_lock.lockname = ffi.new('char[?]', #lockname + 1)
		ffi.copy(dir_lock.lockname, lockname)
		return lib.symlink(path, lockname) == 0
	end

	function delete_lockfile(dir_lock)
		return lib.unlink(dir_lock.lockname)
	end
end

local function unlock_dir(dir_lock)
	if dir_lock.lockname ~= nil then
		dir_lock:delete_lockfile()
		dir_lock.lockname = nil
	end
	return true
end

local dir_lock_type = ffi.metatype(dir_lock_struct,
	{__gc = unlock_dir,
	__index = {
		free = unlock_dir,
		create_lockfile = create_lockfile,
		delete_lockfile = delete_lockfile,
	}}
)

function _M.lock_dir(path, _)
	-- It's interesting that the lock_dir from vanilla lfs just ignores second paramter.
	-- So, I follow this behavior too :)
	local dir_lock = ffi.new(dir_lock_type)
	local lockname = path .. '/lockfile.lfs'
	if not dir_lock:create_lockfile(path, lockname) then
		return nil, errnostr()
	end
	return dir_lock
end

-- stat related
local stattype
local stat_func, lstat_func
if ffi.os == 'Windows' then
	-- Windows
	-- struct stat, _stat64, _wstat64
	require 'ffi.c.sys.stat'
	stat_func = function(filepath, buf)
		if _M.unicode then
			local szfp = win_utf8_to_unicode(filepath);
			return lib._wstat64(szfp, buf)
		else
			return lib._stat64(filepath, buf)
		end
	end
	lstat_func = stat_func
	-- Windows, whhyyy do you have a fluly separate 'struct stat'?!?!?!
	stattype = 'struct _stat64'
else	-- Linux, OSX, BSD, etc
	-- Linux:
	-- struct stat, stat, lstat
	require 'ffi.c.sys.stat'
	stat_func = lib.stat
	lstat_func = lib.lstat
	stattype = 'struct stat'
end

local STAT = {
	FMT   = 0xF000,
	FSOCK = 0xC000,
	FLNK  = 0xA000,
	FREG  = 0x8000,
	FBLK  = 0x6000,
	FDIR  = 0x4000,
	FCHR  = 0x2000,
	FIFO  = 0x1000,
}

local ftype_name_map = {
	[STAT.FREG]  = 'file',
	[STAT.FDIR]  = 'directory',
	[STAT.FLNK]  = 'link',
	[STAT.FSOCK] = 'socket',
	[STAT.FCHR]  = 'char device',
	[STAT.FBLK]  = "block device",
	[STAT.FIFO]  = "named pipe",
}

local function mode_to_ftype(mode)
	local ftype = bit.band(mode, STAT.FMT)
	return ftype_name_map[ftype] or 'other'
end

local function mode_to_perm(mode)
	local perm_bits = bit.band(mode, tonumber(777, 8))
	local perm = new_tab(9, 0)
	local i = 9
	while i > 0 do
		local perm_bit = bit.band(perm_bits, 7)
		perm[i] = (bit.band(perm_bit, 1) > 0 and 'x' or '-')
		perm[i-1] = (bit.band(perm_bit, 2) > 0 and 'w' or '-')
		perm[i-2] = (bit.band(perm_bit, 4) > 0 and 'r' or '-')
		i = i - 3
		perm_bits = bit.rshift(perm_bits, 3)
	end
	return table.concat(perm)
end

local function time_or_timespec(time, timespec)
	local t = tonumber(time)
	if not t and timespec then
		t = tonumber(timespec.tv_sec)
	end
	return t
end

local attr_handlers = {
	access = function(st) return time_or_timespec(st.st_atime, st.st_atimespec) end,
	blksize = function(st) return tonumber(st.st_blksize) end,
	blocks = function(st) return tonumber(st.st_blocks) end,
	change = function(st) return time_or_timespec(st.st_ctime, st.st_ctimespec) end,
	dev = function(st) return tonumber(st.st_dev) end,
	gid = function(st) return tonumber(st.st_gid) end,
	ino = function(st) return tonumber(st.st_ino) end,
	mode = function(st) return mode_to_ftype(st.st_mode) end,
	modification = function(st) return time_or_timespec(st.st_mtime, st.st_mtimespec) end,
	nlink = function(st) return tonumber(st.st_nlink) end,
	permissions = function(st) return mode_to_perm(st.st_mode) end,
	rdev = function(st) return tonumber(st.st_rdev) end,
	size = function(st) return tonumber(st.st_size) end,
	uid = function(st) return tonumber(st.st_uid) end,
}
-- TODO move this into ffi.c.sys.stat (per respective OS)
local stat_type = ffi.metatype(stattype, {
	__index = function(self, attr_name)
		local func = attr_handlers[attr_name]
		return func and func(self)
	end
})

-- Add target field for symlinkattributes, which is the absolute path of linked target
local get_link_target_path
if ffi.os == 'Windows' then
	function get_link_target_path()
		return nil, "could not obtain link target: Function not implemented ", errnolib.ENOSYS
	end
else
	function get_link_target_path(link_path, statbuf)
		local size = statbuf.st_size
		size = size == 0 and stdiolib.FILENAME_MAX or size
		local buf = ffi.new('char[?]', size + 1)
		local read = lib.readlink(link_path, buf, size)
		if read == -1 then
			return nil, "could not obtain link target: "..errnostr(), ffi.errno()
		end
		if read > size then
			return nil, "not enought size for readlink: "..errnostr(), ffi.errno()
		end
		buf[size] = 0
		return ffi.string(buf)
	end
end

local buf = ffi.new(stat_type)
local function attributes(filepath, attr, follow_symlink)
	local func = follow_symlink and stat_func or lstat_func
	if func(filepath, buf) == -1 then
		return nil, string.format("cannot obtain information from file '%s' : %s", tostring(filepath), errnostr()), ffi.errno()
	end

	local atype = type(attr)
	if atype == 'string' then
		local value, err, errn
		if attr == 'target' and not follow_symlink then
			value, err, errn = get_link_target_path(filepath, buf)
			return value, err, errn
		else
			value = buf[attr]
		end
		if value == nil then
			error("invalid attribute name '" .. attr .. "'")
		end
		return value
	else
		local tab = (atype == 'table') and attr or {}
		for k, _ in pairs(attr_handlers) do
			tab[k] = buf[k]
		end
		if not follow_symlink then
			tab.target = get_link_target_path(filepath, buf)
		end
		return tab
	end
end

function _M.attributes(filepath, attr)
	return attributes(filepath, attr, true)
end

function _M.symlinkattributes(filepath, attr)
	return attributes(filepath, attr, false)
end

_M.unicode = HAVE_WFINDFIRST
_M.unicode_errors = false
--this would error with _M.unicode_errors = true
--local cad = string.char(0xE0,0x80,0x80)--,0xFD,0xFF)

return _M
