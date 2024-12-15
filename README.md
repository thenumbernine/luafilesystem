# luafilesystem

Reimplement luafilesystem via LuaJIT FFI.

This is a fork off of Sonoro1234's LuaFileSystem which added Windows support,
which was a fork off of spacewander's LuaFileSystm which was a pure LuaJIT version of LuaFileSystem.

In this version I'm making it dependent on my [lua-ffi-bindings](https://github.com/thenumbernine/lua-ffi-bindings) repo, where I put all my OS-specific include-generated luajit bindings.
The purpose of this is to avoid multiple `ffi.cdef` calls for the same C type.  Best to put them all in one safe place.

I'm also making use of my [lua-ext](https://github.com/thenumbernine/lua-ext)'s `setmetatable`-override to add `__gc` behavior to LuaJIT.

Likewise both Sonoro1234's Windows/Linux version and this version is compatible with my [lua-ext](https://github.com/thenumbernine/lua-ext) project for filesystem operations.

## Docs

It should be compatible with vanilla luafilesystem but with unicode paths in windows:
http://keplerproject.github.io/luafilesystem/manual.html#reference

What you only need is replacing `require 'lfs'` to `require 'lfs_ffi'`.

This version will try to maintain LuaFileSystem compatability, but any alternative function implementations might break compatability with sonoro1234's implementation.

On windows `lfs.dir` iterator will provide an extra return that can be used to get `mode` and `size` attributes in a much more performant way.

This is the canonical way to iterate:

```Lua
local sep = "/"
for file,obj in lfs.dir(path) do
	if file ~= "." and file ~= ".." then
		local f = path..sep..file
		-- obj wont be nil in windows only
		local attr = obj and obj:attr() or lfs.attributes (f)
		assert (type(attr) == "table",f)
		-- do something with f and attr
	end
end
```

## Installation

```
cmake -DLUAJIT_DIR="path to luajit" ../luafilesystem
make install
```

or just copy `lfs_ffi.lua` to lua folder
