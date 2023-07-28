# luafilesystem

Reimplement luafilesystem via LuaJIT FFI.

This is a fork off of Sonoro1234's LuaFileSystem which added Windows support,
which was a fork off of spacewander's LuaFileSystm which was a pure LuaJIT version of LuaFileSystem.

In this version I'm making it dependent on my [lua-ffi-bindings](https://github.com/thenumbernine/lua-ffi-bindings) repo, where I put all my OS-specific include-generated luajit bindings.

Likewise both Sonoro1234's Windows/Linux version and this version is compatible with my [lua-ext](https://github.com/thenumbernine/lua-ext) project for filesystem operations.

## Docs

It should be compatible with vanilla luafilesystem:
http://keplerproject.github.io/luafilesystem/manual.html#reference

What you only need is replacing `require 'lfs'` to `require 'lfs_ffi'`.

## Installation

`[sudo] opm get spacewander/luafilesystem`

Run `resty -e "lfs = require('lfs_ffi') print(lfs.attributes('.', 'mode'))"` to validate the installation.
