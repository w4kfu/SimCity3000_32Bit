# unpack_father

Dll injected in the father process for hooking WriteProcessMemory().

The hook will dump information to file "dbg_msg_father.txt" and inject unpack_son into the son process (ICD process).

# unpack_son

If Vista or greater ?

Hook RtlUserThreadStart

else

Hook kernel32.BaseThreadStart

These Hooks are here for retrieving Original Entry Point.
