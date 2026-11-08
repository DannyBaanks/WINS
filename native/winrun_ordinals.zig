// WINS — winrun_ordinals.zig
// Standard Windows DLL export ordinal to symbol name mapping table.
// Resolves imports by ordinal (thunk MSB set) for WinSock2, OLEAUT32, and WLDAP32.

const std = @import("std");

pub fn getOrdinalName(dll: []const u8, ord: u16) ?[]const u8 {
    if (std.ascii.eqlIgnoreCase(dll, "ws2_32.dll") or std.ascii.eqlIgnoreCase(dll, "wsock32.dll")) {
        return switch (ord) {
            1 => "accept",
            2 => "bind",
            3 => "closesocket",
            4 => "connect",
            5 => "getpeername",
            6 => "getsockname",
            7 => "getsockopt",
            8 => "htonl",
            9 => "htons",
            10 => "ioctlsocket",
            11 => "inet_addr",
            12 => "inet_ntoa",
            13 => "listen",
            14 => "ntohl",
            15 => "ntohs",
            16 => "recv",
            17 => "recvfrom",
            18 => "select",
            19 => "send",
            20 => "sendto",
            21 => "setsockopt",
            22 => "shutdown",
            23 => "socket",
            52 => "gethostbyname",
            53 => "getprotobyname",
            57 => "gethostname",
            103 => "WSAAsyncGetHostByName",
            108 => "WSACancelAsyncRequest",
            111 => "WSAGetLastError",
            112 => "WSASetLastError",
            115 => "WSAStartup",
            116 => "WSACleanup",
            151 => "__WSAFDIsSet",
            else => null,
        };
    }

    if (std.ascii.eqlIgnoreCase(dll, "oleaut32.dll")) {
        return switch (ord) {
            2 => "SysAllocString",
            10 => "SysAllocStringA",
            4 => "SysAllocStringLen",
            6 => "SysFreeString",
            7 => "SysStringLen",
            8 => "VariantInit",
            9 => "VariantClear",
            12 => "VariantCopy",
            149 => "SysStringByteLen",
            150 => "SysAllocStringByteLen",
            200 => "GetErrorInfo",
            else => null,
        };
    }

    if (std.ascii.eqlIgnoreCase(dll, "comctl32.dll")) {
        return switch (ord) {
            17 => "_TrackMouseEvent",
            345 => "SetWindowSubclass",
            381 => "DefSubclassProc",
            410 => "RemoveWindowSubclass",
            411 => "TaskDialogIndirect",
            412 => "TaskDialog",
            413 => "UnregisterClassW",
            else => null,
        };
    }

    if (std.ascii.eqlIgnoreCase(dll, "shell32.dll")) {
        return switch (ord) {
            165 => "SHCreateDirectoryExW",
            else => null,
        };
    }

    if (std.ascii.eqlIgnoreCase(dll, "wldap32.dll")) {
        return switch (ord) {
            22 => "ldap_err2string",
            26 => "ldap_first_entry",
            27 => "ldap_next_entry",
            30 => "ldap_get_dn",
            32 => "ldap_first_attribute",
            33 => "ldap_next_attribute",
            35 => "ldap_get_values_len",
            41 => "ldap_msgfree",
            45 => "ldap_bind_s",
            46 => "ldap_unbind_s",
            50 => "ldap_search_s",
            60 => "ldap_simple_bind_s",
            79 => "ldap_value_free_len",
            200 => "ldap_memfree",
            211 => "ldap_set_option",
            217 => "ldap_sslinit",
            301 => "ber_free",
            else => null,
        };
    }

    return null;
}
