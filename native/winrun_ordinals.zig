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
            10 => "inet_addr",
            11 => "inet_ntoa",
            12 => "ioctlsocket",
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
            51 => "gethostbyaddr",
            54 => "getprotobynumber",
            55 => "getservbyname",
            56 => "getservbyport",
            101 => "WSAAsyncSelect",
            102 => "WSAAsyncGetHostByAddr",
            104 => "WSAAsyncGetProtoByNumber",
            105 => "WSAAsyncGetProtoByName",
            106 => "WSAAsyncGetServByPort",
            107 => "WSAAsyncGetServByName",
            109 => "WSASetBlockingHook",
            110 => "WSAUnhookBlockingHook",
            113 => "WSACancelBlockingCall",
            114 => "WSAIsBlocking",
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
            4 => "SysAllocStringLen",
            6 => "SysFreeString",
            7 => "SysStringLen",
            8 => "VariantInit",
            9 => "VariantClear",
            10 => "VariantCopy",
            11 => "VariantCopyInd",
            12 => "VariantChangeType",
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

    // XInput and DirectSound, derived from the export tables of the real DLLs
    // (DirectX redistributable xinput1_3.dll, and Proton's dsound.dll), not from
    // memory: both use ordinal base 1, so ordinal 2 in XINPUT1_3 really is
    // XInputGetState, and ordinal 11 in DSOUND really is DirectSoundCreate8.
    if (std.ascii.eqlIgnoreCase(dll, "xinput1_3.dll") or std.ascii.eqlIgnoreCase(dll, "xinput1_4.dll") or
        std.ascii.eqlIgnoreCase(dll, "xinput1_2.dll") or std.ascii.eqlIgnoreCase(dll, "xinput9_1_0.dll"))
    {
        return switch (ord) {
            2 => "XInputGetState",
            3 => "XInputSetState",
            4 => "XInputGetCapabilities",
            5 => "XInputEnable",
            6 => "XInputGetDSoundAudioDeviceGuids",
            7 => "XInputGetBatteryInformation",
            8 => "XInputGetKeystroke",
            100 => "XInputGetStateEx",
            else => null,
        };
    }

    if (std.ascii.eqlIgnoreCase(dll, "dsound.dll")) {
        return switch (ord) {
            1 => "DirectSoundCreate",
            6 => "DirectSoundCaptureCreate",
            10 => "DirectSoundFullDuplexCreate",
            11 => "DirectSoundCreate8",
            12 => "DirectSoundCaptureCreate8",
            else => null,
        };
    }

    return null;
}
