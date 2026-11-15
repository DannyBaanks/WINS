/* Synthetic Win32 PE with data-only TLS (0 callbacks).
 * Used to verify that the GUI loader handles TLS data templates and initializes the slot.
 */
typedef unsigned long long uint64_t;
typedef unsigned int uint32_t;

void ExitProcess(uint32_t uExitCode);

uint32_t _tls_index = 0;
char tls_data[8] = {1, 2, 3, 4, 5, 6, 7, 8};

struct ImageTlsDirectory64 {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

const struct ImageTlsDirectory64 _tls_used = {
    (uint64_t)tls_data,
    (uint64_t)tls_data + 8,
    (uint64_t)&_tls_index,
    0,
    0,
    0
};

void wWinMainCRTStartup(void) {
    ExitProcess(41);
}
