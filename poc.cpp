#include <iostream>
#include <windows.h>
#include "FreeImage.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: poc_loader.exe <path_to_poc_bmp>" << std::endl;
        return 1;
    }

    const char* filename = argv[1];

    FreeImage_Initialise();

    FREE_IMAGE_FORMAT fif = FreeImage_GetFileType(filename, 0);
    if (fif == FIF_UNKNOWN) {
        fif = FreeImage_GetFIFFromFilename(filename);
    }

    if (fif == FIF_UNKNOWN) {
        std::cout << "[-] Could not determine file type." << std::endl;
        FreeImage_DeInitialise();
        return 1;
    }

    // Current crash path:
    // FreeImage_Load -> PluginBMP::Load -> LoadWindowsBMP -> LoadPixelData -> fread -> memcpy (CRASH)
    FIBITMAP* dib = FreeImage_Load(fif, filename, 0);

    // If it did not crash and returned a bitmap, free it.
    if (dib) {
        FreeImage_Unload(dib);
    }

    FreeImage_DeInitialise();
    return 0;
}
