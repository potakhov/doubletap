// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#pragma once

#include "defines.h"

namespace netmap {
    bool init();
    void loop();
    void terminate();
}
