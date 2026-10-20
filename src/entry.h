#pragma once

#include "image.h"
#include "module_map.h"

int start_image(ModuleMap* module_map, Module* module);
void detach_image(ModuleMap* module_map, Module* module);
