// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include <string>

#include "pe.h"

namespace efiloader {
class PeManager {
public:
  explicit PeManager(uint16_t mt) : machine_type(mt) {
    inf_set_64bit();
    set_imagebase(0x0);
    if (mt == PECPU_ARM64) {
      set_processor_type("arm", SETPROC_LOADER);
    } else {
      set_processor_type("metapc", SETPROC_LOADER);
    }
  }
  bool process(linput_t *li, const std::string &fname, int ord);
  uint16_t machine_type;

private:
  ushort pe_sel_base = 0;
  ea_t pe_base = 0;
};
} // namespace efiloader
