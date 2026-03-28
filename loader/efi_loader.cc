// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "../ldr/idaldr.h"

#include <algorithm>

#include "pe_manager.h"
#include "uefitool.h"

//--------------------------------------------------------------------------
// IDA loader
static int idaapi accept_file(qstring *fileformatname, qstring * /*processor*/,
                              linput_t *li, const char * /*filename*/) {
  constexpr char sig[] = "_FVH";
  constexpr size_t sig_len = 4;
  static constexpr size_t kBufSize = 4096;

  const int64 file_size = qlsize(li);
  qlseek(li, 0);

  char buf[kBufSize];
  for (int64 pos = 0; pos + static_cast<int64>(sig_len) <= file_size;) {
    qlseek(li, pos);
    auto to_read = qmin(static_cast<int64>(kBufSize), file_size - pos);
    auto nread = qlread(li, buf, static_cast<size_t>(to_read));
    if (nread < static_cast<ssize_t>(sig_len)) {
      break;
    }
    if (std::search(buf, buf + nread, sig, sig + sig_len) != buf + nread) {
      *fileformatname = "UEFI firmware image";
      return 1;
    }
    if (to_read < static_cast<int64>(kBufSize)) {
      break;
    }
    pos += nread - (sig_len - 1);
  }
  return 0;
}

void idaapi load_file(linput_t *li, ushort /*neflag*/,
                      const char * /*fileformatname*/) {
  int64 fsize = qlsize(li);
  if (fsize <= 0) {
    msg("[efiXloader] invalid input file size\n");
    return;
  }
  bytevec_t data;
  data.resize(fsize);
  qlseek(li, 0);
  if (qlread(li, data.begin(), fsize) != fsize) {
    msg("[efiXloader] failed to read input file\n");
    return;
  }

  efiloader::Uefitool uefi_parser(data);
  if (uefi_parser.messages_occurs()) {
    uefi_parser.show_messages();
  }
  uefi_parser.dump();
  uefi_parser.dump_jsons();

  efiloader::PeManager pe_manager(uefi_parser.machine_type);

  // we currently only handle 64-bit binaries with the EFI loader
  add_til("uefi64.til", ADDTIL_DEFAULT);

  if (uefi_parser.files.empty()) {
    msg("[efiXloader] can not parse input firmware\n");
    return;
  }

  int processed = 0;
  for (size_t i = 0; i < uefi_parser.files.size(); i++) {
    const auto &file = uefi_parser.files[i];
    if (file->is_te) {
      continue;
    }
    auto inf = open_linput(file->dump_name.c_str(), false);
    if (!inf) {
      msg("[efiXloader] unable to open file %s\n", file->dump_name.c_str());
      continue;
    }
    if (pe_manager.process(inf, file->dump_name.c_str(), i)) {
      processed++;
    }
  }

  if (processed == 0) {
    msg("[efiXloader] no images were loaded\n");
    return;
  }

  plugin_t *findpat = find_plugin("patfind", true);
  if (findpat) {
    msg("[efiXloader] running the patfind plugin\n");
    run_plugin(findpat, 0);
  }
}

//--------------------------------------------------------------------------
// loader description block
loader_t LDSC = {
    IDP_INTERFACE_VERSION, 0, accept_file, load_file, nullptr, nullptr, nullptr,
};
