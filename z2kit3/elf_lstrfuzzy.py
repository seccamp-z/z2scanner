#
#
#	z2kit v3 : Security Camp track Z2 : sort of analysis framework
#
#	elf_lstrfuzzy.py
#	lstrfuzzy algorithm
#
#	Copyright (C) 2018, 2019 Tsukasa OI.
#
#	Permission to use, copy, modify, and/or distribute this software
#	for any purpose with or without fee is hereby granted, provided
#	that the above copyright notice and this permission notice
#	appear in all copies.
#
#	THE SOFTWARE IS PROVIDED “AS IS” AND ISC DISCLAIMS ALL WARRANTIES
#	WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#	MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL ISC BE LIABLE FOR
#	ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
#	DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
#	WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
#	ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#	PERFORMANCE OF THIS SOFTWARE.
#
#
import ssdeep
from . import elf
from . import elffile

def lstrfuzzy_from_elffile(elffile):
	# 動的リンクされた ELF ファイルでない限り、None を返す
	if elf.DT_STRTAB not in elffile.dynamic_headers:
		return None
	if elf.DT_STRSZ not in elffile.dynamic_headers:
		return None
	# 文字列テーブルの ssdeep ハッシュを取る
	return ssdeep.hash(elffile.read_by_vaddr(elffile.dynamic_headers[elf.DT_STRTAB], elffile.dynamic_headers[elf.DT_STRSZ]))
