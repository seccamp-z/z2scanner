#
#
#	z2kit v3 : Security Camp track Z2 : sort of analysis framework
#
#	utils.py
#	Basic Utilities
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
import math


def get_entropy(data):
	entropy = 0
	counts = [ 0 ] * 256
	for ch in data:
		counts[ch] += 1
	total = len(data)
	for i in range(256):
		if counts[i] == 0:
			continue
		p = float(counts[i]) / total
		entropy -= p * math.log2(p)
	return entropy

def is_ascii_in_strings(byte):
	return ( byte >= 0x20 and byte < 0x7f ) or byte == 9

def get_strings(data, min_strlen=4):
	strings = {}
	s = bytearray()
	for ch in data:
		if is_ascii_in_strings(ch):
			s.append(ch)
		else:
			if len(s) >= min_strlen:
				s = bytes(s)
				if s not in strings:
					strings[s] = 1
				else:
					strings[s] += 1
			s = bytearray()
	if len(s) >= min_strlen:
		s = bytes(s)
		if s not in strings:
			strings[s] = 1
		else:
			strings[s] += 1
	return strings

def get_strings_count(data, bstr):
	l = len(bstr)
	if l == 0:
		return 0
	prev = 0
	n = 0
	while prev < len(data):
		curr = data.find(bstr, prev)
		if curr == -1:
			break
		prev = curr + 1
		b0 = curr
		b1 = curr + l
		if b0 != 0 and is_ascii_in_strings(data[b0-1]):
			continue
		if b1 < len(data) and is_ascii_in_strings(data[b1]):
			continue
		n += 1
	return n

class StringsFinder:
	def __init__(self):
		pass
	def process(self, data, min_strlen=4):
		s = bytearray()
		self.on_begin()
		for ch in data:
			if is_ascii_in_strings(ch):
				s.append(ch)
			else:
				if len(s) >= min_strlen:
					s = bytes(s)
					self.on_str(s)
				s = bytearray()
		if len(s) >= min_strlen:
			s = bytes(s)
			self.on_str(s)
		self.on_end()
	def on_begin(self):
		pass
	def on_str(self, bstr):
		pass
	def on_end(self):
		pass
