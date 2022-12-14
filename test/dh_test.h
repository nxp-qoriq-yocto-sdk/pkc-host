/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of Freescale Semiconductor nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE)ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

static uint8_t S2[] = {
	0x4e, 0x51, 0x30, 0x16, 0xcd, 0xd7, 0xf5, 0x1f, 0xa9, 0xfd, 0x85, 0x95,
	    0xcb, 0xf6, 0x4b,
	0x0e, 0x9b, 0xc3, 0x90, 0xaf, 0x1e
};

static int s2_len = sizeof(S2);

static uint8_t W1[] = {
	0x6d, 0x5b, 0x36, 0x1f, 0x31, 0x38, 0xbd, 0xc7, 0x01, 0x89, 0x42, 0xa1,
	    0x54, 0x67, 0x0e,
	0xba, 0x3e, 0x73, 0x17, 0xd9, 0x17, 0x25, 0x7e, 0x8d, 0xfa, 0x69, 0x24,
	    0x9b, 0x1a, 0x22,
	0xfe, 0xe4, 0xdf, 0xb8, 0xf2, 0xda, 0x7a, 0x00, 0xc6, 0xce, 0x4d, 0xf8,
	    0x97, 0x69, 0x5b,
	0x44, 0xeb, 0x68, 0xb2, 0x9f, 0xa1, 0x29, 0xe4, 0x49, 0x5d, 0x4c, 0x18,
	    0xe7, 0xfb, 0x00,
	0xa4, 0x60, 0xeb, 0xd5, 0xf7, 0xb8, 0xab, 0xd7, 0xe3, 0xad, 0x99, 0x6f,
	    0x4f, 0x78, 0x34,
	0x63, 0x4d, 0xda, 0x0a, 0x5f, 0x72, 0xf2, 0xa6, 0x48, 0x0a, 0x8b, 0x6c,
	    0x28, 0x10, 0xc5,
	0x53, 0x6d, 0xf6, 0x6e, 0x53, 0xbd, 0x2a, 0x31, 0xf1, 0xe5, 0x2f, 0xc6,
	    0x8e, 0xc3, 0xec,
	0xdc, 0xee, 0x53, 0x34, 0x2c, 0x23, 0xcb, 0x0e, 0x7b, 0x19, 0xa0, 0x58,
	    0x0e, 0x46, 0x72,
	0xd3, 0x7a, 0x1f, 0x3e, 0xdc, 0xd6, 0xb8, 0xb1
};

static int w1_len = sizeof(W1);

static uint8_t Q[] = {
	0x8b, 0x1f, 0x58, 0xa3, 0x3e, 0xc7, 0x0b, 0x86, 0xff, 0xb7, 0x15, 0xa9,
	    0x33, 0x7c,
	0x39, 0x75, 0xc1, 0x40, 0xc0, 0x42, 0x86, 0x3f, 0x61, 0xbe, 0x10, 0xa9,
	    0x7a, 0x7e, 0xb6,
	0x98, 0xbd, 0x0b, 0x87, 0x9f, 0xb9, 0x23, 0x18, 0x7d, 0xf5, 0xb0, 0xb6,
	    0x94, 0x4a, 0x43,
	0x21, 0xba, 0x4e, 0xa1, 0xb2, 0x7b, 0x83, 0xee, 0x2d, 0xb4, 0x6b, 0xb8,
	    0x4d, 0xee, 0xd1,
	0x55, 0x84, 0xbb, 0xcf, 0x46, 0x24, 0x5a, 0x59, 0x9f, 0x94, 0xc0, 0x87,
	    0xa6, 0x15, 0xad,
	0xb4, 0x9e, 0xb6, 0x97, 0x1d, 0x2c, 0x0e, 0xe6, 0xbb, 0x58, 0x8f, 0x2d,
	    0xeb, 0x1a, 0xe4,
	0x22, 0x24, 0x2c, 0x99, 0x6e, 0x06, 0x44, 0xc9, 0x34, 0x4d, 0x58, 0x63,
	    0x38, 0xbc, 0xfe,
	0x2c, 0x05, 0xaa, 0x0a, 0xf8, 0xd3, 0x4c, 0x27, 0xc1, 0xfd, 0x0b, 0x04,
	    0x03, 0x14, 0x61,
	0x94, 0x8e, 0x91, 0x81, 0xd9, 0xa8, 0xff, 0x6a, 0x9b
};

static int q_len = sizeof(Q);

static uint8_t S2_2048[] = {
	0x41, 0x92, 0xca, 0x32, 0x13, 0x55, 0x45, 0x17, 0x43, 0xa0, 0x24, 0xa5,
	    0x40, 0xac, 0x98,
	0x20, 0xd1, 0xdd, 0xe8, 0x56, 0x5a, 0x36, 0xf4, 0xcb, 0x36, 0x74, 0x4d,
	    0x8b, 0xbf, 0xec,
	0x69, 0xf5, 0xe3, 0x74, 0xa0, 0x28, 0xf8, 0xbf, 0xf8, 0x0f, 0x55
};

static int s2_len_2048 = sizeof(S2_2048);

static uint8_t W1_2048[] = {
	0x77, 0x31, 0x32, 0xaf, 0x0f, 0x04, 0x27, 0x88, 0xcd, 0x0a, 0x13, 0x7f,
	    0x0a, 0x68, 0xbe,
	0x34, 0x66, 0x29, 0x96, 0xe9, 0xfb, 0xb5, 0x5d, 0x7b, 0x5e, 0x03, 0x2a,
	    0x10, 0x4e, 0x35,
	0x49, 0xda, 0xf4, 0xee, 0x62, 0x0d, 0x71, 0x91, 0x98, 0xbf, 0x36, 0x08,
	    0x69, 0x3c, 0x86,
	0xec, 0x49, 0x42, 0x71, 0x81, 0xdf, 0x8a, 0x2c, 0xa3, 0x01, 0x79, 0xe6,
	    0x8a, 0x6f, 0xb3,
	0xca, 0x37, 0x8d, 0x88, 0xab, 0xca, 0x60, 0x37, 0x86, 0xae, 0x4d, 0x1e,
	    0xe8, 0xa6, 0xb1,
	0xbe, 0x74, 0x0c, 0xef, 0x0c, 0x00, 0x3d, 0xc9, 0x4f, 0xd5, 0x8a, 0x70,
	    0xc0, 0x62, 0xc4,
	0xcf, 0xd8, 0xad, 0xfe, 0xc3, 0xaa, 0x4a, 0x25, 0x55, 0x61, 0xae, 0xe3,
	    0x5a, 0xc6, 0xbe,
	0xb2, 0x05, 0xa6, 0x1e, 0x17, 0xd9, 0xbd, 0x33, 0xd9, 0xb3, 0x12, 0x29,
	    0x7f, 0x00, 0x50,
	0x2d, 0x02, 0x46, 0x20, 0xf8, 0xfd, 0x1c, 0xb1, 0x6c, 0xd6, 0x21, 0xe0,
	    0x42, 0x45, 0x84,
	0x82, 0x0c, 0x48, 0x95, 0x44, 0xa3, 0x8a, 0x2f, 0x88, 0xbd, 0xb3, 0x27,
	    0xf1, 0x9e, 0x65,
	0xc2, 0x44, 0x7d, 0x2c, 0x63, 0xdb, 0xb3, 0xf7, 0xf5, 0xc6, 0xb1, 0x1e,
	    0x0d, 0xfc, 0x0d,
	0xee, 0xa4, 0xd7, 0xc9, 0x75, 0x0d, 0x02, 0xb7, 0x8d, 0xb2, 0xc1, 0xdf,
	    0x1c, 0xee, 0x99,
	0xf0, 0xca, 0xf3, 0x8f, 0xa1, 0x21, 0x1c, 0x49, 0x03, 0x7b, 0x09, 0x81,
	    0xa1, 0x6f, 0x8a,
	0x61, 0x78, 0x8e, 0x0a, 0x81, 0x15, 0x00, 0xcc, 0x15, 0x4f, 0x01, 0x7e,
	    0x4d, 0x7b, 0xd5,
	0xd9, 0x9a, 0x89, 0xec, 0x08, 0xf0, 0x85, 0xd9, 0x8f, 0xce, 0x07, 0xe3,
	    0xcd, 0x24, 0x40,
	0x76, 0xb4, 0xfd, 0x6a, 0xc6, 0x08, 0x0a, 0xcf, 0x14, 0x4c, 0xcc, 0xe6,
	    0xdc, 0x73, 0x6c,
	0xae, 0xbb, 0x4b, 0x90, 0x47, 0xbe, 0xed, 0xcd, 0xe9, 0x80, 0x09, 0x46,
	    0xe5, 0x8b, 0x19,
	0x95
};

static uint8_t Q_2048[] = {
	0xbf, 0x9a, 0xc0, 0x94, 0x97, 0xc0, 0x9e, 0x41, 0xbf, 0x40, 0xe4, 0x90,
	    0x0f, 0xfc,
	0xdf, 0x4a, 0x00, 0xb1, 0xfa, 0x71, 0xab, 0x2c, 0x4a, 0x1f, 0x6c, 0x39,
	    0xfa, 0xed, 0x60,
	0xab, 0x30, 0x67, 0x34, 0x84, 0x3b, 0xc3, 0xcc, 0x41, 0xf7, 0x41, 0x16,
	    0x68, 0x69, 0x19,
	0x44, 0xf7, 0x9b, 0xf7, 0xf7, 0xfb, 0xef, 0x3f, 0x1a, 0x62, 0x2e, 0xb6,
	    0x3a, 0x1a, 0xd3,
	0x5a, 0x39, 0xa6, 0x05, 0x24, 0x30, 0x2e, 0xe5, 0xab, 0x58, 0xb8, 0x90,
	    0x0f, 0x0a, 0x6e,
	0xcc, 0xd8, 0xda, 0xc9, 0x80, 0x4f, 0xbe, 0xa9, 0xf6, 0x39, 0x5c, 0x6c,
	    0x10, 0xdf, 0xa8,
	0xfa, 0xc8, 0xf4, 0xc3, 0xfa, 0xdd, 0x5b, 0xb8, 0x4b, 0xb1, 0x01, 0xaf,
	    0x80, 0x4c, 0x17,
	0xbf, 0xf5, 0xf3, 0x30, 0x6e, 0x60, 0xca, 0x70, 0x2b, 0x92, 0xf9, 0x17,
	    0xdc, 0xbd, 0x46,
	0x0f, 0x0f, 0x60, 0xe8, 0x84, 0xca, 0xf5, 0xab, 0x34, 0x25, 0x89, 0xe0,
	    0xc1, 0x36, 0xdb,
	0x27, 0x07, 0x8c, 0xf4, 0xa2, 0x3a, 0xd4, 0x2d, 0x20, 0x68, 0x3f, 0xa8,
	    0xb1, 0x52, 0x62,
	0xb3, 0x24, 0x68, 0x2a, 0xce, 0x40, 0xf7, 0xd2, 0x46, 0x95, 0xd6, 0x99,
	    0x12, 0xf4, 0x85,
	0x6a, 0xd1, 0x65, 0x28, 0x53, 0xaa, 0xa4, 0xb6, 0x27, 0xe7, 0xea, 0x3f,
	    0x3b, 0xda, 0x25,
	0x0d, 0x6b, 0x0a, 0x5a, 0x57, 0x58, 0xda, 0xc4, 0x4a, 0x65, 0xbc, 0xf6,
	    0x40, 0xd2, 0x4c,
	0x2c, 0x16, 0x84, 0xa8, 0x73, 0x13, 0x5d, 0xba, 0x3d, 0xa9, 0xa5, 0x64,
	    0x2c, 0x15, 0xd9,
	0xbb, 0x6c, 0x8b, 0xac, 0xcb, 0x86, 0x8f, 0xdc, 0xb2, 0x38, 0xad, 0xc1,
	    0x26, 0x96, 0x1e,
	0x57, 0xb3, 0x2c, 0xb5, 0x87, 0x76, 0x1b, 0x0f, 0xd5, 0x7a, 0x38, 0xf7,
	    0xd0, 0x7b, 0x93,
	0x4a, 0x96, 0xa4, 0x4e, 0x10, 0x73, 0xc7, 0xb2, 0xa0, 0x86, 0x34, 0x3b,
	    0xc8, 0x13, 0x05,
	0x65, 0xbb
};

static int q_len_2048 = sizeof(Q_2048);
static int w1_len_2048 = sizeof(W1_2048);

static uint8_t S2_4096[] = {
	0x46, 0x27, 0xe2, 0x07, 0x9d, 0x62, 0xd4, 0x53, 0x75, 0x72, 0xe8, 0xb3,
	    0x35, 0x21, 0x53,
	0x60, 0x05, 0xd1, 0x25, 0x46, 0x10, 0x8e, 0xab, 0x39, 0x44, 0xab, 0x95,
	    0xad, 0x1e, 0x94,
	0xb2, 0x7a, 0xe0, 0x4b, 0x9d, 0xe7, 0xcd, 0x9e, 0x17, 0x14, 0x96, 0xa1,
	    0x42, 0x37, 0x9c,
	0x73, 0xac, 0x66, 0x48, 0x42, 0x0b, 0xc5, 0x2b, 0xee, 0x3d, 0xc7, 0x3d,
	    0xf5, 0x16, 0x43,
	0xc1, 0xa1, 0xda, 0x04, 0xed, 0xa1, 0xc1, 0x58, 0x3c, 0xa8, 0xba, 0xff,
	    0xc9, 0x9c, 0xfa,
	0x18, 0xf1, 0x02, 0x33, 0x10, 0x5d, 0x24, 0x8b, 0x11
};

static int s2_len_4096 = sizeof(S2_4096);
static uint8_t W1_4096[] = {
	0x2b, 0x6a, 0xb5, 0x68, 0x4b, 0x73, 0xba, 0x7f, 0x36, 0xee, 0x5a, 0xa8,
	    0x9b, 0x33, 0x58,
	0xf0, 0xc7, 0xee, 0x1a, 0x8f, 0xcb, 0xbb, 0x21, 0x6f, 0x8c, 0xf8, 0xe4,
	    0x48, 0xf6, 0x81,
	0xc2, 0x78, 0x3c, 0x64, 0x78, 0xe2, 0xc9, 0x30, 0x1f, 0x20, 0x2a, 0xf8,
	    0x8d, 0x79, 0xb5,
	0x50, 0x63, 0x74, 0xff, 0x9b, 0x2e, 0xd9, 0xc6, 0x1f, 0x38, 0x05, 0x8a,
	    0x13, 0xb0, 0xc8,
	0x1f, 0xc7, 0x51, 0x30, 0x2d, 0xe4, 0x6f, 0x8b, 0x38, 0xd2, 0x2d, 0x92,
	    0xf1, 0x74, 0xae,
	0xe5, 0x7e, 0x7d, 0x24, 0x45, 0x8b, 0x53, 0x89, 0x6d, 0x03, 0x96, 0x76,
	    0xb5, 0x42, 0xca,
	0xa8, 0xd4, 0x33, 0x6c, 0xfb, 0x26, 0x55, 0xe1, 0xfc, 0x3b, 0x12, 0x17,
	    0x32, 0xee, 0xac,
	0xc3, 0x4c, 0xe4, 0x29, 0x61, 0x5b, 0x3a, 0xc9, 0x94, 0x1f, 0x28, 0xe3,
	    0x7a, 0x81, 0x4d,
	0xf4, 0x12, 0xbc, 0x6e, 0x9f, 0xc0, 0x89, 0x6d, 0xc9, 0x25, 0x5e, 0xb9,
	    0x3a, 0x82, 0x49,
	0x26, 0x5b, 0x13, 0x83, 0x91, 0xbd, 0xb0, 0xd2, 0x4f, 0xe1, 0xb3, 0x8b,
	    0x6f, 0xc5, 0xd1,
	0xd8, 0x0d, 0xf7, 0x6a, 0xbc, 0xef, 0x9f, 0x45, 0xd8, 0x76, 0xb8, 0x40,
	    0xe7, 0x08, 0xde,
	0x3a, 0x73, 0x8f, 0x78, 0xd6, 0x06, 0xb1, 0x00, 0xfd, 0x59, 0x3d, 0xdb,
	    0xd4, 0x84, 0x5c,
	0x2f, 0xa9, 0x0d, 0xd7, 0x2c, 0xf6, 0x90, 0xbd, 0xb7, 0x3c, 0x9d, 0x5f,
	    0x62, 0xc6, 0x13,
	0x6e, 0x04, 0x73, 0x48, 0x3b, 0x92, 0x4c, 0xb2, 0x3b, 0xbb, 0xe5, 0x90,
	    0x53, 0xea, 0xbd,
	0xda, 0x65, 0xc3, 0x68, 0x6d, 0x2d, 0x72, 0x52, 0x31, 0xc3, 0xa1, 0x77,
	    0x19, 0xcf, 0xe6,
	0xce, 0x35, 0x26, 0x28, 0xf1, 0x43, 0xe9, 0x3e, 0xd2, 0x4b, 0x1e, 0x33,
	    0x70, 0xa7, 0xe0,
	0xbf, 0xc7, 0x9a, 0x49, 0xbd, 0xa5, 0x33, 0x89, 0x64, 0xe0, 0x01, 0x9a,
	    0xca, 0x60, 0x7d,
	0x29, 0x18, 0x5b, 0xc2, 0x95, 0x9d, 0x39, 0x6a, 0xfa, 0x5b, 0x65, 0xce,
	    0x02, 0xcb, 0x5a,
	0xc0, 0xb5, 0x08, 0xec, 0xc4, 0xf3, 0x8d, 0x37, 0x33, 0x38, 0x2a, 0x60,
	    0xaf, 0x62, 0xf5,
	0x3c, 0x7d, 0x4f, 0x5e, 0xa6, 0x5e, 0x05, 0x18, 0xd2, 0xa3, 0x5b, 0x57,
	    0x29, 0x11, 0xb6,
	0x27, 0xb7, 0xe7, 0x55, 0x63, 0xf4, 0x45, 0xf5, 0xda, 0xac, 0x7a, 0xc9,
	    0xb4, 0xee, 0x0f,
	0x8a, 0xf7, 0x53, 0x90, 0xd8, 0x57, 0x2d, 0xbe, 0xda, 0x93, 0xd9, 0xcc,
	    0xd2, 0x1e, 0xe7,
	0x11, 0x2f, 0x5a, 0x1b, 0x43, 0x18, 0xe4, 0x28, 0x11, 0xb6, 0xff, 0xa0,
	    0x12, 0x07, 0x25,
	0xd9, 0xf0, 0x2d, 0x37, 0xf7, 0x51, 0x15, 0x18, 0xc6, 0xc2, 0xb6, 0xf8,
	    0x9b, 0xe3, 0x74,
	0xcd, 0x44, 0x08, 0x91, 0xb6, 0xd9, 0xe5, 0x09, 0x9a, 0x7d, 0xcb, 0x76,
	    0x67, 0x91, 0x78,
	0x5a, 0x3c, 0x99, 0xd9, 0x1f, 0x6e, 0x89, 0x7c, 0x12, 0x10, 0x48, 0x20,
	    0xe3, 0x82, 0xad,
	0x7c, 0xbf, 0x11, 0xa1, 0xd8, 0xba, 0xd6, 0x4e, 0xf4, 0x72, 0x08, 0xa7,
	    0x41, 0xba, 0x4e,
	0xf2, 0x6a, 0x11, 0x8e, 0x8f, 0xee, 0x73, 0x6c, 0x30, 0xa5, 0xe3, 0x8b,
	    0x35, 0x1c, 0xbc,
	0x55, 0xb0, 0x24, 0xe4, 0x29, 0x0b, 0x7d, 0xb0, 0x95, 0x99, 0x80, 0xb5,
	    0x7a, 0x20, 0xbc,
	0x4f, 0xa4, 0x75, 0x9d, 0x17, 0x13, 0x03, 0x99, 0x4d, 0x88, 0x2b, 0xaa,
	    0xe1, 0x25, 0xee,
	0xb8, 0x6b, 0x0f, 0xd4, 0xed, 0xa5, 0x35, 0x95, 0xf8, 0xa1, 0x9e, 0x0c,
	    0xd1, 0x6c, 0x27,
	0xe8, 0xdc, 0x83, 0xc7, 0x59, 0xff, 0x1a, 0xbc, 0x1d, 0xfe, 0x09, 0x66,
	    0xb7, 0xee, 0xc7,
	0xe2, 0x20, 0x16, 0xc7, 0x84, 0x02, 0x48, 0x1c, 0xb6, 0x2c, 0xbe, 0x99,
	    0xa0, 0x52, 0x60,
	0xa4, 0xcf, 0x47, 0x7a, 0xd7, 0xa3, 0x8b, 0xe9, 0x79, 0x38, 0xed, 0x36,
	    0xdc, 0xcc, 0x7a,
	0xa1, 0x74
};

static int w1_len_4096 = sizeof(W1_4096);
static uint8_t Q_4096[] = {
	0xad, 0x06, 0x59, 0xd4, 0xa8, 0x86, 0x4e, 0xc4, 0x45, 0x2f, 0x98, 0xc8,
	    0x22, 0x90,
	0x8c, 0x99, 0xd9, 0xe8, 0x5c, 0x45, 0xe6, 0x34, 0x6d, 0x3f, 0x3d, 0x85,
	    0xab, 0xcd, 0x50,
	0xd7, 0xb8, 0xec, 0x8c, 0x3f, 0x22, 0x57, 0x6c, 0xc2, 0xf8, 0xa4, 0x4e,
	    0x97, 0x11, 0x9a,
	0x76, 0xa3, 0x8a, 0x23, 0x9e, 0x0b, 0x1f, 0x28, 0x02, 0x22, 0xe2, 0xc3,
	    0x91, 0x38, 0xb5,
	0x97, 0xdc, 0xdf, 0xd4, 0x3a, 0xcb, 0x1a, 0x33, 0x87, 0x29, 0x58, 0x96,
	    0x6d, 0x67, 0x37,
	0xa9, 0x20, 0x60, 0x6e, 0xcc, 0xed, 0xd7, 0xaf, 0x5d, 0x5d, 0xe8, 0xfa,
	    0xeb, 0x2c, 0x6d,
	0x81, 0xf8, 0x27, 0x6c, 0x75, 0x74, 0xe1, 0x29, 0x6a, 0x2a, 0xb0, 0xd0,
	    0xe0, 0x1e, 0x3f,
	0xbf, 0x80, 0x60, 0x90, 0x88, 0xd8, 0x0b, 0xd4, 0xd5, 0xae, 0xf7, 0x22,
	    0x9e, 0x06, 0xef,
	0xfa, 0xc6, 0xf4, 0xcc, 0xec, 0x74, 0xb2, 0xc3, 0xb6, 0xcd, 0x3e, 0xc6,
	    0xa0, 0x62, 0x4c,
	0x72, 0xb2, 0x1d, 0x82, 0xd8, 0xd5, 0x99, 0xb8, 0x46, 0x3e, 0x0a, 0xa7,
	    0x3c, 0xa2, 0x4a,
	0x19, 0x98, 0x1c, 0xf6, 0x5e, 0xbf, 0xc7, 0x73, 0x3d, 0xf8, 0x66, 0x65,
	    0x15, 0xf3, 0x5b,
	0xd1, 0x83, 0xea, 0x0d, 0x62, 0xe5, 0x05, 0xd6, 0x78, 0xf0, 0x6a, 0x3b,
	    0xc4, 0x7c, 0x70,
	0xfb, 0xd9, 0x9a, 0x9a, 0x62, 0xe6, 0xa8, 0x4f, 0x76, 0x27, 0x0f, 0xc3,
	    0x9a, 0x5b, 0x8d,
	0xd4, 0x8c, 0xe0, 0x8e, 0x5a, 0xd8, 0xe4, 0xe7, 0x6a, 0xcd, 0xf3, 0x48,
	    0xdc, 0x93, 0x48,
	0x25, 0x09, 0xed, 0xd5, 0x6c, 0xe5, 0x14, 0x54, 0x88, 0x5d, 0x98, 0xe1,
	    0x0d, 0x6a, 0x23,
	0x0c, 0x05, 0x32, 0x02, 0x24, 0xe5, 0x87, 0x1b, 0x50, 0x53, 0xff, 0x4c,
	    0x7d, 0x11, 0xfa,
	0xe0, 0xd5, 0x3d, 0xe6, 0x89, 0x5b, 0xa0, 0x5b, 0x94, 0x39, 0x6a, 0x20,
	    0x61, 0xc7, 0x4e,
	0xd9, 0xf2, 0x16, 0xf2, 0x11, 0x18, 0x0a, 0xe8, 0xeb, 0xe8, 0x55, 0xde,
	    0x58, 0x97, 0x41,
	0xb9, 0x5b, 0x2a, 0x5f, 0xd9, 0x51, 0xb7, 0x83, 0x85, 0xfc, 0x86, 0x97,
	    0x58, 0x5c, 0x0a,
	0xe9, 0x3d, 0x1a, 0x12, 0xd7, 0xb5, 0xe0, 0x8f, 0x93, 0xbb, 0xd9, 0xb9,
	    0xc2, 0xb1, 0x25,
	0x0d, 0xc1, 0x61, 0x56, 0xc7, 0x96, 0x27, 0x88, 0xb0, 0x7c, 0x2f, 0x1a,
	    0xfa, 0xc5, 0xef,
	0x94, 0x66, 0x6d, 0x0c, 0xf2, 0x6b, 0x86, 0xc2, 0xaa, 0x4f, 0x6a, 0xfb,
	    0x6c, 0x55, 0x0e,
	0x1e, 0x56, 0x46, 0xdb, 0x2a, 0x74, 0xab, 0x03, 0x89, 0x7b, 0xe5, 0xab,
	    0x0f, 0x32, 0x54,
	0x73, 0xe3, 0x3f, 0xe3, 0x48, 0x2d, 0xfa, 0x0c, 0xb6, 0xa6, 0x0d, 0x3c,
	    0xcd, 0x2d, 0x4c,
	0xa6, 0x87, 0xd7, 0x37, 0x64, 0x0c, 0x2b, 0xdc, 0x8a, 0x49, 0x09, 0x37,
	    0x2f, 0x9e, 0xa6,
	0xde, 0xe9, 0x37, 0xe5, 0xf9, 0xd5, 0x6f, 0x6f, 0x49, 0x25, 0xbc, 0xc1,
	    0x8f, 0xe8, 0x45,
	0x86, 0x76, 0x1a, 0x7f, 0x21, 0xed, 0xfd, 0x50, 0xb2, 0x07, 0x2c, 0x2c,
	    0xb7, 0xbe, 0xc3,
	0x66, 0x74, 0x30, 0xb0, 0x02, 0x8e, 0xe9, 0x9b, 0x74, 0x1b, 0x8e, 0xa7,
	    0x05, 0xe6, 0x4c,
	0x0b, 0x57, 0xa2, 0x33, 0xe1, 0x64, 0x9e, 0x4b, 0x18, 0xf8, 0x4f, 0x41,
	    0x60, 0x69, 0x39,
	0xda, 0xd5, 0x8d, 0xf1, 0xd2, 0xbb, 0x3d, 0x30, 0x87, 0xee, 0xba, 0x1f,
	    0xb2, 0x37, 0x9a,
	0x20, 0x07, 0xa9, 0xfd, 0xb7, 0x4b, 0xeb, 0xd0, 0xe9, 0x7c, 0xc8, 0x1d,
	    0xff, 0xf7, 0x95,
	0x57, 0xf8, 0x60, 0x98, 0x4a, 0xd5, 0xf6, 0x8c, 0x99, 0x7d, 0xae, 0xab,
	    0xea, 0x0f, 0x07,
	0x74, 0x30, 0x68, 0x8b, 0x57, 0xe6, 0xed, 0xd5, 0x92, 0x94, 0x82, 0x9e,
	    0x45, 0xa4, 0xec,
	0xaa, 0xb2, 0x20, 0xa5, 0xca, 0xc4, 0x4e, 0x50, 0x07, 0x56, 0x7d, 0x2e,
	    0xe9, 0xc6, 0xe5,
	0x97, 0x8e, 0xdb
};

static int q_len_4096 = sizeof(Q_4096);
