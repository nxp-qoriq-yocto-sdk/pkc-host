static uint8_t C[] = {
    0x0, 0x93, 0xb9, 0xb6, 0xad, 0x56, 0x44, 0xe7, 0x15, 0xaa, 0x60, 0x51, 
    0xf2, 0xb6, 0xcb, 0x15, 0x4c, 0xa8, 0x8d, 0xfa, 0xea, 0xbb, 0x1c, 0xcf, 
    0xac, 0xeb, 0xcc, 0xa5, 0x36, 0xaf, 0xef, 0xa6, 0x44, 0x9d, 0x3e, 0xcb
};

static uint8_t D[] = {
    0x3, 0x75, 0x2b, 0x71, 0xbe, 0x7a, 0x1, 0xf1, 0xb0, 0xc4, 0xd4, 0x45, 
    0xa7, 0x95, 0xd, 0x45, 0xa2, 0xb7, 0xdd, 0x52, 0x9b, 0xd1, 0xc7, 0x25, 
    0x75, 0x64, 0x3e, 0x5b, 0x80, 0x6b, 0x5d, 0x48, 0x88, 0xd1, 0xc3, 0x3b
};

static uint8_t M_283[] = {
    0x3d, 0x72, 0x42, 0x37, 0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9,
    0x30, 0xba, 0x7c, 0xe6, 0xe4, 0xd3, 0x9c, 0x88, 0x3d, 0x72, 0x42, 0x37,
    0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9, 0x30, 0xba, 0x7c, 0xe6
};

/*
static uint8_t M_409[] = {
    0x3d, 0x72, 0x42, 0x37, 0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9,
    0x30, 0xba, 0x7c, 0xe6, 0xe4, 0xd3, 0x9c, 0x88, 0x3d, 0x72, 0x42, 0x37,
    0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9, 0x30, 0xba, 0x7c, 0xe6,
    0xe4, 0xd3, 0x9c, 0x88
};

static int m_409_len = sizeof(M_409);

static uint8_t M_571[] = {
    0x3d, 0x72, 0x42, 0x37, 0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9,
    0x30, 0xba, 0x7c, 0xe6, 0xe4, 0xd3, 0x9c, 0x88, 0x3d, 0x72, 0x42, 0x37,
    0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9, 0x30, 0xba, 0x7c, 0xe6,
    0xe4, 0xd3, 0x9c, 0x88, 0x3d, 0x72, 0x42, 0x37, 0xad, 0xc6, 0x22, 0xeb,
    0x57, 0x4d, 0x87, 0xa9, 0x30, 0xba, 0x7c, 0xe6, 0xe4, 0xd3, 0x9c, 0x88,
    0x3d, 0x72, 0x42, 0x37, 0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9,
    0x30, 0xba, 0x7c, 0xe6, 0xe4, 0xd3, 0x9c, 0x88
};

static int m_571_len = sizeof(M_571);

static uint8_t M_283[] = {
    0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
    0X95, 0XFF, 0XC2, 0X24,
    0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
    0X0E, 0XB4, 0X3A, 0X18,
    0X80, 0X0F, 0X19,
    0X2B, 0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A,
    0X78, 0X27, 0X3D, 0X3C,
    0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
    0X95, 0XFF, 0XC2, 0X24,
    0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
    0X0E, 0XB4, 0X3A, 0X18,
    0X80, 0X0F, 0X19, 0X2B, 0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A,
    0X78, 0X27, 0X3D, 0X3C,
    0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
    0X95, 0XFF, 0XC2, 0X24,
    0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
    0X0E, 0XB4, 0X3A, 0X18,
    0X80, 0X0F, 0X19, 0X2B, 0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A,
    0X78, 0X27, 0X3D, 0X3C,
    0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
    0X95, 0XFF, 0XC2, 0X24,
    0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
    0X0E, 0XB4, 0X3A, 0X18,
    0X80, 0X0F, 0X19, 0X2B, 0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A,
    0X78, 0X27, 0X3D, 0X3C,
    0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
    0X95, 0XFF, 0XC2, 0X24,
    0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
    0X0E, 0XB4, 0X3A, 0X18,
    0X80, 0X0F, 0X19, 0X2B, 0X95, 0XFF, 0XC2, 0X24, 0X30, 0X42, 0X80, 0X8A,
    0X78, 0X27, 0X3D, 0X3C,
    0X0F, 0X67, 0XCB, 0XF2, 0X0E, 0XB4, 0X3A, 0X18, 0X80, 0X0F, 0X19, 0X2B,
    0X95, 0XFF, 0XC2, 0X24,
    0X30, 0X42, 0X80, 0X8A, 0X78, 0X27, 0X3D, 0X3C, 0X0F, 0X67, 0XCB, 0XF2,
    0X0E, 0XB4, 0X3A, 0X18,
    0X80
};
static int m_283_len = sizeof(M_283);

*/

/* *************** For P-283 Buffers *************** */

static uint8_t Q_283[] = {
      0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x10,0xA1
};

static uint8_t AB_283[] = {
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x01,
      0x03, 0xD8, 0xC9, 0x3D, 0x3B, 0x0E, 0xA8, 0x1D,
      0x92, 0x94, 0x03, 0x4D, 0x7E, 0xE3, 0x13, 0x5D, 0x0A, 0xC5,
      0xFC, 0x8D, 0x9C, 0xB0, 0x27, 0x6F, 0x72, 0x11, 0xF8, 0x80,
      0xF0, 0xD8, 0x1C, 0xA4, 0xC6, 0xE8, 0x7B, 0x38
};

static uint8_t G_283[] = { 
      0x05,0xF9,0x39,0x25,0x8D,0xB7,0xDD,0x90,0xE1,0x93,    
      0x4F,0x8C,0x70,0xB0,0xDF,0xEC,0x2E,0xED,0x25,0xB8,
      0x55,0x7E,0xAC,0x9C,0x80,0xE2,0xE1,0x98,0xF8,0xCD,
      0xBE,0xCD,0x86,0xB1,0x20,0x53,
      0x03,0x67,0x68,0x54,0xFE,0x24,0x14,0x1C,0xB9,0x8F,    
      0xE6,0xD4,0xB2,0x0D,0x02,0xB4,0x51,0x6F,0xF7,0x02,
      0x35,0x0E,0xDD,0xB0,0x82,0x67,0x79,0xC8,0x13,0xF0,
      0xDF,0x45,0xBE,0x81,0x12,0xF4
};

static uint8_t R_283[] = {
      0x03,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xEF,0x90,
      0x39,0x96,0x60,0xFC,0x93,0x8A,0x90,0x16,0x5B,0x04,
      0x2A,0x7C,0xEF,0xAD,0xB3,0x07
};

static uint8_t PRIV_KEY_EC_283[] = {
0x02,0xbd,0x30,0x20,0xb8,0xc0,0x98,0x44,0xe5,0x32,0x18,0xe8,0x00,0x86,0x18,
0x60,0xbd,0xa5,0x29,0x2c,0xb4,0x16,0x54,0x29,0x0b,0x8a,0x62,0xd3,0x4e,0x34,
0x56,0x20,0x40,0xb2,0xf5,0x6c
};

static uint8_t PUB_KEY_EC_283[] = { 
0x07,0x7b,0x72,0x5c,0xca,0x89,0x96,0xf4,0xb7,0xf2,0xef,0x6c,0xfa,0xe7,
0x1e,0xb8,0xdd,0xa9,0x8c,0x0a,0xde,0xa1,0x5c,0xb2,0x13,0xca,0x43,0xba,0x3a,
0x48,0xcb,0x78,0x96,0xb1,0xcf,0xa3,0x03,0x60,0x39,0xd8,0x3f,0xbb,0x36,0x5a,
0xe6,0x67,0x4e,0xb3,0xac,0x91,0xf5,0xaa,0x1f,0xf7,0x80,0xc7,0xa8,0x76,0xdf,
0xec,0xa8,0x5b,0x77,0x40,0xef,0xb4,0xd2,0x30,0xba,0xfb,0x80,0x0c
};

/* *************** For P-409 Buffers *************** */
static uint8_t C_409[] = {
0x0, 0x98, 0xa8, 0xf4, 0x9f, 0xdd, 0xa5, 0xc7, 0xbb, 0x65, 0xa5, 0xfe, 0x1, 0x43, 0xb5, 0x70, 0xfd, 0x1c, 0x70, 0x71, 0xd3, 0x81, 0xd3, 0x12, 0xd5, 0xc, 0x47, 0xc7, 0x2, 0x23, 0xc, 0x72, 0xe1, 0x1, 0xde, 0xfa, 0x73, 0x40, 0x24, 0xf8, 0x96, 0x81, 0x5c, 0xce, 0xde, 0x73, 0x2c, 0xe1, 0xe8, 0xb6, 0x97, 0xc6
};

static uint8_t D_409[] = {
0x0, 0xe6, 0x95, 0xaa, 0xd2, 0xcf, 0x60, 0x53, 0xaf, 0x70, 0x9b, 0xac, 0xf, 0x28, 0xc7, 0x7f, 0x7f, 0x6c, 0xce, 0x84, 0x3b, 0xc6, 0x61, 0xe1, 0x84, 0xda, 0x49, 0x55, 0x9c, 0xbd, 0xec, 0x8, 0xe9, 0x76, 0x87, 0xbf, 0xa0, 0x8c, 0x90, 0x71, 0x29, 0x72, 0x89, 0xe7, 0x1, 0xe1, 0x89, 0x38, 0x1c, 0xfa, 0x15, 0x88
};

static uint8_t M_409[] = {
    0x3d, 0x72, 0x42, 0x37, 0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9,
    0x30, 0xba, 0x7c, 0xe6, 0xe4, 0xd3, 0x9c, 0x88, 0x3d, 0x72, 0x42, 0x37,
    0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9, 0x30, 0xba, 0x7c, 0xe6,
    0xe4, 0xd3, 0x9c, 0x88, 0x3d, 0x72, 0x42, 0x37, 0xad, 0xc6, 0x22, 0xeb,
    0x57, 0x4d, 0x87, 0xa9
};

static uint8_t Q_409[] = {
      0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x01
};

static uint8_t AB_409[] = {
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x01,
	  0x01, 0x49, 0xB8, 0xB7, 0xBE, 0xBD, 0x9B, 0x63,
      0x65, 0x3E, 0xF1, 0xCD, 0x8C, 0x6A, 0x5D, 0xD1, 0x05, 0xA2,
      0xAA, 0xAC, 0x36, 0xFE, 0x2E, 0xAE, 0x43, 0xCF, 0x28, 0xCE,
      0x1C, 0xB7, 0xC8, 0x30, 0xC1, 0xEC, 0xDB, 0xFA, 0x41, 0x3A,
      0xB0, 0x7F, 0xE3, 0x5A, 0x57, 0x81, 0x1A, 0xE4, 0xF8, 0x8D,
      0x30, 0xAC, 0x63, 0xFB
};

static uint8_t G_409[] = {
	  0x01,0x5D,0x48,0x60,0xD0,0x88,0xDD,0xB3,0x49,0x6B,   
      0x0C,0x60,0x64,0x75,0x62,0x60,0x44,0x1C,0xDE,0x4A,
      0xF1,0x77,0x1D,0x4D,0xB0,0x1F,0xFE,0x5B,0x34,0xE5,
      0x97,0x03,0xDC,0x25,0x5A,0x86,0x8A,0x11,0x80,0x51,
      0x56,0x03,0xAE,0xAB,0x60,0x79,0x4E,0x54,0xBB,0x79,
      0x96,0xA7,
      0x00,0x61,0xB1,0xCF,0xAB,0x6B,0xE5,0xF3,0x2B,0xBF,    
      0xA7,0x83,0x24,0xED,0x10,0x6A,0x76,0x36,0xB9,0xC5,
      0xA7,0xBD,0x19,0x8D,0x01,0x58,0xAA,0x4F,0x54,0x88,
      0xD0,0x8F,0x38,0x51,0x4F,0x1F,0xDF,0x4B,0x4F,0x40,
      0xD2,0x18,0x1B,0x36,0x81,0xC3,0x64,0xBA,0x02,0x73,
      0xC7,0x06
};

static uint8_t R_409[] = {
      0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xE2,0xAA,0xD6,
      0xA6,0x12,0xF3,0x33,0x07,0xBE,0x5F,0xA4,0x7C,0x3C,
      0x9E,0x05,0x2F,0x83,0x81,0x64,0xCD,0x37,0xD9,0xA2,
      0x11,0x73
};

static uint8_t PRIV_KEY_EC_409[] = 
{
0x00,0xb3,0xf8,0xee,0xbc,0x06,0xeb,0xdd,0x5a,0x33,0xc7,0x2a,0x5e,0x83,0x7a,
0x17,0x91,0xa5,0xc8,0x8f,0x59,0x7c,0x12,0xc5,0x1c,0x71,0x2d,0xec,0x4d,0x88,
0x71,0x3c,0x95,0xf5,0xff,0xfd,0x2b,0xca,0x0f,0xcf,0x65,0xe5,0xca,0xa3,0xc9,
0x56,0x0b,0x81,0xad,0xc7,0x43,0x41
};

static uint8_t PUB_KEY_EC_409[] = 
{
0x00,0x58,0xd0,0x4f,0xee,0xd3,0x94,0x92,0x43,0x5e,0x36,0x19,0x5b,0x00,
0x84,0x98,0x04,0xc3,0x26,0x97,0xa0,0x99,0x02,0x72,0x9d,0x97,0xb9,0x33,0xd0,
0x03,0x04,0xa1,0x24,0x31,0x3d,0x8b,0xa3,0xfb,0x39,0x16,0x3b,0xcb,0x05,0x56,
0x73,0x88,0x27,0x3f,0xd2,0xb4,0x22,0xa5,0x00,0x33,0x7e,0x65,0x95,0xcc,0xc3,
0xeb,0xe3,0x39,0x5b,0xd8,0xa2,0x18,0x27,0x0b,0x3c,0x81,0xab,0xa3,0x26,0xbf,
0xc0,0x28,0x1e,0x7f,0xde,0x51,0x5e,0x60,0xac,0x9f,0xe1,0x0e,0x10,0xce,0xba,
0x61,0x07,0x32,0x8b,0x8d,0xc0,0x82,0xec,0x51,0xb6,0x71,0x85,0x29,0xd4,0xad
};

/* *************** For P-571 Buffers *************** */
static uint8_t C_571[] = {
0x0, 0xb8, 0x38, 0xf, 0xae, 0xb1, 0x1e, 0xf2, 0xc3, 0x85, 0x2e, 0x22, 0x9, 0xcd, 0xfa, 0xa7, 0xe6, 0xe2, 0xa, 0xfb, 0x92, 0x37, 0x27, 0x6a, 0x66, 0x9a, 0xce, 0x88, 0x71, 0xb9, 0x54, 0x9c, 0xf9, 0xc4, 0x9, 0xe0, 0x35, 0x7a, 0x88, 0xe3, 0x12, 0x7c, 0x3d, 0x52, 0x1f, 0x64, 0xc6, 0x79, 0x2e, 0xc8, 0x77, 0xe7, 0xb0, 0xc8, 0x9c, 0xd7, 0x24, 0x88, 0x45, 0x49, 0x71, 0x9, 0x28, 0xba, 0x7a, 0x51, 0xf7, 0xf5, 0x6d, 0xb6, 0x23, 0x5f
};

static uint8_t D_571[] = {
0x3, 0x44, 0xb8, 0xce, 0x3e, 0xce, 0x8c, 0xfc, 0x74, 0x94, 0x23, 0x71, 0x50, 0x55, 0xb6, 0x53, 0x9a, 0xc1, 0x63, 0xdb, 0x48, 0x40, 0x3a, 0x16, 0x25, 0xcd, 0xfb, 0xd5, 0x2, 0x8e, 0xed, 0xf7, 0x14, 0xb7, 0xee, 0xc7, 0x1e, 0x9c, 0xd4, 0xbf, 0xdb, 0xe5, 0xf2, 0xce, 0x58, 0x16, 0x25, 0xf2, 0x9, 0x96, 0xab, 0xf2, 0x64, 0xc8, 0xd1, 0xe5, 0xf9, 0xaf, 0xe, 0xb0, 0xa0, 0x8e, 0xe5, 0x11, 0xc1, 0x2, 0xcb, 0xb8, 0x6, 0x5b, 0x97, 0x3 
};

static int32_t d_571_len = sizeof(D_571);

static uint8_t M_571[] = {
    0x3d, 0x72, 0x42, 0x37, 0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9,
    0x30, 0xba, 0x7c, 0xe6, 0xe4, 0xd3, 0x9c, 0x88, 0x3d, 0x72, 0x42, 0x37,
    0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9, 0x30, 0xba, 0x7c, 0xe6,
    0xe4, 0xd3, 0x9c, 0x88, 0x3d, 0x72, 0x42, 0x37, 0xad, 0xc6, 0x22, 0xeb,
    0x57, 0x4d, 0x87, 0xa9, 0x30, 0xba, 0x7c, 0xe6, 0xe4, 0xd3, 0x9c, 0x88,
    0x3d, 0x72, 0x42, 0x37, 0xad, 0xc6, 0x22, 0xeb, 0x57, 0x4d, 0x87, 0xa9
};

static int m_571_len = sizeof(M_571);

static int8_t Q_571[] = {
      0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x04,0x25
};

static int32_t q_571_len = sizeof(Q_571);

static int8_t AB_571[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x01,
    0x06, 0x39, 0x5D, 0xB2, 0x2A, 0xB5, 0x94, 0xB1,
    0x86, 0x8C, 0xED, 0x95, 0x25, 0x78, 0xB6, 0x53, 0x9F, 0xAB,
    0xA6, 0x94, 0x06, 0xD9, 0xB2, 0x98, 0x61, 0x23, 0xA1, 0x85,
    0xC8, 0x58, 0x32, 0xE2, 0x5F, 0xD5, 0xB6, 0x38, 0x33, 0xD5,
    0x14, 0x42, 0xAB, 0xF1, 0xA9, 0xC0, 0x5F, 0xF0, 0xEC, 0xBD,
    0x88, 0xD7, 0xF7, 0x79, 0x97, 0xF4, 0xDC, 0x91, 0x56, 0xAA,
    0xF1, 0xCE, 0x08, 0x16, 0x46, 0x86, 0xDD, 0xFF, 0x75, 0x11,
    0x6F, 0xBC, 0x9A, 0x7A
};

static int32_t ab_571_len = sizeof(AB_571);

static int8_t G_571[] = {
      0x03,0x03,0x00,0x1D,0x34,0xB8,0x56,0x29,0x6C,0x16,    
      0xC0,0xD4,0x0D,0x3C,0xD7,0x75,0x0A,0x93,0xD1,0xD2,
      0x95,0x5F,0xA8,0x0A,0xA5,0xF4,0x0F,0xC8,0xDB,0x7B,
      0x2A,0xBD,0xBD,0xE5,0x39,0x50,0xF4,0xC0,0xD2,0x93,
      0xCD,0xD7,0x11,0xA3,0x5B,0x67,0xFB,0x14,0x99,0xAE,
      0x60,0x03,0x86,0x14,0xF1,0x39,0x4A,0xBF,0xA3,0xB4,
      0xC8,0x50,0xD9,0x27,0xE1,0xE7,0x76,0x9C,0x8E,0xEC,
      0x2D,0x19,
      0x03,0x7B,0xF2,0x73,0x42,0xDA,0x63,0x9B,0x6D,0xCC,    
      0xFF,0xFE,0xB7,0x3D,0x69,0xD7,0x8C,0x6C,0x27,0xA6,
      0x00,0x9C,0xBB,0xCA,0x19,0x80,0xF8,0x53,0x39,0x21,
      0xE8,0xA6,0x84,0x42,0x3E,0x43,0xBA,0xB0,0x8A,0x57,
      0x62,0x91,0xAF,0x8F,0x46,0x1B,0xB2,0xA8,0xB3,0x53,
      0x1D,0x2F,0x04,0x85,0xC1,0x9B,0x16,0xE2,0xF1,0x51,
      0x6E,0x23,0xDD,0x3C,0x1A,0x48,0x27,0xAF,0x1B,0x8A,
      0xC1,0x5B
};

static int32_t g_571_len = sizeof(G_571);

static int8_t R_571[] = {
      0x03,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xE6,0x61,0xCE,0x18,
      0xFF,0x55,0x98,0x73,0x08,0x05,0x9B,0x18,0x68,0x23,
      0x85,0x1E,0xC7,0xDD,0x9C,0xA1,0x16,0x1D,0xE9,0x3D,
      0x51,0x74,0xD6,0x6E,0x83,0x82,0xE9,0xBB,0x2F,0xE8,
      0x4E,0x47
};

static int32_t r_571_len = sizeof(R_571);

static int8_t PRIV_KEY_EC_571[] = 
{
0x02,0x09,0x60,0x71,0x50,0x34,0xb1,0x4d,0xed,0x6e,0xfc,0xea,0xf0,0x2a,0xdf,
0x20,0x51,0x3f,0x00,0x4c,0xec,0x70,0xde,0x6d,0x25,0x12,0x6c,0x4d,0x36,0x23,
0x36,0x0e,0x7d,0xf3,0x18,0x2d,0x16,0x14,0x28,0xb7,0x2e,0xcd,0x79,0xcd,0xb5,
0x0f,0xfe,0x0f,0x4b,0x44,0xc5,0x9c,0xd1,0x48,0xfe,0x8c,0x51,0xd0,0xe7,0x07,
0x2a,0x4c,0x29,0x9c,0xdc,0x56,0x54,0x32,0x94,0xa6,0x3a,0xf7
};

static int32_t priv_key_ec_571_len = sizeof(PRIV_KEY_EC_571);

static int8_t PUB_KEY_EC_571[] = 
{
0x02,0xda,0x7f,0x03,0xec,0xd4,0x40,0xfc,0x79,0x39,0x4f,0x38,0x49,0xef,
0xf4,0x53,0x4b,0x9a,0x9c,0x50,0xcb,0x9e,0x50,0x40,0xec,0xdb,0xb7,0xb1,0x18,
0x9f,0x9a,0x5f,0xcd,0x37,0x49,0xc6,0xcd,0xf5,0x80,0x6b,0xcb,0xb2,0x51,0x69,
0x7f,0x94,0x1a,0x67,0x3a,0xcc,0x57,0x5d,0x5d,0xc4,0x38,0x92,0x1c,0xcc,0x07,
0xa7,0x35,0xf1,0xae,0x84,0xbc,0x42,0xcf,0x19,0xd3,0x6c,0x89,0xc5,0x06,0x94,
0xb0,0x22,0x64,0x96,0xd2,0xfc,0x36,0x4d,0x91,0x9e,0xa8,0x86,0x8e,0x7c,0x8a,
0x17,0xc0,0xd9,0xa0,0x11,0x0f,0xc4,0xa3,0x07,0x1a,0x68,0x07,0x67,0x59,0x41,
0x3a,0x2e,0xe5,0x5f,0x10,0xa1,0x9e,0xc3,0x15,0xcc,0xf7,0x37,0x1c,0x47,0x84,
0x0d,0xe8,0xba,0x85,0x64,0x07,0xd0,0x95,0xbd,0x0d,0xba,0x45,0x6e,0x75,0x08,
0xe7,0xe4,0x4c,0x2d,0x70,0xb1,0x37,0x4b,0x92,0xd7
};

static int32_t pub_key_ec_571_len = sizeof(PUB_KEY_EC_571);

